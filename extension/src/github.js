// GitHub page detection and commit-signature retrieval.
//
// We do not clone or shell out: the REST API hands us both halves we need.
//
//   GET /repos/{owner}/{repo}/commits/{sha}
//   { "commit": { "verification": {
//       "verified": false, "reason": "unknown_signature_type",
//       "signature": "-----BEGIN SSH SIGNATURE-----\n…",
//       "payload":   "tree …\nparent …\nauthor …\ncommitter …\n\nmessage\n" }}}
//
// `signature` is the armored SSHSIG and `payload` is the exact signed bytes.
//
// We deliberately ignore `verification.verified`, which is always false for a
// beam commit: GitHub verifies SSH signatures only against keys a user has
// registered and has no notion of an SSH certificate authority, so it reports
// reason `unknown_signature_type`. We re-verify from the signature ourselves.
(function (root) {
  "use strict";

  const ns = (root.Beamsig = root.Beamsig || {});

  const API = "https://api.github.com";
  // Signatures are immutable once a commit exists, so a hit never goes stale.
  const CACHE_PREFIX = "sig:";
  const CACHE_MAX_ENTRIES = 500;

  const SHA_RE = /^[0-9a-f]{7,40}$/i;

  // ---- page detection -------------------------------------------------------

  // /{owner}/{repo}/commit/{sha}
  // /{owner}/{repo}/pull/{n}/commits/{sha}
  function parseCommitUrl(url) {
    const u = new URL(url, location.origin);
    if (u.hostname !== "github.com") return null;
    const p = u.pathname.replace(/\/+$/, "").split("/").filter(Boolean);
    if (p.length < 4) return null;
    const [owner, repo] = p;
    if (p[2] === "commit" && SHA_RE.test(p[3])) {
      return { owner, repo, sha: p[3], kind: "commit" };
    }
    if (p[2] === "pull" && p[4] === "commits" && SHA_RE.test(p[5] || "")) {
      return { owner, repo, sha: p[5], kind: "pr-commit" };
    }
    return null;
  }

  // Pages that list many commits, where we annotate rows instead.
  function parseListUrl(url) {
    const u = new URL(url, location.origin);
    if (u.hostname !== "github.com") return null;
    const p = u.pathname.replace(/\/+$/, "").split("/").filter(Boolean);
    if (p.length < 3) return null;
    const [owner, repo] = p;
    if (p[2] === "commits") return { owner, repo, kind: "commits" };
    if (p[2] === "pull" && p[4] === "commits") return { owner, repo, kind: "pr-commits" };
    return null;
  }

  // ---- settings and cache ---------------------------------------------------

  async function getSettings() {
    const defaults = {
      githubToken: "",
      annotateLists: true,
      listBudget: 10,
      // User-added trust anchors (options page); loadCAs() in content.js reads them.
      extraCAs: [],
      // Discovery allowlist (globs). Defaults to every Beams tenant so it is
      // hands-free; an empty list turns discovery off. See lib/discover.js.
      discoverAllow: ns.discover ? ns.discover.DEFAULT_ALLOW : [],
    };
    try {
      const got = await chrome.storage.local.get(defaults);
      return { ...defaults, ...got };
    } catch (e) {
      return defaults;
    }
  }

  async function cacheGet(key) {
    try {
      const got = await chrome.storage.local.get(CACHE_PREFIX + key);
      return got[CACHE_PREFIX + key] || null;
    } catch (e) {
      return null;
    }
  }

  async function cachePut(key, value) {
    try {
      await chrome.storage.local.set({ [CACHE_PREFIX + key]: value });
      // Prune on roughly 1 write in 25, not every write: it reads the whole
      // store, and the cache only needs to be approximately bounded.
      if (Math.random() > 1 / 25) return;
      const all = await chrome.storage.local.get(null);
      const keys = Object.keys(all).filter((k) => k.startsWith(CACHE_PREFIX));
      if (keys.length > CACHE_MAX_ENTRIES) {
        const oldest = keys
          .map((k) => [k, all[k] && all[k].fetchedAt ? all[k].fetchedAt : 0])
          .sort((x, y) => x[1] - y[1])
          .slice(0, keys.length - CACHE_MAX_ENTRIES)
          .map(([k]) => k);
        await chrome.storage.local.remove(oldest);
      }
    } catch (e) {
      /* a full or unavailable store is not fatal; we just refetch next time */
    }
  }

  // ---- fetch ----------------------------------------------------------------

  class RateLimited extends Error {}

  async function fetchCommitVerification(owner, repo, sha, settings) {
    const key = `${owner}/${repo}@${sha}`;
    const cached = await cacheGet(key);
    if (cached) return { ...cached, fromCache: true };

    const headers = { Accept: "application/vnd.github+json" };
    if (settings && settings.githubToken) {
      headers.Authorization = `Bearer ${settings.githubToken}`;
    }

    let res;
    try {
      res = await fetch(`${API}/repos/${owner}/${repo}/commits/${sha}`, { headers });
    } catch (e) {
      throw new Error(`could not reach the GitHub API: ${e.message}`);
    }

    if (res.status === 403 || res.status === 429) {
      const remaining = res.headers.get("x-ratelimit-remaining");
      if (remaining === "0") {
        const reset = Number(res.headers.get("x-ratelimit-reset") || 0);
        throw new RateLimited(
          "GitHub API rate limit reached" +
            (reset ? ` (resets ${new Date(reset * 1000).toLocaleTimeString()})` : "") +
            ". Add a token in the extension options to raise it."
        );
      }
      throw new Error(`GitHub API refused the request (HTTP ${res.status})`);
    }
    if (res.status === 404) {
      throw new Error(
        "commit not found via the API — a private repository needs a token with " +
          "access to it (extension options)"
      );
    }
    if (!res.ok) throw new Error(`GitHub API returned HTTP ${res.status}`);

    const json = await res.json();
    const v = (json.commit && json.commit.verification) || {};
    const record = {
      sha: json.sha || sha,
      signature: v.signature || null,
      payload: v.payload || null,
      githubVerified: !!v.verified,
      githubReason: v.reason || null,
      committerLogin: (json.committer && json.committer.login) || null,
      htmlUrl: json.html_url || null,
      fetchedAt: Date.now(),
    };
    await cachePut(key, record);
    return record;
  }

  // ---- commit payload helpers ----------------------------------------------

  // Pull the committer timestamp out of the signed payload. This is the value
  // beamsig calls the "git committer date": it is inside the signed bytes, so
  // it cannot be edited after the fact, and we check it against the certificate
  // window. Format: `committer Name <email> <unixtime> <tzoffset>`.
  function committerTime(payload) {
    const head = payload.split("\n\n")[0];
    for (const line of head.split("\n")) {
      if (!line.startsWith("committer ")) continue;
      const parts = line.slice("committer ".length).trim().split(/\s+/);
      if (parts.length < 2) return null;
      const ts = Number(parts[parts.length - 2]);
      if (!Number.isFinite(ts)) return null;
      return {
        timestamp: ts,
        tz: parts[parts.length - 1],
        identity: parts.slice(0, parts.length - 2).join(" "),
      };
    }
    return null;
  }

  function looksLikeSSHSig(signature) {
    return !!signature && signature.includes("BEGIN SSH SIGNATURE");
  }

  ns.github = {
    API,
    RateLimited,
    parseCommitUrl,
    parseListUrl,
    getSettings,
    fetchCommitVerification,
    committerTime,
    looksLikeSSHSig,
    SHA_RE,
  };
})(typeof globalThis !== "undefined" ? globalThis : self);
