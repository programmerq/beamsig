// beamsig content script: find beam signatures on GitHub pages, verify them
// locally against a pinned Teleport CA, and render the result.
//
// GitHub itself cannot verify these commits — it matches SSH signatures only
// against keys a user registered and has no notion of an SSH certificate
// authority, so the native badge reads "Unverified" with reason `unknown_signature_type`.
// We leave GitHub's badge alone and add our own panel next to it, because
// overwriting it would misrepresent what GitHub checked.
(function () {
  "use strict";

  const ns = globalThis.Beamsig;
  const { github, ui, verify, ca } = ns;

  const DONE = "data-beamsig-done";
  const PANEL_ID = "beamsig-panel";

  let lastKey = null;
  let pending = null;

  const log = (...a) => console.debug("[beamsig]", ...a);

  // ---- trust anchors --------------------------------------------------------

  // Shipped pins, then the user's extra CAs, then CAs discovered earlier and
  // pinned on first use (see lib/discover.js). Order does not matter for
  // verification; it is only the set that counts.
  let casPromise = null;

  async function storedDiscoveredPins() {
    try {
      const all = await chrome.storage.local.get(null);
      return Object.entries(all)
        .filter(([k]) => k.startsWith(ns.discover.PIN_PREFIX))
        .flatMap(([k, v]) =>
          ns.discover.parseExport(v.text, k.slice(ns.discover.PIN_PREFIX.length))
        );
    } catch (e) {
      return []; // no storage (e.g. console bundle): nothing was ever pinned
    }
  }

  function loadCAs(settings) {
    if (!casPromise) {
      const extra = (settings.extraCAs || []).map((e) => ({ ...e, userAdded: true }));
      casPromise = storedDiscoveredPins()
        .then((pins) => verify.loadPinnedCAs([...ca.PINNED_CAS, ...extra, ...pins]))
        .catch((e) => {
          casPromise = null;
          throw e;
        });
    }
    return casPromise;
  }

  // ---- discovery ------------------------------------------------------------

  // Fenced (allowlist, TOFU pin): see lib/discover.js, and beamsig/discover.py which it
  // mirrors. Only reached when no known CA matched AND the certificate names a
  // cluster on the user's allowlist.
  class DiscoveryRefused extends Error {}

  const discovering = new Map(); // cluster -> Promise<CAs>, so rows share one fetch

  function askBackground(cluster) {
    return new Promise((resolve, reject) => {
      try {
        chrome.runtime.sendMessage({ type: "beamsig:fetch-ca", cluster }, (res) => {
          if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
          if (!res || !res.ok) return reject(new Error((res && res.error) || "no answer"));
          resolve(res.text);
        });
      } catch (e) {
        reject(e); // e.g. no extension context (console bundle)
      }
    });
  }

  function discoverCluster(cluster, settings) {
    const patterns = settings.discoverAllow || [];
    if (!patterns.length) {
      throw new DiscoveryRefused(
        "discovery is turned off (the discovery allowlist in the extension " +
          "options is empty)"
      );
    }
    if (!ns.discover.allowed(cluster, patterns)) {
      throw new DiscoveryRefused(
        `cluster ${cluster} is not covered by the discovery allowlist ` +
          `[${patterns.join(", ")}]; add its CA in the extension options if you mean to trust it`
      );
    }
    if (!discovering.has(cluster)) {
      const key = ns.discover.PIN_PREFIX + cluster;
      const p = (async () => {
        let existing = null;
        try {
          existing = (await chrome.storage.local.get(key))[key];
        } catch (e) { /* no storage: nothing is pinned */ }
        if (existing) {
          // Already pinned and it did not verify this certificate, so the
          // cluster's CA changed (rotation) or something is wrong. Never
          // silently overwrite a pin.
          throw new DiscoveryRefused(
            `a pin for ${cluster} already exists but did not verify this ` +
              "certificate. The cluster's user CA may have been rotated; confirm " +
              "the new fingerprint out of band, then forget the discovered CA in " +
              "the extension options"
          );
        }
        const text = await askBackground(cluster);
        const entries = ns.discover.parseExport(text, cluster);
        if (!entries.length) throw new Error(`no CA found in ${cluster}'s export`);
        const cas = await verify.loadPinnedCAs(entries);
        try {
          await chrome.storage.local.set({ [key]: { text, fetchedAt: Date.now() } });
        } catch (e) { /* not fatal: it will be rediscovered next time */ }
        casPromise = null; // so the new pin is part of the known set from now on
        return cas;
      })();
      // Failures are not remembered (a transient network error must not stick);
      // a success is, so concurrent rows from one tenant share the result.
      p.catch(() => discovering.delete(cluster));
      discovering.set(cluster, p);
    }
    return discovering.get(cluster);
  }

  // ---- verification ---------------------------------------------------------

  // Returns {state, att?, message?} where state is one of:
  //   "verified"  a beam signature that passed every check
  //   "notbeam"   a valid signature that simply is not a beam signature
  //   "failed"    beam-shaped but a check failed — this one matters
  //   "nosig" | "notsshsig" | "error"
  async function verifyCommit(owner, repo, sha, settings) {
    const record = await github.fetchCommitVerification(owner, repo, sha, settings);
    if (!record.signature) {
      return { state: "nosig", record };
    }
    if (!github.looksLikeSSHSig(record.signature)) {
      return {
        state: "notsshsig",
        record,
        message:
          "This commit is signed, but not with an SSH signature " +
          `(GitHub reports reason "${record.githubReason}"). beamsig only ` +
          "verifies SSHSIG signatures made with a Teleport beam certificate.",
      };
    }

    const cas = await loadCAs(settings);
    const payloadBytes = ns.wire.TE.encode(record.payload || "");
    const ct = github.committerTime(record.payload || "");
    const attempt = (list) =>
      verify.verifySSHSig(record.signature, payloadBytes, list, {
        namespace: "git",
        claimedTime: ct ? ct.timestamp : undefined,
        claimedTimeSource: "git committer date",
      });

    const classify = (e) => {
      const msg = e.message || String(e);
      // Distinguish "this is somebody else's signature, which is fine" from
      // "this looks like a beam signature and something is wrong".
      return { state: verify.NOT_BEAM_CODES.has(e.code) ? "notbeam" : "failed", message: msg, record };
    };

    try {
      return { state: "verified", att: await attempt(cas), record };
    } catch (e) {
      // Only an unknown CA can be helped by discovery, and the cluster named
      // by the certificate is merely where to ask: the unauthenticated claim.
      const cluster = e.code === "untrusted-ca" ? e.clusterHint : "";
      if (!cluster) return classify(e);

      let found;
      try {
        found = await discoverCluster(cluster, settings);
      } catch (de) {
        log("discovery not done", cluster, de.message);
        const r = classify(e);
        r.message += ` (discovery not attempted: ${de.message})`;
        if (!(de instanceof DiscoveryRefused)) r.message = r.message.replace("not attempted", "failed");
        return r;
      }
      try {
        return { state: "verified", att: await attempt(found), record };
      } catch (e2) {
        if (e2.code === "untrusted-ca") {
          // It claims a cluster we were allowed to ask, but that cluster's CA
          // did not sign it. That is not "someone else's signature": it is a
          // false claim.
          return {
            state: "failed",
            message: `certificate claims cluster ${cluster} but is not signed by its CA`,
            record,
          };
        }
        return classify(e2);
      }
    }
  }

  // ---- anchoring ------------------------------------------------------------

  // GitHub's DOM is not a contract, so this is a cascade that always ends up
  // somewhere visible. Verified against github.com in Chrome 152 (Oct 2026) by
  // test/chrome-check.mjs, which prints the chosen anchor and the live DOM.
  //
  // GitHub currently renders the commit header with Primer React and CSS
  // modules, so class names carry a per-build hash suffix:
  //
  //   button.SignedCommitBadge-module__clickableLabel__seodh   <- "Unverified"
  //   div.ml-2
  //   div.CommitAttribution-module__CommitAttributionContainer__I_rfs
  //   div.d-flex.flex-column.gap-2.width-full
  //   div.prc-PageHeader-Description-w-ejP
  //   div.prc-PageHeader-PageHeader-YLwBQ
  //
  // The module *prefix* survives rebuilds; only the hash changes. So we match on
  // the prefix with [class*=…] and never on a full class name. We also prefer a
  // vertical stack container: the panel is ~800px tall and must not be dropped
  // into the inline flex row that holds the attribution text.
  function findAnchor() {
    const badge = document.querySelector('[class*="SignedCommitBadge-module"]');
    if (badge) {
      // Most precise: become the next sibling of the attribution row, inside
      // the header's gap-spaced column. Ordered before the looser matches
      // because `.flex-column` is a generic Primer utility that also matches
      // far outer containers — anchoring on it put the panel below the diff.
      const attribution = badge.closest('[class*="CommitAttribution-module"]');
      if (attribution) {
        return { node: attribution, how: "badge→CommitAttribution", mode: "after" };
      }

      const desc = badge.closest('[class*="PageHeader-Description"]');
      if (desc) return { node: desc, how: "badge→PageHeader-Description", mode: "after" };

      // Generic, and only as a last badge-relative resort: nearest column flex
      // container, so the panel at least stacks rather than landing in a row.
      const column = badge.closest(".flex-column");
      if (column) return { node: column, how: "badge→.flex-column", mode: "append" };
    }

    // Older GitHub and GitHub Enterprise markup.
    const legacy = [
      ".js-commit-signature-status",
      '[data-testid="commit-signature"]',
      '[data-testid="commit-box-header"]',
      '[data-testid="commit-header"]',
      ".commit.full-commit",
      "#browser-commit",
    ];
    for (const sel of legacy) {
      const node = document.querySelector(sel);
      if (node) return { node, how: `legacy:${sel}`, mode: "after" };
    }

    // Last resort before floating: GitHub's verification pill, by its text.
    const wanted = new Set(["Verified", "Unverified", "Partially verified"]);
    for (const e of document.querySelectorAll("span, div, a, summary, button")) {
      if (wanted.has((e.textContent || "").trim())) {
        const column = e.closest(".flex-column");
        if (column) return { node: column, how: "text→.flex-column", mode: "append" };
        const container = e.closest("div, li, section") || e;
        return { node: container, how: "text", mode: "after" };
      }
    }
    return null;
  }

  function mount(node) {
    document.getElementById(PANEL_ID)?.remove();
    node.id = PANEL_ID;
    const anchor = findAnchor();
    if (anchor) {
      log("anchored via", anchor.how, anchor.mode);
      if (anchor.mode === "append") anchor.node.appendChild(node);
      else anchor.node.insertAdjacentElement("afterend", node);
    } else {
      log("no anchor found; using the floating panel");
      node.classList.add("beamsig-floating");
      document.body.appendChild(node);
    }
    // Recorded so test/chrome-check.mjs can report the anchor exactly rather
    // than inferring it from the panel's siblings.
    document.documentElement.setAttribute(
      "data-beamsig-anchor",
      anchor ? `${anchor.how} (${anchor.mode})` : "floating"
    );
  }

  // ---- single commit page ---------------------------------------------------

  // The user may navigate while a verification is in flight; a late result must
  // not paint a panel for a commit they are no longer looking at.
  const isStale = (key) => key !== lastKey;

  async function runCommitPage(ctx, key) {
    const settings = await github.getSettings();
    let result;
    try {
      result = await verifyCommit(ctx.owner, ctx.repo, ctx.sha, settings);
    } catch (e) {
      if (isStale(key)) return;
      const rateLimited = e instanceof github.RateLimited;
      mount(
        ui.failPanel(
          rateLimited ? "Could not check for a beam signature" : "beamsig error",
          e.message,
          null,
          "info"
        )
      );
      return;
    }

    if (isStale(key)) return;
    const fromCache = { fromCache: !!(result.record && result.record.fromCache) };

    switch (result.state) {
      case "verified":
        mount(ui.panel(result.att, fromCache));
        break;
      case "failed":
        mount(
          ui.failPanel(
            "Beam signature did NOT verify",
            result.message,
            fromCache,
            "bad"
          )
        );
        break;
      case "notbeam":
        mount(
          ui.failPanel("Not a beam signature", result.message, fromCache, "info")
        );
        break;
      case "notsshsig":
        mount(
          ui.failPanel("Not an SSH signature", result.message, fromCache, "info")
        );
        break;
      case "nosig":
      default:
        // Nothing to say about an unsigned commit; stay out of the way.
        break;
    }
  }

  // ---- commit list pages ----------------------------------------------------

  // Each row needs its own API call (the list endpoint carries no verification
  // data), so this is budgeted and cached. Signatures are immutable, so a
  // second visit to the same page is free.
  // Budget is per page view, not per run: GitHub streams rows in, so this
  // function runs repeatedly for the same list and the spend has to accumulate
  // or a long page would keep spending `listBudget` calls on every mutation.
  let listSpend = { key: null, count: 0, shas: new Set() };

  async function runListPage(ctx, key) {
    const settings = await github.getSettings();
    if (!settings.annotateLists) return;

    if (listSpend.key !== key) listSpend = { key, count: 0, shas: new Set() };

    // GitHub links the same commit with both an abbreviated and a full sha, so
    // string equality is not enough — "1dfcd52" and "1dfcd52ab…" are the same
    // commit and must not be fetched twice.
    const samePrefix = (a, b) => a.startsWith(b) || b.startsWith(a);
    const alreadySpent = (sha) => {
      for (const s of listSpend.shas) if (samePrefix(s, sha)) return true;
      return false;
    };
    const remaining = settings.listBudget - listSpend.count;
    if (remaining <= 0) return;

    const seen = new Map();
    for (const a of document.querySelectorAll('a[href*="/commit"]')) {
      const parsed = github.parseCommitUrl(a.href);
      if (!parsed) continue;
      if (parsed.owner !== ctx.owner || parsed.repo !== ctx.repo) continue;
      const rowNode =
        a.closest('[data-testid="commit-row-item"], li, .js-commits-list-item') || a;
      if (rowNode.hasAttribute(DONE)) continue;
      // Also skip by sha: GitHub re-renders rows, which drops the DONE marker
      // and would otherwise re-spend the budget on a commit already handled.
      if (alreadySpent(parsed.sha)) continue;
      // Don't double-badge if a previous pass already annotated this link.
      if (a.nextElementSibling?.classList?.contains("beamsig-badge")) continue;
      let dup = false;
      for (const s of seen.keys()) if (samePrefix(s, parsed.sha)) dup = true;
      if (!dup) seen.set(parsed.sha, { sha: parsed.sha, rowNode, a });
    }

    const targets = [...seen.values()].slice(0, remaining);
    if (!targets.length) return;
    log(`annotating ${targets.length} commit row(s)`);

    for (const t of targets) {
      t.rowNode.setAttribute(DONE, "1");
      listSpend.shas.add(t.sha);
      listSpend.count++;
      let result;
      try {
        result = await verifyCommit(ctx.owner, ctx.repo, t.sha, settings);
      } catch (e) {
        if (e instanceof github.RateLimited) {
          log("rate limited; stopping list annotation");
          return;
        }
        continue;
      }
      if (result.state === "verified") {
        t.a.insertAdjacentElement("afterend", ui.badge(result.att));
      } else if (result.state === "failed") {
        t.a.insertAdjacentElement("afterend", ui.badgeFail(result.message));
      }
    }
  }

  // ---- dispatch and SPA navigation -----------------------------------------

  function run() {
    const commit = github.parseCommitUrl(location.href);
    const list = commit ? null : github.parseListUrl(location.href);
    if (!commit && !list) {
      document.getElementById(PANEL_ID)?.remove();
      lastKey = null;
      return;
    }

    const key = commit
      ? `c:${commit.owner}/${commit.repo}@${commit.sha}`
      : `l:${list.owner}/${list.repo}${location.pathname}`;

    // On a commit page one pass is enough. On a list page we re-run as rows
    // stream in; the DONE marker and the page-view budget keep that bounded.
    if (key === lastKey && commit) return;
    lastKey = key;

    (commit ? runCommitPage(commit, key) : runListPage(list, key)).catch((e) =>
      log("unexpected failure", e)
    );
  }

  function schedule() {
    clearTimeout(pending);
    pending = setTimeout(run, 150);
  }

  // GitHub navigates with Turbo and streams content in, so watch all of it.
  for (const ev of ["turbo:load", "turbo:render", "pjax:end", "popstate"]) {
    window.addEventListener(ev, schedule);
  }

  let lastHref = location.href;
  new MutationObserver(() => {
    // Re-run on navigation, and on any DOM change while on a list page, where
    // rows arrive after the initial render.
    if (location.href !== lastHref) {
      lastHref = location.href;
      schedule();
    } else if (github.parseListUrl(location.href)) {
      schedule();
    }
  }).observe(document.documentElement, { childList: true, subtree: true });

  schedule();
})();
