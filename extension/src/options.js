// Options page logic.
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const DEFAULTS = {
    githubToken: "",
    annotateLists: true,
    listBudget: 10,
    extraCAs: [],
    discoverAllow: globalThis.Beamsig.discover.DEFAULT_ALLOW,
  };

  function status(msg) {
    $("status").textContent = msg;
    setTimeout(() => {
      if ($("status").textContent === msg) $("status").textContent = "";
    }, 2500);
  }

  // Show the shipped pin so it can be eyeballed against the cluster's own
  // export without trusting anything this page fetched.
  function renderShippedCA() {
    const lines = globalThis.Beamsig.ca.PINNED_CAS.map(
      (c) => `${c.cluster}\n${c.fingerprint}`
    );
    $("shipped-ca").textContent = lines.join("\n\n");
  }

  // Accept Teleport export / authorized_keys / allowed_signers shaped lines.
  // We keep the whole line and let verify.loadPinnedCAs pull the blob out, so
  // the parsing stays in exactly one place.
  function parseExtraCAs(text) {
    const out = [];
    for (const raw of text.split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      if (!/\bAAAA\S+/.test(line)) {
        throw new Error(`no base64 key found in: ${line.slice(0, 48)}…`);
      }
      const m = /clustername=([^&\s]+)/.exec(line);
      out.push({ cluster: m ? m[1] : "user-added", line });
    }
    return out;
  }

  async function load() {
    renderShippedCA();
    const s = await chrome.storage.local.get(DEFAULTS);
    $("githubToken").value = s.githubToken || "";
    $("annotateLists").checked = !!s.annotateLists;
    $("listBudget").value = Number.isFinite(s.listBudget) ? s.listBudget : 10;
    $("discoverAllow").value = (s.discoverAllow || []).join("\n");
    $("extraCAs").value = (s.extraCAs || []).map((c) => c.line).join("\n");
    await renderDiscovered();
  }

  // Discovered CAs are pinned on first use and never overwritten, so show what
  // is pinned, with fingerprints to compare against the cluster out of band.
  async function renderDiscovered() {
    const { wire, discover } = globalThis.Beamsig;
    const all = await chrome.storage.local.get(null);
    const lines = [];
    for (const [k, v] of Object.entries(all)) {
      if (!k.startsWith(discover.PIN_PREFIX)) continue;
      const cluster = k.slice(discover.PIN_PREFIX.length);
      for (const e of discover.parseExport(v.text, cluster)) {
        const blob = wire.b64decode(/\bAAAA\S+/.exec(e.line)[0]);
        const d = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
        lines.push(`${cluster}\nSHA256:${wire.b64encode(d).replace(/=+$/, "")}`);
      }
    }
    $("discovered-ca").textContent = lines.length ? lines.join("\n\n") : "none";
  }

  async function save() {
    let extraCAs;
    try {
      extraCAs = parseExtraCAs($("extraCAs").value);
    } catch (e) {
      status(e.message);
      return;
    }
    const discoverAllow = $("discoverAllow")
      .value.split(/[\s,]+/)
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean);
    const badGlob = discoverAllow.find((d) => !/^[a-z0-9*?.-]+$/.test(d) || !d.includes("."));
    if (badGlob) {
      status(`not a hostname pattern: ${badGlob}`);
      return;
    }
    // Hosts beyond *.beams.sh need permission to fetch from. Chrome only grants
    // it in response to a click, which this is.
    const origins = discoverAllow
      .filter((d) => !/^\*\.beams\.sh$/.test(d) && !d.endsWith(".beams.sh"))
      .map((d) => `https://${d}/*`);
    if (origins.length && chrome.permissions) {
      try {
        const granted = await chrome.permissions.request({ origins });
        if (!granted) {
          status("Permission to contact those hosts was declined; discovery will fail for them.");
          return;
        }
      } catch (e) {
        status(`could not request host permission: ${e.message}`);
        return;
      }
    }
    const budget = Math.max(0, Math.min(100, Number($("listBudget").value) || 0));
    await chrome.storage.local.set({
      githubToken: $("githubToken").value.trim(),
      annotateLists: $("annotateLists").checked,
      listBudget: budget,
      extraCAs,
      discoverAllow,
    });
    $("listBudget").value = budget;
    status("Saved. Reload any open GitHub tab.");
  }

  async function clearCache() {
    const all = await chrome.storage.local.get(null);
    const keys = Object.keys(all).filter((k) => k.startsWith("sig:"));
    if (keys.length) await chrome.storage.local.remove(keys);
    status(`Cleared ${keys.length} cached signature${keys.length === 1 ? "" : "s"}.`);
  }

  async function forgetDiscovered() {
    const all = await chrome.storage.local.get(null);
    const keys = Object.keys(all).filter((k) => k.startsWith(globalThis.Beamsig.discover.PIN_PREFIX));
    if (keys.length) await chrome.storage.local.remove(keys);
    await renderDiscovered();
    status(`Forgot ${keys.length} discovered CA${keys.length === 1 ? "" : "s"}. Reload any open GitHub tab.`);
  }

  $("save").addEventListener("click", save);
  $("forgetDiscovered").addEventListener("click", forgetDiscovered);
  $("clearCache").addEventListener("click", clearCache);
  load();
})();
