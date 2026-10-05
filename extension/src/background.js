// Background worker: fetches a Teleport cluster's user CA on behalf of the
// content script, for CA discovery (see lib/discover.js).
//
// It has to live here. A content script's fetch() is subject to the CORS rules
// of the github.com page it runs in, and `/webapi/auth/export` sends no CORS
// headers; a worker with host permission is not subject to them.
//
// It does one thing, and re-checks the allowlist itself rather than trusting the
// message: a compromised or confused page script must not be able to turn this
// into a general-purpose fetch proxy.
/* global importScripts */
if (typeof importScripts === "function") importScripts("lib/discover.js");

(function () {
  "use strict";

  const { discover } = globalThis.Beamsig;
  const TIMEOUT_MS = 10000;

  async function fetchCA(cluster) {
    const got = await chrome.storage.local.get({ discoverAllow: discover.DEFAULT_ALLOW });
    if (!discover.allowed(cluster, got.discoverAllow)) {
      throw new Error(`${cluster} is not covered by the discovery allowlist`);
    }
    // No cookies, and no redirects: a redirect would move the trust anchor to a
    // host the allowlist never saw.
    const res = await fetch(discover.exportUrl(cluster), {
      credentials: "omit",
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`${cluster} answered HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > discover.MAX_EXPORT_BYTES) {
      throw new Error("CA export is unexpectedly large");
    }
    return text;
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || msg.type !== "beamsig:fetch-ca") return false;
    // Only our own content scripts, running on github.com.
    const url = (sender.tab && sender.tab.url) || "";
    if (sender.id !== chrome.runtime.id || !url.startsWith("https://github.com/")) {
      sendResponse({ ok: false, error: "unexpected sender" });
      return false;
    }
    fetchCA(msg.cluster).then(
      (text) => sendResponse({ ok: true, text }),
      (e) => sendResponse({ ok: false, error: e.message || String(e) })
    );
    return true; // answer asynchronously
  });
})();
