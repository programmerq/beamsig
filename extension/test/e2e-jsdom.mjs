// End-to-end test of the content script in jsdom, with a mocked GitHub API and
// chrome.storage. Loads the scripts in manifest order, like Chrome does.
//   cd extension && npm install && npm run test:e2e
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const require = createRequire(process.env.JSDOM_DIR ? process.env.JSDOM_DIR + "/" : import.meta.url);
const { JSDOM } = require("jsdom");

const here = dirname(fileURLToPath(import.meta.url));
const ext = join(here, "..");
const repo = join(ext, "..");
const manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8"));
const scripts = manifest.content_scripts[0].js;
const fx = (p) => readFileSync(join(repo, "fixtures", p), "utf8");

const GOOD = fx("sig-from-cert.sig"), MSG = fx("msg.txt"), BARE = fx("sig-from-key.sig");
let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? pass++ : fail++; console.log(`  ${c ? "ok  " : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const COMMITS = {
  good: { signature: GOOD, payload: MSG, verified: false, reason: "unknown_signature_type" },
  tampered: { signature: GOOD, payload: MSG + "x", verified: false, reason: "unknown_signature_type" },
  bare: { signature: BARE, payload: MSG, verified: false, reason: "unknown_key" },
  pgp: { signature: "-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----", payload: "x", verified: true, reason: "valid" },
  unsigned: { signature: null, payload: null, verified: false, reason: "unsigned" },
};
const SHAS = { good: "a".repeat(40), tampered: "b".repeat(40), bare: "c".repeat(40), pgp: "d".repeat(40), unsigned: "e".repeat(40) };
const bySha = Object.fromEntries(Object.entries(SHAS).map(([k, v]) => [v, k]));

const OTHER_CA = "cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIkK4nb+naLyVCXVigbNvs727vk63PRkkMwknE6R3xJTjRJzDg+cWgF09Ah5ivkrIkRfz7bY4xR4jA4ouI/vPK4= clustername=other.beams.sh&type=user";
const REAL_CA = fx("teleport-user-ca.txt").trim();

// `pinOther`: pin an unrelated CA, so only an on-demand fetch can verify.
// `exportFor(cluster)`: what the background worker would return for it.
async function page(url, html, { status, store = {}, slow = [], pinOther = false, exportFor } = {}) {
  const dom = new JSDOM(`<!doctype html><body>${html}</body>`, { url, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  Object.defineProperty(w, "crypto", { value: globalThis.crypto });
  w.TextEncoder = TextEncoder; w.TextDecoder = TextDecoder;
  const calls = [];
  w.fetch = async (u) => {
    calls.push(u);
    const m = /commits\/([0-9a-f]+)$/.exec(u);
    if (slow.includes(bySha[m[1]])) await sleep(900);
    if (status) return { status, ok: status < 400, headers: { get: (h) => (h === "x-ratelimit-remaining" ? "0" : null) }, json: async () => ({}) };
    const c = COMMITS[bySha[m[1]]];
    if (!c) return { status: 404, ok: false, headers: { get: () => null }, json: async () => ({}) };
    return { status: 200, ok: true, headers: { get: () => null }, json: async () => ({ sha: m[1], commit: { verification: c }, committer: { login: "x" }, html_url: "u" }) };
  };
  w.chrome = { storage: { local: {
    // Like the real API: an object argument returns ONLY the keys it names (with
    // those values as defaults). Returning the whole store here hid a bug where
    // getSettings() silently dropped extraCAs.
    get: async (k) => (k === null ? { ...store } : typeof k === "string" ? { [k]: store[k] }
      : Object.fromEntries(Object.entries(k).map(([key, d]) => [key, key in store ? store[key] : d]))),
    set: async (o) => Object.assign(store, o), remove: async () => {} } } };
  const asked = [];
  w.chrome.runtime = {
    lastError: null,
    sendMessage: (msg, cb) => {
      asked.push(msg.cluster);
      const text = exportFor ? exportFor(msg.cluster) : null;
      setTimeout(() => cb(text === null ? { ok: false, error: "unreachable" } : { ok: true, text }), 5);
    },
  };
  for (const s of scripts) {
    w.eval(readFileSync(join(ext, s), "utf8"));
    if (pinOther && s.endsWith("ca.js") && !s.endsWith("discover.js")) {
      w.Beamsig.ca.PINNED_CAS.splice(0, 1, { cluster: "other.beams.sh", line: OTHER_CA });
    }
  }
  await sleep(700);
  return { w, d: w.document, calls, store, asked };
}

const HEADER = `<div class="d-flex flex-column"><div class="CommitAttribution-module__c__h">by me
  <button class="SignedCommitBadge-module__x__abc">Unverified</button></div></div>`;
const T = (p) => p.d.getElementById("beamsig-panel")?.textContent || "";

console.log("\nverified beam commit");
let p = await page(`https://github.com/o/r/commit/${SHAS.good}`, HEADER);
ok("panel mounted", !!p.d.getElementById("beamsig-panel"));
ok("anchored after CommitAttribution", p.d.querySelector('[class*="CommitAttribution"]').nextElementSibling?.id === "beamsig-panel");
ok("shows beam id", T(p).includes("1786bcd6-04b9-4b9e-ad87-0c13071df7e9"));
ok("owner labelled not the signer", T(p).includes("NOT the signer"));
ok("alias unavailable", T(p).includes("unavailable"));
ok("sandbox caveat shown", T(p).includes("SANDBOX"));
ok("GitHub badge untouched", p.d.querySelector('[class*="SignedCommitBadge"]').textContent === "Unverified");
ok("cache populated", Object.keys(p.store).some((k) => k.startsWith("sig:")));
const p2 = await page(`https://github.com/o/r/commit/${SHAS.good}`, HEADER, { store: p.store });
ok("2nd view served from cache, no fetch", p2.calls.length === 0 && T(p2).includes("cached"));

console.log("\nnegative / other states");
p = await page(`https://github.com/o/r/commit/${SHAS.tampered}`, HEADER);
ok("tampered => 'did NOT verify'", T(p).includes("did NOT verify") && p.d.querySelector(".beamsig-bad"));
p = await page(`https://github.com/o/r/commit/${SHAS.bare}`, HEADER);
ok("bare key => not a beam signature (info)", T(p).includes("Not a beam signature") && p.d.querySelector(".beamsig-info"), T(p));
p = await page(`https://github.com/o/r/commit/${SHAS.pgp}`, HEADER);
ok("PGP => not an SSH signature", T(p).includes("Not an SSH signature"));
p = await page(`https://github.com/o/r/commit/${SHAS.unsigned}`, HEADER);
ok("unsigned => no panel", !p.d.getElementById("beamsig-panel"));
p = await page(`https://github.com/o/r/commit/${SHAS.good}`, HEADER, { status: 403 });
ok("rate limit => info panel mentioning token", T(p).includes("rate limit") && T(p).includes("token"), T(p));
p = await page(`https://github.com/o/r/commit/${SHAS.good}`, HEADER, { status: 404 });
ok("404 => private repo hint", T(p).includes("private"), T(p));
p = await page(`https://github.com/o/r/commit/${"f".repeat(40)}`, HEADER);
ok("unknown sha => error panel", T(p).includes("beamsig error"), T(p));

console.log("\nanchoring fallback");
p = await page(`https://github.com/o/r/commit/${SHAS.good}`, `<div>nothing</div>`);
ok("floating panel when no anchor", p.d.getElementById("beamsig-panel")?.classList.contains("beamsig-floating"));

console.log("\nnon-commit pages");
p = await page(`https://github.com/o/r`, HEADER);
ok("repo root: nothing", !p.d.getElementById("beamsig-panel") && p.calls.length === 0);

console.log("\ncommit list");
const rows = Object.values(SHAS).map((s) => `<li><a href="/o/r/commit/${s}">msg ${s.slice(0,7)}</a></li>`).join("");
p = await page(`https://github.com/o/r/commits/main`, `<ul>${rows}</ul>`);
const badges = [...p.d.querySelectorAll(".beamsig-badge")];
ok("one ok badge + one fail badge", p.d.querySelectorAll(".beamsig-badge-ok").length === 1 && p.d.querySelectorAll(".beamsig-badge-bad").length === 1, `${badges.length}`);
ok("each commit fetched once", p.calls.length === 5, `${p.calls.length}`);
p = await page(`https://github.com/o/r/commits/main`, `<ul>${rows}</ul>`, { store: { listBudget: 2 } });
ok("list budget respected", p.calls.length === 2, `${p.calls.length}`);
p = await page(`https://github.com/o/r/commits/main`, `<ul>${rows}</ul>`, { store: { annotateLists: false } });
ok("annotateLists=false => no calls", p.calls.length === 0);

console.log("\nSPA navigation");
p = await page(`https://github.com/o/r`, HEADER);
p.w.history.pushState({}, "", `/o/r/commit/${SHAS.good}`);
p.d.body.insertAdjacentHTML("beforeend", HEADER); // Turbo swaps the DOM
await sleep(700);
ok("pushState to commit page => panel", !!p.d.getElementById("beamsig-panel"));
p.w.history.pushState({}, "", `/o/r`);
p.d.body.insertAdjacentHTML("beforeend", "<p>x</p>");
await sleep(700);
ok("navigating away removes panel", !p.d.getElementById("beamsig-panel"));

console.log("\ndiscovery (on for *.beams.sh by default, allowlisted, pinned on first use)");
const ALLOW = {}; // defaults: *.beams.sh
const GOODURL = `https://github.com/o/r/commit/${SHAS.good}`;
const serve = (c) => (c === "jeff.beams.sh" ? REAL_CA : null);

p = await page(GOODURL, HEADER, { pinOther: true, exportFor: serve });
ok("ON by default for *.beams.sh, no setup", p.asked.join() === "jeff.beams.sh" && T(p).includes("Signed by beam"), `${p.asked} ${T(p).slice(0, 80)}`);
p = await page(GOODURL, HEADER, { pinOther: true, exportFor: serve, store: { discoverAllow: [] } });
ok("an empty allowlist turns it off: nothing is fetched", p.asked.length === 0);
ok("...and the panel says discovery is turned off", T(p).includes("Not a beam signature") && T(p).includes("turned off"), T(p));

p = await page(GOODURL, HEADER, { pinOther: true, exportFor: serve, store: { ...ALLOW } });
ok("asked the cluster named in the cert", p.asked.join() === "jeff.beams.sh", p.asked.join());
ok("verifies against the discovered CA", T(p).includes("Signed by beam"), T(p).slice(0, 120));
ok("reports it as DISCOVERED, not operator-pinned", T(p).includes("discovered from jeff.beams.sh") && T(p).includes("NOT operator-pinned"));
ok("pinned on first use (persisted)", Object.keys(p.store).includes("pin:jeff.beams.sh"));
const pinned = { ...p.store };
p = await page(GOODURL, HEADER, { pinOther: true, exportFor: () => null, store: { ...pinned, discoverAllow: [] } });
ok("next view uses the stored pin, with discovery turned off", p.asked.length === 0 && T(p).includes("Signed by beam") && T(p).includes("discovered from"), T(p).slice(0, 100));

p = await page(GOODURL, HEADER, { pinOther: true, exportFor: () => REAL_CA, store: { ...ALLOW, "pin:jeff.beams.sh": { text: OTHER_CA.replace("other", "jeff"), fetchedAt: 1 } } });
ok("an existing pin that does not verify is NEVER overwritten", p.asked.length === 0 && p.store["pin:jeff.beams.sh"].fetchedAt === 1, `${p.asked}`);
ok("...and the panel points at rotation", T(p).includes("may have been rotated"), T(p));

p = await page(GOODURL, HEADER, { pinOther: true, exportFor: () => null, store: { ...ALLOW } });
ok("unreachable cluster => info panel, says discovery failed", T(p).includes("Not a beam signature") && T(p).includes("discovery failed"), T(p));
ok("...and nothing is pinned", !Object.keys(p.store).some((k) => k.startsWith("pin:")));
p = await page(GOODURL, HEADER, { pinOther: true, exportFor: () => OTHER_CA.replace("other", "jeff"), store: { ...ALLOW } });
ok("cluster serves a different CA => FAILED (false claim)", T(p).includes("did NOT verify") && T(p).includes("claims cluster"), T(p));
p = await page(GOODURL, HEADER, { pinOther: true, exportFor: serve, store: { discoverAllow: ["*.example.com"] } });
ok("cluster outside the allowlist is never contacted", p.asked.length === 0 && T(p).includes("not covered by the discovery allowlist"), `${p.asked}`);
p = await page(GOODURL, HEADER);
ok("a matching shipped pin is preferred: no discovery", p.asked.length === 0 && !T(p).includes("discovered"));

console.log("\nuser-added CAs from the options page");
p = await page(`https://github.com/o/r/commit/${SHAS.good}`, HEADER, {
  pinOther: true, exportFor: () => null,
  store: { extraCAs: [{ cluster: "jeff.beams.sh", line: REAL_CA }] },
});
ok("extraCAs saved in options are used", T(p).includes("Signed by beam"), T(p).slice(0, 120));
ok("and flagged as a user-added trust anchor", T(p).includes("added in the extension's options"));

console.log("\nstale result after navigation");
p = await page(`https://github.com/o/r`, HEADER, { slow: ["good"] });
p.w.history.pushState({}, "", `/o/r/commit/${SHAS.good}`);
p.d.body.insertAdjacentHTML("beforeend", HEADER);
await sleep(400); // verification now in flight
p.w.history.pushState({}, "", `/o/r`);
p.d.body.insertAdjacentHTML("beforeend", "<p>x</p>");
await sleep(1500);
ok("late result for a page we left paints nothing", !p.d.getElementById("beamsig-panel"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
