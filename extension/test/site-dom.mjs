// Load the real docs/index.html under jsdom, run the real scripts in the real
// order, and assert the page wires itself up correctly: the terminal paints,
// every verifier case renders the right verdict, the evidence tiers appear, and
// the page never claims the owner signed anything.
//
//   node extension/test/site-dom.mjs
//
// This complements site-verify.mjs, which proves the verification logic. This
// one proves the page's own markup and DOM wiring, which is where a landing
// page actually breaks.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const require = createRequire(
  process.env.JSDOM_DIR ? process.env.JSDOM_DIR + "/" : import.meta.url
);
const { JSDOM } = require("jsdom");

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..");
const docs = join(repo, "docs");

let passed = 0;
let failed = 0;
const ok = (label) => {
  console.log(`  ok   ${label}`);
  passed++;
};
const bad = (label, detail) => {
  console.error(`  FAIL ${label}\n       ${detail}`);
  failed++;
};
const check = (label, cond, detail) => (cond ? ok(label) : bad(label, detail || ""));

const html = readFileSync(join(docs, "index.html"), "utf8");

// https:// so the page's secure-context guard takes the happy path, matching
// GitHub Pages.
const dom = new JSDOM(html, {
  url: "https://example.github.io/beamsig/",
  runScripts: "outside-only",
  pretendToBeVisual: true,
});
const w = dom.window;

// jsdom does not ship several globals that every real browser has. Supply the
// genuine implementations rather than stubs, so the libraries under test take
// their normal code paths.
Object.defineProperty(w, "crypto", { value: globalThis.crypto });
w.TextEncoder = TextEncoder;
w.TextDecoder = TextDecoder;
// Report prefers-reduced-motion. That exercises the accessibility path (the
// terminal must render complete rather than typing) and makes this test
// deterministic instead of racing an 18ms-per-character animation.
w.matchMedia = (query) => ({
  matches: /prefers-reduced-motion/.test(query),
  media: query,
  addEventListener() {},
  removeEventListener() {},
});

// Pull the script sources straight out of the document, so this test fails if
// index.html ever loads them in the wrong order or forgets one.
const srcs = [...dom.window.document.querySelectorAll("script[src]")].map(
  (s) => s.getAttribute("src")
);

console.log("script loading");
check(
  "index.html lists the libraries in dependency order",
  JSON.stringify(srcs) ===
    JSON.stringify([
      "vendor/wire.js",
      "vendor/sshcert.js",
      "vendor/sshsig.js",
      "vendor/sshcrypto.js",
      "vendor/ca.js",
      "vendor/verify.js",
      "vendor/avatar.js",
      "vendor/fixture-data.js",
      "assets/site.js",
    ]),
  JSON.stringify(srcs)
);

for (const src of srcs) {
  try {
    w.eval(readFileSync(join(docs, src), "utf8"));
  } catch (e) {
    bad(`evaluating ${src}`, e.message);
  }
}
check("Beamsig attached to the window", !!w.Beamsig, "globalThis.Beamsig missing");
check("fixtures attached to the window", !!w.BEAMSIG_FIXTURES, "BEAMSIG_FIXTURES missing");

const doc = w.document;
const text = (sel) => (doc.querySelector(sel) || {}).textContent || "";
const settle = () => new Promise((r) => setTimeout(r, 60));

// site.js kicks off the default case asynchronously.
await settle();

console.log("\nhero terminal (prefers-reduced-motion)");
// With reduced motion the whole script must be present, not typed in.
for (let i = 0; i < 40 && !/teleport CA/.test(text("#term-body")); i++) await settle();
const term = text("#term-body");
check("terminal painted output", term.length > 0, "#term-body is empty");
check(
  "terminal names the beam, not the owner, as signer",
  /Good "git" signature for beam-1786bcd6/.test(term),
  term.slice(0, 160)
);
check(
  "terminal renders complete under reduced motion",
  /teleport CA/.test(term),
  "the last scripted line never appeared"
);
check(
  "terminal flags the owner as impersonated",
  /impersonated/.test(term),
  "no impersonation caveat in the terminal"
);
check(
  "terminal flags the window as signer-chosen",
  /window chosen by signer/.test(term),
  "no window caveat in the terminal"
);
check("no blinking cursor is left behind", !doc.querySelector("#term-body .cursor"), "cursor remains");

console.log("\ndefault case renders verified");
check(
  "verdict is 'signature verified'",
  /signature verified/i.test(text("#result")),
  text("#result").slice(0, 200)
);
check(
  "beam id is shown",
  /beam 1786bcd6-04b9-4b9e-ad87-0c13071df7e9/.test(text("#result")),
  "beam id missing from the panel"
);
check(
  "owner is labelled as impersonated, not as the signer",
  /impersonated/i.test(text("#result")),
  "the impersonation label is missing"
);
check(
  "the generic 'root' principal is never surfaced",
  !/\broot\b/.test(text("#result")),
  "the panel leaked the cert principal 'root'"
);

console.log("\nevidence tiers");
const tiers = [...doc.querySelectorAll("#result .tier")].map((n) => n.textContent);
check("attested tier present", tiers.includes("attested"), JSON.stringify(tiers));
check("self-reported tier present", tiers.includes("self-reported"), JSON.stringify(tiers));
check(
  "alias is shown as unavailable and self-reported",
  /beam alias/i.test(text("#result")) && /unavailable/.test(text("#result")),
  "alias row missing"
);
// The per-row label was dropped, so the standing caveat is now the thing that
// has to carry "the signer chose this window". Assert it is actually rendered.
check(
  "the signer-chosen window is still disclosed, via the standing caveat",
  /choose the window shown here/i.test(text("#result")),
  "nothing in the panel discloses that the window is signer-chosen"
);
check(
  "standing caveats are rendered",
  doc.querySelectorAll("#result .note.is-caveat").length === 2,
  `${doc.querySelectorAll("#result .note.is-caveat").length} caveat notes`
);

console.log("\navatar");
const img = doc.querySelector("#result .result-avatar img");
check("avatar image exists", !!img, "no avatar img in the result panel");
if (img) {
  check(
    "avatar is an inline data URI",
    (img.getAttribute("src") || "").startsWith("data:image/svg+xml,"),
    (img.getAttribute("src") || "").slice(0, 40)
  );
  check("avatar is decorative for screen readers", img.getAttribute("alt") === "", "alt not empty");
}

console.log("\nevery case");
const expectations = {
  signed: /signature verified/i,
  tampered: /verification failed/i,
  bareKey: /not a beam signature/i,
  untrustedCa: /not a beam signature/i,
  backdated: /signature verified/i,
};
for (const [name, re] of Object.entries(expectations)) {
  const btn = doc.querySelector(`button[data-case="${name}"]`);
  if (!btn) {
    bad(`case ${name}`, "button missing from the page");
    continue;
  }
  btn.dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  await settle();
  check(`case ${name}`, re.test(text("#result")), text("#result").slice(0, 160));
  if (name === "signed" || name === "backdated") {
    check(
      `case ${name} shows a beam id`,
      /beam 1786bcd6/.test(text("#result")),
      "no beam id rendered"
    );
  }
  check(
    `case ${name} marks its button pressed`,
    btn.getAttribute("aria-pressed") === "true",
    btn.getAttribute("aria-pressed")
  );
}

console.log("\nbackdating is presented honestly");
doc
  .querySelector('button[data-case="backdated"]')
  .dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
await settle();
check(
  "the backdated case still verifies",
  /signature verified/i.test(text("#result")),
  "expected the backdated signature to pass"
);
check(
  "and explains that the time was chosen by the signer",
  /chose|chosen/i.test(text("#result")),
  "no explanation of the chosen window"
);

console.log("\nquickstart copy button");
let copied = null;
Object.defineProperty(w.navigator, "clipboard", {
  configurable: true,
  value: {
    writeText(t) {
      copied = t;
      return Promise.resolve();
    },
  },
});
doc.getElementById("copy-qs").dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
await settle();
check("clipboard received the snippet", typeof copied === "string" && copied.length > 0, String(copied));
if (typeof copied === "string") {
  check("prompts are stripped", !/^\$ /m.test(copied), copied.split("\n")[0]);
  check(
    "the commands survive",
    /git clone/.test(copied) && /install-global\.sh/.test(copied),
    copied
  );
  // The block displays example output; pasting that into a shell would error.
  check(
    "example output is not copied",
    !/beam-1786bcd6/.test(copied),
    "an output line leaked into the clipboard"
  );
  check("comments are kept as context", /# venv/.test(copied), copied);
}

console.log("\ndocument hygiene");
const ids = [...doc.querySelectorAll("[id]")].map((n) => n.id);
const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
check("no duplicate element ids", dupes.length === 0, `duplicates: ${[...new Set(dupes)]}`);
check(
  "page has a single h1",
  doc.querySelectorAll("h1").length === 1,
  `${doc.querySelectorAll("h1").length} h1 elements`
);
check("html has a lang attribute", doc.documentElement.lang === "en", doc.documentElement.lang);
check(
  "every section heading is reachable from the nav",
  [...doc.querySelectorAll(".nav-links a[href^='#']")].every((a) =>
    doc.querySelector(a.getAttribute("href"))
  ),
  "a nav anchor points at no element"
);
check(
  "no local asset reference escapes docs/",
  ![...doc.querySelectorAll("[src],[href]")].some((n) => {
    const v = n.getAttribute("src") || n.getAttribute("href") || "";
    return v.startsWith("../") || v.startsWith("/");
  }),
  "a reference would 404 once Pages serves docs/ as the site root"
);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
