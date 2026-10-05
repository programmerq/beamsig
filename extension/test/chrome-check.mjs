// Check the extension against a real GitHub commit page in Chrome, and report
// whether the panel mounted and which DOM anchor it used.
//
//   node extension/test/chrome-check.mjs [url]
//   BEAMSIG_HEADFUL=1 node extension/test/chrome-check.mjs   # watch it happen
//
// GitHub's DOM is not a contract, so findAnchor() is the one part of this
// extension that cannot be tested headlessly. This drives Chrome over the
// DevTools protocol, injects the content scripts into a live commit page, and
// dumps both the panel placement and the surrounding DOM.
//
// Why inject instead of loading the extension properly: Chrome no longer honours
// --load-extension, and the CDP Extensions.loadUnpacked replacement is refused
// on a machine whose policy disables unpacked extensions. Injection runs the
// exact same files in the same page context. The one difference is that
// chrome.storage is absent, so github.js falls back to its defaults — which it
// already does by design, via try/catch.
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const extDir = join(here, "..");
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PORT = Number(process.env.BEAMSIG_PORT || 9224);
const URL_ =
  process.argv[2] || "https://github.com/programmerq/beamsig/commit/1dfcd52";
const HEADLESS = process.env.BEAMSIG_HEADFUL ? [] : ["--headless=new"];

const SCRIPTS = [
  "src/lib/wire.js",
  "src/lib/sshcert.js",
  "src/lib/sshsig.js",
  "src/lib/sshcrypto.js",
  "src/lib/ca.js",
  "src/lib/verify.js",
  "src/lib/discover.js",
  "src/lib/avatar.js",
  "src/github.js",
  "src/ui.js",
  "src/content.js",
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const chrome = spawn(
  CHROME,
  [
    ...HEADLESS,
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=/tmp/beamsig-chrome-${PORT}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1500,2000",
    "about:blank",
  ],
  { stdio: ["ignore", "ignore", "pipe"] }
);
let chromeErr = "";
chrome.stderr.on("data", (d) => (chromeErr += d.toString()));

const cleanup = (code) => {
  try {
    chrome.kill("SIGTERM");
  } catch (e) {}
  process.exit(code);
};

// ---- CDP -------------------------------------------------------------------

async function pageTarget() {
  for (let i = 0; i < 60; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const p = list.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
      if (p) return p;
    } catch (e) {
      /* not up yet */
    }
    await sleep(500);
  }
  return null;
}

const target = await pageTarget();
if (!target) {
  console.error("Chrome never exposed a page target.");
  console.error(chromeErr.split("\n").slice(0, 10).join("\n"));
  cleanup(1);
}

const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((res, rej) => {
  ws.addEventListener("open", res, { once: true });
  ws.addEventListener("error", rej, { once: true });
});

let nextId = 1;
const waiters = new Map();
const consoleLines = [];
const pageErrors = [];

ws.addEventListener("message", (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && waiters.has(msg.id)) {
    const { resolve, reject } = waiters.get(msg.id);
    waiters.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    return;
  }
  if (msg.method === "Runtime.consoleAPICalled") {
    const text = (msg.params.args || [])
      .map((a) => (a.value !== undefined ? a.value : a.description || a.type))
      .join(" ");
    consoleLines.push(`[${msg.params.type}] ${text}`);
  }
  if (msg.method === "Runtime.exceptionThrown") {
    const d = msg.params.exceptionDetails;
    pageErrors.push(d.exception?.description || d.text);
  }
});

const send = (method, params = {}) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    waiters.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });

async function evaluate(expression) {
  const r = await send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (r.exceptionDetails) {
    throw new Error(r.exceptionDetails.exception?.description || "eval failed");
  }
  return r.result.value;
}

await send("Runtime.enable");
await send("Page.enable");

// BEAMSIG_THEME=light|dark forces the colour scheme, so both themes can be
// checked; headless Chrome picks dark on its own.
if (process.env.BEAMSIG_THEME) {
  await send("Emulation.setEmulatedMedia", {
    features: [{ name: "prefers-color-scheme", value: process.env.BEAMSIG_THEME }],
  });
}

const loaded = new Promise((res) => {
  const h = (m) => {
    if (JSON.parse(m.data).method === "Page.loadEventFired") {
      ws.removeEventListener("message", h);
      res();
    }
  };
  ws.addEventListener("message", h);
});
await send("Page.navigate", { url: URL_ });
await loaded;
await sleep(2500); // let GitHub's client-side rendering settle

// ---- what does the page look like BEFORE we touch it? ----------------------

const before = await evaluate(
  readFileSync(join(here, "probe-dom.js"), "utf8") + "\nprobeDom();"
);

// ---- inject the content scripts -------------------------------------------

await evaluate(
  "(() => { const s = document.createElement('style'); s.textContent = " +
    JSON.stringify(readFileSync(join(extDir, "src/content.css"), "utf8")) +
    "; document.head.appendChild(s); })()"
);

for (const f of SCRIPTS) {
  try {
    await evaluate(readFileSync(join(extDir, f), "utf8"));
  } catch (e) {
    console.error(`injecting ${f} failed: ${e.message}`);
    cleanup(1);
  }
}

await sleep(5000); // debounce + GitHub API round trip + verification

const after = await evaluate(`(() => {
  const out = {};
  out.libLoaded = typeof globalThis.Beamsig;
  out.anchor = document.documentElement.getAttribute('data-beamsig-anchor');
  const panel = document.getElementById('beamsig-panel');
  out.panelMounted = !!panel;
  if (!panel) return out;
  out.floating = panel.classList.contains('beamsig-floating');
  out.classes = panel.className;
  out.heading = panel.querySelector('.beamsig-head-title')?.textContent || null;
  out.sub = panel.querySelector('.beamsig-head-sub')?.textContent || null;
  out.sections = [...panel.querySelectorAll('.beamsig-section-title')].map(e => e.textContent);
  out.rows = [...panel.querySelectorAll('.beamsig-row')].map(r => ({
    label: r.querySelector('.beamsig-label')?.textContent,
    value: r.querySelector('.beamsig-value')?.textContent,
    note: r.querySelector('.beamsig-note')?.textContent || null,
  }));
  out.caveats = [...panel.querySelectorAll('.beamsig-caveat')].map(e => e.textContent);
  out.warnings = [...panel.querySelectorAll('.beamsig-warning')].map(e => e.textContent);
  const prev = panel.previousElementSibling;
  const desc = (e) => e ? e.tagName.toLowerCase()
    + (e.getAttribute('data-testid') ? '[data-testid=' + e.getAttribute('data-testid') + ']' : '')
    + (e.getAttribute('class') ? '.' + e.getAttribute('class').trim().split(/\\s+/).slice(0,2).join('.') : '')
    : null;
  out.insertedAfter = desc(prev);
  out.parent = desc(panel.parentElement);
  const r = panel.getBoundingClientRect();
  out.rect = { top: Math.round(r.top), left: Math.round(r.left), w: Math.round(r.width), h: Math.round(r.height) };
  out.visible = r.width > 0 && r.height > 0;
  return out;
})()`);

// Commit-list pages get compact badges instead of a panel.
const badges = await evaluate(`(() => {
  const found = [...document.querySelectorAll('.beamsig-badge')];
  return {
    count: found.length,
    items: found.slice(0, 12).map(b => {
      const r = b.getBoundingClientRect();
      return {
        text: (b.textContent || '').trim(),
        ok: b.classList.contains('beamsig-badge-ok'),
        title: (b.title || '').split('\\n')[0],
        visible: r.width > 0 && r.height > 0,
        after: b.previousElementSibling
          ? b.previousElementSibling.tagName.toLowerCase() +
            ':' + (b.previousElementSibling.textContent || '').trim().slice(0, 32)
          : null,
      };
    }),
  };
})()`);

// ---- report ----------------------------------------------------------------

const line = (k, v) => console.log(`  ${String(k).padEnd(16)} ${v}`);

console.log(`\npage   ${URL_}`);
console.log(`chrome ${process.env.BEAMSIG_HEADFUL ? "headful" : "headless=new"}\n`);

console.log("anchor selectors in content.js, against today's GitHub");
for (const p of before.selectorProbe) line(p.found ? "FOUND" : "absent", p.sel);

console.log("\nGitHub's own signature badge");
if (!before.badge) {
  console.log("  (no SignedCommitBadge element found)");
} else {
  line("text", JSON.stringify(before.badge.text));
  line("element", `<${before.badge.tag}> class="${before.badge.cls}"`);
  console.log("  ancestor chain:");
  for (const [i, a] of before.chain.entries()) {
    console.log(
      `    ${String(i).padStart(2)}  <${a.tag}>` +
        (a.id ? ` id=${a.id}` : "") +
        (a.testid ? ` data-testid=${a.testid}` : "") +
        (a.cls ? ` class="${a.cls}"` : "") +
        `  (${a.kids} children)`
    );
  }
}

console.log("\nstable-looking hooks near the badge");
for (const h of before.stableHooks) {
  line(h.found ? `FOUND x${h.count}` : "absent", h.sel);
}

console.log("\ndata-testid values on the page");
console.log("  " + (before.testIds.join(", ") || "(none)"));

console.log("\npanel");
line("libraries", after.libLoaded);
line("mounted", after.panelMounted ? "yes" : "NO");
if (after.panelMounted) {
  line("anchored via", after.anchor);
  line("placement", after.floating ? "FLOATING FALLBACK" : "inline");
  line("inserted after", after.insertedAfter || "(nothing)");
  line("parent", after.parent);
  line("rect", JSON.stringify(after.rect));
  line("visible", after.visible ? "yes" : "NO (zero size)");
  line("heading", after.heading);
  line("subheading", after.sub);
  console.log(`\n  sections: ${after.sections.join(" | ")}`);
  console.log("  rows:");
  for (const r of after.rows) {
    console.log(`    ${String(r.label).padEnd(19)} ${r.value}`);
    if (r.note) console.log(`    ${" ".repeat(19)} ${r.note}`);
  }
  if (after.caveats.length) {
    console.log("  caveats:");
    for (const c of after.caveats) console.log(`    ! ${c.slice(0, 100)}…`);
  }
  if (after.warnings.length) {
    console.log("  warnings:");
    for (const c of after.warnings) console.log(`    ! ${c}`);
  }
}

console.log("\ncommit-list badges");
line("count", badges.count);
for (const b of badges.items) {
  console.log(
    `  ${b.ok ? "ok " : "BAD"} "${b.text}"${b.visible ? "" : "  (ZERO SIZE)"}` +
      (b.after ? `  after ${b.after}` : "")
  );
}

const beamLines = consoleLines.filter((l) => l.includes("beamsig"));
if (beamLines.length) {
  console.log("\npage console");
  for (const l of beamLines) console.log("  " + l);
}
if (pageErrors.length) {
  console.log("\nuncaught page errors");
  for (const e of pageErrors.slice(0, 5)) console.log("  " + e.split("\n")[0]);
}

// Two screenshots: the panel on its own (readable), and the whole page (for
// placement). A full-page capture of a long diff is useless for judging the
// panel itself, so the clipped one is the default artifact.
async function shoot(name, clip) {
  try {
    const shot = await send("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: true,
      ...(clip ? { clip: { ...clip, scale: 1 } } : {}),
    });
    const out = join(here, name);
    writeFileSync(out, Buffer.from(shot.data, "base64"));
    console.log(`screenshot: ${out}`);
  } catch (e) {
    console.log(`screenshot ${name} failed: ${e.message}`);
  }
}

console.log();
if (after.panelMounted && after.rect) {
  const pad = 12;
  // getBoundingClientRect is viewport-relative; clip wants page coordinates.
  const scrollY = await evaluate("window.scrollY");
  const scrollX = await evaluate("window.scrollX");
  await shoot("chrome-check-panel.png", {
    x: Math.max(0, after.rect.left + scrollX - pad),
    y: Math.max(0, after.rect.top + scrollY - pad),
    width: after.rect.w + pad * 2,
    height: after.rect.h + pad * 2,
  });
}
await shoot("chrome-check.png");

console.log();
// A commit page should mount an inline, visible panel; a list page should
// produce at least one badge. Either is a pass.
const panelOk = after.panelMounted && after.visible && !after.floating;
cleanup(panelOk || badges.count > 0 ? 0 : 1);
