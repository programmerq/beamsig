// The landing page (docs/) loads copies of the extension's libraries, because
// GitHub Pages serving /docs cannot reach ../extension/src/lib/. This asserts
// the copies are byte-identical to the originals, so editing a library without
// re-syncing fails loudly instead of silently leaving a stale page in
// production.
//
//   node extension/test/site-sync.mjs
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..");

const LIBS = [
  "wire.js",
  "sshcert.js",
  "sshsig.js",
  "sshcrypto.js",
  "ca.js",
  "verify.js",
  "avatar.js",
];

// bin/sync-site-libs.sh prepends a provenance header ending in this line.
const SENTINEL = "// --- BEGIN VERBATIM COPY ---\n";
const RESYNC = "bin/sync-site-libs.sh";

let failed = 0;
const fail = (msg) => {
  console.error(`  FAIL  ${msg}`);
  failed++;
};

console.log("docs/vendor is in sync with extension/src/lib");

for (const f of LIBS) {
  const srcPath = join(repo, "extension", "src", "lib", f);
  const dstPath = join(repo, "docs", "vendor", f);

  if (!existsSync(dstPath)) {
    fail(`docs/vendor/${f} is missing — run ${RESYNC}`);
    continue;
  }

  const src = readFileSync(srcPath, "utf8");
  const dst = readFileSync(dstPath, "utf8");

  const at = dst.indexOf(SENTINEL);
  if (at === -1) {
    fail(`docs/vendor/${f} has no provenance header — run ${RESYNC}`);
    continue;
  }
  const copied = dst.slice(at + SENTINEL.length);

  if (copied !== src) {
    fail(
      `docs/vendor/${f} differs from extension/src/lib/${f} — run ${RESYNC}\n` +
        `        (source ${src.length} bytes, copy ${copied.length} bytes)`
    );
    continue;
  }
  console.log(`  ok   ${f}`);
}

// The inlined fixture data must exist and name the three cases the page uses.
const fixturesPath = join(repo, "docs", "vendor", "fixture-data.js");
if (!existsSync(fixturesPath)) {
  fail(`docs/vendor/fixture-data.js is missing — run ${RESYNC}`);
} else {
  const text = readFileSync(fixturesPath, "utf8");
  for (const key of ["signed", "bareKey", "backdated"]) {
    if (!text.includes(`"${key}"`)) {
      fail(`docs/vendor/fixture-data.js has no "${key}" case — run ${RESYNC}`);
    }
  }
  // Catch a regenerated file that lost its signature bodies.
  const sigs = text.split("BEGIN SSH SIGNATURE").length - 1;
  if (sigs < 3) {
    fail(`docs/vendor/fixture-data.js holds ${sigs} signatures, expected 3`);
  }
  if (!failed) console.log("  ok   fixture-data.js");
}

console.log(failed ? `\n${failed} failed` : "\nin sync");
process.exit(failed ? 1 : 0);
