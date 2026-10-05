// Exercise the exact code path the landing page's "verify it yourself" widget
// uses: the docs/vendor copies of the libraries, against the inlined fixture
// data, with the CA pinned in docs/vendor/ca.js.
//
//   node extension/test/site-verify.mjs
//
// This is deliberately run against docs/vendor rather than extension/src/lib.
// site-sync.mjs already proves the two are identical; this proves the thing the
// browser actually loads produces the right verdicts, so a broken page cannot
// pass CI just because the originals are fine.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const vendor = join(here, "..", "..", "docs", "vendor");

// Same global-attach loading the page does with <script src>, in the same
// dependency order.
for (const f of [
  "wire.js",
  "sshcert.js",
  "sshsig.js",
  "sshcrypto.js",
  "ca.js",
  "verify.js",
  "avatar.js",
  "fixture-data.js",
]) {
  eval(readFileSync(join(vendor, f), "utf8"));
}

const { wire, verify, ca, avatar } = globalThis.Beamsig;
const F = globalThis.BEAMSIG_FIXTURES;

const BEAM = "1786bcd6-04b9-4b9e-ad87-0c13071df7e9";
const OWNER = "jeff@goteleport.com";

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
const eq = (label, got, want) =>
  got === want ? ok(label) : bad(label, `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);

const cas = await verify.loadPinnedCAs(ca.PINNED_CAS);
const opts = (c) => ({
  namespace: c.namespace,
  claimedTime: c.claimedTime,
  claimedTimeSource: "fixture",
});
const run = (c, payloadText) =>
  verify.verifySSHSig(c.signature, wire.TE.encode(payloadText ?? c.message), cas, opts(c));

console.log("pinned CA");
eq("exactly one pinned CA", cas.length, 1);
eq("cluster is jeff.beams.sh", cas[0].cluster, "jeff.beams.sh");
eq(
  "fingerprint matches the recorded pin",
  cas[0].fingerprint,
  "SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU"
);

console.log("\ncase: valid beam signature");
try {
  const att = await run(F.signed);
  eq("ok", att.ok, true);
  eq("beam id", att.beamId, BEAM);
  eq("bot name", att.botName, `beam-${BEAM}`);
  eq("owner is the impersonated human", att.owner, OWNER);
  eq("cluster", att.cluster, "jeff.beams.sh");
  eq("namespace", att.namespace, "git");
  eq("two standing caveats are present", att.caveats.length, 2);
  eq("no warnings", att.warnings.length, 0);
  // The page must never present these as the signer.
  if (att.principals.includes("root")) ok("cert still carries the generic 'root' principal");
  else bad("principals", `expected 'root' among ${JSON.stringify(att.principals)}`);
  if (att.validAfter < att.claimedTime && att.claimedTime < att.validBefore)
    ok("claimed time falls inside the certificate window");
  else bad("time window", `${att.validAfter} .. ${att.validBefore}, claimed ${att.claimedTime}`);
} catch (e) {
  bad("valid signature should verify", e.message);
}

console.log("\ncase: tampered payload");
try {
  await run(F.signed, "not the signed payload");
  bad("tampered payload", "verification unexpectedly succeeded");
} catch (e) {
  if (e instanceof verify.VerifyError) ok("rejected with VerifyError");
  else bad("tampered payload", `unexpected error type: ${e}`);
  if (/does not match the payload/.test(e.message)) ok("message names the payload mismatch");
  else bad("tampered payload message", e.message);
  if (!verify.NOT_BEAM_CODES.has(e.code)) ok("treated as a failure, not 'somebody else's key'");
  else bad("tampered payload code", `got NOT_BEAM code ${e.code}`);
}

console.log("\ncase: bare key, no certificate");
try {
  await run(F.bareKey);
  bad("bare key", "verification unexpectedly succeeded");
} catch (e) {
  eq("code is bare-key", e.code, "bare-key");
  if (verify.NOT_BEAM_CODES.has(e.code)) ok("classified as not-a-beam, not a hard failure");
  else bad("bare key", `code ${e.code} is not in NOT_BEAM_CODES`);
}

console.log("\ncase: untrusted CA");
try {
  const broken = cas.map((c) => {
    const blob = c.blob.slice();
    blob[blob.length - 1] ^= 0xff;
    return { ...c, blob };
  });
  await verify.verifySSHSig(
    F.signed.signature,
    wire.TE.encode(F.signed.message),
    broken,
    opts(F.signed)
  );
  bad("untrusted CA", "verification unexpectedly succeeded");
} catch (e) {
  eq("code is untrusted-ca", e.code, "untrusted-ca");
}

console.log("\ncase: backdated but genuinely valid");
try {
  const att = await run(F.backdated);
  eq("ok", att.ok, true);
  eq("same beam as the honest signature", att.beamId, BEAM);
  eq("artifact namespace", att.namespace, "beamsig.artifact.v1");
  // REPORT.md §4(c): signed at 15:11:29, attested as 14:37:27. The claim lands
  // in the first minute of a 61-minute window, 34 minutes before the signing.
  eq("claims the time REPORT.md documents", att.claimedTime, 1791211047);
  if (att.claimedTime - att.validAfter <= 60)
    ok("claims a time in the first minute of the window");
  else
    bad(
      "backdated claim",
      `claimed ${att.claimedTime} is ${att.claimedTime - att.validAfter}s into the window`
    );
  if (att.caveats.some((c) => /never rotates/.test(c)))
    ok("carries the non-rotating-key caveat the page renders");
  else bad("backdated caveats", JSON.stringify(att.caveats));
} catch (e) {
  bad("backdated signature should still verify", e.message);
}

console.log("\navatar");
eq("version matches the Python generator", avatar.VERSION, "v2");
const a1 = avatar.avatar(BEAM, 96);
const a2 = avatar.avatar(BEAM.toUpperCase(), 96);
if (a1 === a2) ok("UUID case does not change the face");
else bad("avatar", "upper/lower case seeds diverged");
if (a1.startsWith("<svg") && a1.includes('viewBox="0 0 128 128"')) ok("renders an SVG");
else bad("avatar", a1.slice(0, 60));
if (avatar.avatar("00000000-0000-0000-0000-000000000000", 96) !== a1)
  ok("a different beam gets a different face");
else bad("avatar", "distinct UUIDs produced identical SVG");

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
