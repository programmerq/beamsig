// Node test harness for the extension's verification libraries.
//
//   node extension/test/run-tests.mjs
//
// The libs are plain scripts that attach to globalThis.Beamsig (so they can be
// loaded as MV3 content scripts, which cannot use ES modules). Here we eval them
// in order and exercise them against the committed fixtures, which still verify
// today against their long-expired certificates.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..");
const lib = join(here, "..", "src", "lib");

for (const f of ["wire.js", "sshcert.js", "sshsig.js", "sshcrypto.js", "ca.js", "verify.js", "discover.js", "avatar.js"]) {
  // eslint-disable-next-line no-eval
  eval(readFileSync(join(lib, f), "utf8"));
}

const { wire, sshsig, sshcert, verify, ca } = globalThis.Beamsig;

const fixture = (p) => readFileSync(join(repo, "fixtures", p));
const text = (p) => fixture(p).toString("utf8");
const bytes = (p) => new Uint8Array(fixture(p));

let pass = 0;
let fail = 0;

function ok(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  ok   ${name}`);
  } else {
    fail++;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

async function expectFail(name, fn, wantSubstring) {
  try {
    await fn();
    fail++;
    console.log(`  FAIL ${name} — expected a failure, got success`);
  } catch (e) {
    const matched = !wantSubstring || e.message.includes(wantSubstring);
    if (matched) {
      pass++;
      console.log(`  ok   ${name} (${e.message.slice(0, 72)}…)`);
    } else {
      fail++;
      console.log(`  FAIL ${name} — wrong error: ${e.message}`);
    }
  }
}

// The fixture's certificate window, and a time inside it (from
// docs/PRESENTATION-NOTES.md "Reproducing locally").
const INSIDE_WINDOW = 1791212000;
const EXPECTED_BEAM_ID = "1786bcd6-04b9-4b9e-ad87-0c13071df7e9";

console.log("\npinned CA");
const cas = await verify.loadPinnedCAs(ca.PINNED_CAS);
ok(
  "pinned CA blob matches its recorded fingerprint",
  cas[0].fingerprint === "SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU",
  cas[0].fingerprint
);
// Cross-check the embedded pin against the committed trust anchor, so a typo in
// the hand-split base64 in ca.js cannot go unnoticed.
const fromFixture = await verify.loadPinnedCAs([
  { cluster: "fixture", line: text("teleport-user-ca.txt") },
]);
ok(
  "embedded pin is byte-identical to fixtures/teleport-user-ca.txt",
  wire.equal(cas[0].blob, fromFixture[0].blob)
);

console.log("\nSSHSIG envelope parsing");
const sigText = text("sig-from-cert.sig");
const parsed = sshsig.parse(sigText);
ok("version is 1", parsed.version === 1);
ok("namespace is git", parsed.namespace === "git", parsed.namespace);
ok("hash algorithm is sha512", parsed.hashAlgorithm === "sha512", parsed.hashAlgorithm);
ok("carries a certificate", parsed.isCertificate === true);
ok(
  "publickey type is an ecdsa cert",
  parsed.publickeyType() === "ecdsa-sha2-nistp256-cert-v01@openssh.com",
  parsed.publickeyType()
);

console.log("\ncertificate parsing");
const cert = sshcert.parse(parsed.publickey);
ok("key id is the owner, not the beam", cert.keyId === "jeff@goteleport.com", cert.keyId);
ok(
  "bot-name extension names the beam",
  wire.TD.decode(cert.extensions.get("bot-name@goteleport.com")) ===
    `beam-${EXPECTED_BEAM_ID}`
);
ok("serial is 0 (REPORT.md §6.4)", cert.serial === 0, String(cert.serial));
ok("cert type is user", cert.certType === 1);
ok(
  "principals are the generic logins",
  cert.validPrincipals.join(",") === "root,beams,-teleport-internal-join",
  cert.validPrincipals.join(",")
);
ok("has disallow-reissue", cert.extensions.has("disallow-reissue"));

console.log("\npositive verification");
const att = await verify.verifySSHSig(sigText, bytes("msg.txt"), cas, {
  namespace: "git",
  claimedTime: INSIDE_WINDOW,
  claimedTimeSource: "test",
});
ok("verifies", att.ok === true);
ok("beam id", att.beamId === EXPECTED_BEAM_ID, att.beamId);
ok(
  "bot instance id",
  att.botInstanceId === "dbe1cf6c-8f89-4ab3-bfee-9e2c7e710f6c",
  att.botInstanceId
);
ok(
  "delegation session id",
  att.delegationSessionId === "bd204fe3-1653-429c-bc81-b64d5a3d514f",
  att.delegationSessionId
);
ok("cluster", att.cluster === "jeff.beams.sh", att.cluster);
ok("owner is the impersonated human", att.owner === "jeff@goteleport.com", att.owner);
ok(
  "roles",
  att.roles.join(",") === "editor,access,auditor,beam-user",
  att.roles.join(",")
);
ok("login ip", att.loginIp === "52.3.207.254", att.loginIp);
ok(
  "signing key fingerprint",
  att.signingKeyFp === "SHA256:4jXdejzBCenjWfYrR8qs6BT/esGtkz3cqVJTUWxDhf8",
  att.signingKeyFp
);
ok("sig algorithm", att.sigAlgorithm === "ecdsa-sha2-nistp256", att.sigAlgorithm);
ok("two standing caveats are attached", att.caveats.length === 2);
ok(
  "no spurious warnings",
  att.warnings.length === 0,
  JSON.stringify(att.warnings)
);
console.log(
  `       window ${verify.iso(att.validAfter)} .. ${verify.iso(att.validBefore)}`
);

console.log("\nnegative cases");
await expectFail(
  "bare key signature has no identity",
  () =>
    verify.verifySSHSig(text("sig-from-key.sig"), bytes("msg.txt"), cas, {
      namespace: "git",
      claimedTime: INSIDE_WINDOW,
    }),
  "bare public key"
);

await expectFail(
  "tampered payload",
  () =>
    verify.verifySSHSig(sigText, wire.TE.encode("not the signed payload"), cas, {
      namespace: "git",
      claimedTime: INSIDE_WINDOW,
    }),
  "does not match the payload"
);

await expectFail(
  "namespace mismatch is rejected (no cross-context replay)",
  () =>
    verify.verifySSHSig(sigText, bytes("msg.txt"), cas, {
      namespace: "beamsig.artifact.v1",
      claimedTime: INSIDE_WINDOW,
    }),
  "namespace mismatch"
);

await expectFail(
  "claimed time after the certificate window",
  () =>
    verify.verifySSHSig(sigText, bytes("msg.txt"), cas, {
      namespace: "git",
      claimedTime: att.validBefore + 1,
    }),
  "outside the certificate"
);

await expectFail(
  "claimed time before the certificate window",
  () =>
    verify.verifySSHSig(sigText, bytes("msg.txt"), cas, {
      namespace: "git",
      claimedTime: att.validAfter - 1,
    }),
  "outside the certificate"
);

await expectFail(
  "certificate from an untrusted CA",
  () =>
    verify.verifySSHSig(sigText, bytes("msg.txt"), cas.map((c) => ({
      ...c,
      // flip a byte in the pinned CA key
      blob: (() => {
        const b = c.blob.slice();
        b[b.length - 1] ^= 0xff;
        return b;
      })(),
    })), {
      namespace: "git",
      claimedTime: INSIDE_WINDOW,
    }),
  "not signed by any pinned"
);

await expectFail(
  "beam id mismatch",
  () =>
    verify.verifySSHSig(sigText, bytes("msg.txt"), cas, {
      namespace: "git",
      claimedTime: INSIDE_WINDOW,
      expectBeamId: "00000000-0000-0000-0000-000000000000",
    }),
  "beam id mismatch"
);

console.log("\nknown break: backdating (REPORT.md §4(c))");
// Note the namespace: this fixture is an artifact signature, not a commit, so
// it carries beamsig.artifact.v1. Namespaces are per-use and enforced above.
const back = await verify.verifySSHSig(
  text("backdated.sig"),
  bytes("backdated.txt"),
  cas,
  {
    namespace: "beamsig.artifact.v1",
    claimedTime: 1791211047,
    claimedTimeSource: "test",
  }
);
ok(
  "a deliberately backdated signature still verifies — this is expected",
  back.ok === true && back.beamId === EXPECTED_BEAM_ID
);
console.log(
  `       attested window ${verify.iso(back.validAfter)} .. ${verify.iso(
    back.validBefore
  )} (chosen by the signer)`
);

console.log("\nmissing claimed time downgrades to a warning, not a pass");
const noTime = await verify.verifySSHSig(sigText, bytes("msg.txt"), cas, {
  namespace: "git",
});
ok(
  "warns that no claimed time was supplied",
  noTime.warnings.some((w) => w.includes("no claimed time")),
  JSON.stringify(noTime.warnings)
);

// ---- github.js: URL routing and committer-date extraction -------------------
// These need a `location` to resolve relative URLs against, but no DOM and no
// extension APIs (getSettings falls back to defaults when `chrome` is absent).
globalThis.location = { origin: "https://github.com", href: "https://github.com/" };
// eslint-disable-next-line no-eval
eval(readFileSync(join(here, "..", "src", "github.js"), "utf8"));
const { github } = globalThis.Beamsig;

console.log("\ngithub.js URL routing");
const SHA = "1cca822b4f8e0e1e8b9c0a7d6f5e4c3b2a190817";

const c1 = github.parseCommitUrl(`https://github.com/programmerq/beamsig/commit/${SHA}`);
ok("commit page", c1 && c1.owner === "programmerq" && c1.repo === "beamsig" && c1.sha === SHA);

const c2 = github.parseCommitUrl(
  `https://github.com/programmerq/beamsig/pull/7/commits/${SHA}`
);
ok("PR commit page", c2 && c2.kind === "pr-commit" && c2.sha === SHA);

const c3 = github.parseCommitUrl(`https://github.com/o/r/commit/${SHA}?diff=split#foo`);
ok("query string and fragment are ignored", c3 && c3.sha === SHA);

const c4 = github.parseCommitUrl("https://github.com/o/r/commit/abc1234");
ok("abbreviated sha accepted", c4 && c4.sha === "abc1234");

ok("tree page is not a commit", github.parseCommitUrl("https://github.com/o/r/tree/main") === null);
ok("repo root is not a commit", github.parseCommitUrl("https://github.com/o/r") === null);
ok(
  "a non-github host is rejected",
  github.parseCommitUrl(`https://evil.example/programmerq/beamsig/commit/${SHA}`) === null
);
ok(
  "a non-hex sha is rejected",
  github.parseCommitUrl("https://github.com/o/r/commit/not-a-sha-zzzz") === null
);

const l1 = github.parseListUrl("https://github.com/programmerq/beamsig/commits/main");
ok("commit list page", l1 && l1.kind === "commits" && l1.repo === "beamsig");
const l2 = github.parseListUrl("https://github.com/o/r/pull/7/commits");
ok("PR commits tab", l2 && l2.kind === "pr-commits");

console.log("\ngithub.js committer date");
// The shape GitHub returns in verification.payload.
const payload =
  "tree 9f1a2b3c4d5e6f708192a3b4c5d6e7f809112233\n" +
  "parent 00112233445566778899aabbccddeeff00112233\n" +
  "author beam-1786bcd6 <jeff@goteleport.com> 1791215600 +0000\n" +
  "committer beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9 <jeff@goteleport.com> 1791215633 +0000\n" +
  "\n" +
  "a beam did this\n";
const ct = github.committerTime(payload);
ok("committer timestamp", ct && ct.timestamp === 1791215633, ct && String(ct.timestamp));
ok("committer timezone", ct && ct.tz === "+0000", ct && ct.tz);
ok(
  "committer identity keeps its spaces",
  ct && ct.identity === "beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9 <jeff@goteleport.com>",
  ct && ct.identity
);
ok(
  "a committer line in the message body is not picked up",
  github.committerTime("tree abc\n\ncommitter fake <x@y> 1 +0000\n") === null
);
ok("unsigned payload yields no time", github.committerTime("") === null);

console.log("\ngithub.js signature shape");
ok("SSHSIG is recognised", github.looksLikeSSHSig(sigText) === true);
ok(
  "a PGP signature is not mistaken for SSHSIG",
  github.looksLikeSSHSig("-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----") === false
);
ok("a null signature is handled", github.looksLikeSSHSig(null) === false);

console.log("\navatar (JS port vs Python golden)");
{
  const { avatar } = globalThis.Beamsig;
  const golden = JSON.parse(readFileSync(join(here, "avatar-golden.json"), "utf8"));
  ok("version matches the Python", avatar.VERSION === golden.version, avatar.VERSION);
  const bad = golden.cases.filter((c) => avatar.avatar(c.seed, 24) !== c.svg);
  ok(
    `${golden.cases.length} seeds render byte-identical SVG`,
    bad.length === 0,
    bad.length ? `first mismatch: ${JSON.stringify(bad[0].seed)}` : ""
  );
  const sha = avatar.sha256(new TextEncoder().encode("abc"));
  ok(
    "sync sha256 known-answer",
    Buffer.from(sha).toString("hex") ===
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  );
  ok(
    "seed is trimmed and case-folded",
    avatar.avatar("  JEFF@Example.com ") === avatar.avatar("jeff@example.com")
  );
}

console.log("\ndiscover: which clusters may be asked for a CA");
{
  const { discover } = globalThis.Beamsig;
  const D = ["*.beams.sh"];
  const yes = (h, d = D) => ok(`allowed: ${h}`, discover.allowed(h, d) === true);
  const no = (h, d = D) => ok(`refused: ${JSON.stringify(h)}`, discover.allowed(h, d) === false);
  yes("quiet-hat.beams.sh");
  yes("jeff.beams.sh");
  yes("a.b.beams.sh");
  yes("quiet-hat.beams.sh", ["quiet-*.beams.sh"]);
  yes("quiet-hat.beams.sh", ["quiet-hat.beams.sh"]);
  yes("quiet-hat.beams.sh", ["  *.BEAMS.sh "]);
  no("beams.sh"); // the apex is not a tenant
  no("evilbeams.sh");
  no("beams.sh.evil.com");
  no("evil.com");
  no("quiet-hat.beams.sh:8443");
  no("user@quiet-hat.beams.sh");
  no("quiet-hat.beams.sh/x");
  no("https://quiet-hat.beams.sh");
  no("Quiet-Hat.beams.sh"); // must already be lowercase
  no("quiet-hat.beams.sh.");
  no("a..beams.sh");
  no("-x.beams.sh");
  no("127.0.0.1");
  no("");
  no(undefined);
  no("quiet-hat.beams.sh", []); // empty allowlist = discovery off
  no("quiet-hat.beams.sh", [""]);
  no("quiet-hat.beams.sh", ["example.com"]);
  no("quiet-hat.beams.sh", ["*.corp.example"]);

  const line = text("teleport-user-ca.txt").trim();
  const ents = discover.parseExport(line + "\n", "jeff.beams.sh");
  ok("export line parsed and marked discovered", ents.length === 1 && ents[0].discovered === true && ents[0].cluster === "jeff.beams.sh", JSON.stringify(ents));
  ok("a line naming another cluster is dropped", discover.parseExport(line, "other.beams.sh").length === 0);
  ok("junk yields no CAs", discover.parseExport("<html>nope</html>", "jeff.beams.sh").length === 0);
  ok(
    "export URL is https and on the asked host",
    discover.exportUrl("quiet-hat.beams.sh") === "https://quiet-hat.beams.sh/webapi/auth/export?type=user"
  );
}

console.log("\ndiscovered CA, and which cluster is authoritative");
{
  const { discover } = globalThis.Beamsig;
  const ents = discover.parseExport(text("teleport-user-ca.txt"), "jeff.beams.sh");
  const good = await verify.loadPinnedCAs(ents);
  const att = await verify.verifySSHSig(text("sig-from-cert.sig"), bytes("msg.txt"), good, {
    namespace: "git", claimedTime: INSIDE_WINDOW,
  });
  ok("verifies against a discovered CA", att.ok && att.caDiscovered === true);
  ok("flagged as discovered, not chosen", att.warnings.some((w) => w.includes("discovered, not chosen")));
  // Authoritative cluster = the one bound to the verifying CA, not the claim.
  ok("cluster comes from the CA's label", att.cluster === "jeff.beams.sh" && att.clusterPinned && att.clusterClaimed === "jeff.beams.sh");
  const other = await verify.loadPinnedCAs(
    discover.parseExport(text("teleport-user-ca.txt"), "jeff.beams.sh").map((e) => ({ ...e, cluster: "other.beams.sh", discovered: false }))
  );
  const att2 = await verify.verifySSHSig(text("sig-from-cert.sig"), bytes("msg.txt"), other, {
    namespace: "git", claimedTime: INSIDE_WINDOW,
  });
  ok("a disagreeing claim is not authoritative", att2.cluster === "other.beams.sh" && att2.clusterClaimed === "jeff.beams.sh");
  ok("...and is surfaced as a warning, not a failure", att2.ok && att2.warnings.some((w) => w.includes("treating")));
  ok("an operator-pinned CA is not flagged as discovered", att2.caDiscovered === false);
  // An untrusted-CA failure carries the (unauthenticated) cluster hint.
  try {
    await verify.verifySSHSig(text("sig-from-cert.sig"), bytes("msg.txt"), [{ ...cas[0], blob: new Uint8Array(cas[0].blob).reverse() }], {});
    ok("untrusted CA throws", false);
  } catch (e) {
    ok("untrusted-ca error carries clusterHint", e.code === "untrusted-ca" && e.clusterHint === "jeff.beams.sh", `${e.code} ${e.clusterHint}`);
  }
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
