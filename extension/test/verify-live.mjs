// End-to-end check against real commits on github.com, using the same code
// paths the content script uses. Needs network; the rest of the suite does not.
//
//   node extension/test/verify-live.mjs [owner/repo] [sha ...]
//
// Defaults to the three commits in programmerq/beamsig, two of which are beam
// signed and one of which (the initial commit) is unsigned.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const lib = join(here, "..", "src", "lib");

for (const f of ["wire.js", "sshcert.js", "sshsig.js", "sshcrypto.js", "ca.js", "verify.js"]) {
  // eslint-disable-next-line no-eval
  eval(readFileSync(join(lib, f), "utf8"));
}
globalThis.location = { origin: "https://github.com", href: "https://github.com/" };
// eslint-disable-next-line no-eval
eval(readFileSync(join(here, "..", "src", "github.js"), "utf8"));

const { wire, verify, ca, github } = globalThis.Beamsig;

const repo = process.argv[2] || "programmerq/beamsig";
const shas = process.argv.length > 3 ? process.argv.slice(3) : ["1dfcd52", "1cca822", "9675390"];
const [owner, name] = repo.split("/");

const cas = await verify.loadPinnedCAs(ca.PINNED_CAS);
console.log(`pinned CA: ${cas[0].fingerprint} (${cas[0].cluster})\n`);

let bad = 0;

for (const sha of shas) {
  const res = await fetch(`https://api.github.com/repos/${owner}/${name}/commits/${sha}`, {
    headers: { Accept: "application/vnd.github+json" },
  });
  if (!res.ok) {
    console.log(`${sha}  HTTP ${res.status} — skipped`);
    bad++;
    continue;
  }
  const json = await res.json();
  const v = (json.commit && json.commit.verification) || {};
  const short = json.sha.slice(0, 7);
  const subject = (json.commit.message || "").split("\n")[0].slice(0, 48);

  console.log(`${short}  ${subject}`);
  console.log(`   github says      : verified=${v.verified} reason=${v.reason}`);

  if (!v.signature) {
    console.log("   beamsig          : no signature — nothing to show\n");
    continue;
  }
  if (!github.looksLikeSSHSig(v.signature)) {
    console.log("   beamsig          : signed, but not an SSH signature\n");
    continue;
  }

  const ct = github.committerTime(v.payload);
  try {
    const att = await verify.verifySSHSig(v.signature, wire.TE.encode(v.payload), cas, {
      namespace: "git",
      claimedTime: ct ? ct.timestamp : undefined,
      claimedTimeSource: "git committer date",
    });
    console.log(`   beamsig          : VERIFIED`);
    console.log(`   beam id          : ${att.beamId}`);
    console.log(`   bot instance     : ${att.botInstanceId}`);
    console.log(`   cluster          : ${att.cluster}`);
    console.log(`   roles            : ${att.roles.join(", ")}`);
    console.log(`   owner            : ${att.owner}  (impersonated, NOT the signer)`);
    console.log(`   cert window      : ${verify.iso(att.validAfter)} .. ${verify.iso(att.validBefore)}`);
    console.log(`   committer date   : ${verify.iso(att.claimedTime)}  (in window)`);
    console.log(`   signing key      : ${att.signingKeyFp}`);
    console.log(`   issuing CA       : ${att.caFp}`);
    for (const w of att.warnings) console.log(`   ! ${w}`);
    console.log();
  } catch (e) {
    console.log(`   beamsig          : FAILED — ${e.message}\n`);
    bad++;
  }
}

process.exit(bad ? 1 : 0);
