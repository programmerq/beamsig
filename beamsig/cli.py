"""beamsig CLI: sign and verify beam-attributable signatures."""
import argparse
import base64
import dataclasses
import hashlib
import json
import os
import subprocess
import sys

from . import attest as attest_mod, discover as disc_mod, gitobj, \
    identity as ident_mod, sshsig, verify as vmod
from .hwagent import HardwareKeyAgent, HASH_SHA256
from .sshagentshim import der_to_ssh_ecdsa_sig
from .wire import Reader

# Trust is per tenant and must not be hardwired to one. The default store is a
# directory of cluster-labelled pins; the local cluster's export URL is only a
# convenience fallback for interactive use on a beam.
_CONFIG_DIR = os.environ.get("BEAMSIG_CONFIG_DIR",
                             os.path.expanduser("~/.config/beamsig"))
DEFAULT_TRUST_STORE = os.environ.get("BEAMSIG_TRUST_STORE",
                                     os.path.join(_CONFIG_DIR, "trusted"))
LOCAL_CA_URL = (("https://" + os.environ["TELEPORT_CLUSTER"]
                 + "/webapi/auth/export?type=user")
                if os.environ.get("TELEPORT_CLUSTER") else None)


# ---------------------------------------------------------------- signing

def _sign_blob(payload: bytes, namespace: str, hash_alg: str = "sha512",
               identity_path=None, agent_dir=None, cert_from=None) -> bytes:
    ident = ident_mod.load(identity_path)
    if not ident.hw_key:
        raise SystemExit("identity has no hardware key reference")
    hw = HardwareKeyAgent(agent_dir)
    parts = ident.ssh_cert_line.split()
    cert_blob = base64.b64decode(parts[1])
    if cert_from:
        # Deliberately embed a DIFFERENT (e.g. archived, already-expired)
        # certificate for the same key. Demonstrates that because the beam key
        # never rotates, the signer chooses which validity window a verifier
        # will see.
        other = ident_mod.load(cert_from)
        cert_blob = base64.b64decode(other.ssh_cert_line.split()[1])
    keytype = parts[0].decode().replace("-cert-v01@openssh.com", "")
    sdata = sshsig.signed_data(namespace, hash_alg, payload)
    der = hw.sign(ident.hw_key, hashlib.sha256(sdata).digest(), HASH_SHA256,
                  command=f"beamsig sign (ns={namespace})")
    inner = der_to_ssh_ecdsa_sig(keytype, der)
    return sshsig.armor(sshsig.build(cert_blob, namespace, hash_alg, inner))


def cmd_sign(a):
    data = sys.stdin.buffer.read() if a.file == "-" else open(a.file, "rb").read()
    out = _sign_blob(data, a.namespace, identity_path=a.identity,
                     agent_dir=a.agent_dir, cert_from=a.cert_from)
    if a.out:
        with open(a.out, "wb") as f:
            f.write(out)
        print(f"wrote {a.out}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(out)
    return 0


# ---------------------------------------------------------------- verifying

def _trust(a):
    """Resolve the trust store: explicit --ca wins, else the store dir, else
    the local cluster's export."""
    sources = list(a.ca or [])
    if not sources:
        # Operator pins first, then anything previously discovered. Both may be
        # absent on a fresh machine, which is fine: discovery fills them in.
        anchors = []
        if os.path.isdir(DEFAULT_TRUST_STORE):
            anchors += vmod.load_trust_anchors([DEFAULT_TRUST_STORE],
                                               allow_empty=True)
        cache = disc_mod.cache_dir()
        if os.path.isdir(cache):
            # Mark these, so a previously discovered CA keeps reporting itself
            # as discovered rather than quietly becoming indistinguishable
            # from something an operator chose.
            for anchor in vmod.load_trust_anchors([cache], allow_empty=True):
                anchor.discovered = True
                anchors.append(anchor)
        return anchors
    # Tolerate an empty store: when discovery is enabled, starting with no
    # anchors is legitimate and verification will raise UnknownTenant, which
    # is what triggers the fetch.
    return vmod.load_trust_anchors(sources, allow_empty=True)


def _verify_with_discovery(a, fn):
    """Run `fn(anchors)`; on an unknown tenant, optionally pin and retry once.

    Exit codes: 0 verified, 2 invalid, 3 untrusted tenant. 3 is distinct on
    purpose -- "we do not trust that tenant" is a different outcome from "this
    signature is bad", and callers (CI, a UI) should be able to tell them
    apart.
    """
    anchors = _trust(a)
    patterns = disc_mod.allow_patterns(getattr(a, "discover_allow", None))
    offline = disc_mod.is_offline(getattr(a, "offline", False))
    try:
        return fn(anchors)
    except vmod.UnknownTenant as e:
        # Fetch the CA for the cluster the certificate names. The request is
        # verified HTTPS, so WebPKI authenticates that hostname; the cluster
        # then forms part of the reported identity rather than being a trust
        # decision made here. Pins are loaded first and are never replaced.
        try:
            new = disc_mod.discover(e.cluster_claimed, patterns=patterns,
                                    offline=offline)
        except disc_mod.DiscoveryRefused as refused:
            print(f"BEAMSIG UNTRUSTED TENANT: {e}", file=sys.stderr)
            print(f"  {refused}", file=sys.stderr)
            return 3
        print(f"NOTE: fetched the user CA for {e.cluster_claimed} over HTTPS "
              f"({', '.join(x.fingerprint for x in new)}) and cached it. "
              "The cluster name is authenticated by TLS; whether you accept "
              "that cluster is policy -- see --cluster.", file=sys.stderr)
        try:
            return fn(anchors + new)
        except vmod.VerifyError as e2:
            print(f"BEAMSIG VERIFY FAILED: {e2}", file=sys.stderr)
            return 2
    except vmod.VerifyError as e:
        print(f"BEAMSIG VERIFY FAILED: {e}", file=sys.stderr)
        return 2


def _emit(att, as_json):
    if as_json:
        d = dataclasses.asdict(att)
        print(json.dumps(d, indent=2, sort_keys=True))
    else:
        print(vmod.render(att))


def cmd_verify(a):
    data = sys.stdin.buffer.read() if a.file == "-" else open(a.file, "rb").read()
    sig = open(a.signature, "rb").read()

    def run(anchors):
        att = vmod.verify_sshsig(
            sig, data, anchors, namespace=a.namespace,
            claimed_time=a.claimed_time, claimed_time_source="--claimed-time",
            require_beam=not a.allow_non_beam, expect_beam_id=a.beam_id,
            expect_cluster=a.cluster)
        _emit(att, a.json)
        return 0

    return _verify_with_discovery(a, run)


def cmd_verify_commit(a):
    repo = a.repo
    rev = subprocess.check_output(
        ["git", "-C", repo, "rev-parse", a.commit]).decode().strip()
    obj = gitobj.raw_object(rev, repo, "commit")
    payload, sig = gitobj.split_signature(obj)
    if not sig:
        print(f"BEAMSIG VERIFY FAILED: commit {rev} is not signed", file=sys.stderr)
        return 2
    meta = gitobj.commit_metadata(obj)
    ctime = meta.get("committer", {}).get("timestamp")

    def run(anchors):
        att = vmod.verify_sshsig(
            sig, payload, anchors, namespace="git",
            claimed_time=ctime, claimed_time_source="git committer date",
            require_beam=not a.allow_non_beam, expect_beam_id=a.beam_id,
            expect_cluster=a.cluster)
        _emit_commit(a, att, rev, meta)
        return 0

    return _verify_with_discovery(a, run)


def _emit_commit(a, att, rev, meta):
    if a.json:
        d = dataclasses.asdict(att)
        d["commit"] = rev
        d["committer"] = meta.get("committer", {}).get("identity")
        d["author"] = meta.get("author", {}).get("identity")
        print(json.dumps(d, indent=2, sort_keys=True))
    else:
        print(f"commit               : {rev}")
        print(f"committer            : {meta.get('committer', {}).get('identity')}")
        print(vmod.render(att))


def cmd_attest(a):
    subjects = []
    for f in a.files:
        subjects.append({"name": os.path.basename(f),
                         "digest": {"sha256": attest_mod.digest_file(f)}})
    stmt = attest_mod.build_statement(subjects)
    env = attest_mod.build_envelope(
        stmt, lambda payload, ns: _sign_blob(payload, ns,
                                             identity_path=a.identity,
                                             agent_dir=a.agent_dir))
    out = json.dumps(env, indent=2, sort_keys=True) + "\n"
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(out)
        print(f"wrote {a.out}", file=sys.stderr)
    else:
        sys.stdout.write(out)
    return 0


def cmd_verify_attestation(a):
    with open(a.envelope) as fh:
        env = json.load(fh)
    try:
        stmt, raw, sig = attest_mod.open_envelope(env)
    except ValueError as e:
        print(f"BEAMSIG VERIFY FAILED: {e}", file=sys.stderr)
        return 2
    def run(anchors):
        att = vmod.verify_sshsig(
            sig, raw, anchors, namespace=attest_mod.NAMESPACE,
            claimed_time=a.claimed_time, claimed_time_source="--claimed-time",
            require_beam=not a.allow_non_beam, expect_beam_id=a.beam_id,
            expect_cluster=a.cluster)
        return _finish_attestation(a, att, stmt)

    return _verify_with_discovery(a, run)


def _finish_attestation(a, att, stmt):
    # check the subject digests against files on disk, if asked
    problems = []
    if a.subject_dir:
        for subj in stmt.get("subject", []):
            path = os.path.join(a.subject_dir, subj["name"])
            if not os.path.exists(path):
                problems.append(f"subject {subj['name']} not found")
                continue
            got = attest_mod.digest_file(path)
            want = subj["digest"]["sha256"]
            if got != want:
                problems.append(f"subject {subj['name']} digest mismatch: "
                                f"expected {want}, got {got}")
    if problems:
        for p_ in problems:
            print(f"BEAMSIG VERIFY FAILED: {p_}", file=sys.stderr)
        return 2

    _emit(att, a.json)
    if not a.json:
        print()
        print("  -- subjects (digests verified against disk: "
              f"{'yes' if a.subject_dir else 'NO, --subject-dir not given'}) --")
        for subj in stmt.get("subject", []):
            print(f"  {subj['digest']['sha256']}  {subj['name']}")
        sr = stmt["predicate"]["selfReported"]
        print()
        print("  -- self-reported, NOT PROVEN by the certificate --")
        print(f"  beam alias           : {sr.get('beamAlias')!r}  <-- unverifiable")
        print(f"  signedAt             : {sr.get('signedAt')!r}  <-- unverifiable")
        if sr.get("beamId") and sr["beamId"] != att.beam_id:
            print(f"  ! selfReported beamId {sr['beamId']} != "
                  f"certificate beam id {att.beam_id}")
    return 0


def cmd_inspect(a):
    sig = open(a.signature, "rb").read()
    s = sshsig.parse(sig)
    print(f"version        : {s.version}")
    print(f"namespace      : {s.namespace}")
    print(f"hash algorithm : {s.hash_algorithm}")
    print(f"publickey type : {s.publickey_type}")
    print(f"is certificate : {s.is_certificate}")
    if s.is_certificate:
        from . import sshcert
        c = sshcert.parse(s.publickey)
        print(f"key id         : {c.key_id}")
        print(f"principals     : {c.valid_principals}")
        print(f"valid          : {c.valid_after} .. {c.valid_before}")
        print("extensions     :")
        for k in sorted(c.extensions):
            v = c.extensions[k]
            try:
                v = v.decode()
            except Exception:
                v = v.hex()
            print(f"  {k} = {v}")
    return 0


def cmd_trust(a):
    import urllib.request
    store = a.store or DEFAULT_TRUST_STORE
    if a.list or not a.cluster:
        for label, d in (("pinned", store), ("discovered", disc_mod.cache_dir())):
            print(f"{label}: {d}")
            if not os.path.isdir(d):
                print("  (none)")
                continue
            anchors = vmod.load_trust_anchors([d], allow_empty=True)
            if not anchors:
                print("  (none)")
                continue
            for anchor in anchors:
                print(f"  {anchor.cluster or '(unlabelled)':36s} "
                      f"{anchor.fingerprint}")
        return 0
    os.makedirs(store, mode=0o700, exist_ok=True)
    url = f"https://{a.cluster}/webapi/auth/export?type=user"
    with urllib.request.urlopen(url, timeout=20) as r:
        data = r.read()
    dest = os.path.join(store, f"{a.cluster}.ca")
    with open(dest, "wb") as f:
        f.write(data)
    anchors = vmod.load_trust_anchors([dest])
    print(f"pinned {a.cluster}:")
    for anchor in anchors:
        print(f"  {anchor.fingerprint}  -> {dest}")
    print("Check that fingerprint against the cluster operator out of band; "
          "fetching it over TLS only proves you reached the host.")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser("beamsig")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_verify_opts(q):
        q.add_argument("--ca", action="append", metavar="SRC",
                       help="trust anchor: a file, a directory of "
                            "<cluster>.ca pins, an export URL, or "
                            "cluster=path. Repeatable; defaults to "
                            f"{DEFAULT_TRUST_STORE}")
        q.add_argument("--cluster", help="require this exact Teleport cluster")
        q.add_argument("--trust-store", help="directory of operator pins")
        q.add_argument("--discover-allow", action="append", metavar="GLOB",
                       help="restrict CA discovery to clusters matching GLOB, "
                            "e.g. '*.beams.sh'. Repeatable. Unrestricted by "
                            "default; the cluster is reported either way.")
        q.add_argument("--offline", action="store_true",
                       help="never fetch a CA; only use local pins and cache")
        q.add_argument("--beam-id", help="require this exact beam id")
        q.add_argument("--allow-non-beam", action="store_true",
                       help="accept any Teleport user cert, not just beams")
        q.add_argument("--json", action="store_true")

    s = sub.add_parser("sign", help="sign a file as this beam")
    s.add_argument("file")
    s.add_argument("-n", "--namespace", default="beamsig.artifact.v1")
    s.add_argument("-o", "--out")
    s.add_argument("--identity")
    s.add_argument("--agent-dir")
    s.add_argument("--cert-from", metavar="IDENTITY_FILE",
                   help="embed the certificate from another identity file "
                        "(e.g. an archived, expired one) instead of the "
                        "current cert; for backdating experiments")
    s.set_defaults(fn=cmd_sign)

    s = sub.add_parser("verify", help="verify a detached signature over a file")
    s.add_argument("file")
    s.add_argument("-s", "--signature", required=True)
    s.add_argument("-n", "--namespace", default="beamsig.artifact.v1")
    s.add_argument("--claimed-time", type=int,
                   help="unix time the artifact claims to have been signed at")
    add_verify_opts(s)
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("verify-commit", help="verify a signed git commit")
    s.add_argument("commit", nargs="?", default="HEAD")
    s.add_argument("-C", "--repo", default=".")
    add_verify_opts(s)
    s.set_defaults(fn=cmd_verify_commit)

    s = sub.add_parser("attest", help="emit a signed attestation envelope")
    s.add_argument("files", nargs="+")
    s.add_argument("-o", "--out")
    s.add_argument("--identity")
    s.add_argument("--agent-dir")
    s.set_defaults(fn=cmd_attest)

    s = sub.add_parser("verify-attestation", help="verify an attestation envelope")
    s.add_argument("envelope")
    s.add_argument("--subject-dir",
                   help="directory holding the subject files, to check digests")
    s.add_argument("--claimed-time", type=int)
    add_verify_opts(s)
    s.set_defaults(fn=cmd_verify_attestation)

    s = sub.add_parser("trust", help="pin another tenant's CA, or list pins")
    s.add_argument("cluster", nargs="?",
                   help="cluster to fetch and pin, e.g. other.teleport.sh")
    s.add_argument("--store", help=f"trust store dir (default {DEFAULT_TRUST_STORE})")
    s.add_argument("--list", action="store_true")
    s.set_defaults(fn=cmd_trust)

    s = sub.add_parser("inspect", help="dump an SSHSIG without verifying")
    s.add_argument("-s", "--signature", required=True)
    s.set_defaults(fn=cmd_inspect)

    a = p.parse_args(argv)
    return a.fn(a)
