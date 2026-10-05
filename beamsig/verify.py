"""Beam-specific verification of SSHSIG signatures made with a Teleport bot cert.

What this adds over `ssh-keygen -Y verify`:

  * requires the signature to carry a *certificate* (not a bare key)
  * verifies the certificate against a pinned Teleport SSH user CA
  * requires a `bot-name@goteleport.com` extension matching `beam-<uuid>`
  * checks a caller-supplied claimed time against the certificate window
  * surfaces bot instance id / delegation session id / roles / owner

`ssh-keygen -Y verify` cannot do any of the beam-specific parts: it only
matches certificate *principals*, which on a beam are the generic Unix logins
`root` / `beams` and are shared by every user cert in the cluster.
"""
import base64
import datetime
import os
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature

from . import sshcert, sshcrypto, sshsig
from .wire import Reader

BOT_NAME_EXT = "bot-name@goteleport.com"
BOT_INSTANCE_EXT = "bot-instance-id@goteleport.com"
DELEGATION_EXT = "delegation-session-id@goteleport.com"
ROLES_EXT = "teleport-roles"
TRAITS_EXT = "teleport-traits"
ROUTE_EXT = "teleport-route-to-cluster"
LOGIN_IP_EXT = "login-ip"

BEAM_BOT_RE = re.compile(
    r"^beam-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")

CERT_TYPE_USER = 1


class VerifyError(Exception):
    """Verification failed. The message says exactly which check failed."""


class UnknownTenant(VerifyError):
    """The signature is self-consistent but its issuing CA is not pinned.

    Distinct from a bad signature: nothing is wrong with the bytes, we simply
    have no basis for trusting the tenant that issued the certificate. Callers
    should report this differently from tampering, and may offer to pin the
    cluster -- see beamsig.discover.
    """

    def __init__(self, message, cluster_claimed="", beam_id="", bot_name="",
                 ca_fp="", signing_key_fp=""):
        super().__init__(message)
        self.cluster_claimed = cluster_claimed
        self.beam_id = beam_id
        self.bot_name = bot_name
        self.ca_fp = ca_fp
        self.signing_key_fp = signing_key_fp


@dataclass
class Attestation:
    ok: bool = False
    namespace: str = ""
    payload_sha256: str = ""
    # beam identity
    beam_id: str = ""
    bot_name: str = ""
    bot_instance_id: str = ""
    delegation_session_id: str = ""
    owner: str = ""              # cert Key ID = the impersonated human
    roles: list = field(default_factory=list)
    principals: list = field(default_factory=list)
    login_ip: str = ""
    cluster: str = ""            # authoritative: the cluster of the matching anchor
    cluster_claimed: str = ""    # what the certificate itself says
    cluster_pinned: bool = False # the anchor carried a cluster label
    cluster_trust: str = ""      # "pinned" | "discovered" | "unlabelled"
    # crypto
    signing_key_fp: str = ""
    ca_fp: str = ""
    cert_serial: int = 0
    sig_algorithm: str = ""
    # time
    valid_after: int = 0
    valid_before: int = 0
    claimed_time: int = None
    claimed_time_source: str = ""
    warnings: list = field(default_factory=list)


def _iso(v):
    return datetime.datetime.fromtimestamp(v, datetime.timezone.utc).isoformat()


@dataclass
class TrustAnchor:
    """A pinned Teleport user CA, bound to the cluster it belongs to.

    The binding matters as soon as more than one tenant is trusted. A
    certificate's `teleport-route-to-cluster` extension is only a claim made by
    whichever CA signed it, so if two tenants are trusted, tenant A can mint a
    certificate claiming to be from tenant B. The authoritative cluster is
    therefore the one attached to the *pin*, never the one in the certificate.
    """
    blob: bytes
    cluster: str = ""      # "" means the pin carries no cluster label
    source: str = ""
    discovered: bool = False   # fetched over HTTPS rather than operator-placed

    @property
    def fingerprint(self) -> str:
        return fp(self.blob)


def _cluster_from_name(name: str) -> str:
    """Treat a trust-store filename like `example.teleport.sh.ca` as a label."""
    stem = re.sub(r"\.(ca|txt|pub|pem)$", "", os.path.basename(name))
    return stem if "." in stem and " " not in stem else ""


def _parse_anchors(text: str, source: str, label: str = "",
                   discovered: bool = False) -> list:
    """Pull CA keys out of a Teleport export, allowed_signers or known_hosts.

    Teleport's /webapi/auth/export?type=user response ends with
    `clustername=<cluster>&type=user`, which is used as the cluster label when
    one was not supplied explicitly. That label is operator-asserted pin
    metadata -- it is not signed -- and it is trustworthy only because you
    fetched the file from that cluster over TLS and chose to pin it.
    """
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cluster = label
        m = re.search(r"clustername=([^&\s]+)", line)
        if not cluster and m:
            cluster = m.group(1)
        for tok in line.split():
            if tok.startswith("AAAA"):
                try:
                    blob = base64.b64decode(tok)
                    Reader(blob).string()
                except Exception:
                    break
                out.append(TrustAnchor(blob=blob, cluster=cluster, source=source,
                                       discovered=discovered))
                break
    return out


def load_trust_anchors(sources, allow_empty: bool = False) -> list:
    """Build a trust store from files, directories and/or export URLs.

    A directory is treated as a trust store: every file in it is a pin, and the
    filename (minus extension) is the cluster label, so dropping
    `other-tenant.teleport.sh.ca` in makes that tenant verifiable without
    touching anything else. Nothing here is specific to one tenant.
    """
    if isinstance(sources, (str, bytes)):
        sources = [sources]
    anchors = []
    for src in sources:
        if not src:
            continue
        if src.startswith("http://") or src.startswith("https://"):
            label = urllib.parse.urlsplit(src).hostname or ""
            with urllib.request.urlopen(src, timeout=20) as r:
                anchors += _parse_anchors(r.read().decode(), src, label)
        elif os.path.isdir(src):
            for name in sorted(os.listdir(src)):
                path = os.path.join(src, name)
                if not os.path.isfile(path):
                    continue
                with open(path) as f:
                    anchors += _parse_anchors(f.read(), path,
                                              _cluster_from_name(name))
        else:
            # An explicit "cluster=path" pins the label regardless of content.
            label = ""
            if "=" in src and not os.path.exists(src):
                label, _, src = src.partition("=")
            with open(src) as f:
                anchors += _parse_anchors(f.read(), src,
                                          label or _cluster_from_name(src))
    if not anchors and not allow_empty:
        raise VerifyError(f"no SSH CA public keys found in {sources}")
    return anchors


def load_ca_blobs(source) -> list:
    """Backwards-compatible shim: just the key material, no cluster binding."""
    return [a.blob for a in load_trust_anchors(source)]


def fp(blob: bytes) -> str:
    import hashlib
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()).decode().rstrip("=")


def verify_sshsig(sig_bytes: bytes, payload: bytes, trust, 
                  namespace: str = "git", claimed_time: int = None,
                  claimed_time_source: str = "caller",
                  require_beam: bool = True,
                  expect_beam_id: str = None,
                  expect_cluster: str = None) -> Attestation:
    """`trust` is a list of TrustAnchor, or of raw CA blobs (no cluster binding)."""
    anchors = [a if isinstance(a, TrustAnchor) else TrustAnchor(blob=a)
               for a in trust]
    import hashlib

    att = Attestation()

    # ---- 1. parse the SSHSIG envelope
    try:
        s = sshsig.parse(sig_bytes)
    except Exception as e:
        raise VerifyError(f"malformed SSHSIG: {e}")
    if s.version != 1:
        raise VerifyError(f"unsupported SSHSIG version {s.version}")
    att.namespace = s.namespace
    att.payload_sha256 = hashlib.sha256(payload).hexdigest()
    if namespace is not None and s.namespace != namespace:
        raise VerifyError(
            f"namespace mismatch: signature is for {s.namespace!r}, "
            f"expected {namespace!r}")
    if s.hash_algorithm not in sshsig.HASHES:
        raise VerifyError(f"unsupported hash algorithm {s.hash_algorithm}")

    # ---- 2. the signature MUST carry a certificate, else there is no identity
    if not s.is_certificate:
        raise VerifyError(
            "signature carries a bare public key, not a certificate; "
            "no beam identity can be established (re-sign using the "
            "Teleport SSH certificate)")
    cert = sshcert.parse(s.publickey)

    # ---- 3. the certificate must chain to a pinned Teleport user CA
    matched = None
    for anchor in anchors:
        try:
            sshcrypto.verify(anchor.blob, cert.signature, cert.signed_bytes)
            matched = anchor
            break
        except (InvalidSignature, ValueError):
            continue
    if matched is None:
        # Before reporting anything, establish whether the signature is at
        # least internally consistent: does it verify against the public key in
        # the certificate it carries? If so this is an untrusted tenant rather
        # than a corrupt signature, and saying so is the difference between
        # "someone tampered with this" and "we have never heard of that
        # cluster".
        self_ok = False
        try:
            sdata0 = sshsig.signed_data(s.namespace, s.hash_algorithm, payload,
                                        s.reserved)
            sshcrypto.verify(cert.pubkey_blob, s.signature, sdata0)
            self_ok = True
        except Exception:
            self_ok = False
        claimed = (cert.extensions.get(ROUTE_EXT, b"") or b"").decode("utf-8", "replace")
        bot = (cert.extensions.get(BOT_NAME_EXT, b"") or b"").decode("utf-8", "replace")
        m0 = BEAM_BOT_RE.match(bot or "")
        trusted = [(a.cluster or "?", a.fingerprint) for a in anchors]
        if self_ok:
            raise UnknownTenant(
                "the signature is intact, but its issuing Teleport user CA "
                f"({cert.ca_fingerprint}) is not pinned. The certificate says "
                f"it came from cluster {claimed or '(unstated)'!r}. Pin that "
                "cluster to verify it, e.g. `beamsig trust "
                f"{claimed or '<cluster>'}`. Currently trusted: {trusted}",
                cluster_claimed=claimed, beam_id=(m0.group(1) if m0 else ""),
                bot_name=bot, ca_fp=cert.ca_fingerprint,
                signing_key_fp=cert.key_fingerprint)
        raise VerifyError(
            "certificate is not signed by any trusted Teleport user CA "
            f"(cert says CA={cert.ca_fingerprint}, trusted={trusted})")
    att.ca_fp = cert.ca_fingerprint
    att.signing_key_fp = cert.key_fingerprint
    att.cert_serial = cert.serial

    if cert.cert_type != CERT_TYPE_USER:
        raise VerifyError(f"certificate is not a user certificate "
                          f"(type={cert.cert_type})")

    # ---- 4. the SSHSIG signature itself, over the SSHSIG signed-data blob
    sdata = sshsig.signed_data(s.namespace, s.hash_algorithm, payload, s.reserved)
    try:
        att.sig_algorithm = sshcrypto.verify(cert.pubkey_blob, s.signature, sdata)
    except InvalidSignature:
        raise VerifyError(
            "signature does not match the payload (payload tampered, "
            "or signature does not belong to this payload)")
    except ValueError as e:
        raise VerifyError(f"signature could not be checked: {e}")

    # ---- 5. beam identity from the certificate extensions
    def ext(name):
        v = cert.extensions.get(name)
        return v.decode("utf-8", "replace") if v else ""

    att.bot_name = ext(BOT_NAME_EXT)
    att.bot_instance_id = ext(BOT_INSTANCE_EXT)
    att.delegation_session_id = ext(DELEGATION_EXT)
    att.owner = cert.key_id
    att.principals = cert.valid_principals
    att.login_ip = ext(LOGIN_IP_EXT)
    # The certificate's own cluster extension is a CLAIM, scoped to whoever
    # signed it. The authoritative value is the cluster bound to the pin that
    # verified the certificate.
    att.cluster_claimed = ext(ROUTE_EXT)
    att.cluster = matched.cluster or att.cluster_claimed
    att.cluster_pinned = bool(matched.cluster)
    att.cluster_trust = ("discovered" if matched.discovered
                         else "pinned" if matched.cluster else "unlabelled")
    if matched.discovered:
        att.warnings.append(
            f"the CA for {att.cluster!r} was discovered over HTTPS, not pinned "
            "by an operator. WebPKI authenticates that hostname, so the "
            "cluster name is sound -- but deciding whether you accept that "
            "cluster is your policy call; use --cluster to enforce one")
    if not matched.cluster:
        att.warnings.append(
            "the trust anchor carries no cluster label, so the cluster name "
            f"{att.cluster_claimed!r} is taken from the certificate and is not "
            "independently verified; label the pin (e.g. name the trust-store "
            "file <cluster>.ca) to bind it")
    elif att.cluster_claimed and att.cluster_claimed != matched.cluster:
        # Legitimate in a root/leaf trusted-cluster setup, so not fatal, but it
        # is also exactly what cross-tenant spoofing looks like.
        att.warnings.append(
            f"certificate claims cluster {att.cluster_claimed!r} but was signed "
            f"by the CA pinned for {matched.cluster!r}; treating "
            f"{matched.cluster!r} as authoritative")
    if expect_cluster and att.cluster != expect_cluster:
        raise VerifyError(
            f"cluster mismatch: signature verifies under the "
            f"{att.cluster_trust} CA for {att.cluster!r}, expected "
            f"{expect_cluster!r}")
    roles_raw = ext(ROLES_EXT)
    if roles_raw:
        import json
        try:
            att.roles = json.loads(roles_raw).get("roles", [])
        except Exception:
            att.warnings.append(f"could not parse teleport-roles: {roles_raw!r}")

    if require_beam:
        if not att.bot_name:
            raise VerifyError(
                "certificate has no bot-name@goteleport.com extension: this is "
                "an ordinary Teleport user certificate, not a beam identity")
        m = BEAM_BOT_RE.match(att.bot_name)
        if not m:
            raise VerifyError(
                f"bot-name {att.bot_name!r} is not of the form beam-<uuid>; "
                "this is a Machine ID bot but not a beam")
        att.beam_id = m.group(1)
        if expect_beam_id and att.beam_id != expect_beam_id:
            raise VerifyError(
                f"beam id mismatch: signature is from beam {att.beam_id}, "
                f"expected {expect_beam_id}")
        if not att.bot_instance_id:
            att.warnings.append("no bot-instance-id extension")

    # ---- 6. time window
    att.valid_after = cert.valid_after
    att.valid_before = cert.valid_before
    att.claimed_time = claimed_time
    att.claimed_time_source = claimed_time_source
    if claimed_time is not None:
        if not (cert.valid_after <= claimed_time < cert.valid_before):
            raise VerifyError(
                f"claimed time {claimed_time} ({_iso(claimed_time)}) is outside "
                f"the certificate validity window "
                f"{_iso(cert.valid_after)} .. {_iso(cert.valid_before)}; "
                f"the timestamp is self-reported and does not match when the "
                f"signing certificate was valid")
    else:
        att.warnings.append(
            "no claimed time supplied: the signature was only proved to have "
            "been made at SOME point, bounded by the certificate window")

    if "disallow-reissue" not in cert.extensions:
        att.warnings.append(
            "certificate lacks disallow-reissue: it could be used to mint "
            "further certificates")

    att.ok = True
    return att


def render(att: Attestation) -> str:
    L = []
    L.append("BEAM SIGNATURE ATTESTATION")
    L.append("=" * 64)
    L.append(f"  result               : {'VERIFIED' if att.ok else 'FAILED'}")
    L.append(f"  namespace            : {att.namespace}")
    L.append(f"  payload sha256       : {att.payload_sha256}")
    L.append("")
    L.append("  -- signed by --")
    L.append(f"  beam id              : {att.beam_id}")
    L.append(f"  bot name             : {att.bot_name}")
    L.append(f"  bot instance id      : {att.bot_instance_id}   (stable per beam boot)")
    L.append(f"  delegation session   : {att.delegation_session_id}")
    suffix = {"pinned": "   (operator-pinned CA)",
              "discovered": "   (CA discovered over HTTPS)",
              "unlabelled": "   (from the certificate; CA carries no cluster label)"}
    L.append(f"  teleport cluster     : {att.cluster}"
             + suffix.get(att.cluster_trust, ""))
    if att.cluster_claimed and att.cluster_claimed != att.cluster:
        L.append(f"  cluster claimed      : {att.cluster_claimed}   (NOT authoritative)")
    L.append(f"  owner (cert Key ID)  : {att.owner}   (impersonated human, NOT the signer)")
    L.append(f"  teleport roles       : {', '.join(att.roles)}")
    L.append(f"  cert principals      : {', '.join(att.principals)}")
    L.append(f"  login ip             : {att.login_ip}")
    L.append("")
    L.append("  -- crypto --")
    L.append(f"  signing key          : {att.signing_key_fp}")
    L.append(f"  issuing CA           : {att.ca_fp}")
    L.append(f"  signature algorithm  : {att.sig_algorithm}")
    L.append("")
    L.append("  -- time --")
    L.append(f"  cert valid after     : {att.valid_after} {_iso(att.valid_after)}")
    L.append(f"  cert valid before    : {att.valid_before} {_iso(att.valid_before)}")
    if att.claimed_time is not None:
        L.append(f"  claimed time         : {att.claimed_time} "
                 f"{_iso(att.claimed_time)}  (from {att.claimed_time_source})")
        L.append("  claimed time in window: yes")
    else:
        L.append("  claimed time         : (none supplied)")
    if att.warnings:
        L.append("")
        L.append("  -- warnings --")
        for w in att.warnings:
            L.append(f"  ! {w}")
    return "\n".join(L)
