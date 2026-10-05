"""Automatic, transparent discovery of a Teleport user CA.

Teams do not share one Beams tenant, so a repository routinely holds commits
from several. Requiring every tenant to be pinned in advance makes the common
case fail, and makes the failure look like a bad signature.

So discovery is on by default. When a certificate names a cluster we have no CA
for, we fetch it:

    GET https://<cluster>/webapi/auth/export?type=user

Why that is sound, and why an earlier version of this file was wrong about it:

  * **The fetch is authenticated.** It is HTTPS with full certificate
    verification, so WebPKI proves we are talking to whoever controls that DNS
    name. "Discovered" is not "unauthenticated" -- the earlier wording here
    claiming otherwise was simply incorrect.
  * **The cluster name is part of the identity, not a trust decision.** A
    verified signature says "beam <uuid> of cluster <host>". An attacker can
    certainly mint their own CA and a certificate claiming
    `teleport-route-to-cluster=attacker.example`, and discovery will fetch
    their CA and validate it -- but the resulting statement is *true*: that
    signature really is from a beam of a Teleport cluster at
    attacker.example. It is not, and cannot be made into, a statement about
    your cluster.
  * **Pins still win.** A cluster you have pinned is never replaced by
    discovery, so an attacker cannot talk us out of an existing anchor by
    claiming to be one.

The actual hazard is therefore not forgery, it is a reader seeing "VERIFIED"
and ignoring *which* cluster. That is a presentation problem, addressed by
always reporting the cluster and whether it was pinned or discovered, and by
`--cluster` for callers that want to enforce a policy.

Two genuine residual caveats:

  * Discovery needs the network. Offline verification still requires a pin,
    which is why `beamsig trust <cluster>` and `--offline` exist.
  * A verifier makes an HTTPS request to a hostname that came from the artifact
    it is checking. In a CI runner that is a (minor) outbound-request
    consideration; `--discover-allow` can restrict it to domains you own, and
    `--offline` switches it off entirely.
"""
import fnmatch
import os
import re
import ssl
import urllib.error
import urllib.request

from .verify import TrustAnchor, load_trust_anchors

# A conservative DNS name. Rejects paths, spaces, schemes, ports and the like,
# so a cluster label can never be coerced into something else.
CLUSTER_RE = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")

USER_AGENT = "beamsig/0.1"


class DiscoveryRefused(Exception):
    """Discovery was not attempted, and why."""


def valid_cluster(cluster: str) -> bool:
    return bool(cluster) and bool(CLUSTER_RE.match(cluster)) and ".." not in cluster


def allowed(cluster: str, patterns) -> bool:
    """`patterns` is an optional restriction. Empty/None means no restriction."""
    if not valid_cluster(cluster):
        return False
    if not patterns:
        return True
    return any(fnmatch.fnmatch(cluster, p) for p in patterns)


def default_store(config_dir=None) -> str:
    cfg = config_dir or os.environ.get(
        "BEAMSIG_CONFIG_DIR", os.path.expanduser("~/.config/beamsig"))
    return os.path.join(cfg, "trusted")


def cache_dir(config_dir=None) -> str:
    """Discovered CAs are cached separately from operator-placed pins.

    Keeping them apart means the distinction survives: a pin stays a pin, and
    anything that arrived by discovery can always be reported as such.
    """
    cfg = config_dir or os.environ.get(
        "BEAMSIG_CONFIG_DIR", os.path.expanduser("~/.config/beamsig"))
    return os.path.join(cfg, "discovered")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: the response must come from the host we asked."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DiscoveryRefused(
            f"the CA export for {req.host} redirected to {newurl!r}; refusing "
            "to follow it")


def fetch_ca(cluster: str, timeout: float = 10.0) -> bytes:
    """Fetch a cluster's SSH user CA export over verified HTTPS."""
    if not valid_cluster(cluster):
        raise DiscoveryRefused(f"{cluster!r} is not a valid cluster hostname")
    url = f"https://{cluster}/webapi/auth/export?type=user"
    ctx = ssl.create_default_context()      # verifies hostname and chain
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.read(1 << 20)
    except urllib.error.URLError as e:
        raise DiscoveryRefused(f"could not fetch the user CA for {cluster}: "
                               f"{getattr(e, 'reason', e)}")


def discover(cluster: str, store=None, patterns=None, timeout: float = 10.0,
             offline: bool = False, cache=None) -> list:
    """Fetch, cache and return the trust anchors for `cluster`.

    Raises DiscoveryRefused with a usable explanation on any refusal.
    """
    if offline:
        raise DiscoveryRefused(
            f"offline: cluster {cluster!r} is not pinned locally. Pin it with "
            f"`beamsig trust {cluster}` on a machine with network access")
    if not valid_cluster(cluster):
        raise DiscoveryRefused(
            f"the certificate names {cluster!r} as its cluster, which is not a "
            "valid hostname, so there is nothing to fetch")
    if not allowed(cluster, patterns):
        raise DiscoveryRefused(
            f"cluster {cluster!r} is outside the discovery allowlist "
            f"{list(patterns)}; pin it explicitly with `beamsig trust "
            f"{cluster}` if you mean to accept it")

    data = fetch_ca(cluster, timeout=timeout)

    cache = cache or cache_dir()
    os.makedirs(cache, mode=0o700, exist_ok=True)
    dest = os.path.join(cache, f"{cluster}.ca")
    tmp = dest + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, dest)

    anchors = load_trust_anchors([f"{cluster}={dest}"])
    for a in anchors:
        a.discovered = True
    return anchors


def allow_patterns(explicit=None):
    """Optional restriction, from flags and/or $BEAMSIG_DISCOVER_ALLOW."""
    pats = list(explicit or [])
    env = os.environ.get("BEAMSIG_DISCOVER_ALLOW", "")
    pats += [p.strip() for p in env.split(",") if p.strip()]
    return pats


def is_offline(explicit=False) -> bool:
    return bool(explicit) or bool(os.environ.get("BEAMSIG_OFFLINE"))
