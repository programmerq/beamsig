// Lazy pinning of a Teleport user CA for an unseen tenant (hands-free for
// *.beams.sh). JS twin of beamsig/discover.py; read the docstring there, which
// carries the full argument.
//
// The short version. When a certificate names a cluster we have no CA for, we
// fetch `https://<cluster>/webapi/auth/export?type=user`. That is verified
// HTTPS, so WebPKI authenticates the hostname -- "discovered" is not
// "unauthenticated". And the cluster name is not a trust decision, it is part
// of the identity being reported: an attacker who mints their own CA and a cert
// claiming `evil.example.com` will have it fetched and validated, but the
// resulting statement is *true* -- that signature really is from a beam of a
// Teleport cluster at evil.example.com. It is not, and cannot become, a
// statement about your cluster.
//
// (An earlier version of this comment called that "circular trust" and argued
// discovery should be off by default. The Python docstring it referred to was
// corrected; this is the corrected reasoning. Signing establishes provenance,
// not trust and not safety.)
//
// The real hazard is a reader seeing a tick and ignoring *which* cluster, which
// is a presentation problem. So discovery is:
//
//   * ON for `*.beams.sh` by default so it is hands-free for Beams users, and
//     switched off by emptying the allowlist in the options page;
//   * restricted to that hostname allowlist (globs), never "any host" --
//     which matters because discovery also writes to local state;
//   * trust-on-first-use: the fetched CA is stored and pinned from then on, so a
//     later change of CA is refused loudly rather than followed silently;
//   * always reported as DISCOVERED, never as operator-pinned, so the panel can
//     say which it was.
//
// It is a convenience for a team whose tenants are all its own. It is not a
// substitute for pinning.
(function (root) {
  "use strict";

  const ns = (root.Beamsig = root.Beamsig || {});

  // Every Beams tenant. Anything else must be added by the user.
  const DEFAULT_ALLOW = ["*.beams.sh"];
  const PIN_PREFIX = "pin:";
  const MAX_EXPORT_BYTES = 20000;
  const MAX_CA_LINES = 10;

  // A bare, lowercase DNS hostname: no scheme, port, path, userinfo or IP
  // literal. Stricter than the Python CLUSTER_RE because anything else would be
  // a surprising thing to hand to fetch().
  const HOSTNAME_RE =
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

  // fnmatch semantics, as in discover.py: `*` any run, `?` one character.
  function globToRegExp(glob) {
    const esc = String(glob)
      .trim()
      .toLowerCase()
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".");
    return new RegExp(`^${esc}$`);
  }

  function allowed(cluster, patterns) {
    if (typeof cluster !== "string" || !HOSTNAME_RE.test(cluster) || cluster.includes("..")) {
      return false;
    }
    return (patterns || []).some((p) => String(p).trim() && globToRegExp(p).test(cluster));
  }

  function exportUrl(cluster) {
    return `https://${cluster}/webapi/auth/export?type=user`;
  }

  // Turn a `/webapi/auth/export?type=user` body into entries that
  // verify.loadPinnedCAs understands. One `cert-authority <type> <key>
  // clustername=<name>&type=user` line per active CA (more than one during a
  // rotation). A line naming a DIFFERENT cluster than the one we asked is
  // dropped rather than trusted.
  function parseExport(text, cluster) {
    const out = [];
    for (const raw of String(text).split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      if (!/\bAAAA\S+/.test(line)) continue;
      const m = /clustername=([^&\s]+)/.exec(line);
      if (m && m[1] !== cluster) continue;
      out.push({ cluster, line, discovered: true });
      if (out.length >= MAX_CA_LINES) break;
    }
    return out;
  }

  ns.discover = {
    DEFAULT_ALLOW,
    PIN_PREFIX,
    MAX_EXPORT_BYTES,
    allowed,
    globToRegExp,
    exportUrl,
    parseExport,
  };
})(typeof globalThis !== "undefined" ? globalThis : self);
