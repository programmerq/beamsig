// Pinned Teleport SSH user CA(s).
//
// PINNED BY VALUE, DELIBERATELY. Do not make this fetch from the cluster at
// render time: that trusts the network instead of the pin, and /webapi/auth/export
// is not CORS-accessible from github.com anyway. See REPORT.md §5 and
// docs/PRESENTATION-NOTES.md "Trust anchor".
//
// Source: GET https://<cluster>/webapi/auth/export?type=user
// Note the export format is NOT valid OpenSSH allowed_signers (it has no
// leading principal field) — see REPORT.md §6.5. We only need the base64 blob,
// so we parse it with sshcert.parseLine, which picks out the AAAA... token.
(function (root) {
  "use strict";

  const ns = (root.Beamsig = root.Beamsig || {});

  // Each entry: a line in Teleport export / authorized_keys / allowed_signers
  // shape. The cluster name is a label for the UI only; the pin is the key.
  const PINNED_CAS = [
    {
      cluster: "jeff.beams.sh",
      // Expected fingerprint, cross-checked at verify time as a tripwire
      // against someone editing the blob without updating this.
      fingerprint: "SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU",
      line:
        "cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz" +
        "dHAyNTYAAABBBC2rt1luLsu92AtID5MrxjSSDK6HqeJbKzERdXu/8MLHr5kcohFzhTpJvUlqx9cN" +
        "uWUEkdLZs/f0YlCAytnHluo= clustername=jeff.beams.sh&type=user",
    },
  ];

  ns.ca = { PINNED_CAS };
})(typeof globalThis !== "undefined" ? globalThis : self);
