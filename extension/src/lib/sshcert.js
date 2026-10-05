// Parse OpenSSH certificates (PROTOCOL.certkeys).
// Port of beamsig/sshcert.py.
(function (root) {
  "use strict";

  const ns = (root.Beamsig = root.Beamsig || {});
  const { Reader, Writer, b64decode, b64encode } = ns.wire;

  const CERT_TYPE_USER = 1;
  const CERT_TYPE_HOST = 2;

  async function sha256Fingerprint(bytes) {
    const d = await crypto.subtle.digest("SHA-256", bytes);
    return "SHA256:" + b64encode(new Uint8Array(d)).replace(/=+$/, "");
  }

  // critical options / extensions are a sequence of (name, data) string pairs.
  // Many Teleport extensions wrap their payload in a second string layer; peel
  // it only when the inner string accounts for the whole value, exactly as
  // beamsig/sshcert.py:_kv_pairs does.
  function kvPairs(buf) {
    const out = new Map();
    const r = new Reader(buf);
    while (!r.eof()) {
      const name = r.cstring();
      const data = r.string();
      let val = data;
      if (data.length) {
        try {
          const inner = new Reader(data);
          const s = inner.string();
          if (inner.eof()) val = s;
        } catch (e) {
          /* keep the raw value */
        }
      }
      out.set(name, val);
    }
    return out;
  }

  function parse(blob) {
    const r = new Reader(blob);
    const keytype = r.cstring();
    if (!keytype.includes("-cert-v01@openssh.com")) {
      throw new Error(`not an OpenSSH certificate: ${keytype}`);
    }
    const nonce = r.string();

    let pubkeyBlob;
    if (keytype.startsWith("ecdsa-sha2-")) {
      const curve = r.string();
      const point = r.string();
      pubkeyBlob = new Writer()
        .string(keytype.replace("-cert-v01@openssh.com", ""))
        .string(curve)
        .string(point)
        .bytes();
    } else if (keytype.startsWith("ssh-ed25519")) {
      const pk = r.string();
      pubkeyBlob = new Writer().string("ssh-ed25519").string(pk).bytes();
    } else if (keytype.startsWith("ssh-rsa")) {
      const e = r.string();
      const n = r.string();
      pubkeyBlob = new Writer().string("ssh-rsa").string(e).string(n).bytes();
    } else {
      throw new Error(`unsupported cert key type ${keytype}`);
    }

    const serial = r.u64();
    const certType = r.u32();
    const keyId = r.cstring();

    const principalsReader = new Reader(r.string());
    const validPrincipals = [];
    while (!principalsReader.eof()) validPrincipals.push(principalsReader.cstring());

    const validAfter = r.u64();
    const validBefore = r.u64();
    const criticalOptions = kvPairs(r.string());
    const extensions = kvPairs(r.string());
    const reserved = r.string();
    const signatureKey = r.string();
    // Everything up to (not including) the signature is what the CA signed.
    const signedLen = r.i;
    const signature = r.string();

    return {
      keytype,
      nonce,
      pubkeyBlob,
      serial,
      certType,
      keyId,
      validPrincipals,
      validAfter,
      validBefore,
      criticalOptions,
      extensions,
      reserved,
      signatureKey,
      signature,
      signedBytes: blob.subarray(0, signedLen),
      blob,
    };
  }

  // Pull the base64 blob out of an authorized_keys / allowed_signers /
  // known_hosts / Teleport `cert-authority ...` style line.
  function parseLine(line) {
    for (const tok of line.trim().split(/\s+/)) {
      if (tok.startsWith("AAAA")) return parse(b64decode(tok));
    }
    throw new Error("no base64 blob found in line");
  }

  ns.sshcert = {
    parse,
    parseLine,
    kvPairs,
    sha256Fingerprint,
    CERT_TYPE_USER,
    CERT_TYPE_HOST,
  };
})(typeof globalThis !== "undefined" ? globalThis : self);
