// Verify SSH-format signatures using WebCrypto. Port of beamsig/sshcrypto.py,
// which uses python-cryptography; here the same job needs two conversions the
// Python does not, because WebCrypto's shapes differ from OpenSSH's:
//
//   * ECDSA: SSH encodes the signature as `mpint r, mpint s` (variable length,
//     possibly with a leading zero pad). WebCrypto wants fixed-width r||s.
//   * RSA: SSH encodes the key as `mpint e, mpint n`. WebCrypto wants SPKI DER,
//     so we hand-roll the few DER nodes needed.
//
// Ed25519 needs neither conversion. RSA support is here because older Teleport
// clusters may have an RSA user CA; the beam leaf key itself is ECDSA P-256.
(function (root) {
  "use strict";

  const ns = (root.Beamsig = root.Beamsig || {});
  const { Reader, concat } = ns.wire;

  const CURVES = {
    nistp256: { named: "P-256", hash: "SHA-256", size: 32 },
    nistp384: { named: "P-384", hash: "SHA-384", size: 48 },
    nistp521: { named: "P-521", hash: "SHA-512", size: 66 },
  };

  const RSA_HASHES = {
    "ssh-rsa": "SHA-1",
    "rsa-sha2-256": "SHA-256",
    "rsa-sha2-512": "SHA-512",
  };

  class UnsupportedKey extends Error {}
  class InvalidSignature extends Error {}

  // ---- DER, just enough for an RSA SubjectPublicKeyInfo ---------------------

  function derLen(n) {
    if (n < 0x80) return new Uint8Array([n]);
    const bytes = [];
    let v = n;
    while (v > 0) {
      bytes.unshift(v & 0xff);
      v >>>= 8;
    }
    return new Uint8Array([0x80 | bytes.length, ...bytes]);
  }

  function derTLV(tag, body) {
    return concat(new Uint8Array([tag]), derLen(body.length), body);
  }

  // DER INTEGER is signed, so a value whose top bit is set needs a 0x00 prefix.
  function derInteger(mpint) {
    let i = 0;
    while (i < mpint.length - 1 && mpint[i] === 0) i++;
    let v = mpint.subarray(i);
    if (v.length === 0) v = new Uint8Array([0]);
    if (v[0] & 0x80) v = concat(new Uint8Array([0]), v);
    return derTLV(0x02, v);
  }

  const OID_RSA = new Uint8Array([
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  ]);
  const DER_NULL = new Uint8Array([0x05, 0x00]);

  function rsaSpki(e, n) {
    const algId = derTLV(0x30, concat(OID_RSA, DER_NULL));
    const rsaPubKey = derTLV(0x30, concat(derInteger(n), derInteger(e)));
    const bitString = derTLV(0x03, concat(new Uint8Array([0x00]), rsaPubKey));
    return derTLV(0x30, concat(algId, bitString));
  }

  // ---- key loading ----------------------------------------------------------

  async function loadSSHPublicKey(blob) {
    const r = new Reader(blob);
    const kt = r.cstring();

    if (kt.startsWith("ecdsa-sha2-")) {
      const curveName = r.cstring();
      const point = r.string();
      const curve = CURVES[curveName];
      if (!curve) throw new UnsupportedKey(`unsupported EC curve ${curveName}`);
      if (point[0] !== 0x04) {
        throw new UnsupportedKey("EC point is not in uncompressed form");
      }
      const key = await crypto.subtle.importKey(
        "raw",
        point,
        { name: "ECDSA", namedCurve: curve.named },
        false,
        ["verify"]
      );
      return { kt, kind: "ecdsa", key, curve };
    }

    if (kt === "ssh-ed25519") {
      const pk = r.string();
      const key = await crypto.subtle.importKey("raw", pk, { name: "Ed25519" }, false, [
        "verify",
      ]);
      return { kt, kind: "ed25519", key };
    }

    if (kt === "ssh-rsa") {
      const e = r.string();
      const n = r.string();
      return { kt, kind: "rsa", spki: rsaSpki(e, n) };
    }

    throw new UnsupportedKey(`unsupported SSH key type ${kt}`);
  }

  // ---- signature conversion -------------------------------------------------

  function mpintToFixed(bytes, size) {
    let i = 0;
    while (i < bytes.length && bytes[i] === 0) i++;
    const v = bytes.subarray(i);
    if (v.length > size) throw new Error("ECDSA integer too large for curve");
    const out = new Uint8Array(size);
    out.set(v, size - v.length);
    return out;
  }

  // ---- verify ---------------------------------------------------------------

  // Verify an SSH signature blob (`string alg, string sigdata`) over `message`.
  // Returns the signature algorithm name, or throws InvalidSignature /
  // UnsupportedKey / Error.
  async function verify(pubkeyBlob, sigBlob, message) {
    const loaded = await loadSSHPublicKey(pubkeyBlob);
    const r = new Reader(sigBlob);
    const alg = r.cstring();
    const sigdata = r.string();

    if (loaded.kind === "ecdsa") {
      if (!alg.startsWith("ecdsa-sha2-")) {
        throw new Error(`algorithm ${alg} does not match an ECDSA key`);
      }
      if (alg !== loaded.kt) {
        throw new Error(`signature alg ${alg} != key type ${loaded.kt}`);
      }
      const inner = new Reader(sigdata);
      const rr = inner.string();
      const ss = inner.string();
      if (!inner.eof()) throw new Error("trailing bytes in ECDSA signature");
      const raw = concat(
        mpintToFixed(rr, loaded.curve.size),
        mpintToFixed(ss, loaded.curve.size)
      );
      const ok = await crypto.subtle.verify(
        { name: "ECDSA", hash: { name: loaded.curve.hash } },
        loaded.key,
        raw,
        message
      );
      if (!ok) throw new InvalidSignature("ECDSA signature did not verify");
      return alg;
    }

    if (loaded.kind === "ed25519") {
      if (alg !== "ssh-ed25519") {
        throw new Error(`signature alg ${alg} != ssh-ed25519`);
      }
      const ok = await crypto.subtle.verify("Ed25519", loaded.key, sigdata, message);
      if (!ok) throw new InvalidSignature("Ed25519 signature did not verify");
      return alg;
    }

    if (loaded.kind === "rsa") {
      const hash = RSA_HASHES[alg];
      if (!hash) throw new Error(`unsupported RSA signature alg ${alg}`);
      let key;
      try {
        key = await crypto.subtle.importKey(
          "spki",
          loaded.spki,
          { name: "RSASSA-PKCS1-v1_5", hash: { name: hash } },
          false,
          ["verify"]
        );
      } catch (e) {
        // Browsers may refuse SHA-1 outright. Say so rather than reporting a
        // bad signature, which would be a different and misleading claim.
        throw new UnsupportedKey(
          `this browser will not verify RSA with ${hash}: ${e.message}`
        );
      }
      const ok = await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        key,
        sigdata,
        message
      );
      if (!ok) throw new InvalidSignature("RSA signature did not verify");
      return alg;
    }

    throw new UnsupportedKey("unsupported key");
  }

  ns.sshcrypto = {
    verify,
    loadSSHPublicKey,
    mpintToFixed,
    rsaSpki,
    CURVES,
    UnsupportedKey,
    InvalidSignature,
  };
})(typeof globalThis !== "undefined" ? globalThis : self);
