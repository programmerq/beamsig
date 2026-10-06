# Beam-attributable signing on Teleport Beams — hackathon PoC report

Beam: `clever-nebula` / `1786bcd6-04b9-4b9e-ad87-0c13071df7e9`, cluster `jeff.beams.sh`, owner `owner@example.com`.
No private key material was extracted (it turns out it cannot be).

Experiments were originally run in a scratch directory `/tmp/beamsig-lab`; the
command transcripts below still show those paths verbatim, because that is what
was actually executed. The code, evidence logs and fixtures now live in this
repository — see §8. Everything is re-runnable from a clone via `bin/setup.sh`.

Experiments 8–10 and papercuts 20–27 were added after the first draft, and
§4(a), §4(d)–(d3) and §5 were revised. Three of those revisions correct the
draft rather than extend it, and each is called out where it appears:

* the trust model was effectively single-tenant (§4(d), Exp 8);
* `%GS` turns out to carry no evidential value at all, not merely to be
  misleading (§4(a));
* CA discovery was described as "circular trust" and disabled by default. That
  reasoning was wrong — the fetch is verified HTTPS, so the hostname *is*
  authenticated, and the cluster is part of the identity rather than a trust
  decision. Discovery is now automatic (§4(d2), Exp 9).

---

## 1. TL;DR

1. **It works, and the primary mechanism is SSH**: `ssh-keygen -Y sign` with the Teleport **certificate** embeds the *entire cert*, including `bot-name@goteleport.com`, in the SSHSIG blob — so a signature is self-contained and verifiable offline against only the exported Teleport user CA, forever.
2. **The identity file contains no private key.** It is a PIV slot reference; the key is non-exportable behind an undocumented gRPC-over-TLS *hardware key agent*. `ssh-keygen -Y sign -f key` and `openssl cms -sign -inkey key` are impossible; I had to write an ssh-agent shim over that agent.
3. **`ssh-keygen -Y verify` alone cannot prove "a beam signed this"** — it only matches cert principals, which are the generic `root`/`beams`. Beam attribution requires a custom verifier that reads the cert extensions; mine passes 12 rejection cases plus 5 multi-tenant ones.
4. **Biggest caveat: the beam key never rotates, only the cert does.** The signer picks which cert to embed, so it chooses the validity window a verifier sees. I backdated a signature 34 minutes with full verification success. The time bound is "somewhere in this beam's lifetime", not ±61 minutes.
5. **The alias is never bound** to any credential, and the only `BEAM_ID → BEAM_ALIAS` mappings are live cluster queries that disappear with the beam.
6. **Trust is keyed by cluster, and CA discovery is automatic**: an unknown cluster's CA is fetched over verified HTTPS, so cross-tenant repositories just work. A signature therefore proves **provenance, not trust** — "beam `<uuid>` of cluster `<host>`" — and the cluster must be read as part of the claim, with policy in `--cluster`/`--offline`.

---

## 2. Versions

| Component | Version |
|---|---|
| OS | Debian 12 (bookworm), x86-64 |
| `git` | 2.39.5 |
| `ssh-keygen` / OpenSSH | OpenSSH_9.2p1 Debian-2+deb12u10 |
| `openssl` | OpenSSL 3.0.22 25 Aug 2026 |
| `tsh` / `tctl` | Teleport v18.11.2 `git:v18.11.2-0-ga60e531e` go1.26.8 |
| Teleport proxy / auth | 18.11.2 |
| `tbot` (in-beam, from `bot_instance` heartbeat) | 18.11.2, `BOT_KIND_TBOT`, join method `bound_keypair` |
| Python | 3.11.2 (+ grpcio 1.84.0, cryptography 50.0.2, asn1crypto 1.5.1) |
| `gpgsm` | present at `/usr/bin/gpgsm` (unused; replaced by a shim) |

Not installed by default and needed: `python3.11-venv`, `acl` (`getfacl`). Absent entirely: `file`, `strace`, `grpcurl`, Go.

---

## 3. Findings per experiment

### Experiment 1 — Inventory

**The headline: there is no private key in the identity file.**

```
$ awk '/BEGIN PIV/{f=1;next}/END PIV/{f=0}f' /var/run/tbot/identity/identity | base64 -d
{"serial_number":4294967295,"slot_key":154,"policy":{"TouchRequired":false,
 "PINRequired":false},"attestation_statement":{},"pin_cache_ttl":0,
 "public_key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpdSD5CoF0HoCqY96..."}
```

`slot_key: 154` = PIV slot `0x9A`, `serial_number: 4294967295` = `0xFFFFFFFF` (sentinel — there is no YubiKey; `/dev/bus/usb` does not exist and no `pcscd` is running). The block carries a **public** key only.

```
$ ssh-keygen -y -f privkey.block
Load key "privkey.block": error in libcrypto
$ openssl pkey -in /var/run/tbot/identity/identity -noout
Could not read key from /var/run/tbot/identity/identity
...error:1E08010C:DECODER routines:OSSL_DECODER_from_bio:unsupported:No supported data to decode.
```

Yet signing works, because `tsh` delegates to an agent. Proof by removal:

```
$ env -u TELEPORT_KEY_AGENT_DIR tsh apps ls
ERROR: cannot relogin in non-interactive session
  connection error: ... "transport: authentication handshake failed: tls: failed to
  sign handshake: connecting to pcsc: the Smart card resource manager is not running"
```

From `lib/hardwarekey/agent.go` (Teleport branch/v18) the agent is gRPC **wrapped in TLS**, server cert at `$TELEPORT_KEY_AGENT_DIR/cert.pem`, SNI `localhost`, **no client authentication**:

```go
creds, err := credentials.NewClientTLSFromFile(certPath, "localhost")
return hardwarekeyagent.NewClient(socketPath, creds)
```

That is why raw bytes and plaintext gRPC both just get EOF. With TLS:

```
$ ./venv/bin/python ... st.Ping(pb.PingRequest())
Ping OK -> agent pid = 1
$ ... st.Sign(digest=sha256(b'hello beam'), hash=HASH_SHA256, key_ref=...)
SIGNED, der len = 71 3045022058a39c2c9e39fe36eb189d4c ...
VERIFY OK against identity public key
```

The service (`api/proto/teleport/hardwarekeyagent/v1`) is a clean generic oracle: `Sign(digest, hash, salt_length, key_ref, key_info, command) -> DER signature`. **It will sign any digest you hand it.**

**SSH certificate contents** (`bin/inventory.py`, full output `logs/exp1-inventory.txt`):

```
keytype      : ecdsa-sha2-nistp256-cert-v01@openssh.com
serial       : 0
type         : 1 (user)
key id       : owner@example.com          <-- the OWNER, not the beam
principals   : ['root', 'beams', '-teleport-internal-join']
valid        : 2026-10-05T14:36:27Z .. 2026-10-05T15:37:27Z   (3660s = 61 min)
CA           : SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU
extensions:
  bot-instance-id@goteleport.com       = dbe1cf6c-8f89-4ab3-bfee-9e2c7e710f6c
  bot-name@goteleport.com              = beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9
  delegation-session-id@goteleport.com = bd204fe3-1653-429c-bc81-b64d5a3d514f
  disallow-reissue                     =
  login-ip                             = 52.3.207.254
  private-key-policy                   = none
  teleport-roles                       = {"roles":["editor","access","auditor","beam-user"]}
  teleport-route-to-cluster             = jeff.beams.sh
  teleport-traits                      = {...,"logins":["root"],"mcp_tools":["parallel"],...}
  permit-agent-forwarding / permit-port-forwarding / permit-pty
```

Notes: `disallow-reissue` is present (good — the cert cannot mint further certs). `private-key-policy = none` despite the key being hardware-backed. `BEAM_ALIAS` appears **nowhere**.

**X.509 leaf** carries the same facts as subject RDNs: `1.3.9999.2.18` = bot name, `1.3.9999.2.20` = bot instance id, `1.3.9999.2.30` = delegation session id (all confirmed), plus `1.3.9999.1.7` = cluster, `1.3.9999.1.9` = client IP, `1.3.9999.1.20=local`, `1.3.9999.1.15=none`. Same key as the SSH cert:

```
x509 leaf pub == PIV ref pub : True
ssh cert pub   == PIV ref pub : True
```

**Gotcha:** the X.509 CA bundled *inside* the identity file is **not** the issuer of the leaf. Bundled CA serial `162940567589269845164590583852679760964` = the **host** CA (`export?type=tls-host`); the leaf's issuer serial is `122272357919907635617575441175229030869` = the **user** CA (`export?type=tls-user`). Using the bundled one fails with `unable to get local issuer certificate`.

**Renewal behaviour** (`bin/watch-renewal.py`, 4 versions over ~1h):

```
valid_after  window (UTC)         life  inode   pubkey sha256  cert sig
1791210987   14:36:27..15:37:27   3660  612357  f676a50e6896   8e12268060
1791212187   14:56:27..15:57:27   3660  612357  f676a50e6896   eb660a1052
1791213387   15:16:27..16:17:27   3660  612357  f676a50e6896   5f5694d59a
1791214587   15:36:27..16:37:27   3660  612357  f676a50e6896   546b9d9497

key rotated across any renewal : False
inode changed across renewals  : False      (rewritten IN PLACE)
bot_instance_id stable         : True
delegation_session_id stable   : True
renewal gaps (s)               : [1200, 1200, 1200]
```

**Conclusion:** renewal every **20 min**, lifetime **61 min** (so ~3 valid certs overlap at any time); the file is rewritten in place; **only the certificate changes — the key is constant for the beam's life**; `bot-instance-id` and `delegation-session-id` are stable and are the durable beam identifiers.

---

### Experiment 2 — SSH signing, raw. *This is the most important finding.*

The `-f <keyfile>` route cannot work (no key). I wrote `beamsig/sshagentshim.py`, an ssh-agent that exposes the beam cert + bare key and proxies `SSH_AGENTC_SIGN_REQUEST` to the hardware key agent:

```
$ SSH_AUTH_SOCK=run/agent.sock ssh-add -l
256 SHA256:4jXdejzBCenjWfYrR8qs6BT/esGtkz3cqVJTUWxDhf8 beam-cert clever-nebula (ECDSA-CERT)
256 SHA256:4jXdejzBCenjWfYrR8qs6BT/esGtkz3cqVJTUWxDhf8 beam-key  clever-nebula (ECDSA)
```

```
$ ssh-keygen -Y sign -f beam-cert.pub -n git msg.txt     # 2075 bytes
$ ssh-keygen -Y sign -f beam-key.pub  -n git msg.txt     # 387 bytes
$ env -u SSH_AUTH_SOCK ssh-keygen -Y sign -f beam-cert.pub -n git msg.txt
No private key found for public key "beam-cert.pub"
```

Dissecting both (`bin/dissect-sig.py`):

```
sig-from-key.sig    publickey field : 104 bytes,  type=ecdsa-sha2-nistp256
                    IS CERTIFICATE  : False

sig-from-cert.sig   publickey field : 1351 bytes, type=ecdsa-sha2-nistp256-cert-v01@openssh.com
                    IS CERTIFICATE  : True
  --- certificate recovered FROM THE SIGNATURE ALONE ---
    key id     : owner@example.com
    valid      : 2026-10-05T14:36:27Z .. 2026-10-05T15:37:27Z
    CA         : SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU
    ext bot-name@goteleport.com              = beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9
    ext bot-instance-id@goteleport.com       = dbe1cf6c-8f89-4ab3-bfee-9e2c7e710f6c
    ext delegation-session-id@goteleport.com = bd204fe3-1653-429c-bc81-b64d5a3d514f
    ext teleport-roles                       = {"roles":["editor","access","auditor","beam-user"]}
```

**Conclusion:** SSHSIG's `publickey` field holds the **full certificate** when you sign with the cert. Every beam fact plus the validity window and the CA binding travels with the signature. This is what makes offline, after-the-fact, beam-specific attestation possible, and it is the entire basis of the design. Signing with the bare key throws all identity away — and OpenSSH does that *silently* if you point `-f` at a private key (see Papercut 6).

---

### Experiment 3 — SSH verification against the Teleport CA

The export is **not** valid `allowed_signers` syntax (no principal field), and it fails *silently*:

```
$ cat ca/export-user.txt
cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNh... clustername=jeff.beams.sh&type=user
$ ssh-keygen -Y verify -f allowed_signers.naive -I root -n git -s sig-from-cert.sig < msg.txt
Could not verify signature.
```

Fixed by `bin/make-allowed-signers.sh` (prepend a principal pattern):

```
* cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNh... teleport-user-ca jeff.beams.sh
$ ssh-keygen -Y verify -f allowed_signers -I root -n git -s sig-from-cert.sig < msg.txt
Good "git" signature for root with ECDSA-CERT key SHA256:4jXdejzBCenjWfYrR8qs6BT/esGtkz3cqVJTUWxDhf8
```

The SSH user CA from `export?type=user` is byte-identical to the `signature_key` in the cert. **Principal matching — hypothesis confirmed exactly:**

```
-I 'root'                                      rc=0    Good "git" signature for root
-I 'beams'                                     rc=0    Good "git" signature for beams
-I '-teleport-internal-join'                   rc=0    Good "git" signature
-I 'owner@example.com'                       rc=255  Certificate invalid: name is not a listed principal
-I 'beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9' rc=255  Certificate invalid: name is not a listed principal

$ ssh-keygen -Y find-principals -s sig-from-cert.sig -f allowed_signers
root
beams
-teleport-internal-join
```

A bare-key signature correctly cannot verify against a `cert-authority` entry.

`-Overify-time` works precisely (window is half-open, `valid_before` exclusive):

```
20261005143000Z  rc=255  Certificate invalid: not yet valid
20261005143627Z  rc=0    Good                              <- valid_after, inclusive
20261005150000Z  rc=0    Good
20261005153727Z  rc=255  Certificate invalid: expired      <- valid_before, exclusive
20261005160000Z  rc=255  Certificate invalid: expired
20271005150000Z  rc=255  Certificate invalid: expired
```

**Can a verifier extract `bot-name` from the signature alone?** The data is there (Exp 2) but **`ssh-keygen` cannot**: it reports only principals. `ssh-keygen -L` cannot even render the extensions — `bot-name@goteleport.com UNKNOWN OPTION: 000000296265616d2d...`.

**Conclusion:** `ssh-keygen -Y verify` proves *"signed by some holder of a user certificate from this Teleport cluster"*. Since `root`/`beams` are shared by every user cert in the cluster, that is **not** beam attribution. A custom verifier is mandatory. Demonstrated in Exp 5.

---

### Experiment 4 — Git commit signing

```
git config gpg.format ssh
git config user.signingkey /tmp/beamsig-lab/exp2/beam-cert.pub   # the CERT
git config gpg.ssh.allowedSignersFile /tmp/beamsig-lab/exp2/allowed_signers
SSH_AUTH_SOCK=run/agent.sock git commit -S -m "..."
$ git verify-commit HEAD
Good "git" signature for root with ECDSA-CERT key SHA256:4jXdejzBCenjWfYrR8qs6BT/esGtkz3cqVJTUWxDhf8
```

**Git does pass the commit timestamp as verify-time.** Forged dates fail:

```
$ git log --format='%h %G? cdate=%cI %s'
febb48e  U  cdate=2027-10-05T15:00:00+00:00  forged future timestamp
bf99ccd  U  cdate=2025-10-05T15:00:00+00:00  forged past timestamp
51fbefe  G  cdate=2026-10-05T14:58:39+00:00  signed commit 1 (cert valid)

$ git verify-commit febb48e
Good "git" signature with ECDSA-CERT key SHA256:4jXdejzBCenjWfYrR8qs6BT/esGtkz3cqVJTUWxDhf8
/tmp/beamsig-lab/exp2/allowed_signers:1: no valid principals found
No principal matched.           # rc=1
```

Note the trap: the string `Good "git" signature` is printed *and then* it fails. `grep -q Good` → "TRUSTED (WRONG!)". Use the exit code or `%G?`.

**Renewal continuity.** First attempt genuinely broke, which is itself the finding:

```
[15:17:05Z] error: Signing file /tmp/.git_signing_buffer_tmp9UIrS1
Couldn't sign message (signer): agent refused operation?
fatal: failed to write commit object
```

My shim cached the cert blob at startup; after the 20-minute renewal git offered the **new** cert blob and the agent rejected it. The bare public key is stable, the **certificate blob is not**. Fixed by reloading the identity file on every request. **Any beam signing tool must re-read the identity file per operation.**

After the fix, commits across a renewal, and the decisive expiry test:

```
=== verification pass at 15:39:06Z ===
commit d1e5ee9  (gen-A)   signing cert: 14:56:27Z..15:57:27Z  [VALID]
  git verify-commit    : rc=0  Good "git" signature for root ...
  beamsig verify-commit: rc=0  result: VERIFIED
commit 12098ec  (gen-B after renewal)  signing cert: 15:16:27Z..16:17:27Z  [VALID]
  git verify-commit    : rc=0  Good "git" signature for root ...
  beamsig verify-commit: rc=0  result: VERIFIED

# POST-EXPIRY VERIFICATION  15:39:05Z
## commit 51fbefe was signed with cert 14:36:27..15:37:27, now EXPIRED
--- git verify-commit ---      Good "git" signature for root ...   rc=0
--- beamsig verify-commit ---  result: VERIFIED
     cert valid 14:36:27..15:37:27, claimed time 14:58:39 (git committer date)  rc=0

--- ssh-keygen -Y verify, same cert, NO verify-time ---
allowed_signers:1: certificate not authorized: Certificate invalid: expired
Could not verify signature.                                         rc=255
```

**Conclusion — the key asymmetry:** signed git commits are **durable** past certificate expiry because git pins verify-time to the committer date. A bare detached signature is **not**, because `ssh-keygen -Y verify` defaults to *now*. Any artifact format must therefore carry a claimed time and the verifier must pass it explicitly.

---

### Experiment 5 — Beam-specific verifier

`beamsig/verify.py` + `bin/beamsig`. Checks, in order: SSHSIG well-formed → namespace matches → **publickey must be a certificate** → cert signature verifies against a *pinned* Teleport user CA → cert is a user cert → SSHSIG signature verifies over the payload → `bot-name` present and matches `^beam-<uuid>$` → optional `--beam-id` equality → claimed time ∈ `[valid_after, valid_before)`.

```
$ ./bin/beamsig verify-commit 51fbefe -C repos/demo --ca ca/pinned-user-ca.txt
BEAM SIGNATURE ATTESTATION
  result               : VERIFIED
  payload sha256       : 95716945aae9b416e0f22c5ff84e880c0121303c53f5bb77c05c5ce3b299158b
  -- signed by --
  beam id              : 1786bcd6-04b9-4b9e-ad87-0c13071df7e9
  bot name             : beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9
  bot instance id      : dbe1cf6c-8f89-4ab3-bfee-9e2c7e710f6c   (stable per beam boot)
  delegation session   : bd204fe3-1653-429c-bc81-b64d5a3d514f
  owner (cert Key ID)  : owner@example.com   (impersonated human, NOT the signer)
  teleport roles       : editor, access, auditor, beam-user
  -- time --
  cert valid after     : 1791210987 2026-10-05T14:36:27+00:00
  cert valid before    : 1791214647 2026-10-05T15:37:27+00:00
  claimed time         : 1791212319 2026-10-05T14:58:39+00:00  (from git committer date)
```

`bin/negative-tests.sh` — **12 PASS, 0 unexpected** (`logs/exp5-negative.txt`). Fixtures are built through a throwaway `ssh-agent` so they really embed certificates (verified: `is certificate : True` for all four).

| Test | Result |
|---|---|
| genuine signature / correct payload / `--beam-id` matches | VERIFIED |
| tampered payload | `signature does not match the payload` |
| wrong CA (host CA pinned) | `certificate is not signed by any trusted Teleport user CA (cert says CA=SHA256:c/8F7..., trusted=['SHA256:IdY3Z...'])` |
| **rogue CA + forged `bot-name`**, checked against the real CA | `certificate is not signed by any trusted Teleport user CA` |
| cert with **no** `bot-name` (ordinary user cert), its own CA trusted | `certificate has no bot-name@goteleport.com extension: this is an ordinary Teleport user certificate, not a beam identity` |
| bot that is **not** a beam (`bot-name=ci-runner`), its own CA trusted | `bot-name 'ci-runner' is not of the form beam-<uuid>` |
| timestamp ±1 year, or +2h (cert lives 61m) | `claimed time ... is outside the certificate validity window ...` |
| namespace confusion | `namespace mismatch: signature is for 'some.other.namespace', expected 'beamsig.artifact.v1'` |
| wrong `--beam-id` | `beam id mismatch: signature is from beam 1786bcd6-..., expected 00000000-...` |

The contrast that justifies the whole tool — same forged cert, `ssh-keygen` with the rogue CA trusted:

```
$ ssh-keygen -Y verify -f rogue_allowed_signers -I root -n beamsig.artifact.v1 -s forged.sig < good.txt
Good "beamsig.artifact.v1" signature for root with ECDSA-CERT key SHA256:6RhhxbPvDNBtbi4POK4yUXSrJeNwjl+D2CUSVpjCshU
rc=0
$ ssh-keygen -Y find-principals -s forged.sig -f rogue_allowed_signers
root
beams
```

That certificate carries `bot-name@goteleport.com=beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9`. `ssh-keygen` never reads, checks or prints it.

---

### Experiment 6 — X.509 path (artifacts)

The brief's `openssl cms -sign ... -inkey <key>` is **impossible as written**:

```
$ openssl cms -sign -in artifact.bin -signer x509-leaf.pem -inkey privkey.block -outform DER -out artifact.p7s
Could not read signing key from privkey.block
...error:1E08010C:DECODER routines:OSSL_DECODER_from_bio:unsupported:No supported data to decode.
```

So I assembled CMS SignedData myself (`beamsig/cmssign.py`, asn1crypto) taking the one signature from the hardware agent. Output is verifiable by **stock openssl**. `bin/exp6-cms.sh` — **10 PASS, 0 unexpected**:

| Test | Result |
|---|---|
| default purpose | **reject** — `Verify error: unsuitable certificate purpose` |
| `-purpose any`, `-attime` mid-window | `CMS Verification successful` |
| `-attime` 1s before `notBefore` | `certificate is not yet valid` |
| `-attime` 1s after `notAfter` / +1 year | `certificate has expired` |
| wrong CA (tls-host) | `unable to get local issuer certificate` |
| tampered embedded content | `content verify error` |
| detached + correct file (**`-binary` required**) | `CMS Verification successful` |
| detached + wrong file | `content verify error` |

Two real frictions: (a) the Teleport leaf's EKU is `serverAuth, clientAuth`, so the default S/MIME purpose check fails — you must pass `-purpose any`; (b) detached verification needs `-binary` or SMIME text canonicalisation silently breaks the digest (the attribute matched `sha256(artifact.bin)` exactly, yet verification failed until `-binary` was added).

Upside: `openssl` prints the beam identity straight out of the subject:

```
1.3.9999.2.18=beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9
1.3.9999.2.20=dbe1cf6c-8f89-4ab3-bfee-9e2c7e710f6c
1.3.9999.2.30=bd204fe3-1653-429c-bc81-b64d5a3d514f
```

**`gpg.format=x509` assessment.** git drives the x509 program exactly like gpg (logged with a stub): sign `--status-fd=2 -bsau <keyid>`, verify `--status-fd=1 --keyid-format=long --verify <sigfile> -`, and requires `-----BEGIN SIGNED MESSAGE-----` armor. I wrote a working shim (`bin/beamsig-gpgsm-shim.py`, ~150 lines, ~40 min):

```
$ git -c gpg.format=x509 commit -S -m "..."   # works
$ git log --format='%G? signer=%GS' -1
G signer=beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9     # nicer than ssh's "root"
$ git verify-commit HEAD; echo rc=$?            rc=0
$ BEAMSIG_X509_CA=<host CA> git verify-commit HEAD; echo rc=$?   rc=1   (%G? = B)
$ git verify-commit <forged-timestamp commit>; echo rc=$?        rc=1   (%G? = B)
```

But note **why** the forged-timestamp case fails: git does **not** pass the commit time to the x509 program (`-Overify-time` is ssh-only). With stock `gpgsm` every beam commit would stop verifying 61 minutes after it was made. My shim only works because it parses the committer date out of the commit object it is handed and feeds it to `-attime` — something `gpgsm` would never do.

**Comparison / recommendation**

| | SSH / SSHSIG | X.509 / CMS |
|---|---|---|
| identity travels in signature | **yes, whole cert** | yes, whole cert |
| git support | native, stable, time-pinned | needs a bespoke shim to be time-pinned |
| verify with stock tooling | `ssh-keygen -Y verify` (but no beam attribution) | `openssl cms -verify` (needs `-purpose any`, `-binary`) |
| identity legible to stock tooling | **no** (`UNKNOWN OPTION`) | **yes** (numeric OIDs) |
| ecosystem for artifacts | thin | rich (CMS/S-MIME, timestamping RFC 3161) |

**Use SSH for git commits** — native, time-pinned, no shim. **Use SSH for artifacts too, as the primary**, with one verifier and one trust anchor for both; keep **CMS as the interop/export format** where a counterparty already consumes CMS, and because it has a standards-track path to RFC 3161 trusted timestamps, which is the real fix for the backdating problem.

---

### Experiment 7 — Audit anchoring and alias resolution

**`BEAM_ID → BEAM_ALIAS`: yes, three live paths.**

```
$ tsh beams ls --format=json
[{"id":"clever-nebula","uuid":"1786bcd6-04b9-4b9e-ad87-0c13071df7e9",
  "owner":"owner@example.com","expires":"2026-10-06T13:54:29Z",
  "url":"tcp://clever-nebula-1786.jeff.beams.sh:8080","region":"us-east-1"}]

$ tctl --auth-server=$TELEPORT_PROXY bots instances ls
beam-1786bcd6-.../dbe1cf6c-...  bound_keypair  18.11.2  clever-nebula  Healthy  2026-10-05T14:57:28Z

$ tctl ... get bot_instance        # status.initial_heartbeat.hostname == "clever-nebula"
```

All three are **live cluster state that dies with the beam** (`bot_instance` `metadata.expires: 2026-10-05T16:02:27Z`). There is **no durable, offline-verifiable** `uuid → alias` mapping. Also the alias is not obviously unique over time, so a future beam could reuse `clever-nebula`.

**`bot_instance` is a good server-side anchor while it lives** — it records exact renewal times, matching the certs I observed:

```
initial_authentication.authenticated_at: 2026-10-05T13:57:26.902Z   generation 1
latest_authentications: gen 1 13:57:26.902  gen 2 14:17:27.225
                        gen 3 14:37:27.224  gen 4 14:57:27.222
initial_heartbeat: hostname clever-nebula, os linux, arch amd64, version 18.11.2
join_method: bound_keypair, join_token: beam-1786bcd6-...
```

**Audit events: readable (the `auditor` role works), and Athena-backed SQL is available.**

```
$ tsh recordings ls --last 24h          # works, returns app-chunk sessions
$ tctl ... audit query exec "select time, cert_type, identity_user, identity_impersonator,
      identity_expires, identity_disallow_reissue from cert_create
      where event_date = date '2026-10-05' order by time desc limit 12"
2026-10-05T14:57:27.836Z user owner@example.com                ""              2026-10-05T15:57:27.815Z true
2026-10-05T14:57:27.277Z user bot-beam-1786bcd6-...              ""              2026-10-05T15:57:27.118Z
2026-10-05T14:57:27.154Z user bot-beam-1786bcd6-...  bot-beam-1786bcd6-...        2026-10-05T15:57:27.109Z true
```

The first row **is** our cert (`identity_expires` 15:57:27 matches the cert window exactly). But:

* `cert_create` has 43 columns and **none** of them are `bot_name`, `bot_instance_id`, certificate **serial**, or a **public-key fingerprint**.
* The event for the actual beam cert has `identity_user = owner@example.com` and `identity_impersonator = ""` — **empty**. The beam is invisible in its own cert issuance event.
* `bot_join` has `bot_name` but no `bot_instance_id`.

**Conclusion: a verifier cannot cryptographically correlate a signature to an audit event today.** You can show "a certificate with this expiry was issued around then", but several unrelated `owner@example.com` certs share the same second, and nothing in the event binds the key that made the signature. Audit anchoring would remove reliance on the self-reported timestamp — it is the right fix — but it needs the schema additions in §6.

---

### Experiment 8 — Multi-tenant trust

Added after the first draft, when it became clear the trust model only really
worked for one tenant. No tenant was ever hardcoded — everything derives from
`$TELEPORT_CLUSTER` — but trust was a flat list of CA blobs with no cluster
binding, and the cluster name was read from the certificate's
`teleport-route-to-cluster` extension. **That extension is only a claim made by
whoever signed the certificate.** So the moment two tenants were trusted, either
could mint a certificate claiming to be the other.

A second tenant was simulated with a local CA (`bin/multitenant-tests.sh`),
which is sufficient because the question is purely whether trust is keyed by CA.

```
$ ./bin/beamsig trust --list --store store
trust store: store
  jeff.beams.sh             SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU
  other-tenant.example.sh   SHA256:TUyoqZ74Svw7FwAOA2LGaa97BAgXoVKC8IwDCI50UFA
```

| Test | Result |
|---|---|
| tenant 1 (real beam) verifies | VERIFIED |
| tenant 2 (simulated beam) verifies from the **same** store | VERIFIED |
| tenant 2 signature, `--cluster other-tenant.example.sh` | VERIFIED |
| tenant 2 signature, `--cluster jeff.beams.sh` demanded | rejected |
| **tenant 2 mints a cert claiming to be tenant 1**, `--cluster jeff.beams.sh` | rejected |

The spoof case is the one that matters. Without `--cluster` it is attributed to
the tenant that actually signed it, and the false claim is flagged rather than
believed:

```
  teleport cluster     : other-tenant.example.sh
  cluster claimed      : jeff.beams.sh   (NOT authoritative)
  ! certificate claims cluster 'jeff.beams.sh' but was signed by the CA pinned
    for 'other-tenant.example.sh'; treating 'other-tenant.example.sh' as authoritative
```

**Conclusion:** trust is now a store of cluster-labelled pins
(`~/.config/beamsig/trusted/<cluster>.ca`) and the authoritative cluster is the
one bound to the **pin that verified the certificate**, never the one the
certificate asserts. A disagreement warns rather than fails, because a
root/leaf trusted-cluster setup legitimately routes to a cluster other than the
signer. An *unlabelled* pin cannot vouch for a cluster name at all: beamsig
falls back to the certificate's claim and says so loudly.

Two consequences. A beam's identity is really the pair **(cluster, beam id)** —
`--beam-id` alone is under-specified across tenants. And `allowed_signers` has
no syntax for which cluster a `cert-authority` line belongs to, so with several
tenants listed **stock `ssh-keygen` cannot tell them apart at all**; it is
strictly less safe than `beamsig verify` here.

---

### Experiment 9 — Commits from an unpinned tenant

What a repository with commits from several tenants actually does. Built a
genuine foreign-tenant commit (own CA, own beam bot-name,
`teleport-route-to-cluster=other.example.sh`) and verified it against a store
that does not contain its CA.

```
$ git log --show-signature -1        # stock ssh-keygen
Good "git" signature with ECDSA-CERT key SHA256:qoOp6kLYO6Fq3b3H2pihOAxceLdem6G04adObAuSdmk
No principal matched.
$ git log -1 --format='%G?|%GS'
U|
```

**`U`, not `B`** — good signature, unknown trust. The semantics were already
right; the output was useless, and to a reader it looks like tampering.

A surprise that cost some time: **git never calls `-Y verify` here.** When
`find-principals` finds no match it calls `-Y check-novalidate` instead, so a
hook placed in the verify path never runs.

```
argv: -Y find-principals -f .../allowed_signers -s /tmp/.git_vtag_tmpBwvXb4 -Overify-time=20261005204050
argv: -Y check-novalidate -n git -s /tmp/.git_vtag_tmpBwvXb4 -Overify-time=20261005204050
```

With the explanation added at `check-novalidate`, and `%G?` still `U`:

```
Good "git" signature with ECDSA-CERT key SHA256:qoOp6kLYO6Fq3b3H2pihOAxceLdem6G04adObAuSdmk
UNTRUSTED TENANT: the signature is intact, but its Teleport CA is not pinned here.
  claims cluster  other.example.sh  (unverified: this comes from the certificate itself)
  claims beam     5d41402a-bc4b-2a76-b971-9d911017c592  (unverified)
  issuing CA      SHA256:48TyCfGeffUJFJ8EF60O5RtCnnoFQ8oanLMqS3xy/rU
  to trust it     beamsig trust other.example.sh
```

`beamsig verify*` now exits **3** for an untrusted tenant, distinct from **2**
for an invalid signature. That distinction matters: "we have never heard of
that tenant" is not "this signature is bad", and CI or a UI must be able to
tell them apart.

**CA discovery is automatic.** When the certificate names a cluster we have no
CA for, beamsig fetches
`https://<cluster>/webapi/auth/export?type=user`, caches it under
`~/.config/beamsig/discovered/`, and carries on.

An earlier draft of this report had discovery disabled by default and described
it as "circular trust" with an "unauthenticated" first use. **That reasoning was
wrong on the central point.** The fetch is verified HTTPS, so WebPKI
authenticates the hostname: discovery is not unauthenticated at all. And the
cluster name is not a trust decision, it is *part of the identity* being
reported. An attacker can certainly mint their own CA and a certificate
claiming `teleport-route-to-cluster=attacker.example`, and discovery will fetch
their CA and validate it — but the resulting statement is **true**: that
signature really is from a beam of a Teleport cluster at attacker.example. It
is not, and cannot be turned into, a statement about your cluster. Operator
pins are loaded first and are never replaced, so an attacker also cannot talk a
verifier out of an anchor it already has.

The framing that matters: **signing establishes provenance, not trust or
safety.** The real hazard is not forgery, it is a reader seeing `VERIFIED` and
ignoring *which* cluster it names. That is a presentation problem, so the
cluster is always reported alongside whether its CA was pinned or discovered:

```
  teleport cluster     : jeff.beams.sh   (CA discovered over HTTPS)
  teleport cluster     : jeff.beams.sh   (operator-pinned CA)
```

Policy is explicit and separate from verification: `--cluster <name>` to
require a tenant, `--discover-allow <glob>` to restrict discovery,
`--offline`/`BEAMSIG_OFFLINE` to forbid fetching, `beamsig trust <cluster>` to
pin ahead of time.

A consequence worth stating, because it caught one of my own tests: **`--ca` is
a seed, not a whitelist.** With discovery on, pinning the wrong CA no longer
prevents verification — the right one is fetched for the cluster the
certificate names. The negative test asserting "wrong CA → reject" began
passing verification, correctly. It now tests the knobs that actually restrict:

| Test | Result |
|---|---|
| wrong CA pinned, discovery on | **verifies** (`--ca` is not a whitelist) |
| wrong CA pinned, `--offline` | rejected — trust anchors gate |
| discovery on, `--cluster other.example.sh` | rejected |
| discovery on, `--discover-allow '*.nope.example'` | rejected |

Hostnames are validated before any request (`../../etc/passwd`, `a b`,
`localhost`, `no-dot`, `a..b`, `http://x.com`, `x.com:8080` and over-long names
all refused), redirects are not followed, and TLS verification is mandatory.

Two residual caveats stand. Discovery needs the network, so offline
verification still requires a pin. And a verifier makes an HTTPS request to a
hostname supplied by the artifact it is checking — a minor outbound-request
consideration in CI, bounded by `--discover-allow` and `--offline`. Note that a
literal IP such as `127.0.0.1` passes hostname validation; it will fail TLS in
practice, but the request is still attempted. I left that permissive rather
than block private ranges, because legitimate internal clusters need internal
names.

**Conclusion:** discovery on by default is the right trade. It makes the common
case — a repository spanning several of a team's own tenants — work without
pre-registration, and it does not weaken what a signature proves, because the
cluster was never a trust decision in the first place. What it does demand is
that consumers render the cluster and apply policy themselves.

---

### Experiment 10 — Cross-beam verification, confirmed

The headline claim, actually demonstrated rather than argued. A second beam
(`vapor-jet`, `8bba9461-…`) was created, provisioned by copying one file, and
made to sign. This beam (`clever-nebula`) verified it.

```
$ git log --show-signature -1 origin/vapor-jet-demo
Good "git" signature for beam-8bba9461-0638-4a00-9752-c9064f9d832f with ECDSA-CERT key SHA256:FVjefo3v…
  bot instance  c39a4a51-f694-47ef-abc2-bb96340810d7
  owner         owner@example.com  (impersonated, NOT the signer)
  cert window   2026-10-05T17:16:27Z .. 2026-10-05T18:17:27Z
  teleport CA   SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU
```

Different signing key (`FVjefo3v…` vs `4jXdejzB…`), different bot instance,
different delegation session, **same CA**. No shared secret; the only thing the
verifier needed was the cluster's public user CA. Demanding the wrong
`--beam-id` fails with rc=2. The same held for the artifact path: an artifact
signed on `vapor-jet` verified here after being copied over, and each beam has
its own key, so the key fingerprint is a per-beam identifier.

---

## 4. Security analysis

The one-line framing, which the rest of this section elaborates: **a signature
establishes provenance, not trust and not safety.** It says which beam of which
cluster produced some bytes. It says nothing about whether those bytes are
good, reviewed, or from anyone you ought to listen to.

### What a verified `beamsig` signature **does** prove

1. The payload is byte-exact (ECDSA P-256 over SSHSIG signed-data).
2. The signing key was certified by the **Teleport user CA of cluster `jeff.beams.sh`** — verified against a pinned CA, not a self-asserted one.
3. The certificate was issued to Machine ID bot `beam-<uuid>`, i.e. **that specific beam**, with bot instance `dbe1cf6c-…` and delegation session `bd204fe3-…`.
4. The beam's Teleport roles at issuance (`editor, access, auditor, beam-user`) and the owner it impersonates (`owner@example.com`).
5. The signature was produced **at some point during that certificate's 61-minute window** — *subject to the backdating caveat below*.
6. Verifiable **offline, forever**, with only the exported CA (`webapi/auth/export?type=user`, ~200 bytes). The beam, its certs, and the whole cluster can be gone.

### What it does **not** prove

**(a) Impersonation: Key ID is the owner, not the beam — and the reported "signer" is worse than misleading, it is verifier-controlled cosmetics.** The cert's Key ID is `owner@example.com` and the principals are `root`/`beams`. Any tool that reports "who signed this" from the Key ID or principals — which is every stock tool — will say **the human**. The beam identity is *only* in the extensions.

The first draft called `%GS` merely misleading. It is weaker than that. Git does not know who signed: it runs `ssh-keygen -Y find-principals`, takes the **first line**, and feeds it back as `-I`; `ssh-keygen` then echoes that same string into `Good "git" signature for <X>`. So `%GS` is the first of the certificate's SSH login principals that *the verifier's own* `allowed_signers` happens to accept. Same commit, same signature, same key, only the trust file edited:

| `allowed_signers` principals | `%GS` reports |
|---|---|
| `*` | `root` |
| `beams` | **`beams`** |
| `beams,root` | **`beams`** |
| `nonexistent-principal` | *(empty, `%G?`=U, rc=1)* |

And it can never be the thing you want — `-I beam-1786bcd6-…` or `-I owner@example.com` both give `name is not a listed principal`, because `allowed_signers` matching is defined over certificate *principals* only, and the bot name is an extension. `%GS` therefore has **no evidential value**, not even as a weak signal, and a UI must not surface it. (`bin/git-beamsig-keygen` exploits the same mechanism deliberately to put the beam name there — which is honest only because it also performs the beam checks before printing it.)

Mitigation: the verifier must read `bot-name` and must *display* the owner as "impersonated, not the signer". Consequence: a beam signature is **not** evidence the human reviewed anything.

**(b) Anything in the beam can sign — the key is not readable, but it is freely usable.** This is more nuanced than "can read the key". The key is genuinely non-exportable; I could not extract it and neither can an attacker. But the hardware key agent has:

* **no client authentication** (`NewServerTLSFromCert`, no `ClientCAs`; the client only authenticates the *server*),
* no PIN (`PINRequired: false`), no touch (`TouchRequired: false`), `private-key-policy = none`,
* an unrestricted `Sign(digest, …)` method — it will sign **any 32 bytes** with no idea what they mean,
* and the only gate is filesystem reachability:

```
# file: var/run/tbot/identity/          user::rwx  user:beams:r-x  other::---
# file: var/run/tbot/identity/cert.pem  user::rw-  user:beams:r--  other::---
# file: var/run/tbot/identity/agent.sock user::rwx group::rwx other::rwx
$ awk -F: '$3>=1000 && $3<65534 {print $1,$3}' /etc/passwd
beams 1000
```

`agent.sock` is mode 0777, but the directory ACL only lets `root` and `beams` traverse in. Since `beams` is the only non-system user and runs everything (including me, an LLM agent, and any code I execute), **every process in the beam is fully authorised to sign as the beam**. `cert.pem` is not an access control — it is the TLS server cert the client pins, and a client is free not to verify it.

So the signature attests to the **beam as a sandbox**, never to a particular program, commit author, or human intent. Prompt injection, a malicious dependency, or `curl | sh` inside the beam all produce signatures indistinguishable from mine.

**(c) The self-reported timestamp, and the backdating break.** Two layers:

*Layer 1 (expected):* the claimed time is signer-supplied. For git it is the committer date — signed, so it cannot be altered afterwards, and `git verify-commit` rejects dates outside the cert window. That bounds a commit to ±61 minutes. Good.

*Layer 2 (the real problem, and the single biggest caveat in this report):* **the key never rotates — only the cert does.** Every cert the beam has ever held binds the *same* key. The signer therefore chooses which certificate to embed, and so chooses the window a verifier will see. Demonstrated:

```
$ date -u                                           # 2026-10-05T15:11:29Z
$ ./bin/beamsig sign backdated.txt -o backdated.sig --cert-from archive/identity-000-1791210987
$ ./bin/beamsig verify backdated.txt -s backdated.sig --ca ca/pinned-user-ca.txt \
      --beam-id $BEAM_ID --claimed-time 1791211047          # 14:37:27Z
  result               : VERIFIED
  beam id              : 1786bcd6-04b9-4b9e-ad87-0c13071df7e9
  cert valid after     : 1791210987 2026-10-05T14:36:27+00:00
  cert valid before    : 1791214647 2026-10-05T15:37:27+00:00
  claimed time         : 1791211047 2026-10-05T14:37:27+00:00
  claimed time in window: yes
```

Signed at 15:11:29, attested as 14:37:27 — **34 minutes earlier, fully VERIFIED, including `--beam-id`**. tbot overwrites the identity file in place, so old certs are *normally* gone; but any process in the beam can archive them as they arrive (exactly what `bin/watch-renewal.py` does in 60 lines). Therefore:

> The achievable time bound is **"somewhere between this beam's first certificate and its current one"** — i.e. up to the beam's whole lifetime (24h here) — **not 61 minutes**. Backdating only; forward-dating is impossible (you cannot produce a future cert).

This is **not fixable in the verifier**. It needs an external timestamp (RFC 3161 TSA, a transparency log, or correlation to a server-side audit event). I would not claim a tight "during `<time window>`" without one.

**(d) Cross-tenant impersonation, if trust is not keyed by cluster.** Covered in Experiment 8. The short version: `teleport-route-to-cluster` is a claim scoped to whoever signed the certificate, so a flat list of trusted CAs lets any trusted tenant impersonate any other. The authoritative cluster must come from the pin. This was a real flaw in the first draft's design, not a hypothetical. Related: `allowed_signers` cannot express cluster at all, so stock `ssh-keygen` with several tenants listed cannot distinguish them — any trusted tenant's beam will verify as any other's.

**(d2) Automatic CA discovery, and a correction.** An earlier draft called this "circular trust" and disabled it by default. That was wrong on the central point: the fetch is verified HTTPS, so WebPKI authenticates the hostname, and the cluster name is part of the *identity* reported rather than a trust decision taken on the verifier's behalf. Discovery is now on by default.

What a discovered anchor proves is exactly what it says: the signer controls a Teleport cluster at that hostname. Anyone can stand one up, so **a `VERIFIED` result is provenance, not trust or safety** — the cluster must be read as part of the claim. Operator pins are loaded first and never replaced, so discovery cannot displace an existing anchor. Policy lives in `--cluster`, `--discover-allow` and `--offline`, deliberately separate from verification.

Consequence: `--ca` is a seed, not a whitelist. Pinning the wrong CA no longer blocks verification, which is how this was caught — a negative test asserting "wrong CA → reject" started passing. Use `--offline` when the trust store must be the only authority. Residual: discovery needs the network, and the verifier makes a request to a hostname named by the artifact (bounded by `--discover-allow`/`--offline`; a literal IP passes name validation but fails TLS).

**(d3) The signing shim hijacked every signature.** Worth recording because it bit me rather than being theorised: installed globally, `git-beamsig-keygen` ignored `user.signingkey` entirely and signed *everything* as the beam. A developer with their own SSH or GPG signing key would have had it silently replaced. It was found when a test fixture meant to be signed by a second tenant came out signed by this beam, with output confidently naming the wrong beam. Fixed: the shim now only claims a signature when the configured key really is the beam's, and otherwise hands back to the real `ssh-keygen`. The general lesson — a tool that takes over a global code path must be conservative about *when* it takes over.

**(e) The alias is not bound.** `BEAM_ALIAS` appears in no certificate, SSH extension, or X.509 OID. My attestation envelope carries it under `selfReported` and renders it `<-- unverifiable`. Resolving `uuid → alias` needs a live cluster query that dies with the beam, so a third party verifying later **cannot** establish the alias at all. Only the UUID is durable. Anyone building on this should treat the alias as a cosmetic label and the UUID as the identity. Aliases also look reusable across beams over time.

**(f) Renewal / rotation behaviour.** Renewal every 20 min, 61-min lifetime, file rewritten in place (same inode), **key constant**, `bot-instance-id` and `delegation-session-id` stable. Implications: signing tools must re-read the identity file per operation or they break ~20 minutes in (Exp 4) — and this failure is *silent in the sense that it looks like an agent error, not a cert problem*. Durability is fine: expired certs still verify when the verifier supplies the right time. And because the key is stable, the **key fingerprint is itself a beam-lifetime identifier** — a useful cross-check, and also the thing that enables (c).

**(g) Every beam signature permanently carries the owner's email address.** The certificate's Key ID *is* the owner's address, so it is embedded in every signature, forever, and travels wherever the artifact goes. There is no way to sign as a beam without disclosing it: it is not an optional field, it is the identity the beam impersonates. Noticed while scrubbing a real address out of this repository's own prose, and finding it still inside the committed test fixtures and in git history, where it cannot be removed without invalidating the signatures. Consequences: a public repository of beam-signed commits publishes the launching human's address for every commit; and a public demo page that runs a real verifier will display it unless it masks it deliberately (`docs/assets/site.js` now does, labelled as masked, since the point being taught is that verification *does* reveal the owner). Anyone deploying this to a public repo should decide whether that is acceptable before, not after.

**(h) Smaller points.** `disallow-reissue` is present, so a leaked cert cannot mint more certs — good. There is no revocation story: if a beam is compromised, already-made signatures remain valid forever and nothing in the envelope can be revoked (Teleport CRLs cover TLS, not SSHSIG). `teleport-traits` leaks `mcp_tools`, `logins`, and the owner's login IP into every signature — a mild privacy consideration for public repos. I did not verify whether `Sign` calls are audited server-side; the agent is local to the beam and I saw no evidence they are, so assume **signing is unaudited**.

---

## 5. Proposal: `beamsig`

Prototype implemented and exercised in this report; `bin/beamsig` with `sign`, `verify`, `verify-commit`, `attest`, `verify-attestation`, `inspect`.

### Architecture

```
 ┌─────────────── beam ────────────────┐
 │ tbot ── identity file (cert only)   │
 │   └─ hardware key agent (gRPC/TLS)  │  <- the only signing oracle
 │          ▲                          │
 │  beamsig-agent (ssh-agent shim)     │  <- re-reads identity EVERY request
 │          ▲                          │
 │   git -S  /  beamsig sign|attest    │
 └─────────────────────────────────────┘
        signature embeds the FULL Teleport certificate
                       │
 ┌───────────── third party, offline, years later ─────────────┐
 │ trust store: ~/.config/beamsig/trusted/<cluster>.ca         │
 │   one ~200-byte pin per tenant, cluster-labelled            │
 │ beamsig verify → match a pin, take the cluster FROM the pin,│
 │                  require bot-name=beam-<uuid>,              │
 │                  check claimed time ⊂ cert window           │
 └─────────────────────────────────────────────────────────────┘
```

A **store of cluster-labelled pins**, not a single anchor: teams do not all share one Beams tenant. Pin **by value** and publish alongside the artifacts; `--ca <url>` is a convenience for live use only and should refuse to run in strict mode. The authoritative cluster is the one bound to the pin that verified the certificate, never the one the certificate claims (Experiment 8). `beamsig trust <cluster>` adds a tenant; `--discover-allow <glob>` permits opt-in TOFU for a domain you own (Experiment 9).

Three outcomes, not two:

| exit | meaning |
|---|---|
| 0 | verified |
| 2 | invalid — bad signature, tampered payload, out-of-window, not a beam |
| 3 | **untrusted tenant** — intact signature, CA not pinned |

Collapsing 3 into 2 is the mistake to avoid: in a repository spanning tenants it makes "we have not pinned them" indistinguishable from "this is forged".

### Signing

* **git**: `gpg.format=ssh` plus `gpg.ssh.program` = `bin/git-beamsig-keygen`, installed beam-wide by `bin/install-global.sh`. The shim keeps git's native verify-time pinning, reports the beam rather than `root` in `git log` and `%GS`, performs the pinned-CA and bot-name checks the stock tooling cannot, explains unpinned tenants instead of emitting `No principal matched.`, and reads the current certificate on every signature so the 20-minute rotation is invisible. It must only claim a signature when the configured key really is the beam's — see §4(d3).
* **artifacts**: SSHSIG in namespace `beamsig.artifact.v1`, or an attestation envelope for multiple subjects. Optional CMS export for CMS-native consumers.
* **Namespaces are mandatory and distinct** per use (`git`, `beamsig.artifact.v1`, `beamsig.attestation.v1`) so a signature cannot be replayed across contexts — tested.

### Attestation format (in-toto/DSSE flavoured)

```json
{
  "payloadType": "application/vnd.beamsig.statement+json",
  "payload": "<base64 canonical JSON>",
  "signatures": [{ "sshsig": "-----BEGIN SSH SIGNATURE-----\n..." }]
}
```

Statement:

```json
{
  "_type": "https://beamsig.dev/Statement/v1",
  "subject": [{"name": "out1.bin", "digest": {"sha256": "778d19f1..."}}],
  "predicateType": "https://beamsig.dev/BeamProvenance/v1",
  "predicate": {
    "selfReported": {
      "beamAlias": "clever-nebula",
      "beamId": "1786bcd6-...",
      "cluster": "jeff.beams.sh",
      "signedAt": "2026-10-05T15:15:40+00:00",
      "note": "beamAlias and signedAt are NOT bound by the Teleport certificate and must be treated as unverified claims"
    }
  }
}
```

Design rules, each learned from a failure above:

1. **Authoritative facts come only from the embedded certificate — and the cluster only from the pin.** `beamId`, roles and window are re-derived from the cert; the statement copies are advisory and cross-checked. `cluster` comes from the matching trust anchor, with `cluster_claimed` and `cluster_pinned` exposed separately so a consumer can tell a pinned tenant from a self-asserted one. Treat a beam's identity as the pair *(cluster, beam id)*.
2. **Unprovable claims are quarantined** under `selfReported` and rendered `<-- unverifiable`. The alias and wall-clock time live there.
3. **Canonical JSON is enforced on verify** — a non-canonical payload would allow two readings of the same signed bytes; `open_envelope` rejects it.
4. **Exactly one signature**, to avoid "which signature did you actually check" confusion.
5. Verification is **fail-closed with a specific message**; the renderer never prints the word "Good" unless the exit code is 0.

```
$ ./bin/beamsig verify-attestation bundle.json --subject-dir . --ca ca/pinned-user-ca.txt --beam-id $BEAM_ID
  result               : VERIFIED
  beam id              : 1786bcd6-04b9-4b9e-ad87-0c13071df7e9
  -- subjects (digests verified against disk: yes) --
  778d19f164a4e89c370c6c57296ef7786bd074ff4c3e275d8f978db1ea31ab1b  out1.bin
  -- self-reported, NOT PROVEN by the certificate --
  beam alias           : 'clever-nebula'  <-- unverifiable
  signedAt             : '...'            <-- unverifiable
$ # tampered subject file  -> subject out1.bin digest mismatch   (rc=2)
$ # rewritten payload      -> signature does not match the payload (rc=2)
```

### Hardening I would add before trusting this

1. **An RFC 3161 timestamp** over the SSHSIG blob, counter-signed by an external TSA, stored in the envelope. This is the only clean fix for the backdating break in §4(c) and converts "sometime in this beam's life" into "before time T".
2. **Refuse archived certificates**: require the embedded cert's `valid_after` to be the newest the verifier can corroborate, or publish a signed ledger of `(bot_instance_id, generation, valid_after)` so a verifier can tell which cert *should* have been used. Partially possible today from `bot_instance.latest_authentications`, while the beam lives.
3. **Append-only transparency log** of `(payload_sha256, cert_serial, bot_instance_id, time)`, so the window is pinned by a third party and signatures become discoverable/auditable.
4. **Capture the alias at signing time, server-attested** — see §6.1.
5. `--strict` mode: CA pinned by fingerprint from a local file only, claimed time mandatory, `disallow-reissue` required, namespace required.

---

## 6. Feature requests for Beams / Teleport

**1. Put the beam alias in the certificate.**
*Why:* the alias is the only name humans use (`clever-nebula`), and it is in **nothing** — no SSH extension, no X.509 OID. *Why current state is insufficient:* the only `uuid → alias` mappings (`tsh beams ls`, `tctl bots instances ls`, `bot_instance.status.initial_heartbeat.hostname`) are live cluster state that expires with the beam (`metadata.expires` was ~2h out). A third party verifying a signature next year cannot recover the alias at all, so `beamsig` must print it as unverifiable. Requested: `beam-alias@goteleport.com` SSH extension + a matching OID. Also please state whether aliases are unique over time; if they are reusable, say so, because people will treat them as identities.

**2. A dedicated signing credential, or at least a signing-capable EKU.**
*Why:* today the beam signs artifacts with the same key it uses for TLS client auth and SSH login. *Why insufficient:* (a) `openssl cms -verify` rejects it by default — `unsuitable certificate purpose` — because EKU is `serverAuth, clientAuth`, forcing every verifier to pass `-purpose any`, which disables purpose checking wholesale; (b) a signing key with an unauthenticated, PIN-less, touch-less oracle is a cross-protocol risk. Requested: a separate short-lived signing cert (distinct key, `emailProtection`/`codeSigning` EKU, its own PIV slot), or at minimum add a signing EKU.

**3. Make the beam visible in its own `cert_create` audit event.**
*Why:* this is the one change that would let a verifier anchor a signature to server-attested time and kill the backdating break. *Why insufficient:* `cert_create` has 43 columns and **none** of `bot_name`, `bot_instance_id`, certificate `serial`, or a public-key fingerprint; worse, the event for the beam's actual cert shows `identity_user = owner@example.com` with `identity_impersonator` **empty**, so the beam is invisible. Requested: add `identity_bot_name`, `identity_bot_instance_id`, `identity_delegation_session_id`, `cert_serial_number`, and `public_key_fingerprint` to `cert_create`; add `bot_instance_id` to `bot_join`. Then a verifier can ask "was *this* key certified for *this* beam at *this* time" instead of guessing from an expiry timestamp shared by unrelated certs.

**4. Non-zero, unique certificate serial numbers for user certs.**
*Why:* the SSH cert `serial` is `0`. *Why insufficient:* with serial 0 there is no compact handle to reference a specific certificate in an audit event, a revocation list, or a transparency log; you are left comparing validity windows, which collide (several certs shared the same second in my `cert_create` output).

**5. Publish the CA export in a format OpenSSH actually accepts.**
*Why:* `webapi/auth/export?type=user` emits `cert-authority <type> <key> clustername=…&type=user`, which is neither valid `allowed_signers` (no principal field) nor valid `known_hosts` (no `@`). *Why insufficient:* pasting it into `allowed_signers` fails **silently** — `ssh-keygen` says `Could not verify signature`, not a syntax error, which is a long debugging session for anyone setting up git signing. Requested: `?format=allowed_signers` returning `* cert-authority ecdsa-sha2-nistp256 AAAA…`, and document the fingerprint for pinning.

**6. Ship a beam-aware verify command.**
*Why:* `ssh-keygen -Y verify` on a beam signature prints `Good "git" signature for root`, and `ssh-keygen -L` renders every Teleport extension as `UNKNOWN OPTION: 000000296265616d…`. *Why insufficient:* "root" is shared by every user cert in the cluster, so stock tooling structurally cannot distinguish a beam from any other cert holder — I demonstrated a forged `bot-name` that `ssh-keygen` accepts and reports as `Good … for root`. Everyone will otherwise reimplement SSH certificate parsing (I did). Requested: `tsh beams verify-signature` / `tbot verify`, plus a library, that enforces bot-name and prints the owner as impersonated.

**7. Authenticate, scope and audit the hardware key agent.**
*Why:* `$TELEPORT_KEY_AGENT_DIR/agent.sock` is mode 0777 with **no client authentication**, no PIN, no touch, and an unrestricted `Sign(digest)`. *Why insufficient:* every process running as `beams` — i.e. all workload code, including anything an LLM agent is tricked into running — can sign arbitrary digests as the beam, indistinguishably and (as far as I can tell) unaudited. Requested: peer-credential checks (SO_PEERCRED) with an allow-list, a per-namespace or per-purpose restriction on what may be signed, and a local audit trail of `Sign` calls including the `command` field the protocol already carries.

**8. Document the identity file and the agent.**
*Why:* a `BEGIN PIV YUBIKEY PRIVATE KEY` block that contains no private key, on a machine with no YubiKey, with sentinel serial `0xFFFFFFFF`, is actively misleading. *Why insufficient:* the failure modes are opaque (`error in libcrypto`; `No supported data to decode`; `connecting to pcsc: the Smart card resource manager is not running`), and I had to read Teleport's Go source to discover the agent needs TLS with `cert.pem` and SNI `localhost`. Also document that **only the cert rotates, every 20 minutes, in place** — consumers that cache the cert blob break (Exp 4), and that the bundled X.509 CA is the **host** CA, not the issuer of the leaf.

**9. Let `allowed_signers` express which cluster a CA belongs to.**
*Why:* a verifier that trusts several Teleport clusters cannot tell them apart with stock OpenSSH. *Why insufficient:* `allowed_signers` has no field for it, so every trusted `cert-authority` line is interchangeable and any trusted tenant's certificate verifies as any other's. I had to key trust by cluster in `beamsig` and accept that the `ssh-keygen` path is strictly less safe. This is really an OpenSSH request, but Teleport could help by documenting the hazard, and by emitting the cluster name in the export in a form tools can bind to (an `allowed_signers` option such as `cluster="..."`, were one to exist).

**10. Make the signing cluster unambiguous in the certificate.**
*Why:* `teleport-route-to-cluster` is the only cluster name in the credential, and it is a routing hint rather than an assertion of the issuer. *Why insufficient:* it is set by whoever signs, so it cannot be used to distinguish tenants, and in a root/leaf setup it legitimately differs from the signer — which means a verifier cannot even treat a mismatch as an error. An extension naming the *issuing* cluster (or the issuing CA's fingerprint) would let a verifier bind a signature to a tenant without relying on operator-maintained pin labels.

**11. Optional: bind the workload.** Even a coarse signal (the `command` string, a cgroup, or a caller-supplied purpose string) recorded in a signing audit event would let a reviewer distinguish "the build system signed this" from "something else in the sandbox signed this". Today the attestation is sandbox-level only.

---

## 7. Papercuts

1. **The identity file's "private key" is not a key.** `ssh-keygen -y -f privkey.block` → `Load key "privkey.block": error in libcrypto`. `openssl pkey -in /var/run/tbot/identity/identity -noout` → `Could not read key ... error:1E08010C:DECODER routines:OSSL_DECODER_from_bio:unsupported:No supported data to decode.` `openssl cms -sign -inkey privkey.block` → `Could not read signing key from privkey.block`. (OpenSSH 9.2p1, OpenSSL 3.0.22.) It is base64 JSON naming PIV slot `0x9A` with serial `0xFFFFFFFF`; the beam has no smartcard at all.

2. **The signing agent is undiscoverable without reading Teleport's source.** `SSH_AUTH_SOCK=/var/run/tbot/identity/agent.sock ssh-add -l` → `error fetching identities: communication with agent failed` (it is not an ssh-agent). Raw bytes and an HTTP/2 preface both get **0 bytes / EOF**. Plaintext gRPC → `UNAVAILABLE: Socket closed`. It is gRPC **over TLS**, CA = `cert.pem` in the same dir, SNI `localhost`, found only in `lib/hardwarekey/agent.go`. (Teleport 18.11.2.)

3. **Removing the agent produces a misleading smartcard error.** `env -u TELEPORT_KEY_AGENT_DIR tsh apps ls` → `tls: failed to sign handshake: connecting to pcsc: the Smart card resource manager is not running`. Nothing points at `TELEPORT_KEY_AGENT_DIR`. Also `tsh --debug` logs nothing about the agent at all. Worse, `tsh` **exits 0** on this error.

4. **The CA export is not valid `allowed_signers`, and fails silently.** Using `webapi/auth/export?type=user` verbatim: `ssh-keygen -Y verify -f allowed_signers.naive -I root -n git -s sig.sig < msg` → `Could not verify signature.` — no hint that the line was unparseable (it lacks the leading principal field). (OpenSSH 9.2p1.)

5. **The X.509 CA inside the identity file is the wrong CA.** It is the **host** CA (serial `162940567589269845164590583852679760964`); the leaf's issuer is the **user** CA (serial `122272357919907635617575441175229030869`). Using the bundled one: `openssl cms -verify -CAfile <bundled>` → `Verify error: unable to get local issuer certificate`.

6. **`ssh-keygen -Y sign -f <privatekey>` silently discards the certificate.** With `u` and `u-cert.pub` side by side, `ssh-keygen -Y sign -f u -n test m.txt` produces `is certificate : False` — all identity gone, no warning. You must pass `-f u-cert.pub` (which then finds `u` on its own). This made two of my own negative tests pass for the wrong reason until I checked the fixtures. (OpenSSH 9.2p1.)

7. **`ssh-keygen -Y verify` principals cannot be the beam.** `-I beam-1786bcd6-…` or `-I owner@example.com` → `allowed_signers:1: certificate not authorized: Certificate invalid: name is not a listed principal`. Only `root` / `beams` / `-teleport-internal-join` work — generic across the whole cluster.

8. **`ssh-keygen -L` cannot render Teleport extensions.** `bot-name@goteleport.com UNKNOWN OPTION: 000000296265616d2d31373836626364362d…(len 45)`. Every extension that matters is hex. (OpenSSH 9.2p1.)

9. **git prints `Good … signature` and then fails.** For a commit dated outside the cert window: `git verify-commit` emits `Good "git" signature with ECDSA-CERT key SHA256:…` followed by `No principal matched.`, exit 1. A `grep -q Good` check reports `TRUSTED (WRONG!)`. Use the exit code or `%G?` (`U` vs `G`). (git 2.39.5.)

10. **A cached certificate breaks signing ~20 minutes in.** After a tbot renewal: `error: Signing file /tmp/.git_signing_buffer_tmp9UIrS1` / `Couldn't sign message (signer): agent refused operation?` / `fatal: failed to write commit object`. Cause: the cert blob changed, the bare key did not. Tools must re-read the identity file per operation. (git 2.39.5 + my shim.)

11. **`openssl cms -verify` rejects Teleport leaves by default.** `Verify error: unsuitable certificate purpose` — EKU is `serverAuth, clientAuth`, not `emailProtection`. Needs `-purpose any`, which disables purpose checking entirely. (OpenSSL 3.0.22.)

12. **Detached CMS silently needs `-binary`.** Without it: `CMS_SignerInfo_verify_content:verification failure` / `content verify error`, even though the `messageDigest` attribute equals `sha256(artifact.bin)` exactly (verified byte-for-byte). SMIME text canonicalisation. (OpenSSL 3.0.22.)

13. **git's x509 path drops the commit timestamp.** `-Overify-time` is ssh-format-only, so with stock `gpgsm` every beam commit would go `%G? = B` 61 minutes after being made. My shim had to parse the committer date out of the commit object and pass `-attime`. git invokes the program as `--status-fd=2 -bsau <keyid>` and requires `-----BEGIN SIGNED MESSAGE-----` armor — none of which is documented in `git config` docs. (git 2.39.5.)

14. **`tctl` demands `--auth-server` because of an env var you did not set.** `tctl status` → `ERROR: tctl --identity also requires --auth-server`. `--identity` was never passed; it is inferred from `$TELEPORT_IDENTITY_FILE`. (Teleport 18.11.2.)

15. **`tctl audit query exec` errors are unhelpful and misspelled.** `"show tables"` → `rpc error: code = Unknown desc = failed to run audit query`. A non-existent table → `ERROR: <nil>` / `field to run user query: code 1500` (`field` should be `failed`, and `<nil>` is not an error message). Table names are undiscoverable; I had to guess `cert_create` vs `certificate_create`. (Teleport 18.11.2.)

16. **`cert_create` cannot identify a bot.** 43 columns, none of them `bot_name`, `bot_instance_id`, cert serial, or key fingerprint — and the beam's own cert event has `identity_impersonator = ""`. (Teleport 18.11.2.)

17. **`asn1crypto` chicken-and-egg building CMS `SignedData`.** Constructing from one dict: `TypeError: encap_content_info value must be asn1crypto.cms.ContentInfo, not asn1crypto.cms.EncapsulatedContentInfo`; passing `ContentInfo` → `AttributeError: 'ContentInfo' object has no attribute 'keys'`; passing a dict → `TypeError: content value must be ParsableOctetString, not OctetString`. `SignedData._encap_content_info_spec()` picks the class from `self['version']`, which is not yet readable. Fix: build the Sequence incrementally, `version` first. (asn1crypto 1.5.1.)

18. **Environment gaps.** `python3 -m venv` → `ensurepip is not available ... apt install python3.11-venv`. `file`, `getfacl`, `strace`, `grpcurl` and Go are all absent. Minor, but every one cost a round trip.

19. **`pkill -f <pattern>` matched my own shell** (the pattern appears in the shell's own argv), killing the session mid-command. Not a Beams bug; noting it because it silently destroyed one experiment's state.

20. **The beam image ships stale apt lists, so the remedy in papercut 18 fails on a fresh beam.** Following the `ensurepip` hint verbatim is a dead end until the index is refreshed, and the error names a package that cannot be installed rather than one that can:
    ```
    $ sudo apt-get install -y python3-venv
    Package python3-venv is not available, but is referred to by another package.
    E: Package 'python3-venv' has no installation candidate
    $ sudo apt-get update && sudo apt-get install -y python3.11-venv   # works
    ```
    Two separate costs: the image's package index is not primed, and `python3-venv` (the virtual package `bin/setup.sh` recommends) has no candidate on this image even after `update` — only the versioned `python3.11-venv` does. A beam image intended for Python workloads should either pre-install `python3.11-venv` or prime the apt index. (Debian 12 bookworm, Python 3.11.2, beam image as of 2026-10-05.)
21. **git parses only the *first line* of the verify program's output, and demands `ssh-keygen`'s exact wording.** A richer first line such as `Good "git" signature from beam <uuid>` yields `%G?` = `B` — reported as a *bad* signature — while the detail lines print fine under `--show-signature`. The accepted shapes are `Good "git" signature for <principal> with <TYPE> key <FP>` (→ `G`) and `Good "git" signature with <TYPE> key <FP>` (→ `U`). `%GS` is taken from that line, not from `find-principals`. None of this is in `git config` documentation; it came from reading `parse_ssh_output()`. (git 2.39.5.)

22. **git never calls `-Y verify` when `find-principals` finds no match.** It calls `-Y check-novalidate` instead, so a hook in the verify path is silently dead on exactly the case you care about — a commit from an unpinned tenant. Discovered by logging `gpg.ssh.program` argv. (git 2.39.5.)

23. **`tsh beams exec` re-splits its arguments, mangling quoted shell.** `tsh beams exec <beam> -- bash -c 'rm -rf a b c'` produced `rm: missing operand`, and a heredoc passed the same way had its backticks evaluated locally, committing a file with holes in it. Workaround: only ever invoke a script by path, and branch on the caller's side. (Teleport 18.11.2.)

24. **A freshly created beam can have no apt package lists.** `sudo apt-get install -y python3-venv` → `Package 'python3.11-venv' has no installation candidate`, where the same command succeeds on a beam that has been up a while. Needs `apt-get update` first. (Debian 12 beam image.)

25. **`user.signingkey` pointing at a certificate file breaks every ~20 minutes.** `error: Couldn't sign message (signer): agent refused operation?` / `fatal: failed to write commit object`. The cause is not the agent: the certificate rotated, git offered the new blob, and a cached one no longer matched. The error names the wrong component, which is a long way from the real problem. (git 2.39.5 + tbot 18.11.2.)

26. **Packaging with a list of `tar --exclude` paths shipped private keys to another machine.** The excludes missed `exp5/`, where `bin/negative-tests.sh` mints throwaway CA and user keys, and they were copied to a second beam. Disposable keys, no real impact — but a blocklist will always miss something. Fixed by packing from an allowlist (`git ls-files --cached --others --exclude-standard`). The same class of mistake recurred immediately afterwards: `.gitignore` enumerated `exp2/ exp5/ exp6/ …` and so missed `exp-multitenant/`, staging its keys. Now `exp*/`. **Enumerate what you want, never what you do not.**

27. **`except SomeError as e:` unbinds `e` at the end of the block.** Python 3 deletes the name on exit from the `except` clause, so referring to `e` afterwards raises `NameError` — which crashed the new untrusted-tenant reporting path the first time it ran. Capture it into another variable if you need it later. (Python 3.11.2.)

28. **An empty trust store was fatal before discovery could run.** `load_trust_anchors` raised `no SSH CA public keys found`, so the very situation discovery exists to resolve — nothing pinned yet — could never reach it. Also crashed `beamsig trust --list` on a fresh store. My own bug, noted because "fail closed on empty input" is the obvious choice and is wrong when a later step can populate it.

---

## 8. Artifacts

All committed to this repository (`beamsign`, branch `main`). Run `bin/setup.sh`
then `bin/start-agent.sh` to reproduce from a clone; see `README.md`.

**Library (`beamsig/`)** — `identity.py` (parse the tbot identity file), `hwagent.py` (hardware key agent client), `wire.py` (SSH wire format), `sshcert.py` (OpenSSH cert parser incl. Teleport extensions), `sshsig.py` (SSHSIG parse/build), `sshcrypto.py` (SSH signature verification), `gitobj.py` (commit payload/signature split), `verify.py` (the beam-aware verifier, trust anchors, cluster binding), `discover.py` (opt-in TOFU CA pinning), `attest.py` (attestation envelope), `sshagentshim.py` (ssh-agent over the hardware agent), `cmssign.py`, `cli.py`.

**Install / integration** — `main.sh` (install onto a Beam over `tsh beams scp`/`exec`; creates one if not given), `setup-beamsig.sh` (runs on the Beam: unpack, build, configure, smoke-test, `--uninstall`), `bin/install-global.sh` (beam-wide `~/.gitconfig`, `--trust <cluster>`), `bin/git-beamsig-keygen` (drop-in `gpg.ssh.program`: beam-aware `git log`/`%GS`, pinned-CA and bot-name checks, untrusted-tenant reporting, rotation-proof signing).

**Executables (`bin/`)** — `setup.sh`, `beamsig` (CLI: `sign`, `verify`, `verify-commit`, `attest`, `verify-attestation`, `trust`, `inspect`), `beamsig-agent` + `start-agent.sh`, `split-identity.sh`, `inventory.py`, `watch-renewal.py` + `start-watch.sh`, `dissect-sig.py`, `make-allowed-signers.sh`, `negative-tests.sh` (12 cases), `multitenant-tests.sh` (5 cases incl. cross-tenant spoofing), `exp4-renewal.sh` + `exp4-driver.sh` + `start-exp4.sh`, `cms-sign.py`, `exp6-cms.sh`, `beamsig-gpgsm-shim.py`.

**Docs / demo** — `README.md`, `docs/PRESENTATION-NOTES.md` (hand-off for a UI layer: the JSON contract, the trust model, the three claims a UI must not make, and a GitHub userscript sketch), `demo/record-demo.py` + two asciinema casts + `demo/README.md`.

**Evidence (`logs/`)** — `exp1-inventory.txt`, `exp2-dissect.txt`, `exp5-negative.txt`, `exp6-cms.txt`, `exp4-renewal.txt` (including the post-expiry pass), `renewal.jsonl` (the 4 identity versions, diffed).

**Fixtures (`fixtures/`)** — `sig-from-cert.sig` / `sig-from-key.sig` + `msg.txt` (the Exp 2 pair proving the certificate is embedded), `attestation-bundle.json`, `artifact.p7s` + `artifact.bin` (CMS), `backdated.sig` + `backdated.txt` (the backdating demonstration), `allowed_signers`, and the four CA exports `teleport-{user,host}-ca.txt` / `teleport-tls-{user,host}-ca.pem`. All still verify today against their long-expired certificates when the verifier is given the right `--claimed-time` — which is itself the durability property from Exp 4.

**Vendored (`proto/`)** — `teleport/hardwarekeyagent/v1/hardwarekeyagent_service.proto` and the `beams/v1` protos, from `gravitational/teleport` `branch/v18` (Apache-2.0). gRPC stubs are generated into `gen/` by `bin/setup.sh` and not committed.

**Second beam** — `vapor-jet` (`8bba9461-0638-4a00-9752-c9064f9d832f`) was created from this one, provisioned by copying a single file, and left running. Branch `vapor-jet-demo` on the remote carries a commit it signed; Experiment 10 verifies it from here.

**Deliberately not committed** (see `.gitignore`):

* `archive/`, `inventory/` — copies of the live tbot identity file. They contain the beam's SSH and X.509 certificates plus the owner's email, roles and login IP. No private key can be in them (the beam key is non-exportable), but they are credential files, they trip secret scanners on the `BEGIN PIV YUBIKEY PRIVATE KEY` header, and the certs expire 61 minutes after issue. Recreate with `bin/watch-renewal.py`.
* `exp*/` — the throwaway CA and user keys the test scripts mint (`rogueca`, `rogueuser`, `forged`, `human`, `otherbot`, and the simulated second tenant). Private keys, even disposable ones, should not be committed; the test scripts regenerate them on every run. Globbed rather than enumerated, after an enumerated list missed `exp-multitenant/` — see papercut 25.
* `repos/` — the demo/renewal/x509 git repositories are nested git repos; their transcripts are preserved in `logs/exp4-renewal.txt` instead.
* `venv/`, `gen/`, `ca/`, `run/` and the `exp*/` scratch directories — all regenerated.

**Private key material:** none of the beam's exists anywhere in this repo or on disk — it is non-exportable by construction.
