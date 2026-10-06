# Notes for a presentation / UI layer over beam signatures

Hand this to whatever agent is building the UI. It covers where the data lives,
what you may claim, and what you must not. Full detail is in `../REPORT.md`.

## What a beam signature actually is

A git commit signed by a Teleport Beam carries a `gpgsig` header containing an
**SSHSIG** blob (OpenSSH signature, `PROTOCOL.sshsig`). The important property:

> Because the beam signs with its Teleport **certificate** rather than a bare
> key, the SSHSIG's `publickey` field contains the **entire OpenSSH
> certificate** — including the Teleport extensions that name the beam.

So the signature is self-contained. You do not need the beam, the cluster API,
or anything else to render it. You need the signature, the signed payload, and
one small public CA blob.

```
gpgsig -----BEGIN SSH SIGNATURE-----
 U1NIU0lHAAAAAQAABUYAAAAoZWNkc2Etc2hhMi1uaXN0cDI1Ni1jZXJ0LXYwMUBvcGVuc3...
```

Inside, the fields you care about are certificate *extensions*:

| Extension | Example | Meaning |
|---|---|---|
| `bot-name@goteleport.com` | `beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9` | **the beam identity** |
| `bot-instance-id@goteleport.com` | `dbe1cf6c-…` | stable per beam boot |
| `delegation-session-id@goteleport.com` | `bd204fe3-…` | the session that spawned it |
| `teleport-roles` | `{"roles":["editor","access",…]}` | roles at issuance |
| `login-ip` | `52.3.207.254` | |

Plus certificate fields: `key id` (the **owner**, see below), `valid_principals`
(`root`, `beams`, …), and `valid after` / `valid before` (a ~61 minute window).

## Easiest integration: shell out, consume JSON

Don't reimplement SSH certificate parsing unless you must.

```bash
beamsig verify-commit <sha> -C <repo> --ca <pinned-ca> --beam-id <uuid> --json
```

```json
{
  "ok": true,
  "beam_id": "1786bcd6-04b9-4b9e-ad87-0c13071df7e9",
  "bot_name": "beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9",
  "bot_instance_id": "dbe1cf6c-8f89-4ab3-bfee-9e2c7e710f6c",
  "delegation_session_id": "bd204fe3-1653-429c-bc81-b64d5a3d514f",
  "cluster": "jeff.beams.sh",
  "owner": "owner@example.com",
  "roles": ["editor", "access", "auditor", "beam-user"],
  "principals": ["root", "beams", "-teleport-internal-join"],
  "login_ip": "52.3.207.254",
  "signing_key_fp": "SHA256:4jXdejzBCenjWfYrR8qs6BT/esGtkz3cqVJTUWxDhf8",
  "ca_fp": "SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU",
  "sig_algorithm": "ecdsa-sha2-nistp256",
  "valid_after": 1791214587,
  "valid_before": 1791218247,
  "claimed_time": 1791215633,
  "claimed_time_source": "git committer date",
  "payload_sha256": "638867e2…",
  "commit": "1cca822b…",
  "committer": "beam-1786bcd6-… <owner@example.com>",
  "warnings": []
}
```

Exit code is the contract: `0` verified, `2` invalid, **`3` untrusted tenant**.
`ok` is never `true` on a failure path. Also render `warnings[]` — it is where
we put "this was not checked" rather than silently omitting it.

**Treat 3 as a third state, not an error.** A repository can hold commits from
several Beams tenants, and one whose CA you have not pinned is *not* a bad
signature — git itself reports `%G?` = `U`, good signature with unknown trust.
Show it as "unknown tenant" with the cluster and beam it *claims* (both clearly
unverified), not as tampering. stderr carries the claimed cluster and the
command to pin it.

The same tool does artifacts (`beamsig verify`) and multi-subject attestation
bundles (`beamsig verify-attestation`), with the same JSON shape.

## Trust anchor

One blob, ~200 bytes, from any Teleport cluster, no auth:

```
GET https://<cluster>/webapi/auth/export?type=user
cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNh… clustername=<c>&type=user
```

**Pin it by value in your build.** If the UI fetches its own trust anchor at
render time it is trusting the network, not the pin. The CA is long-lived
(`tctl status` reports the user CA as "standby (never rotated)"). Note the
response is *not* valid OpenSSH `allowed_signers` syntax — it is missing the
leading principal field — so if you pass it to `ssh-keygen` you must prepend
one. See `bin/make-allowed-signers.sh`.

**Do not assume one tenant.** Keep a *map* of cluster → CA, not a single
anchor, and key it by cluster so the UI can serve more than one Beams tenant.
`beamsig` stores pins as `~/.config/beamsig/trusted/<cluster>.ca` and
discovered CAs under `discovered/`; `beamsig trust <cluster>` pins one.

**A signature is provenance, not trust or safety.** This is the single most
important thing for a UI to get right. A verified result means "beam `<uuid>`
of cluster `<host>` signed these bytes" — nothing about whether the content is
good, reviewed, or from anyone you should listen to. beamsig fetches an unknown
cluster's CA automatically over verified HTTPS, so *any* Teleport cluster's beam
can produce a `VERIFIED` result for its own cluster. **Never render a bare
green tick.** Render the cluster with equal prominence, and apply your own
policy on top (`cluster` field, or `--cluster`). `cluster_trust` tells you
whether the CA was `pinned`, `discovered` or `unlabelled`.

**Take the cluster from the pin, never from the certificate.** This is a real
spoofing vector, not a theoretical one. `teleport-route-to-cluster` is just a
claim made by whoever signed the certificate, so if you trust two tenants,
either can mint a certificate claiming to be the other. The JSON reflects this:

| field | meaning |
|---|---|
| `cluster` | **authoritative** — the cluster the verifying pin is bound to |
| `cluster_claimed` | what the certificate says; display only, may differ |
| `cluster_pinned` | `false` means the anchor was unlabelled and `cluster` fell back to the claim |
| `cluster_trust` | `pinned` (operator-placed), `discovered` (fetched over HTTPS), or `unlabelled` |

Render `cluster`. If `cluster_pinned` is `false`, or `cluster_claimed` differs
from `cluster`, say so — both land in `warnings[]` too. And treat a beam's
identity as the pair *(cluster, beam_id)*; a beam id alone is not unique across
tenants as far as a verifier can prove.

## Three things you must NOT claim

These are the ways a UI will mislead people. Please get them right.

**1. The "signer" is not the person. Key ID is the owner.**
The certificate's Key ID is `owner@example.com` — a human — because the beam
impersonates its owner. The beam is *only* in `bot-name`. Do not render the Key
ID or the committer email as "signed by". Label it explicitly:

> signed by **beam clever-nebula** · on behalf of owner@example.com *(owner,
> impersonated — did not review this)*

Stock tooling gets this wrong: plain `git log --show-signature` reports
`Good "git" signature for root`, where `root` is just the first SSH login
principal that the verifier's `allowed_signers` happens to accept. It is
verifier-controlled cosmetics with no evidential value — we could make it say
`beams` by editing our own trust file. Never surface it.

**2. The alias is not bound to anything.**
`clever-nebula` appears in **no** certificate, extension or OID. Only the UUID
is cryptographically attested. The `uuid → alias` mapping exists solely in live
cluster state (`tsh beams ls --format=json`, `tctl get bot_instance` →
`status.initial_heartbeat.hostname`) which is deleted when the beam dies. If you
show an alias, mark it unverified, and never match or filter on it — aliases may
be reused by later beams.

**3. The timestamp is weaker than it looks.**
The commit time is self-reported. It is *signed*, and we check it falls inside
the certificate's 61-minute window, so it cannot be edited after the fact. But
the beam's key **never rotates** — only the certificate does, every 20 minutes —
so a signer can embed an older certificate it still has and choose which window
a verifier sees. We demonstrated backdating a signature 34 minutes with full
verification success (`fixtures/backdated.sig`).

So the honest claim is **"somewhere within this beam's lifetime"**, not a tight
window. Do not render a precise "signed at 15:53:53" as if it were attested.
Prefer *"signed during a window the beam itself selected"*, or show the
certificate window as a range. Backdating only — forward-dating is impossible.

Also: anything running inside the beam can sign as the beam (no PIN, no touch,
no client auth on the signing agent). The signature attests to a **sandbox**,
never to a program, an author, or human intent.

## Suggested rendering

```
✓ beam clever-nebula                      (unverified alias)
  1786bcd6-04b9-4b9e-ad87-0c13071df7e9    beam id        [attested]
  instance dbe1cf6c…                      boot           [attested]
  cluster jeff.beams.sh                   [attested]
  roles editor, access, auditor           [attested]
  on behalf of owner@example.com        owner, impersonated, not the signer
  signed within 16:16:27Z – 17:17:27Z     window chosen by signer
  Teleport user CA SHA256:c/8F7ip…        pinned
```

A good UI distinguishes three tiers: **attested** (from the certificate, chained
to the pinned CA), **self-reported** (alias, exact time), and **not checked**
(anything in `warnings[]`).

## GitHub

Today we push to a private host, not GitHub. If we did push there:

GitHub **cannot** verify these commits. It verifies SSH signatures only against
SSH keys a user has registered as signing keys; it has no notion of an SSH
certificate authority, and our signature's public key is a *certificate* issued
by the Teleport user CA. The badge reads **Unverified** with
`reason: unknown_signature_type` — measured against the pushed commits, not
`unknown_key` as first guessed: GitHub does not recognise the *key type*
`ecdsa-sha2-nistp256-cert-v01@openssh.com` at all, so it never gets as far as
looking for a matching key. That is GitHub's model, not a bug in the signature.

A userscript (Greasemonkey/Violentmonkey) can fix the display, and the data is
available without cloning:

```
GET /repos/{owner}/{repo}/commits/{sha}
{ "commit": { "verification": {
    "verified": false, "reason": "unknown_signature_type",
    "signature": "-----BEGIN SSH SIGNATURE-----\n…",
    "payload":   "tree …\nparent …\nauthor …\ncommitter …\n\nmessage\n" }}}
```

`signature` is the armored SSHSIG and `payload` is the exact signed bytes, so a
userscript has everything needed to verify client-side and replace the badge.
Sketch:

1. Scrape the SHA from the page; fetch the commit JSON.
2. Base64-decode the SSHSIG; walk the SSH wire format to the `publickey` field;
   confirm it is a `…-cert-v01@openssh.com` blob; parse out the extensions.
3. Verify the certificate's CA signature over its signed portion, and the
   SSHSIG signature over
   `"SSHSIG" ‖ namespace ‖ reserved ‖ hashalg ‖ SHA512(payload)`,
   against the **CA pinned in the script**. ECDSA P-256 is in WebCrypto
   (`ECDSA` / `P-256` / `SHA-256`), so no crypto library is needed — but note
   SSH signatures are raw `r‖s`-as-mpints and certificates use DER, so you need
   a small conversion either way.
4. Check the committer timestamp against the certificate window.
5. Replace the badge, applying the three caveats above.

Two gotchas: don't fetch the CA from the Teleport cluster at render time (CORS,
and it defeats pinning — embed it); and parse the signature yourself rather than
trusting `verification.verified`, which will always be `false` here.

`beamsig/sshsig.py`, `beamsig/sshcert.py` and `beamsig/sshcrypto.py` are small,
dependency-light and are the reference for steps 2–3 — port from those rather
than from the spec.

## Reproducing locally

```bash
./bin/setup.sh            # venv, gRPC stubs, CA export
./bin/install-global.sh   # beam-wide git signing + beam-aware git log
git log                   # now shows the beam
```

`fixtures/` has committed, ready-to-use samples that still verify today against
their long-expired certificates — good for building a UI with no beam running:

| File | Use |
|---|---|
| `fixtures/sig-from-cert.sig` + `msg.txt` | a signature **with** the certificate embedded |
| `fixtures/sig-from-key.sig` | the same payload signed with a bare key — no identity at all; good negative case |
| `fixtures/attestation-bundle.json` | multi-subject attestation envelope |
| `fixtures/backdated.sig` + `backdated.txt` | a deliberately backdated signature that verifies |
| `fixtures/teleport-user-ca.txt` | the pinned trust anchor |

Verify any of them with `--claimed-time` inside the embedded window, e.g.

```bash
./bin/beamsig verify fixtures/msg.txt -s fixtures/sig-from-cert.sig -n git \
    --ca fixtures/teleport-user-ca.txt --claimed-time 1791212000 --json
```
