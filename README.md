# beamsign

Making work produced inside a **Teleport Beam** attestable to that specific
beam — git commits first, arbitrary artifacts second — so that a third party
holding only the Teleport cluster CA can later verify *"this was signed by beam
`<BEAM_ID>`, owned by `<user>`, during `<time window>`"*, after the beam and its
certificates are gone.

**Read [`REPORT.md`](REPORT.md) first.** It is the findings write-up: what
works, what it proves, what it does not, exact commands and output, and a list
of papercuts and feature requests.

## The one thing to know before reading any code

The tbot identity file at `$TELEPORT_IDENTITY_FILE` contains **no private key**.
The `BEGIN PIV YUBIKEY PRIVATE KEY` block is base64 JSON referencing PIV slot
`0x9A` on a virtual hardware key with sentinel serial `0xFFFFFFFF`:

```json
{"serial_number":4294967295,"slot_key":154,
 "policy":{"TouchRequired":false,"PINRequired":false},
 "public_key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."}
```

The key is non-exportable and lives behind Teleport's **hardware key agent**:
gRPC **over TLS** on `$TELEPORT_KEY_AGENT_DIR/agent.sock`, with `cert.pem` in
the same directory as the server certificate / pinned CA, and SNI `localhost`.
There is no client authentication.

So `ssh-keygen -Y sign -f <key>` and `openssl cms -sign -inkey <key>` cannot
work. Everything here routes signatures through that agent.

## Why a custom verifier is necessary

`ssh-keygen -Y sign` with the Teleport **certificate** embeds the *entire
certificate* — including `bot-name@goteleport.com` — in the SSHSIG blob, so a
signature is self-contained and verifiable offline forever. But
`ssh-keygen -Y verify` only matches certificate **principals**, which on a beam
are the generic `root` / `beams`, shared by every user certificate in the
cluster. It will report `Good "git" signature for root` for a certificate
carrying a *forged* `bot-name`, because it never reads that extension.

`beamsig` chains to a pinned Teleport user CA, requires
`bot-name@goteleport.com` to match `beam-<uuid>`, and checks the claimed time
against the certificate window.

## Trust is per tenant, not baked in

Nothing here is wired to one Teleport cluster. The trust anchor is discovered
at install time from `$TELEPORT_CLUSTER` and pinned into a store of
cluster-labelled files:

```
~/.config/beamsig/trusted/<cluster>.ca
```

To verify beams from another tenant, add its CA — then both verify from the
same store:

```bash
./bin/beamsig trust other-tenant.teleport.sh      # fetch and pin
./bin/beamsig trust --list
./bin/install-global.sh --trust other-tenant.teleport.sh
```

**The authoritative cluster comes from the pin, never from the certificate.**
A certificate's `teleport-route-to-cluster` extension is only a claim made by
whoever signed it, so once two tenants are trusted, either could mint a
certificate claiming to be the other. `beamsig` reports the cluster that the
*verifying CA* is pinned for, and flags a disagreeing claim as not
authoritative:

```
teleport cluster     : other-tenant.example.sh
cluster claimed      : jeff.beams.sh   (NOT authoritative)
! certificate claims cluster 'jeff.beams.sh' but was signed by the CA pinned
  for 'other-tenant.example.sh'; treating 'other-tenant.example.sh' as authoritative
```

`--cluster <name>` scopes a verification to one tenant and fails otherwise.
`bin/multitenant-tests.sh` exercises this, including the spoofing case.

Two consequences worth knowing. A beam's identity is really the pair
*(cluster, beam id)* — `--beam-id` alone is under-specified across tenants, so
pass `--cluster` too when it matters. And an **unlabelled** pin cannot vouch for
a cluster name: beamsig falls back to the certificate's claim and says so
loudly, which is why the store uses `<cluster>.ca` filenames.

Stock `ssh-keygen` cannot do any of this: `allowed_signers` has no way to say
which cluster a `cert-authority` line belongs to, so with several tenants
listed it cannot tell them apart.

## Commits from several tenants in one repository

This works, and it is worth knowing exactly what you see. A commit whose
issuing CA is not pinned is reported as `%G?` = **`U`** — *good signature,
unknown trust* — not `B`. Nothing is wrong with the bytes; there is simply no
basis for trusting the tenant. Stock `ssh-keygen` says only
`No principal matched.`, so `beamsig` explains it instead:

```
Good "git" signature with ECDSA-CERT key SHA256:qoOp6kLYO6Fq3b3H2pihOAxceLdem6G04adObAuSdmk
UNTRUSTED TENANT: the signature is intact, but its Teleport CA is not pinned here.
  claims cluster  other.example.sh  (unverified: this comes from the certificate itself)
  claims beam     5d41402a-bc4b-2a76-b971-9d911017c592  (unverified)
  issuing CA      SHA256:48TyCfGeffUJFJ8EF60O5RtCnnoFQ8oanLMqS3xy/rU
  to trust it     beamsig trust other.example.sh
```

`beamsig verify*` exits **3** for an untrusted tenant, distinct from **2** for
an invalid signature, so CI and UIs can tell "we don't know them" from "this is
broken".

### CA discovery is automatic

When a certificate names a cluster you have no CA for, beamsig fetches it:

```
GET https://<cluster>/webapi/auth/export?type=user
```

That request is **verified HTTPS**, so WebPKI authenticates the hostname. The
fetched CA is cached under `~/.config/beamsig/discovered/` — kept separate from
operator pins in `trusted/`, so the distinction survives and is always
reported:

```
teleport cluster     : jeff.beams.sh   (CA discovered over HTTPS)
teleport cluster     : jeff.beams.sh   (operator-pinned CA)
```

An operator pin always wins; discovery never replaces one.

**A signature establishes provenance, not trust or safety.** A verified result
says "beam `<uuid>` of cluster `<host>`, at some point in this certificate's
window". The cluster is part of that identity, not a judgement about it.
Anyone can stand up a Teleport cluster, mint a CA, and produce a signature that
verifies as *their* cluster — and that statement is true and useful; it simply
is not a statement about yours. The hazard is a reader seeing `VERIFIED` and
ignoring which cluster it names.

So policy is explicit and separate from verification:

| knob | effect |
|---|---|
| `--cluster <name>` | require this exact cluster; fail otherwise |
| `--discover-allow '<glob>'` | restrict discovery to matching clusters (repeatable) |
| `--offline` / `BEAMSIG_OFFLINE=1` | never fetch; local pins and cache only |
| `beamsig trust <cluster>` | pin deliberately, ahead of time |

Discovery is bounded to `*.beams.sh` by default — every Beams tenant — matching
`DEFAULT_ALLOW` in the browser extension. That bound does real work, because
discovery also **rewrites `allowed_signers`**: `beamsig verify` reads the trust
store directly, but `git log` shells out to stock `ssh-keygen` against
`gpg.ssh.allowedSignersFile`, which knows nothing about the store. Without the
rewrite a cross-tenant commit verifies under `beamsig verify-commit` while
`git log` reports `%G?`=`U` forever. Widen with `--discover-allow '*'`.

Note that `--ca` is a **seed, not a whitelist**: with discovery on, pinning the
wrong CA does not block verification, because the right one gets fetched. Use
`--offline` if you want the trust store to be the only authority.

Two residual caveats. Discovery needs the network, so offline verification
still requires a pin. And a verifier makes an HTTPS request to a hostname that
came from the artifact it is checking — in a CI runner that is a minor
outbound-request consideration, bounded by `--discover-allow` and `--offline`.

## Robot avatars in the terminal

Each beam has a deterministic robot, generated from its UUID by
`extension/tools/avatar/teleport_avatar.py` (from the browser-extension work).
`beamsig` renders the *same* robot in the terminal rather than inventing its
own, so the CLI and the extension cannot drift:

```bash
beamsig avatar <beam-id|commit>     # or it appears beside `git log` output
```

Two backends. **`blocks`** is Unicode half-blocks with 24-bit colour — just
text and SGR, so it survives a pipe, `less -R` and CI logs. **`image`** is a
real inline image (iTerm2 OSC 1337, or the kitty protocol), used only when
nothing is in the way.

Inline images do **not** work through a pager, which is worth stating plainly
because it is tempting to assume otherwise. Measured by piping each form
through `less` on a pty:

| payload | `LESS=FRX` (git's default) | `LESS=FX` |
|---|---|---|
| SGR half-blocks | **survives** | stripped |
| iTerm2 OSC 1337 | mangled | mangled |
| kitty APC | mangled | mangled |

`less` eats the OSC introducer and prints the base64 payload as text across
your screen. So `git log` always gets `blocks`, detected via
`GIT_PAGER_IN_USE` and `isatty()`. Override with
`BEAMSIG_AVATAR=off|blocks|iterm|kitty|auto`.

The avatar needs the generator plus `cairosvg` (for SVG rasterisation); without
either it is silently skipped. **It is a recognition aid, never evidence** — a
pure function of the beam UUID, so anyone can draw any beam's robot.

## Biggest caveat

The beam key **never rotates** — only the certificate does, every 20 minutes,
rewritten in place. Every certificate the beam has ever held binds the same key,
so a signer can embed an older one and choose the validity window a verifier
sees. `bin/beamsig sign --cert-from <archived identity>` backdates a signature
34 minutes with full verification success. The achievable time bound is
*"somewhere in this beam's lifetime"*, not ±61 minutes. Fixing this needs an
external timestamp (RFC 3161) or a server-side audit anchor; see REPORT.md §4(c)
and §6.3.

## Setup

### Onto a Beam, from a machine with this checkout

Run after logging in to your Beams cluster with `tsh`:

```bash
./main.sh                        # create a new Beam, then set up beamsig
./main.sh daring-lab             # set up an existing Beam (name or UUID)
./main.sh daring-lab --uninstall
./main.sh --help
```

`main.sh` packs the tree, copies it plus `setup-beamsig.sh` with
`tsh beams scp`, and runs the setup over `tsh beams exec`. The target Beam needs
**no git remote credentials and clones nothing** — it only reaches its own
cluster for the public CA export. The payload is ~82 KB; the virtualenv is built
on the Beam rather than shipped. A newly created Beam can be listed before its
SSH node registers, so it waits for SSH before copying anything.

It packs from an allowlist (`git ls-files --cached --others --exclude-standard`),
so local uncommitted edits travel but anything `.gitignore`d stays behind. That
is deliberate: `.gitignore` hides the throwaway private keys the negative tests
mint under `exp5/` and the archived copies of the identity file.

Nothing outlives the Beam. `setup-beamsig.sh --uninstall` removes the install
directory, `~/.config/beamsig` and the git config keys.

### In place, on the machine you are already on

```bash
sudo apt-get install -y python3-venv      # if needed
./bin/setup.sh                            # venv, gRPC stubs, Teleport CA export
./bin/install-global.sh                   # beam-wide git signing (recommended)
```

`install-global.sh` writes `~/.gitconfig` so that **every** repository in the
beam signs as the beam and `git log` reports who signed, with no per-repo setup:

```console
$ cd /some/fresh/repo && git commit -m "a beam did this"
$ git log
commit 29305411ae0b812c0fdec10a3129e3362560fa72
Good "git" signature for beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9 with ECDSA-CERT key SHA256:4jXdejzB…
  beam alias    clever-nebula  (self-reported, not in the certificate)
  bot instance  dbe1cf6c-8f89-4ab3-bfee-9e2c7e710f6c
  roles         editor, access, auditor, beam-user
  owner         jeff@goteleport.com  (impersonated, NOT the signer)
  cert window   2026-10-05T16:16:27Z .. 2026-10-05T17:17:27Z
  commit time   2026-10-05T16:26:44Z  in window
  teleport CA   SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU  (jeff.beams.sh)

$ git log -1 --format='%G? %GS'
G beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9
```

This works through `gpg.ssh.program` = `bin/git-beamsig-keygen`, a drop-in
replacement for `ssh-keygen` in git's signing path. It is **not** a cosmetic
filter: the real `ssh-keygen` still does the certificate-chain and time-window
check, and the shim then additionally requires the certificate to chain to a
*pinned* Teleport user CA and to carry `bot-name@goteleport.com = beam-<uuid>`.
Point it at the wrong CA or forge a commit date and `%G?` goes to `B` / `U` and
the exit code is non-zero.

It also intercepts *signing*, which removes two sharp edges: the beam
certificate is replaced every ~20 minutes, so any `user.signingkey` file goes
stale and git starts failing with `agent refused operation`; and signing via
`ssh-keygen` needs an ssh-agent and `SSH_AUTH_SOCK`. The shim reads the current
certificate on every signature and talks to the hardware key agent directly, so
**no agent daemon and no environment variables are required**.

Undo with `./bin/install-global.sh --uninstall`. Options: `--no-autosign`,
`--no-showsig` (`log.showSignature=true` verifies every commit it displays,
which is fine for a demo and slow on a long history).

For a single repository instead, or to use stock `ssh-keygen`, there is still
`./bin/start-agent.sh` (ssh-agent shim) plus the per-repo config shown below.

## Use

```bash
# artifacts
./bin/beamsig sign file -o file.sig
./bin/beamsig verify file -s file.sig --ca ca/pinned-user-ca.txt \
    --beam-id "$BEAM_ID" --claimed-time "$(date -u +%s)"

# attestation bundle over several subjects
./bin/beamsig attest out1 out2 -o bundle.json
./bin/beamsig verify-attestation bundle.json --subject-dir . \
    --ca ca/pinned-user-ca.txt --beam-id "$BEAM_ID"

# git
git config gpg.format ssh
git config user.signingkey "$PWD/ca/beam-cert.pub"   # the CERTIFICATE, not a key
git config gpg.ssh.allowedSignersFile "$PWD/ca/allowed_signers"
SSH_AUTH_SOCK="$PWD/run/agent.sock" git commit -S -m msg
./bin/beamsig verify-commit HEAD --ca ca/pinned-user-ca.txt --beam-id "$BEAM_ID"

# inspect any SSHSIG without verifying
./bin/beamsig inspect -s fixtures/sig-from-cert.sig
```

Verification is fail-closed; a non-zero exit code is the only trustworthy
signal. Note that both `git verify-commit` and `ssh-keygen -Y verify` print the
word `Good` on a line *before* failing, so never grep for it.

## Layout

| Path | What |
|---|---|
| `REPORT.md` | the findings write-up — start here |
| `main.sh` | install onto a Beam over `tsh beams scp` / `exec` (no git access needed there) |
| `setup-beamsig.sh` | runs on the Beam; unpacks, builds, configures, smoke-tests |
| `docs/PRESENTATION-NOTES.md` | hand-off note for a UI / presentation layer, incl. the GitHub userscript route |
| `beamsig/` | the library (see below) |
| `bin/beamsig` | CLI: `sign`, `verify`, `verify-commit`, `attest`, `verify-attestation`, `inspect` |
| `bin/git-beamsig-keygen` | drop-in `gpg.ssh.program`: beam-aware `git log` / `git verify-commit`, and rotation-proof signing |
| `bin/install-global.sh` | beam-wide `~/.gitconfig` setup (`--uninstall` to undo) |
| `bin/beamsig-agent`, `bin/start-agent.sh` | ssh-agent shim, for stock `ssh-keygen` / per-repo use |
| `bin/setup.sh` | venv + gRPC stubs + CA export |
| `bin/split-identity.sh`, `bin/inventory.py` | Exp 1: decode the identity file, SSH extensions, X.509 OIDs |
| `bin/watch-renewal.py`, `bin/start-watch.sh` | Exp 1: archive and diff every identity version |
| `bin/dissect-sig.py` | Exp 2: does SSHSIG embed the full certificate? |
| `bin/make-allowed-signers.sh` | Exp 3: fix the Teleport CA export into valid `allowed_signers` |
| `bin/exp4-renewal.sh`, `bin/exp4-driver.sh` | Exp 4: commits across renewal and expiry |
| `bin/negative-tests.sh` | Exp 5: 12 must-fail cases |
| `bin/cms-sign.py`, `bin/exp6-cms.sh` | Exp 6: CMS SignedData via the agent + `openssl cms -verify` matrix |
| `bin/beamsig-gpgsm-shim.py` | Exp 6: gpgsm-compatible shim for `gpg.format=x509` |
| `proto/` | Teleport hardware key agent protobuf (vendored from `gravitational/teleport`) |
| `logs/` | captured output of every experiment — the evidence behind REPORT.md |
| `fixtures/` | signatures, CMS blobs, CA exports and an attestation bundle |

Library modules: `identity.py` (parse the tbot identity file), `hwagent.py`
(hardware key agent client), `wire.py` (SSH wire format), `sshcert.py` (OpenSSH
certificate parser incl. Teleport extensions), `sshsig.py` (SSHSIG parse/build),
`sshcrypto.py` (SSH signature verification), `gitobj.py` (commit payload /
signature split), `verify.py` (the beam-aware verifier), `attest.py`
(attestation envelope), `sshagentshim.py`, `cmssign.py`, `cli.py`.

## What is deliberately not committed

See `.gitignore`. In short: copies of the live identity file (`archive/`,
`inventory/`) because they are credential files that trip secret scanners, and
the throwaway CA/user keys the negative tests generate (`exp5/`) because private
keys should never be committed even when they are disposable.
`bin/watch-renewal.py` and `bin/negative-tests.sh` recreate both.

## Status

Hackathon proof of concept. The crypto paths are exercised and the negative
tests pass, but read REPORT.md §4 before relying on any of it — in particular
the backdating break, the fact that the certificate Key ID is the *owner* rather
than the beam, and that every process in the beam can sign as the beam.
