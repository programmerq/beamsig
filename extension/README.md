# beamsig browser extension

Detects Teleport Beam signatures on GitHub commits and renders what the
certificate actually attests to. GitHub cannot do this itself.

## Why GitHub says "Unverified"

GitHub verifies SSH signatures only against keys a user has registered as
signing keys. It has no notion of an SSH **certificate authority**, and a beam's
signature carries a *certificate* issued by the Teleport user CA — so GitHub
reports:

```json
"verification": { "verified": false, "reason": "unknown_signature_type" }
```

Measured against the pushed commits in this repo. The reason is
`unknown_signature_type`, not `unknown_key`: GitHub does not recognise the key
type `ecdsa-sha2-nistp256-cert-v01@openssh.com` at all, so it never reaches the
question of which key to match.

That is GitHub's trust model, not a defect in the signature. The signature is
self-contained: because the beam signs with its certificate rather than a bare
key, the SSHSIG's `publickey` field holds the **entire OpenSSH certificate**,
including the Teleport extensions that name the beam. Everything needed to
verify is in the commit plus one ~200-byte CA blob.

This extension does that verification locally and adds its own panel. It
deliberately **does not** overwrite GitHub's badge — GitHub's "Unverified" is a
true statement about what GitHub checked, and replacing it would misrepresent
that.

## Install

Nothing to build; it is plain JavaScript with no dependencies.

**Chrome / Edge / Brave** — `chrome://extensions` → enable Developer mode →
*Load unpacked* → select this `extension/` directory.

**Firefox** (129+, for WebCrypto Ed25519) — `about:debugging#/runtime/this-firefox`
→ *Load Temporary Add-on* → select `extension/manifest.json`.

Then open any commit page in a repository whose commits were signed by a beam.

## Try it in two minutes

1. Open `chrome://extensions`, switch on **Developer mode** (top right).
2. Click **Load unpacked** and choose this `extension/` folder (the one
   containing `manifest.json`).
3. Open <https://github.com/programmerq/beamsig/commit/1dfcd52>. Under the
   commit title, below GitHub's grey "Unverified" badge, a **Signed by beam
   1786bcd6…** panel should appear.
4. Check the negative case: <https://github.com/programmerq/beamsig/commit/9675390>
   is unsigned, so no panel appears.
5. Check a list page: <https://github.com/programmerq/beamsig/commits/main>
   should show a small `✓ beam 1786bcd6…` badge beside the signed commits.

**If Chrome blocks unpacked extensions** (managed machines), paste the extension
into the page instead — no install needed:

```bash
node extension/tools/console-bundle.mjs | pbcopy
```

Open a commit page on github.com, open DevTools → Console, type `allow pasting`
and press Enter (Chrome's paste guard), then paste and press Enter. It runs the
same scripts; nothing persists (no cache, token or extra CAs, and no CA
discovery, which needs the background worker) and it lasts until
you reload the tab. Re-paste after each full page load.

If nothing appears, open DevTools → Console and filter on `beamsig`; the line
`anchored via …` confirms the script ran. If Chrome says unpacked extensions are
disabled by your administrator, use Firefox (see Install) or the no-install
checks under **Tests**.

## How it verifies

Mirrors `beamsig verify-commit`, in the browser, via WebCrypto:

1. Route the page: `/{owner}/{repo}/commit/{sha}` or a PR commit/list page.
2. `GET /repos/{owner}/{repo}/commits/{sha}` → `verification.signature` (armored
   SSHSIG) and `verification.payload` (the exact signed bytes). No clone needed.
   `verification.verified` is ignored; it is always `false` here.
3. Walk the SSHSIG wire format to the `publickey` field and require it to be a
   `…-cert-v01@openssh.com` blob. A bare key carries no identity and is rejected.
4. Verify the certificate's CA signature against a **pinned** Teleport user CA,
   compiled into `src/lib/ca.js` and cross-checked against its recorded
   fingerprint on every load.
5. Verify the SSHSIG signature over
   `"SSHSIG" ‖ namespace ‖ reserved ‖ hashalg ‖ H(payload)`, requiring
   namespace `git`.
6. Require a `bot-name@goteleport.com` extension matching `beam-<uuid>`.
7. Check the committer date — which is inside the signed bytes — against the
   certificate's validity window.

Two conversions are needed that the Python reference does not do, because
WebCrypto's shapes differ from OpenSSH's: ECDSA signatures arrive as
`mpint r, mpint s` and must become fixed-width `r‖s`, and RSA keys arrive as
`mpint e, mpint n` and must become SPKI DER. Both are in `src/lib/sshcrypto.js`.

## What the panel claims, and what it refuses to claim

The three rules from `../docs/PRESENTATION-NOTES.md` are enforced in `src/ui.js`:

- **The signer is not the person.** The certificate's Key ID is the *owner*, a
  human, because the beam impersonates them. The panel shows the owner under
  "On behalf of", labelled *impersonated — NOT the signer, and did not review
  this*. The beam is only ever named from `bot-name`.
- **The alias is not bound to anything.** `clever-nebula` appears in no
  certificate, extension or OID, and the `uuid → alias` mapping is live cluster
  state that dies with the beam. The panel therefore shows the alias as
  **unavailable** rather than leaving a gap, and only the UUID is presented as
  identity.
- **The timestamp is weaker than it looks.** The certificate window is shown as
  a range, labelled *window chosen by the signer*. The beam's key never rotates
  — only its certificate does — so a signer can embed an older certificate and
  pick the window a verifier sees. Backdating within the beam's lifetime is
  possible; forward-dating is not.

Plus the standing caveat, shown on every verified panel: anything running inside
a beam can sign as the beam, so the signature attests to a **sandbox**, never to
a program, an author, or human intent.

Values are rendered in three visually distinct tiers — **attested** (from the
certificate, chained to the pinned CA), **self-reported**, and **not checked**
(the `warnings` list). Nothing is silently omitted.

## Trust anchor

Pinned by value in `src/lib/ca.js`, exported from
`GET https://<cluster>/webapi/auth/export?type=user`. The pin is always tried
first and is the strongest anchor. It is never fetched at render time *in place
of* the pin; discovery below applies only when no known CA matches.

**Other Beams tenants are discovered automatically.** A repo can hold beam commits from any
tenant, so a CA shipped at install time is not enough. This works the way
`beamsig/discover.py` does; read its docstring first, because the argument is
the same. The cluster name in a certificate (`teleport-route-to-cluster`) comes
from the artifact being verified, so fetching a CA for it is circular: an
attacker who mints their own CA and a cert claiming `evil.example.com` would
cause us to fetch that CA, which validates their certificate. It shows the
signer controls a Teleport cluster at that hostname. It does not show the signer
is trusted.

So discovery is fenced the same way, even though it is on for Beams:

- **Hands-free for Beams, off for everything else.** The options page has a
  *discovery allowlist* (globs, the analogue of `--discover-allow`). It defaults to
  `*.beams.sh`, so any Beams tenant just works with no setup. Empty it to turn
  discovery off; add patterns to cover other domains.
- **Allowlisted hostnames only.** Only a cluster matching a pattern is ever
  contacted, over HTTPS by a background worker (the endpoint sends no CORS
  headers, so a page script cannot), with no cookies and no redirects. Hosts
  outside `*.beams.sh` need a permission Chrome asks for when you click Save.
- **Trust on first use.** The first CA fetched for a cluster is stored and pinned.
  A pin that later fails to verify a cert is **never overwritten**; the panel says
  the CA may have been rotated, and you clear it deliberately with *Forget
  discovered CAs* after checking the new fingerprint out of band. The options
  page lists what is pinned, with fingerprints.
- **Reported as discovered.** The issuing CA reads "discovered from `<cluster>` ·
  pinned on first use · NOT operator-pinned", with a matching warning. A cert that
  names an allowlisted cluster but is not signed by its CA is **did NOT verify**.
- **The cluster comes from the CA, not the cert.** As in `verify.py`, the
  authoritative cluster is the one bound to the CA that verified the cert. A cert
  claiming a *different* cluster (legitimate in a root/leaf setup) shows the pinned
  cluster, lists the claim as "NOT authoritative", and warns.

It is a convenience for a team whose tenants are all its own. It is not a
substitute for pinning. Shipped pins and your own extra CAs are always tried
first.

Additional CAs can be added in the options page for other clusters. A signature
accepted by one of those is flagged in the panel as resting on a trust anchor the
extension did not ship.

## Rate limits

Unauthenticated GitHub API requests are capped at 60/hour per IP. Verified
results are cached in `chrome.storage.local` forever — a commit's signature is
immutable — so repeat views are free, but a first pass over a long commit list
can exhaust the quota. Add a read-only token in the options page to raise it to
5,000/hour; it is also required for private repositories.

Commit-list annotation costs one call per row (GitHub's list endpoint carries no
signature data), so it is budgeted — 10 rows per page view by default.

## Tests

```bash
cd extension && npm install              # once; jsdom is a dev-only dependency
npm test                                 # unit + jsdom end-to-end, no network, no browser
node extension/test/run-tests.mjs        # 56 assertions, no network, no browser
node extension/test/e2e-jsdom.mjs        # content script in jsdom, mocked GitHub API
node extension/test/verify-live.mjs      # real commits via the GitHub API
node extension/test/chrome-check.mjs     # real page in Chrome; checks the anchor
```

Runs the real crypto against the committed fixtures, which still verify today
against their long-expired certificates. Covers the positive path, the negative
cases from `REPORT.md` §4 (tampered payload, bare key, untrusted CA, namespace
mismatch, time outside the window, beam-id mismatch), the known backdating break,
and the URL/payload parsing in `github.js`.

`e2e-jsdom.mjs` loads the scripts in manifest order into a simulated GitHub
page with a mocked API and `chrome.storage`, and checks the whole path: every
panel state, caching, rate limits, the list budget, SPA navigation, and that a
late result never paints a panel for a page the user already left.

`verify-live.mjs` runs the real commits in `programmerq/beamsig` through the
same code path the content script uses: two beam-signed commits verify, the
unsigned initial commit is reported as having nothing to show.

`chrome-check.mjs` drives Chrome over the DevTools protocol, opens a real commit
page, injects the content scripts, and prints which anchor was chosen, where the
panel landed, every row it rendered, and the surrounding DOM. It writes
`chrome-check-panel.png` (the panel, clipped and readable) and
`chrome-check.png` (the whole page, for placement). Options:

```bash
BEAMSIG_HEADFUL=1    node extension/test/chrome-check.mjs   # watch it
BEAMSIG_THEME=light  node extension/test/chrome-check.mjs   # force a theme
node extension/test/chrome-check.mjs <any commit or commits URL>
```

It **injects** rather than loading the extension, because Chrome 152 no longer
honours `--load-extension`, and the CDP replacement `Extensions.loadUnpacked` is
refused on a machine whose policy disables unpacked extensions
(`Loading of unpacked extensions is disabled by the administrator`). Injection
runs the same files in the same page context; the only difference is that
`chrome.storage` is absent, so `github.js` falls back to its defaults — which it
already does by design. If your Chrome allows unpacked extensions, load it
normally and the behaviour is identical plus caching.

For the UI alone, open `extension/test/preview.html` directly in a browser — it
renders every panel state from the fixtures with real verification, no GitHub and
no beam required. Its fixture data is generated:

```bash
node extension/test/make-preview-data.mjs
```

## Known limitations

- **GitHub's DOM is not a contract.** Verified against github.com in Chrome 152
  (October 2026), where the commit header is Primer React with CSS modules, so
  class names carry a per-build hash: the "Unverified" badge is
  `button.SignedCommitBadge-module__clickableLabel__seodh`. `findAnchor()`
  matches on the module *prefix* with `[class*=…]`, never a full class name,
  because the prefix survives rebuilds and the hash does not. It anchors as the
  next sibling of `CommitAttribution-module…`, then tries
  `PageHeader-Description`, then a column flex container, then six legacy /
  GitHub Enterprise selectors, then GitHub's pill by text, then a floating panel
  so the result is never lost.

  All six legacy selectors are **absent** from today's github.com — they are
  kept only for older GitHub Enterprise. Anchoring on the generic Primer
  `.flex-column` utility was tried and rejected: it matches a far outer
  container and put the panel below the diff at `top: 1249`. The chosen anchor
  is logged (`[beamsig] anchored via …`) and recorded in
  `document.documentElement[data-beamsig-anchor]`. Expect to revisit this after
  a GitHub redesign; `chrome-check.mjs` is the tool for it.
- **The payload comes from GitHub.** We verify the signature over the bytes
  GitHub reports as the signed payload. That is the same data `git` would give
  us and it cannot be forged into a *passing* signature — a wrong payload fails
  the check — but it does mean a GitHub-side bug shows up as a verification
  failure rather than as a mismatch we can name.
- **RSA user CAs with SHA-1.** Supported in code, but browsers may refuse
  `RSASSA-PKCS1-v1_5` with SHA-1 outright. That case reports "this browser will
  not verify…" rather than claiming a bad signature, which would be a different
  and misleading claim.
- **No revocation.** Consistent with `REPORT.md` §4(f): nothing here can be
  revoked, and a signature from a compromised beam keeps verifying.
- **No server-side time anchor.** The window shown is the one the signer chose.
  Fixing that needs an RFC 3161 timestamp or an audit anchor —
  `REPORT.md` §5 "Hardening" items 1–3.

## Files

| Path | What |
|---|---|
| `manifest.json` | MV3 manifest; content scripts load the libs in order |
| `src/lib/wire.js` | SSH wire format (RFC 4251) over `Uint8Array` |
| `src/lib/sshcert.js` | OpenSSH certificate parser, incl. Teleport extensions |
| `src/lib/sshsig.js` | SSHSIG envelope parse + signed-data construction |
| `src/lib/sshcrypto.js` | WebCrypto verification; mpint→`r‖s` and RSA→SPKI DER |
| `src/lib/ca.js` | the pinned Teleport user CA, by value |
| `src/lib/discover.js` | discovery: allowlist match and CA-export parsing (twin of `beamsig/discover.py`) |
| `src/background.js` | background worker that fetches a cluster's CA for discovery (content scripts cannot: CORS) |
| `src/lib/verify.js` | the beam-aware policy — port of `beamsig/verify.py` |
| `src/lib/avatar.js` | deterministic robot avatar seeded by beam UUID — JS port of `tools/avatar/teleport_avatar.py` |
| `src/github.js` | page routing, API fetch, cache, committer-date extraction |
| `src/ui.js` | panel and badge rendering, and the three-tier honesty rules |
| `src/content.js` | orchestration, DOM anchoring, SPA navigation |
| `src/content.css` | styling, following GitHub's own colour tokens |
| `src/options.html`, `src/options.js` | token, extra CAs, list budget, cache |
| `tools/avatar/` | Python source of truth for the robot generator, `contact_sheet.py` for tuning parts, `make-golden.py` |
| `test/avatar-golden.json` | SVGs rendered by the Python; `run-tests.mjs` checks the JS port matches byte-for-byte |
| `test/run-tests.mjs` | headless test suite |
| `test/e2e-jsdom.mjs` | content script end-to-end in jsdom, mocked API |
| `test/verify-live.mjs` | end-to-end against real commits via the GitHub API |
| `test/chrome-check.mjs` | drives Chrome, checks the anchor, screenshots |
| `test/probe-dom.js` | injected DOM probe used by `chrome-check.mjs` |
| `test/preview.html` | every panel state, rendered from the fixtures |

`src/lib/verify.js` is a port of `beamsig/verify.py` and the two need to stay in
step; the checks are in the same order in both, with the same messages.

## Beam avatars

The robot generator is Jeff's work (owner@example.com); the JS port and the
extension wiring build on it.

Each beam gets a generated robot (grey paneled body, coloured highlights), seeded
by its UUID, shown in the panel header and in list badges so the same beam is
recognisable at a glance. It is decoration only: it carries no information and
attests to nothing.

The Python in `tools/avatar/` is the source of truth; `src/lib/avatar.js` is a
port. After changing a part or weight, bump `VERSION` in both (existing avatars
reshuffle otherwise), run `python3 tools/avatar/make-golden.py`, and `npm test`.
Preview every variant with `python3 tools/avatar/contact_sheet.py -o sheet.html`.
