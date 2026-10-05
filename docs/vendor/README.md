# docs/vendor — generated, do not edit

Everything in this directory is generated. Edit the sources, then re-sync:

```bash
bin/sync-site-libs.sh
```

| File | Source of truth |
|---|---|
| `wire.js` `sshcert.js` `sshsig.js` `sshcrypto.js` `ca.js` `verify.js` `avatar.js` | `extension/src/lib/` |
| `fixture-data.js` | `fixtures/` (via `bin/make-site-fixtures.mjs`) |

## Why copies exist

GitHub Pages serving `/docs` publishes **only** the contents of `docs/`, so
`docs/index.html` cannot reference `../extension/src/lib/` — those files would
not be deployed at all. The same applies to the repo-root `fixtures/`, which is
why the fixture bytes are inlined into a JavaScript file rather than fetched
(`fetch()` is also blocked on `file://`).

`extension/src/lib/` remains the single source of truth. The copies are checked,
not trusted: `extension/test/site-sync.mjs` asserts each file here is
byte-identical to its original and fails with the re-sync command if not, and
`extension/test/site-verify.mjs` runs the page's verification cases against
*these* copies so a stale page cannot pass CI.

Both run as part of `npm test` in `extension/`.

## Load order

These are classic scripts that attach to `globalThis.Beamsig`, not ES modules.
Each destructures its dependencies when it executes, so the order in
`index.html` is mandatory:

```
wire → sshcert → sshsig → sshcrypto → ca → verify → avatar
```

`avatar.js` is the exception — it has no dependencies and ships its own
synchronous SHA-256, so it can be loaded on its own.
