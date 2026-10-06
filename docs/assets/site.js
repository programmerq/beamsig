/* beamsig landing page behaviour: the hero terminal replay and the live
 * verification widget.
 *
 * The widget runs the real verifier from extension/src/lib (copied into
 * vendor/ by bin/sync-site-libs.sh) against the real signatures committed in
 * fixtures/ (inlined into vendor/fixture-data.js). Nothing is mocked and
 * nothing is fetched.
 *
 * Everything user-visible is built with createElement/textContent rather than
 * innerHTML. The verifier's output includes certificate-derived strings, and
 * those must never be able to inject markup.
 */
(function () {
  "use strict";

  const reduceMotion =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const el = (tag, className, text) => {
    const n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  };

  /* ------------------------------------------------------------ hero terminal */

  // cls "cmd" lines type out character by character; everything else appears
  // whole, as real command output does.
  const SCRIPT = [
    { cls: "cmd", text: "./bin/install-global.sh" },
    { cls: "c-out", text: "== pinning the Teleport SSH user CA ==" },
    { cls: "c-dim", text: "   ~/.config/beamsig/pinned-user-ca.txt" },
    { cls: "c-out", text: "Every repository in this beam now signs as the beam." },
    { cls: "blank" },
    { cls: "cmd", text: 'git commit -m "fix the parser"' },
    { cls: "c-dim", text: "[main 4f21ab9] fix the parser" },
    { cls: "blank" },
    { cls: "cmd", text: "git log --show-signature -1" },
    {
      cls: "c-good",
      text: 'Good "git" signature for beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9',
    },
    { cls: "c-out", text: "  beam alias    luminous-locator" },
    { cls: "c-out", text: "  bot instance  dbe1cf6c-8f89-4ab3-bfee-9e2c7e710f6c" },
    { cls: "c-out", text: "  owner         owner@example.com" },
    { cls: "c-warn", text: "                (impersonated — did not review this)" },
    { cls: "c-out", text: "  cert window   16:16:27Z .. 17:17:27Z" },
    { cls: "c-warn", text: "                (window chosen by signer)" },
    { cls: "c-key", text: "  teleport CA   SHA256:c/8F7ipW3zBqBRe0Eau/…  (pinned)" },
  ];

  // The owner's address is the certificate's Key ID, so it is permanently
  // inside every beam signature -- including the fixtures this page verifies.
  // This is a public page, so mask the local part for display. The label says
  // it is masked, because the point being taught is that verification *does*
  // reveal the owner; the address just does not need publishing.
  function maskOwner(addr) {
    if (!addr) return addr;
    const at = addr.lastIndexOf("@");
    if (at < 1) return "\u2022\u2022\u2022";
    return addr[0] + "\u2022\u2022\u2022" + addr.slice(at);
  }

  function runTerminal(body, onDone) {
    body.textContent = "";
    let cancelled = false;
    let i = 0;

    const cursor = el("span", "cursor");

    const sleep = (ms) =>
      new Promise((r) => setTimeout(r, reduceMotion ? 0 : ms));

    async function step() {
      while (i < SCRIPT.length) {
        if (cancelled) return;
        const line = SCRIPT[i++];

        if (line.cls === "blank") {
          body.appendChild(document.createTextNode("\n"));
          await sleep(90);
          continue;
        }

        if (line.cls === "cmd") {
          const prompt = el("span", "c-prompt", "$ ");
          const span = el("span", "c-cmd");
          body.appendChild(prompt);
          body.appendChild(span);
          body.appendChild(cursor);
          if (reduceMotion) {
            span.textContent = line.text;
          } else {
            for (const ch of line.text) {
              if (cancelled) return;
              span.textContent += ch;
              await sleep(18);
            }
          }
          body.appendChild(document.createTextNode("\n"));
          await sleep(260);
        } else {
          body.appendChild(el("span", line.cls, line.text));
          body.appendChild(document.createTextNode("\n"));
          body.appendChild(cursor);
          await sleep(140);
        }
      }
      if (cursor.parentNode) cursor.parentNode.removeChild(cursor);
      if (onDone) onDone();
    }

    step();
    return () => {
      cancelled = true;
    };
  }

  const termBody = document.getElementById("term-body");
  const termReplay = document.getElementById("term-replay");
  if (termBody) {
    let cancel = runTerminal(termBody);
    if (termReplay) {
      termReplay.addEventListener("click", () => {
        if (cancel) cancel();
        cancel = runTerminal(termBody);
      });
    }
  }

  /* --------------------------------------------------------- copy quickstart */

  const copyBtn = document.getElementById("copy-qs");
  const qsCode = document.getElementById("qs-code");
  if (copyBtn && qsCode) {
    copyBtn.addEventListener("click", async () => {
      // Keep only prompts and comments, then strip the "$ ", so what lands on
      // the clipboard is runnable. The block also shows example *output*,
      // which would be a syntax error if it were pasted into a shell.
      const text = qsCode.textContent
        .split("\n")
        .filter((l) => /^\$ /.test(l) || /^\s*#/.test(l) || l.trim() === "")
        .map((l) => l.replace(/^\$ /, ""))
        .join("\n")
        .replace(/\n{3,}/g, "\n\n")
        .trim();
      try {
        await navigator.clipboard.writeText(text);
        copyBtn.textContent = "copied";
      } catch {
        copyBtn.textContent = "select manually";
      }
      setTimeout(() => {
        copyBtn.textContent = "copy";
      }, 1800);
    });
  }

  /* ------------------------------------------------------- verifier widget */

  const resultBox = document.getElementById("result");
  const caseList = document.getElementById("case-list");

  const B = globalThis.Beamsig;
  const F = globalThis.BEAMSIG_FIXTURES;

  function fatal(message) {
    if (!resultBox) return;
    resultBox.textContent = "";
    const body = el("div", "result-body");
    body.appendChild(el("p", "lede", message));
    resultBox.appendChild(body);
    if (caseList) {
      caseList
        .querySelectorAll("button")
        .forEach((b) => b.setAttribute("disabled", "disabled"));
    }
  }

  if (!resultBox || !caseList) return;

  if (!B || !B.verify || !F) {
    fatal("The verification libraries did not load, so this demo is unavailable.");
    return;
  }

  // crypto.subtle only exists in a secure context (https, localhost, file://).
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    fatal(
      "Your browser exposes no Web Crypto API here, which means this page is " +
        "not in a secure context. Load it over https or from a local file to " +
        "run the verification."
    );
    return;
  }

  const { wire, verify, ca, avatar } = B;

  const iso = (unix) =>
    new Date(unix * 1000).toISOString().replace(".000Z", "Z");

  // Tier chips carry the same meaning everywhere: what the certificate proves,
  // what somebody merely told us, and what was not checked at all.
  const TIER = {
    attested: ["tier-attested", "attested"],
    reported: ["tier-reported", "self-reported"],
    unchecked: ["tier-unchecked", "not checked"],
  };

  function addFact(dl, label, value, tier, note) {
    const row = el("div", "fact");
    row.appendChild(el("dt", null, label));
    const dd = el("dd", null, value);
    if (note) {
      const small = el("div", "verdict-sub", note);
      dd.appendChild(small);
    }
    row.appendChild(dd);
    if (tier) {
      const [cls, text] = TIER[tier];
      row.appendChild(el("span", "tier " + cls, text));
    }
    dl.appendChild(row);
    return row;
  }

  function avatarImg(seed) {
    const box = el("div", "result-avatar");
    const svg = avatar.avatar(seed, 128);
    const img = document.createElement("img");
    // A data URI keeps the SVG out of the document, so the generator's
    // duplicate clipPath ids cannot collide with anything on the page.
    img.src = "data:image/svg+xml," + encodeURIComponent(svg);
    img.alt = "";
    img.width = 64;
    img.height = 64;
    box.appendChild(img);
    return box;
  }

  function renderSuccess(att, caseMeta) {
    resultBox.textContent = "";

    const head = el("div", "result-head is-ok");
    head.appendChild(avatarImg(att.beamId));
    const v = el("div", "result-verdict");
    v.appendChild(el("div", "verdict-label", "signature verified"));
    v.appendChild(el("div", "verdict-main", "beam " + att.beamId));
    v.appendChild(
      el(
        "div",
        "verdict-sub",
        "on behalf of " + maskOwner(att.owner) + " — owner, impersonated, did not review this"
      )
    );
    head.appendChild(v);
    resultBox.appendChild(head);

    const body = el("div", "result-body");

    if (caseMeta && caseMeta.lead) {
      body.appendChild(el("p", "lede", caseMeta.lead));
    }

    const dl = el("dl", "facts");
    addFact(dl, "beam id", att.beamId, "attested");
    if (att.botInstanceId)
      addFact(dl, "bot instance", att.botInstanceId, "attested", "stable per beam boot");
    if (att.delegationSessionId)
      addFact(dl, "delegation", att.delegationSessionId, "attested");
    addFact(dl, "cluster", att.cluster || "—", "attested");
    if (att.roles && att.roles.length)
      addFact(dl, "roles", att.roles.join(", "), "attested", "at time of issuance");
    addFact(
      dl,
      "owner",
      maskOwner(att.owner),
      "attested",
      "the human the beam impersonates — not the signer (masked here)"
    );
    addFact(
      dl,
      "beam alias",
      "unavailable",
      "reported",
      "aliases appear in no certificate; the mapping dies with the beam"
    );
    addFact(
      dl,
      "cert window",
      iso(att.validAfter) + "  ..  " + iso(att.validBefore),
      "attested"
    );
    if (att.claimedTime !== undefined && att.claimedTime !== null)
      addFact(dl, "claimed time", iso(att.claimedTime), "reported");
    addFact(dl, "namespace", att.namespace, "attested", "signatures cannot be replayed across contexts");
    addFact(dl, "signing key", att.signingKeyFp, "attested");
    addFact(dl, "teleport CA", att.caFp, "attested");
    body.appendChild(dl);

    const notes = el("div", "notes");
    (att.caveats || []).forEach((c) => {
      const n = el("div", "note is-caveat");
      n.appendChild(el("span", "note-mark", "▲"));
      n.appendChild(el("span", null, c));
      notes.appendChild(n);
    });
    (att.warnings || []).forEach((w) => {
      const n = el("div", "note");
      n.appendChild(el("span", "note-mark", "!"));
      n.appendChild(el("span", null, w));
      notes.appendChild(n);
    });
    if (notes.childNodes.length) body.appendChild(notes);

    resultBox.appendChild(body);
  }

  function renderFailure(err, caseMeta) {
    resultBox.textContent = "";

    // A bare key or an unknown CA is not a broken signature — it is somebody
    // else's signature. Showing those in alarm red would cry wolf.
    const soft = verify.NOT_BEAM_CODES.has(err.code);

    const head = el("div", "result-head " + (soft ? "is-info" : "is-bad"));
    const v = el("div", "result-verdict");
    v.appendChild(
      el("div", "verdict-label", soft ? "not a beam signature" : "verification failed")
    );
    v.appendChild(
      el("div", "verdict-main", soft ? "no beam identity established" : "rejected")
    );
    if (err.code) v.appendChild(el("div", "verdict-sub", "code: " + err.code));
    head.appendChild(v);
    resultBox.appendChild(head);

    const body = el("div", "result-body");
    if (caseMeta && caseMeta.lead) body.appendChild(el("p", "lede", caseMeta.lead));

    const n = el("div", "note");
    n.appendChild(el("span", "note-mark", "✕"));
    n.appendChild(el("span", null, err.message));
    const notes = el("div", "notes");
    notes.appendChild(n);
    body.appendChild(notes);

    resultBox.appendChild(body);
  }

  // Each case resolves to the exact bytes and options handed to the verifier.
  const CASES = {
    signed: {
      lead: "The beam's certificate is embedded in the signature, so the identity below came out of the signature itself.",
      build: (cas) => ({
        sig: F.signed.signature,
        payload: wire.TE.encode(F.signed.message),
        cas,
        opts: optsFor(F.signed),
      }),
    },
    tampered: {
      lead: "The same genuine signature, checked against a payload that has been altered.",
      build: (cas) => ({
        sig: F.signed.signature,
        payload: wire.TE.encode(F.signed.message + " (altered)"),
        cas,
        opts: optsFor(F.signed),
      }),
    },
    bareKey: {
      lead: "This signature is cryptographically fine, but it was made with a bare key instead of the certificate — so it names nobody.",
      build: (cas) => ({
        sig: F.bareKey.signature,
        payload: wire.TE.encode(F.bareKey.message),
        cas,
        opts: optsFor(F.bareKey),
      }),
    },
    untrustedCa: {
      lead: "The genuine signature, checked against a deliberately corrupted trust anchor. This is what an untrusted cluster looks like.",
      build: (cas) => ({
        sig: F.signed.signature,
        payload: wire.TE.encode(F.signed.message),
        cas: cas.map((c) => {
          const blob = c.blob.slice();
          blob[blob.length - 1] ^= 0xff;
          return Object.assign({}, c, { blob });
        }),
        opts: optsFor(F.signed),
      }),
    },
    backdated: {
      lead: "This artifact was signed roughly 34 minutes after the time it claims, by embedding a certificate the beam still held. It verifies completely — which is why the timestamp must be read as a window the signer chose.",
      build: (cas) => ({
        sig: F.backdated.signature,
        payload: wire.TE.encode(F.backdated.message),
        cas,
        opts: optsFor(F.backdated),
      }),
    },
  };

  function optsFor(fx) {
    return {
      namespace: fx.namespace,
      claimedTime: fx.claimedTime,
      claimedTimeSource: "fixture",
    };
  }

  let pinnedCAs = null;

  async function runCase(name) {
    const meta = CASES[name];
    if (!meta) return;

    try {
      if (!pinnedCAs) pinnedCAs = await verify.loadPinnedCAs(ca.PINNED_CAS);
    } catch (e) {
      fatal("The pinned certificate authority failed to load: " + e.message);
      return;
    }

    const { sig, payload, cas, opts } = meta.build(pinnedCAs);
    try {
      const att = await verify.verifySSHSig(sig, payload, cas, opts);
      renderSuccess(att, meta);
    } catch (e) {
      renderFailure(e, meta);
    }
  }

  caseList.addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-case]");
    if (!btn) return;
    caseList
      .querySelectorAll("button[data-case]")
      .forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
    runCase(btn.dataset.case);
  });

  // Start on the honest case so the section is never empty.
  const first = caseList.querySelector('button[data-case="signed"]');
  if (first) {
    first.setAttribute("aria-pressed", "true");
    runCase("signed");
  }
})();
