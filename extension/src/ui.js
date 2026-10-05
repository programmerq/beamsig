// Rendering. The hard requirements here come from
// docs/PRESENTATION-NOTES.md "Three things you must NOT claim":
//
//   1. The signer is NOT the person. The certificate's Key ID is the owner,
//      a human, because the beam impersonates them. Never render the Key ID or
//      the committer email as "signed by".
//   2. The alias is not bound to anything. It appears in no certificate, so we
//      cannot show one at all here — only the UUID is attested. We say so
//      rather than leaving a blank the reader fills in with a guess.
//   3. The timestamp is weaker than it looks. Show the certificate window as a
//      range the signer chose, never a precise "signed at".
//
// And the standing caveat: a beam signature attests to a SANDBOX, not to a
// program, an author, or human intent.
//
// Three tiers, visually distinct: attested (from the certificate, chained to
// the pinned CA), self-reported (unbound claims), and not checked (warnings).
(function (root) {
  "use strict";

  const ns = (root.Beamsig = root.Beamsig || {});
  const { iso } = ns.verify;

  const SHORT = (s) => (s && s.length > 8 ? s.slice(0, 8) + "…" : s || "");

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }

  // The robot is a recognition aid seeded by the beam UUID: the same beam
  // always looks the same. It is decoration, not evidence, and is omitted
  // rather than breaking the panel if the generator is unavailable.
  function avatar(beamId, size, cls) {
    if (!ns.avatar || !beamId) return document.createDocumentFragment();
    const a = ns.avatar.avatarElement(beamId, size);
    if (cls) a.classList.add(cls);
    return a;
  }

  function row(label, value, note, tier) {
    const r = el("div", "beamsig-row");
    r.appendChild(el("span", "beamsig-label", label));
    const v = el("span", "beamsig-value", value);
    if (tier) v.classList.add(`beamsig-tier-${tier}`);
    r.appendChild(v);
    if (note) r.appendChild(el("span", "beamsig-note", note));
    return r;
  }

  function section(title) {
    const s = el("div", "beamsig-section");
    s.appendChild(el("div", "beamsig-section-title", title));
    return s;
  }

  // ---- the verified panel ---------------------------------------------------

  function panel(att, ctx) {
    const box = el("div", "beamsig-panel beamsig-ok");

    const head = el("div", "beamsig-head");
    head.appendChild(avatar(att.beamId, 40, "beamsig-avatar-lg"));
    head.appendChild(el("span", "beamsig-check", "✓"));
    const headText = el("div", "beamsig-head-text");
    headText.appendChild(
      el("div", "beamsig-head-title", `Signed by beam ${SHORT(att.beamId)}`)
    );
    headText.appendChild(
      el(
        "div",
        "beamsig-head-sub",
        "Verified in your browser against a pinned Teleport CA — not by GitHub"
      )
    );
    head.appendChild(headText);
    box.appendChild(head);

    // -- attested
    const a = section("Attested by the certificate");
    a.appendChild(row("beam id", att.beamId, "the only durable identity", "attested"));
    a.appendChild(
      row("bot instance", att.botInstanceId, "stable per beam boot", "attested")
    );
    a.appendChild(row("delegation session", att.delegationSessionId, "", "attested"));
    a.appendChild(
      row(
        "cluster",
        att.cluster,
        att.clusterPinned ? "bound to the CA that verified this" : "from the certificate, unpinned",
        att.clusterPinned ? "attested" : "selfreported"
      )
    );
    if (att.clusterClaimed && att.clusterClaimed !== att.cluster) {
      a.appendChild(
        row("cluster claimed", att.clusterClaimed, "what the certificate says — NOT authoritative", "selfreported")
      );
    }
    a.appendChild(row("roles at issuance", att.roles.join(", "), "", "attested"));
    a.appendChild(
      row("principals", att.principals.join(", "), "generic logins, shared cluster-wide", "attested")
    );
    if (att.loginIp) a.appendChild(row("login ip", att.loginIp, "", "attested"));
    box.appendChild(a);

    // -- the owner, carefully labelled
    const o = section("On behalf of");
    const ownerRow = row(
      "owner",
      att.owner,
      "impersonated — NOT the signer, and did not review this",
      "attested"
    );
    ownerRow.classList.add("beamsig-owner");
    o.appendChild(ownerRow);
    box.appendChild(o);

    // -- time, as a range
    const t = section("Time");
    t.appendChild(
      row(
        "certificate window",
        `${iso(att.validAfter)} .. ${iso(att.validBefore)}`,
        "window chosen by the signer",
        "attested"
      )
    );
    if (att.claimedTime) {
      t.appendChild(
        row(
          "committer date",
          iso(att.claimedTime),
          "signed, and inside the window above",
          "selfreported"
        )
      );
    }
    box.appendChild(t);

    // -- crypto
    const c = section("Crypto");
    c.appendChild(row("signing key", att.signingKeyFp, "constant for the beam's life", "attested"));
    c.appendChild(
      row(
        "issuing CA",
        att.caFp,
        att.caDiscovered
          ? `discovered from ${att.caCluster} · pinned on first use · NOT operator-pinned`
          : `pinned${att.caCluster ? ` · ${att.caCluster}` : ""}`,
        att.caDiscovered ? "selfreported" : "attested"
      )
    );
    c.appendChild(row("algorithm", att.sigAlgorithm, "", "attested"));
    c.appendChild(row("payload sha256", SHORT(att.payloadSha256), "", "attested"));
    box.appendChild(c);

    // -- not attested / unavailable
    const u = section("Not attested");
    u.appendChild(
      row(
        "beam alias",
        "unavailable",
        "aliases are in no certificate and die with the beam — only the UUID is attested",
        "unchecked"
      )
    );
    box.appendChild(u);

    // -- caveats: always shown, these bound what a pass means
    if (att.caveats && att.caveats.length) {
      const cv = section("What this does not prove");
      for (const text of att.caveats) {
        cv.appendChild(el("div", "beamsig-caveat", text));
      }
      box.appendChild(cv);
    }

    // -- warnings: things we did not check
    if (att.warnings && att.warnings.length) {
      const w = section("Not checked");
      for (const text of att.warnings) {
        w.appendChild(el("div", "beamsig-warning", text));
      }
      box.appendChild(w);
    }

    box.appendChild(footer(ctx));
    return box;
  }

  // ---- failure / informational panels --------------------------------------

  function failPanel(title, detail, ctx, kind) {
    const box = el("div", `beamsig-panel beamsig-${kind || "bad"}`);
    const head = el("div", "beamsig-head");
    head.appendChild(el("span", "beamsig-check", kind === "info" ? "•" : "✕"));
    const headText = el("div", "beamsig-head-text");
    headText.appendChild(el("div", "beamsig-head-title", title));
    if (detail) headText.appendChild(el("div", "beamsig-head-sub", detail));
    head.appendChild(headText);
    box.appendChild(head);
    box.appendChild(footer(ctx));
    return box;
  }

  function footer(ctx) {
    const f = el("div", "beamsig-footer");
    f.appendChild(
      el(
        "span",
        "beamsig-footer-text",
        ctx && ctx.fromCache ? "beamsig · cached" : "beamsig"
      )
    );
    return f;
  }

  // ---- compact badge for commit-list rows -----------------------------------

  function badge(att) {
    const b = el("span", "beamsig-badge beamsig-badge-ok");
    b.appendChild(avatar(att.beamId, 14, "beamsig-avatar-sm"));
    b.appendChild(el("span", "beamsig-badge-check", "✓"));
    b.appendChild(el("span", "beamsig-badge-text", `beam ${SHORT(att.beamId)}`));
    b.title =
      `beam ${att.beamId}\n` +
      `cluster ${att.cluster}\n` +
      `roles ${att.roles.join(", ")}\n` +
      `on behalf of ${att.owner} (impersonated, not the signer)\n` +
      `window ${iso(att.validAfter)} .. ${iso(att.validBefore)} (chosen by signer)\n` +
      "\nVerified in-browser against a pinned Teleport CA, not by GitHub.\n" +
      "Attests to a sandbox, not to a program or human intent.";
    return b;
  }

  function badgeFail(message) {
    const b = el("span", "beamsig-badge beamsig-badge-bad");
    b.appendChild(el("span", "beamsig-badge-check", "✕"));
    b.appendChild(el("span", "beamsig-badge-text", "beam?"));
    b.title = message;
    return b;
  }

  ns.ui = { panel, failPanel, badge, badgeFail, el, row, section, SHORT };
})(typeof globalThis !== "undefined" ? globalThis : self);
