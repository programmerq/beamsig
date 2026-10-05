// Injected by chrome-check.mjs and evaluated in the page, BEFORE the content
// scripts run. Reports what GitHub's commit page actually looks like today, so
// findAnchor() in src/content.js can be checked against reality rather than
// against what GitHub's markup used to be.
//
// Kept in its own file because it is full of nested quotes and selector strings
// that are painful to embed in a template literal.
function probeDom() {
  var out = {};

  // The selector cascade findAnchor() tries, in order.
  var selectors = [
    ".js-commit-signature-status",
    '[data-testid="commit-signature"]',
    '[data-testid="commit-box-header"]',
    '[data-testid="commit-header"]',
    ".commit.full-commit",
    "#browser-commit",
  ];
  out.selectorProbe = selectors.map(function (s) {
    return { sel: s, found: !!document.querySelector(s) };
  });

  // GitHub ships CSS-module class names with a per-build hash suffix, e.g.
  // SignedCommitBadge-module__clickableLabel__seodh. The prefix is stable across
  // builds; the hash is not. Find the badge by that prefix.
  var badge = null;
  var els = document.querySelectorAll("*");
  for (var i = 0; i < els.length; i++) {
    var cls = els[i].getAttribute("class") || "";
    if (cls.indexOf("SignedCommitBadge-module") !== -1) {
      badge = els[i];
      break;
    }
  }

  if (badge) {
    out.badge = {
      tag: badge.tagName.toLowerCase(),
      cls: badge.getAttribute("class"),
      text: (badge.textContent || "").trim().slice(0, 40),
    };
    out.chain = [];
    var n = badge;
    for (var d = 0; d < 9 && n; d++) {
      out.chain.push({
        tag: n.tagName.toLowerCase(),
        cls: (n.getAttribute("class") || "").slice(0, 110),
        testid: n.getAttribute("data-testid"),
        id: n.id || null,
        kids: n.children.length,
      });
      n = n.parentElement;
    }
  } else {
    out.badge = null;
    out.chain = [];
  }

  // Candidate anchors that do not depend on a build hash.
  var hooks = [
    '[class*="SignedCommitBadge-module"]',
    '[class*="CommitHeader-module"]',
    '[class*="Commit-module"]',
    "[data-testid]",
    'div[class*="Box"]',
    "#repo-content-pjax-container",
    '[data-hpc]',
  ];
  out.stableHooks = hooks.map(function (s) {
    var found = document.querySelectorAll(s);
    return { sel: s, found: found.length > 0, count: found.length };
  });

  // Every data-testid on the page; the most likely source of a durable hook.
  var ids = [];
  var withId = document.querySelectorAll("[data-testid]");
  for (var k = 0; k < withId.length && ids.length < 60; k++) {
    var v = withId[k].getAttribute("data-testid");
    if (ids.indexOf(v) === -1) ids.push(v);
  }
  out.testIds = ids;

  return out;
}
