"""Render a contact sheet HTML for tuning teleport_avatar parts.

    python contact_sheet.py                      # 120 synthetic seeds
    python contact_sheet.py --seeds users.txt    # one seed per line (real emails/usernames)
    python contact_sheet.py -n 300 -o sheet.html --version v2

Sections: dense 32px grid, 128px grid with part labels (hover for seed),
a parts sheet showing every variant of every slot in isolation, and
distribution / collision stats. Toggle dark background to check contrast
against dark-mode UIs.
"""
from __future__ import annotations

import argparse
import html
import random
from collections import Counter, defaultdict
from pathlib import Path

import teleport_avatar as ta

FIRST = ["alex", "sam", "jordan", "priya", "wei", "maria", "oluwa", "kenji", "fatima", "lars",
         "noor", "diego", "anya", "tomás", "jeff", "ines", "raj", "chloe", "yusuf", "mei"]
DOMAINS = ["goteleport.com", "example.com", "acme.io", "corp.internal"]


def synthetic_seeds(n: int) -> list[str]:
    rng = random.Random(42)  # stable across runs so you can compare edits
    seeds = set()
    while len(seeds) < n:
        style = rng.random()
        name = rng.choice(FIRST)
        if style < 0.5:
            seeds.add(f"{name}.{rng.choice(FIRST)}@{rng.choice(DOMAINS)}")
        elif style < 0.8:
            seeds.add(f"{name}{rng.randint(1, 999)}")
        else:
            seeds.add(f"bot-{name}-{rng.randint(1, 50)}")  # machine-id style names
    return sorted(seeds)


def tile(seed: str, size: int, label: bool, version: str | None = None) -> str:
    c = ta.choices_for(seed, version)
    d = ta.describe(c)
    tip = html.escape(f"{seed}\n" + "\n".join(f"{k}: {v}" for k, v in d.items()))
    cap = ""
    if label:
        cap = (f'<figcaption><b>{html.escape(seed)}</b>'
               f'<span>{html.escape(d["base"] + " + " + d["highlight"] + (" (tinted)" if d["tint"] == "tinted" else ""))}</span>'
               f'<span>{html.escape(" / ".join(d[s] for s in ["head", "face", "eyes", "detail"]))}</span>'
               f'</figcaption>')
    return f'<figure title="{tip}">{ta.render(c, size=size)}{cap}</figure>'


def parts_sheet() -> str:
    # Reference robot: light grey, violet highlight, screen face, ball antenna, bolts.
    ref = {a: 0 for a in ta.AXES}
    ref.update(antenna=ta._idx("antenna", "ball"), ears=ta._idx("ears", "bolts"),
               mouth=ta._idx("mouth", "grille"), body=ta._idx("body", "panel"))
    rows = []
    for axis, parts in ta.AXES.items():
        total = sum(p.weight for p in parts)
        cells = []
        for i, part in enumerate(parts):
            c = dict(ref, **{axis: i})
            pct = 100 * part.weight / total
            cells.append(f'<figure>{ta.render(c, size=96)}{ta.render(c, size=32)}'
                         f'<figcaption>{html.escape(part.name)} <small>{pct:.0f}%</small></figcaption></figure>')
        rows.append(f'<h3>{axis} <small>{len(parts)}</small></h3><div class="row">{"".join(cells)}</div>')
    return "".join(rows)


def stats(seeds: list[str], version: str | None = None) -> str:
    combos = defaultdict(list)
    per_slot = {a: Counter() for a in ta.AXES}
    for s in seeds:
        c = ta.choices_for(s, version)
        combos[tuple(sorted(c.items()))].append(s)
        for k, v in ta.describe(c).items():
            per_slot[k][v] += 1
    collisions = [v for v in combos.values() if len(v) > 1]
    hist = []
    for slot, counts in per_slot.items():
        options = ta.options(slot)
        top = max(counts.values()) if counts else 1
        bars = "".join(
            f'<div class="bar"><span>{html.escape(o)}</span>'
            f'<i style="width:{100 * counts[o] / top:.0f}%"></i><em>{counts[o]}</em></div>'
            for o in options)
        hist.append(f'<div class="hist"><h4>{slot}</h4>{bars}</div>')
    coll = ("".join(f'<li>{html.escape(", ".join(g))}</li>' for g in collisions)
            or "<li>None</li>")
    return (f'<p>{len(seeds)} seeds, {len(combos)} distinct avatars, '
            f'{ta.TOTAL_COMBOS:,} possible combinations (before rules).</p>'
            f'<div class="hists">{"".join(hist)}</div>'
            f'<h4>Exact collisions</h4><ul>{coll}</ul>'
            f'<p class="note">Weights and rule fix-ups (see _apply_rules) skew these on purpose.</p>')


CSS = """
:root{--bg:#F7F7FB;--fg:#1C1B29;--muted:#6B6A80;--line:#DCDBE8;--bar:#512FC9}
body.dark{--bg:#13121C;--fg:#EDEBFA;--muted:#9C9AB5;--line:#2C2A3D;--bar:#9B87FF}
*{box-sizing:border-box}
body{margin:0;padding:24px 32px 64px;background:var(--bg);color:var(--fg);
  font:14px/1.45 "IBM Plex Sans",system-ui,sans-serif}
header{display:flex;align-items:baseline;gap:16px;flex-wrap:wrap;margin-bottom:8px}
h1{font-size:22px;margin:0}
h2{font-size:17px;margin:36px 0 12px;padding-top:16px;border-top:1px solid var(--line)}
h3{font-size:14px;margin:18px 0 6px}
h3 small,.note,header p{color:var(--muted);font-weight:400}
button{font:inherit;padding:6px 12px;border:1px solid var(--line);border-radius:6px;
  background:transparent;color:var(--fg);cursor:pointer}
button:focus-visible{outline:2px solid var(--bar);outline-offset:2px}
figure{margin:0}
.grid32{display:flex;flex-wrap:wrap;gap:6px}
.grid32 svg{border-radius:50%;display:block}
.grid128{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:16px}
.grid128 svg{border-radius:18px;display:block}
.grid128 figcaption{margin-top:6px;font-size:12px;overflow-wrap:anywhere}
.grid128 figcaption span{display:block;color:var(--muted)}
.row{display:flex;flex-wrap:wrap;gap:18px}
.row figure{display:flex;flex-direction:column;align-items:center;gap:6px}
.row svg{border-radius:14px}
.row svg[width="32"]{border-radius:50%}
.row figcaption{font-size:12px;color:var(--muted)}
.hists{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:20px}
.hist h4{margin:0 0 6px}
.bar{display:grid;grid-template-columns:90px 1fr 32px;align-items:center;gap:8px;font-size:12px}
.bar i{display:block;height:8px;background:var(--bar);border-radius:4px}
.bar em{font-style:normal;color:var(--muted);text-align:right}
"""


def build(seeds: list[str], version: str) -> str:
    g32 = "".join(tile(s, 32, False, version) for s in seeds)
    g128 = "".join(tile(s, 128, True, version) for s in seeds[:60])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Robot avatars {html.escape(version)}</title><style>{CSS}</style></head>
<body><header><h1>Robot avatar contact sheet</h1>
<p>{html.escape(version)} &middot; {len(seeds)} seeds</p>
<button type="button" onclick="document.body.classList.toggle('dark')">Toggle dark background</button></header>
<h2>32px, circular crop</h2><div class="grid32">{g32}</div>
<h2>128px, first 60 seeds</h2><div class="grid128">{g128}</div>
<h2>Parts sheet</h2><p class="note">Each option varies alone against a reference robot, at 96px and 32px, with its selection weight.</p>{parts_sheet()}
<h2>Distribution</h2>{stats(seeds, version)}
</body></html>"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--count", type=int, default=160)
    ap.add_argument("--seeds", type=Path, help="file with one seed per line")
    ap.add_argument("-o", "--out", type=Path, default=Path("contact_sheet.html"))
    ap.add_argument("--version", default=ta.VERSION)
    a = ap.parse_args()
    seeds = ([l.strip() for l in a.seeds.read_text().splitlines() if l.strip()]
             if a.seeds else synthetic_seeds(a.count))
    a.out.write_text(build(seeds, a.version), encoding="utf-8")
    print(f"wrote {a.out} ({len(seeds)} seeds)")


if __name__ == "__main__":
    main()
