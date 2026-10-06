"""Deterministic seed -> robot avatar SVG.

Robot generator by Jeff.

Look: grey paneled robots with color highlights (most of the time), plus a
rare "solid" variant where the body takes the highlight color and the
highlights go grey. Shadows are either neutral grey or tinted toward the
highlight hue.

Color is three independent axes (base, highlight, tint); geometry is a set
of slots. Every option is a Part with an optional weight, so you can make
some looks rarer without duplicating entries.

Freeze option lists per VERSION: adding a variant or changing a weight
changes the mapping and reshuffles existing avatars. Bump VERSION then.
"""
from __future__ import annotations

import hashlib
from math import prod
from typing import Callable, NamedTuple

VERSION = "v2"
SIZE = 128


class Part(NamedTuple):
    name: str
    value: object          # draw fn, color dict, etc.
    weight: int = 1
    meta: dict | None = None


# --- color helpers ----------------------------------------------------------
def _rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def mix(a: str, b: str, t: float) -> str:
    """Linear blend a -> b by t (0..1)."""
    ra, rb = _rgb(a), _rgb(b)
    return "#" + "".join(f"{round(x + (y - x) * t):02X}" for x, y in zip(ra, rb))


# --- color axes -------------------------------------------------------------
# Bases: body/panel grey, shade grey, face (dark screen), ink (bare-eye color).
BASES = [
    Part("light",    dict(body="#E6E8EF", shade="#B9BECC", face="#23252F", ink="#2A2D3A"), 3),
    Part("silver",   dict(body="#CDD1DC", shade="#9CA2B3", face="#1F2129", ink="#262833"), 3),
    Part("steel",    dict(body="#9AA0AF", shade="#6E7485", face="#1B1D25", ink="#1E2029"), 2),
    Part("graphite", dict(body="#4E5363", shade="#363A47", face="#15161D", ink="#E6E8EF"), 2),
    Part("solid",    dict(solid=True), 1),  # body = highlight; ~1 in 11
]

HIGHLIGHTS = [
    Part("violet",  "#7B5CFF"),
    Part("teal",    "#00BFA6"),
    Part("coral",   "#FF6257"),
    Part("amber",   "#FFB020"),
    Part("sky",     "#35A2FF"),
    Part("magenta", "#E14FD0"),
    Part("lime",    "#5FCB4B"),
]

TINTS = [
    Part("neutral", 0.0),
    Part("tinted",  0.28),  # how far shadows lean toward the highlight hue
]


def build_palette(base: Part, hl: Part, tint: Part) -> dict[str, str]:
    h = hl.value
    if base.value.get("solid"):
        body = h
        shade = mix(h, "#000000", 0.28)
        p = dict(body=body, shade=shade, accent="#F2F3F7", glow="#FFFFFF",
                 face="#1B1D25", ink="#1B1D25")
    else:
        b = base.value
        p = dict(body=b["body"], shade=mix(b["shade"], h, tint.value), accent=h,
                 glow=mix(h, "#FFFFFF", 0.35), face=b["face"], ink=b["ink"])
    p["bg"] = mix("#F4F5F8", h, 0.14)
    return p


# --- geometry ---------------------------------------------------------------
# Heads carry their top/bottom so clipped details and shadows can follow them.
HEADS = [
    Part("square", lambda f: f'<rect x="24" y="28" width="80" height="64" rx="12" fill="{f}"/>', 1, dict(top=28, bottom=92, left=24, right=104)),
    Part("round",  lambda f: f'<rect x="22" y="30" width="84" height="60" rx="30" fill="{f}"/>', 1, dict(top=30, bottom=90, left=22, right=106)),
    Part("tall",   lambda f: f'<rect x="30" y="22" width="68" height="72" rx="16" fill="{f}"/>', 1, dict(top=22, bottom=94, left=30, right=98)),
    Part("dome",   lambda f: f'<path d="M24 92 V62 A40 40 0 0 1 104 62 V92 Z" fill="{f}"/>', 1, dict(top=22, bottom=92, left=24, right=104)),
]

BODIES = [
    Part("block", lambda p: (
        f'<rect x="34" y="92" width="60" height="44" rx="10" fill="{p["body"]}"/>'
        f'<rect x="34" y="92" width="60" height="7" fill="{p["shade"]}"/>'
        f'<rect x="44" y="108" width="40" height="5" rx="2.5" fill="{p["accent"]}"/>')),
    Part("shoulders", lambda p: (
        f'<rect x="14" y="98" width="100" height="40" rx="20" fill="{p["body"]}"/>'
        f'<rect x="48" y="96" width="32" height="10" rx="5" fill="{p["accent"]}"/>'
        f'<rect x="14" y="118" width="100" height="20" fill="{p["shade"]}"/>')),
    Part("chest-light", lambda p: (
        f'<rect x="56" y="88" width="16" height="14" fill="{p["shade"]}"/>'
        f'<rect x="28" y="98" width="72" height="40" rx="12" fill="{p["body"]}"/>'
        f'<circle cx="64" cy="114" r="8" fill="{p["face"]}"/>'
        f'<circle cx="64" cy="114" r="4.5" fill="{p["accent"]}"/>')),
    Part("panel", lambda p: (
        f'<rect x="28" y="96" width="72" height="40" rx="8" fill="{p["body"]}"/>'
        f'<rect x="38" y="104" width="52" height="14" rx="4" fill="{p["shade"]}"/>'
        f'<rect x="43" y="108" width="12" height="6" rx="2" fill="{p["accent"]}"/>'
        f'<rect x="59" y="108" width="12" height="6" rx="2" fill="{p["glow"]}"/>'
        f'<rect x="75" y="108" width="10" height="6" rx="2" fill="{p["accent"]}"/>')),
]

# Drawn behind the head so stalks tuck under it.
ANTENNAE = [
    Part("none", lambda p: ""),
    Part("ball", lambda p: (
        f'<line x1="64" y1="36" x2="64" y2="12" stroke="{p["shade"]}" stroke-width="4"/>'
        f'<circle cx="64" cy="11" r="6" fill="{p["accent"]}"/>'), 2),
    Part("twin", lambda p: (
        f'<path d="M48 36 L40 13 M80 36 L88 13" stroke="{p["shade"]}" stroke-width="4" stroke-linecap="round"/>'
        f'<circle cx="40" cy="12" r="4.5" fill="{p["accent"]}"/><circle cx="88" cy="12" r="4.5" fill="{p["accent"]}"/>')),
    Part("bolt", lambda p: (
        f'<polyline points="64,36 64,22 71,16 58,9" fill="none" stroke="{p["accent"]}" '
        f'stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>')),
    Part("dish", lambda p: (
        f'<line x1="64" y1="36" x2="64" y2="18" stroke="{p["shade"]}" stroke-width="4"/>'
        f'<path d="M51 16 A13 13 0 0 0 77 16 Z" fill="{p["accent"]}"/>')),
]

EARS = [
    Part("none",  lambda p: ""),
    Part("bolts", lambda p: "".join(
        f'<circle cx="{x}" cy="60" r="8" fill="{p["shade"]}"/><circle cx="{x}" cy="60" r="3.5" fill="{p["accent"]}"/>'
        for x in (18, 110))),
    Part("fins",  lambda p: (
        f'<rect x="11" y="46" width="16" height="28" rx="5" fill="{p["shade"]}"/>'
        f'<rect x="101" y="46" width="16" height="28" rx="5" fill="{p["shade"]}"/>'
        f'<rect x="15" y="52" width="4" height="16" rx="2" fill="{p["accent"]}"/>'
        f'<rect x="109" y="52" width="4" height="16" rx="2" fill="{p["accent"]}"/>')),
    Part("nubs",  lambda p: (
        f'<rect x="12" y="55" width="14" height="10" rx="3" fill="{p["accent"]}"/>'
        f'<rect x="102" y="55" width="14" height="10" rx="3" fill="{p["accent"]}"/>')),
]

# Head details are clipped to the head shape, so they follow any silhouette.
DETAILS = [
    Part("none",        lambda p, hm: "", 2),
    Part("top-stripe",  lambda p, hm: f'<rect x="0" y="{hm["top"]}" width="128" height="8" fill="{p["accent"]}"/>'),
    Part("side-plates", lambda p, hm: (
        f'<rect x="0" y="0" width="{hm["left"] + 9}" height="128" fill="{p["shade"]}"/>'
        f'<rect x="{hm["right"] - 9}" y="0" width="{128 - hm["right"] + 9}" height="128" fill="{p["shade"]}"/>'
        f'<rect x="{hm["left"] + 9}" y="0" width="2" height="128" fill="{p["accent"]}"/>'
        f'<rect x="{hm["right"] - 11}" y="0" width="2" height="128" fill="{p["accent"]}"/>')),
    Part("cheeks",      lambda p, hm: (
        f'<circle cx="37" cy="76" r="4.5" fill="{p["accent"]}"/>'
        f'<circle cx="91" cy="76" r="4.5" fill="{p["accent"]}"/>')),
]

# Face sets up what the eyes sit on and which colors they use.
FACES = [
    Part("screen", lambda p: f'<rect x="33" y="44" width="62" height="29" rx="11" fill="{p["face"]}"/>', 3,
         dict(eye="glow", pupil="face")),
    Part("bare",   lambda p: "", 2, dict(eye="ink", pupil="accent")),
    Part("band",   lambda p: f'<rect x="0" y="46" width="128" height="25" fill="{p["accent"]}"/>', 1,
         dict(eye="face", pupil="glow", clip=True)),
]

EYES = [
    Part("dots",    lambda p: f'<circle cx="48" cy="58" r="8" fill="{p["eye"]}"/><circle cx="80" cy="58" r="8" fill="{p["eye"]}"/>'),
    Part("ring",    lambda p: "".join(
        f'<circle cx="{x}" cy="58" r="9.5" fill="{p["eye"]}"/><circle cx="{x}" cy="59" r="4" fill="{p["pupil"]}"/>'
        for x in (47, 81))),
    Part("visor",   lambda p: (
        f'<rect x="38" y="51" width="52" height="15" rx="7.5" fill="{p["eye"]}"/>'
        f'<rect x="47" y="55" width="10" height="7" rx="3" fill="{p["pupil"]}"/>'
        f'<rect x="71" y="55" width="10" height="7" rx="3" fill="{p["pupil"]}"/>')),
    Part("happy",   lambda p: (
        f'<path d="M40 62 Q48 51 56 62 M72 62 Q80 51 88 62" fill="none" stroke="{p["eye"]}" '
        f'stroke-width="5.5" stroke-linecap="round"/>')),
    Part("cyclops", lambda p: f'<circle cx="64" cy="58" r="12" fill="{p["eye"]}"/><circle cx="64" cy="58" r="5" fill="{p["pupil"]}"/>'),
    Part("square",  lambda p: (
        f'<rect x="40" y="50" width="16" height="16" rx="4" fill="{p["eye"]}"/>'
        f'<rect x="72" y="50" width="16" height="16" rx="4" fill="{p["eye"]}"/>')),
]

MOUTHS = [
    Part("line",    lambda p: f'<rect x="50" y="78" width="28" height="5" rx="2.5" fill="{p["accent"]}"/>'),
    Part("grille",  lambda p: "".join(
        f'<rect x="{47 + i * 9}" y="76" width="5" height="9" rx="1.5" fill="{p["accent"]}"/>' for i in range(4))),
    Part("smile",   lambda p: f'<path d="M50 76 Q64 87 78 76" fill="none" stroke="{p["accent"]}" stroke-width="5" stroke-linecap="round"/>'),
    Part("speaker", lambda p: (
        f'<rect x="46" y="75" width="36" height="11" rx="5.5" fill="{p["face"]}"/>'
        + "".join(f'<circle cx="{55 + i * 9}" cy="80.5" r="2.2" fill="{p["accent"]}"/>' for i in range(3)))),
    Part("none",    lambda p: ""),
]

COLOR_AXES = {"base": BASES, "highlight": HIGHLIGHTS, "tint": TINTS}
SLOTS = {
    "body": BODIES, "antenna": ANTENNAE, "ears": EARS, "head": HEADS,
    "detail": DETAILS, "face": FACES, "eyes": EYES, "mouth": MOUTHS,
}
AXES = {**COLOR_AXES, **SLOTS}
TOTAL_COMBOS = prod(len(v) for v in AXES.values())


def options(axis: str) -> list[str]:
    return [p.name for p in AXES[axis]]


# --- selection --------------------------------------------------------------
def _digest(seed: str, version: str | None = None) -> bytes:
    return hashlib.sha256(f"{version or VERSION}:{seed.strip().lower()}".encode()).digest()


def _weighted(byte: int, parts: list[Part]) -> int:
    """Map one hash byte to an index, honoring weights."""
    r = byte % sum(p.weight for p in parts)
    for i, p in enumerate(parts):
        r -= p.weight
        if r < 0:
            return i
    raise AssertionError


def _idx(axis: str, name: str) -> int:
    return options(axis).index(name)


def _apply_rules(c: dict[str, int]) -> dict[str, int]:
    """Deterministic fix-ups for combos that look bad. Keep rules few and explicit."""
    n = describe(c)
    if n["eyes"] == "happy" and n["mouth"] == "none":
        c["mouth"] = _idx("mouth", "smile")          # otherwise reads as asleep
    if n["eyes"] == "cyclops" and n["mouth"] == "speaker":
        c["mouth"] = _idx("mouth", "line")           # too busy at 32px
    if n["head"] in ("tall", "dome") and n["antenna"] == "dish":
        c["antenna"] = _idx("antenna", "ball")       # head swallows the dish
    if n["face"] == "band" and n["detail"] == "top-stripe":
        c["detail"] = _idx("detail", "none")         # two accent stripes is too much
    if n["face"] == "band" and n["detail"] == "side-plates":
        c["detail"] = _idx("detail", "none")         # plates would cover the band ends
    return c


def choices_for(seed: str, version: str | None = None) -> dict[str, int]:
    h = _digest(seed, version)
    c = {axis: _weighted(h[i], parts) for i, (axis, parts) in enumerate(AXES.items())}
    return _apply_rules(c)


def describe(c: dict[str, int]) -> dict[str, str]:
    return {axis: AXES[axis][c[axis]].name for axis in AXES}


# --- rendering --------------------------------------------------------------
def render(c: dict[str, int], size: int | None = None, background: bool = True) -> str:
    p = build_palette(BASES[c["base"]], HIGHLIGHTS[c["highlight"]], TINTS[c["tint"]])
    head = HEADS[c["head"]]
    face = FACES[c["face"]]
    hm = head.meta
    cid = f"tah-{head.name}"  # same id => same shape, so duplicates across one page are harmless
    clip = f'<clipPath id="{cid}">{head.value("#000")}</clipPath>'

    eye_p = dict(p, eye=p[face.meta["eye"]], pupil=p[face.meta["pupil"]])
    shadow = f'<rect x="0" y="{hm["bottom"] - 11}" width="128" height="11" fill="{p["shade"]}"/>'
    face_svg = face.value(p)
    clipped = SLOTS["detail"][c["detail"]].value(p, hm) + shadow
    if face.meta.get("clip"):
        clipped += face_svg
        face_svg = ""

    svg = [
        f'<defs>{clip}</defs>',
        f'<rect width="{SIZE}" height="{SIZE}" fill="{p["bg"]}"/>' if background else "",
        BODIES[c["body"]].value(p),
        ANTENNAE[c["antenna"]].value(p),
        EARS[c["ears"]].value(p),
        head.value(p["body"]),
        f'<g clip-path="url(#{cid})">{clipped}</g>',
        face_svg,
        EYES[c["eyes"]].value(eye_p),
        MOUTHS[c["mouth"]].value(p),
    ]
    dims = f' width="{size}" height="{size}"' if size else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SIZE} {SIZE}"{dims}>'
            + "".join(svg) + "</svg>")


def avatar(seed: str, size: int | None = None, version: str | None = None) -> str:
    return render(choices_for(seed, version), size=size)


if __name__ == "__main__":
    import sys
    print(avatar(sys.argv[1] if len(sys.argv) > 1 else "jeff@example.com"))
