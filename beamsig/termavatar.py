"""Render a beam's robot avatar in a terminal.

The browser extension shows a deterministic robot per beam UUID, which is a
genuinely good recognition aid: you learn a beam's face faster than you learn
32 hex digits. This brings the same robot to `git log` and `beamsig verify`.

The robot design is NOT reimplemented here. `extension/tools/avatar/
teleport_avatar.py` is the single source of truth; its `choices_for(seed)` is
the identity and its SVG is one rendering. We rasterise that SVG and emit a
second rendering. Reimplementing the look would guarantee the CLI and the
extension drift apart, and that file warns that touching the option lists
reshuffles every existing avatar.

Two backends, because terminals differ and -- more importantly -- because a
pager is in the way:

  blocks   Unicode half-blocks with 24-bit SGR colour. Just text and colour
           codes, so it survives a pipe, `less -R`, CI logs and `script`.
           This is the default.
  image    Real inline images: iTerm2's OSC 1337, or the kitty graphics
           protocol. Sharper, but only safe straight to a capable terminal.

Why `blocks` is the default even on a capable terminal: `git log` runs a
pager, and our output reaches it via git's own buffer. Neither git nor `less`
tracks the screen geometry of an inline image, so scrolling corrupts the
display. `less -R` is documented to handle colour sequences; anything else is
passed through with the cursor accounting left wrong. Images are therefore used
only when nothing is in the way, detected via GIT_PAGER_IN_USE and isatty().

Override with BEAMSIG_AVATAR=off|blocks|iterm|kitty|auto.
"""
import base64
import os
import struct
import sys
import zlib

BACKENDS = ("off", "blocks", "iterm", "kitty", "auto")


# --- locating the generator ------------------------------------------------

def _load_generator():
    """Import teleport_avatar from the repo, or None if unavailable."""
    path = os.environ.get("BEAMSIG_AVATAR_MODULE")
    if not path:
        home = os.environ.get("BEAMSIG_HOME") or os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(home, "extension", "tools", "avatar",
                            "teleport_avatar.py")
    if not os.path.exists(path):
        return None
    import importlib.util
    spec = importlib.util.spec_from_file_location("_beamsig_avatar", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def describe(seed: str):
    """The robot's parts, for a text-only summary. None if unavailable."""
    gen = _load_generator()
    if gen is None:
        return None
    try:
        return gen.describe(gen.choices_for(seed))
    except Exception:
        return None


def png_for(seed: str, size: int = 128):
    """PNG bytes of the beam's robot, or None if we cannot render one."""
    gen = _load_generator()
    if gen is None:
        return None
    try:
        import cairosvg
    except ImportError:
        return None
    try:
        # background=False: the robot comes out transparent so it can be
        # flattened onto whatever the terminal's background actually is. The
        # SVG's own light background would be a white card on a dark theme.
        svg = gen.render(gen.choices_for(seed), size=size, background=False)
        return cairosvg.svg2png(bytestring=svg.encode(),
                                output_width=size, output_height=size)
    except Exception:
        return None


# --- a minimal PNG reader, so `blocks` needs no extra dependency -----------

def _png_pixels(data: bytes):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    pos = 8
    width = height = depth = ctype = None
    idat = bytearray()
    palette = None
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctag = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if ctag == b"IHDR":
            width, height, depth, ctype = struct.unpack(">IIBB", body[:10])
            if struct.unpack(">B", body[12:13])[0]:
                raise ValueError("interlaced PNG unsupported")
        elif ctag == b"PLTE":
            palette = body
        elif ctag == b"IDAT":
            idat += body
        elif ctag == b"IEND":
            break
    if depth != 8:
        raise ValueError(f"unsupported bit depth {depth}")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[ctype]
    raw = zlib.decompress(bytes(idat))
    stride = width * channels
    out, prev = [], bytearray(stride)
    i = 0
    for _ in range(height):
        f = raw[i]
        line = bytearray(raw[i + 1:i + 1 + stride])
        i += 1 + stride
        if f == 1:
            for x in range(channels, stride):
                line[x] = (line[x] + line[x - channels]) & 0xFF
        elif f == 2:
            for x in range(stride):
                line[x] = (line[x] + prev[x]) & 0xFF
        elif f == 3:
            for x in range(stride):
                a = line[x - channels] if x >= channels else 0
                line[x] = (line[x] + ((a + prev[x]) >> 1)) & 0xFF
        elif f == 4:
            for x in range(stride):
                a = line[x - channels] if x >= channels else 0
                b = prev[x]
                c = prev[x - channels] if x >= channels else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[x] = (line[x] + pr) & 0xFF
        elif f != 0:
            raise ValueError(f"bad PNG filter {f}")
        row = []
        for x in range(width):
            px = line[x * channels:(x + 1) * channels]
            if ctype == 6:
                r, g, b, a = px
            elif ctype == 2:
                r, g, b, a = px[0], px[1], px[2], 255
            elif ctype == 4:
                r = g = b = px[0]
                a = px[1]
            elif ctype == 0:
                r = g = b = px[0]
                a = 255
            else:                                   # palette
                off = px[0] * 3
                r, g, b = palette[off], palette[off + 1], palette[off + 2]
                a = 255
            row.append((r, g, b, a))
        out.append(row)
        prev = line
    return width, height, out


# --- backends --------------------------------------------------------------

def blocks(seed: str, cols: int = 12, bg=(13, 17, 23)):
    """Half-block art: one text row per two pixel rows.

    Pure SGR, so it survives git's buffer, `less -R` and a plain pipe.
    """
    png = png_for(seed, size=max(16, cols * 2))
    if png is None:
        return None
    try:
        w, h, px = _png_pixels(png)
    except Exception:
        return None
    step = max(1, w // cols)
    lines = []
    for y in range(0, (h // step // 2) * step * 2, step * 2):
        parts = []
        for x in range(0, cols * step, step):
            top = px[min(y, h - 1)][min(x, w - 1)]
            bot = px[min(y + step, h - 1)][min(x, w - 1)]
            tr, tg, tb = _flatten(top, bg)
            br, bgn, bb = _flatten(bot, bg)
            parts.append(f"\x1b[38;2;{tr};{tg};{tb}m"
                         f"\x1b[48;2;{br};{bgn};{bb}m\u2580")
        lines.append("".join(parts) + "\x1b[0m")
    return lines


def _flatten(px, bg):
    r, g, b, a = px
    if a == 255:
        return r, g, b
    f = a / 255.0
    return (int(r * f + bg[0] * (1 - f)),
            int(g * f + bg[1] * (1 - f)),
            int(b * f + bg[2] * (1 - f)))


def iterm(seed: str, cells: int = 4):
    """iTerm2 / WezTerm inline image (OSC 1337)."""
    png = png_for(seed, size=128)
    if png is None:
        return None
    b64 = base64.b64encode(png).decode()
    return (f"\x1b]1337;File=inline=1;width={cells};height={cells};"
            f"preserveAspectRatio=1:{b64}\x07")


def kitty(seed: str, cells: int = 4):
    """kitty graphics protocol: PNG payload, chunked at 4096 base64 bytes."""
    png = png_for(seed, size=128)
    if png is None:
        return None
    b64 = base64.b64encode(png).decode()
    chunks = [b64[i:i + 4096] for i in range(0, len(b64), 4096)]
    out = []
    for n, chunk in enumerate(chunks):
        more = 1 if n < len(chunks) - 1 else 0
        if n == 0:
            out.append(f"\x1b_Ga=T,f=100,t=d,c={cells},r={cells},"
                       f"m={more};{chunk}\x1b\\")
        else:
            out.append(f"\x1b_Gm={more};{chunk}\x1b\\")
    return "".join(out)


# --- detection -------------------------------------------------------------

def detect(stream=None) -> str:
    """Pick a backend. Conservative: images only with nothing in the way."""
    forced = (os.environ.get("BEAMSIG_AVATAR") or "").strip().lower()
    if forced in BACKENDS and forced != "auto":
        return forced
    if os.environ.get("NO_COLOR"):
        return "off"

    stream = stream or sys.stdout
    piped = not getattr(stream, "isatty", lambda: False)()
    # git sets this when it has spawned a pager; our output is then buffered by
    # git and replayed through less, where an image's geometry is untracked.
    paged = os.environ.get("GIT_PAGER_IN_USE") == "true"

    if piped or paged:
        return "blocks"
    if os.environ.get("TERM") == "xterm-kitty" or os.environ.get("KITTY_WINDOW_ID"):
        return "kitty"
    if os.environ.get("TERM_PROGRAM") in ("iTerm.app", "WezTerm", "vscode"):
        return "iterm"
    if os.environ.get("KONSOLE_VERSION"):
        return "kitty"
    return "blocks"


def render(seed: str, backend: str = None, cols: int = 12, cells: int = 4):
    """Return a list of output lines for `seed`, or None."""
    backend = backend or detect()
    if backend == "off" or not seed:
        return None
    if backend == "blocks":
        return blocks(seed, cols=cols)
    if backend == "iterm":
        one = iterm(seed, cells=cells)
        return [one] if one else blocks(seed, cols=cols)
    if backend == "kitty":
        one = kitty(seed, cells=cells)
        return [one] if one else blocks(seed, cols=cols)
    return None


def side_by_side(avatar_lines, text_lines, gutter: int = 2):
    """Lay the robot to the left of a block of text.

    Width is counted in cells, not bytes: each half-block cell is one column
    however many bytes of SGR precede it.
    """
    if not avatar_lines:
        return list(text_lines)
    cells = avatar_lines[0].count("\u2580")
    if not cells:
        # An inline image, not half-blocks. The terminal advances the cursor by
        # the image's width on the first row only, so laying text alongside it
        # would overlap rows 2..n. There is no portable way to ask how many
        # cells it occupied, so stack instead of guessing.
        return list(avatar_lines) + list(text_lines)
    pad = " " * (cells + gutter)
    out = []
    for i in range(max(len(avatar_lines), len(text_lines))):
        left = avatar_lines[i] + " " * gutter if i < len(avatar_lines) else pad
        right = text_lines[i] if i < len(text_lines) else ""
        out.append(left + right)
    return out
