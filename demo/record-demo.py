#!/usr/bin/env python3
"""Generate asciinema v2 recordings of a beamsig session.

Two loops, written as separate .cast files so each can become its own GIF:

  beamsig-install.cast   ./main.sh <beam>, then tsh beams ssh, then prove the
                         git config landed
  beamsig-commit.cast    make a commit, inspect the signature with git log

The transcripts are reconstructed, not captured. The text is copied from real
runs against beams clever-nebula and vapor-jet, but a live recording would
spend about three minutes on apt and pip output that nobody wants to watch in a
loop. Timings are chosen for readability.

Usage:
    ./record-demo.py                 write both .cast files here
    ./record-demo.py --outdir DIR
    ./record-demo.py --play install  render to this terminal to preview
    ./record-demo.py --play commit
    ./record-demo.py --ascii         use '$' instead of the chevron prompt

Turn them into GIFs with agg (https://github.com/asciinema/agg):
    agg --theme asciinema beamsig-install.cast beamsig-install.gif
or play them with:
    asciinema play beamsig-install.cast
"""
import argparse
import json
import os
import random
import sys
import time

WIDTH = 104
HEIGHT = 28

# --- palette --------------------------------------------------------------
R = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"


def fg(n):
    return f"\x1b[38;5;{n}m"


CYAN, GREEN, YELLOW, BLUE, MAGENTA, GREY, RED, ORANGE = (
    fg(44), fg(78), fg(179), fg(75), fg(176), fg(245), fg(203), fg(215))

# git's own colouring for `git log`
GIT_COMMIT = "\x1b[33m"


class Cast:
    """An asciinema v2 recording."""

    def __init__(self, title, width=WIDTH, height=HEIGHT, seed=7):
                                            # deterministic typing jitter, so
                                            # regenerating does not churn files
        self.rng = random.Random(seed)
        self.t = 0.0
        self.events = []
        self.header = {
            "version": 2,
            "width": width,
            "height": height,
            "timestamp": 1791220000,
            "title": title,
            "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
        }

    def wait(self, seconds):
        self.t += seconds
        return self

    def write(self, text):
        if text:
            self.events.append([round(self.t, 3), "o", text])
        return self

    def line(self, text="", pause=0.05):
        self.write(text + "\r\n")
        return self.wait(pause)

    def lines(self, block, pause=0.05):
        for ln in block.strip("\n").split("\n"):
            self.line(ln, pause)
        return self

    def prompt(self, text):
        return self.write(text).wait(0.5)

    def type(self, cmd, cps=24):
        """Type a command a character at a time, with human-ish jitter."""
        for ch in cmd:
            self.write(ch)
            self.wait(self.rng.uniform(0.45, 1.8) / cps)
        self.wait(0.45)
        return self.write("\r\n")

    def dump(self, path):
        with open(path, "w") as f:
            f.write(json.dumps(self.header) + "\n")
            for e in self.events:
                f.write(json.dumps(e) + "\n")
        return path

    def play(self):
        """Replay to the real terminal, for previewing."""
        last = 0.0
        for at, _, data in self.events:
            time.sleep(max(0.0, at - last))
            last = at
            sys.stdout.write(data)
            sys.stdout.flush()
        sys.stdout.write(R + "\n")


# --- prompts --------------------------------------------------------------

def prompts(ascii_only):
    chevron = "$" if ascii_only else "\u276f"
    laptop = (f"{BOLD}{CYAN}jeff{R}{GREY}@{R}{BOLD}{BLUE}laptop{R}"
              f"{GREY}:{R}{MAGENTA}~/beamsig{R} {GREEN}{chevron}{R} ")
    beam = (f"{BOLD}{YELLOW}beams{R}{GREY}@{R}{BOLD}{ORANGE}vapor-jet{R}"
            f"{GREY}:{R}{MAGENTA}~/work{R} {GREEN}{chevron}{R} ")
    return laptop, beam


# --- loop 1: install ------------------------------------------------------

def build_install(ascii_only=False):
    laptop, beam = prompts(ascii_only)
    c = Cast("beamsig: install onto a Beam")

    c.wait(0.8).prompt(laptop).type("./main.sh vapor-jet")
    c.wait(0.3)
    c.lines(f"""
{GREY}Setting up Beam: vapor-jet{R}
{GREY}Waiting for SSH to become ready...{R}
{GREY}SSH is ready.{R}
""", pause=0.35)
    c.lines(f"""
{GREY}Packing the checkout...{R}
{GREY}Packed 83769 bytes.{R}
{GREY}Copying the installer and the beamsig tree...{R}
{GREY}Running beamsig setup on the Beam...{R}
""", pause=0.3)
    c.wait(0.4).line()
    c.line(f"Configuring beamsig for beam {BOLD}vapor-jet{R} "
           f"{GREY}(8bba9461-0638-4a00-9752-c9064f9d832f){R}")
    c.line()
    # The real run prints a lot more here. Keep the shape, skip the noise.
    c.lines(f"""
{BOLD}== installing requirements =={R}
{BOLD}== generating hardware key agent gRPC stubs =={R}
{BOLD}== pinning Teleport SSH user CAs =={R}
""", pause=0.5)
    c.line(f"   {GREY}~/.config/beamsig/trusted/jeff.beams.sh.ca{R}")
    c.line(f"   {GREY}SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU{R}")
    c.wait(0.3)
    c.line(f"{BOLD}== writing ~/.gitconfig =={R}").wait(0.5)
    c.line()
    c.line("Verifying end to end...").wait(1.1)
    c.line(f"{GREEN}Signed and verified as beam-8bba9461-0638-4a00-9752-c9064f9d832f{R}")
    c.wait(0.5).line()
    c.line(f"{BOLD}{GREEN}beamsig is ready.{R} "
           f"Connect with: {BOLD}tsh beams ssh vapor-jet{R}")
    c.wait(1.4)

    # hop onto the beam
    c.prompt(laptop).type("tsh beams ssh vapor-jet")
    c.wait(1.0)
    c.line(f"{GREY}Connected to vapor-jet (us-east-1). Expires in 23 hours.{R}")
    c.wait(0.6)

    # prove the install actually took effect
    c.prompt(beam).type("git config --global gpg.ssh.program")
    c.wait(0.4)
    c.line(f"{BOLD}{GREEN}/home/beams/.beamsig/bin/git-beamsig-keygen{R}")
    c.wait(0.9)
    c.prompt(beam).type("git config --global commit.gpgsign")
    c.wait(0.3)
    c.line(f"{BOLD}{GREEN}true{R}")
    c.wait(0.9)
    c.prompt(beam).type("beamsig trust --list")
    c.wait(0.4)
    c.line(f"{GREY}trust store: ~/.config/beamsig/trusted{R}")
    c.line(f"  {BOLD}jeff.beams.sh{R}  "
           f"{GREY}SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU{R}")
    c.wait(0.6)
    c.prompt(beam)
    c.wait(2.6)                            # breathing room before the loop
    return c


# --- loop 2: commit and inspect ------------------------------------------

def build_commit(ascii_only=False):
    _, beam = prompts(ascii_only)
    c = Cast("beamsig: sign a commit and inspect it")

    c.wait(0.8).prompt(beam).type('git commit -am "Tune the retry backoff"')
    c.wait(0.7)
    c.line(f"[main {GIT_COMMIT}9f3c1ad{R}] Tune the retry backoff")
    c.line(" 1 file changed, 4 insertions(+), 2 deletions(-)")
    c.wait(1.3)

    c.prompt(beam).type("git log")
    c.wait(0.6)
    c.line(f"{GIT_COMMIT}commit 9f3c1ad4e0b7129a5c3e8f61d2ab40795e6c8b31{R}")
    c.wait(0.25)
    # Exactly what bin/git-beamsig-keygen prints, via gpg.ssh.program.
    c.line(f'{GREEN}Good "git" signature for '
           f'beam-8bba9461-0638-4a00-9752-c9064f9d832f{R}')
    c.line(f'{GREEN}  with ECDSA-CERT key SHA256:FVjefo3vO1p2S4vBcRzXBMESHU+n1s0SDom8mmEJSmw{R}')
    c.wait(0.2)
    for ln in [
        f"  {GREY}beam alias   {R} vapor-jet  {YELLOW}(self-reported, not in the certificate){R}",
        f"  {GREY}bot instance {R} c39a4a51-f694-47ef-abc2-bb96340810d7",
        f"  {GREY}delegation   {R} 53e4631e-b513-4fcb-8a2b-52f2d801a28c",
        f"  {GREY}roles        {R} editor, access, auditor, beam-user",
        f"  {GREY}owner        {R} owner@example.com  "
        f"{YELLOW}(impersonated, NOT the signer){R}",
        f"  {GREY}cert window  {R} 2026-10-05T17:16:27Z .. 2026-10-05T18:17:27Z",
        f"  {GREY}commit time  {R} 2026-10-05T17:19:52Z  {GREEN}in window{R}",
        f"  {GREY}signing key  {R} SHA256:FVjefo3vO1p2S4vBcRzXBMESHU+n1s0SDom8mmEJSmw",
        f"  {GREY}cluster      {R} jeff.beams.sh",
        f"  {GREY}teleport CA  {R} SHA256:c/8F7ipW3zBqBRe0Eau/ZBDU8hpFtLzZI9bH32668UU",
    ]:
        c.line(ln, pause=0.16)
    c.wait(0.3)
    c.line(f"Author: beam-8bba9461-0638-4a00-9752-c9064f9d832f "
           f"{GREY}<owner@example.com>{R}")
    c.line(f"Date:   Mon Oct 5 17:19:52 2026 +0000")
    c.line()
    c.line("    Tune the retry backoff")
    c.line()
    c.wait(1.6)

    # the one-line machine-readable form
    c.prompt(beam).type("git log -1 --format='%G? %GS'")
    c.wait(0.4)
    c.line(f"{BOLD}{GREEN}G{R} beam-8bba9461-0638-4a00-9752-c9064f9d832f")
    c.wait(1.0)

    # and that it is not merely cosmetic
    c.prompt(beam).type("beamsig verify-commit HEAD --beam-id 00000000-0000-0000-0000-000000000000")
    c.wait(0.6)
    c.line(f"{RED}BEAMSIG VERIFY FAILED{R}{GREY}: beam id mismatch: signature is from{R}")
    c.line(f"{GREY}  beam 8bba9461-0638-4a00-9752-c9064f9d832f,{R}")
    c.line(f"{GREY}  expected 00000000-0000-0000-0000-000000000000{R}")
    c.wait(0.5)
    c.prompt(beam)
    c.wait(2.6)
    return c


# --- loop 1b: install, abridged ------------------------------------------

def build_install_short(ascii_only=False):
    """A shorter, more legible install loop.

    Deliberately less faithful than build_install(). The beam-side setup output
    is collapsed into one summary line and the beam UUID is elided, which buys
    a 80x20 terminal instead of 104x28 -- so the same pixel width carries much
    larger text -- and about half the duration. Fidelity traded, in order:

      * the four `== ... ==` setup stages become one line;
      * the pinned CA path and fingerprint are dropped (they are in the full
        version, and a fingerprint is unreadable at a glance anyway);
      * `beam-8bba9461-...` is elided after the first component;
      * `git config commit.gpgsign` and `beamsig trust --list` are cut, leaving
        one proof that the install took effect;
      * `$HOME` is shown as `~` in the resulting path.

    Nothing misleading is added: every line still appears in a real run.
    """
    chevron = "$" if ascii_only else "\u276f"
    laptop = (f"{BOLD}{CYAN}jeff{R}{GREY}@{R}{BOLD}{BLUE}laptop{R}"
              f"{GREY}:{R}{MAGENTA}~/beamsig{R} {GREEN}{chevron}{R} ")
    beam = (f"{BOLD}{YELLOW}beams{R}{GREY}@{R}{BOLD}{ORANGE}vapor-jet{R}"
            f"{GREY}:{R}{MAGENTA}~{R} {GREEN}{chevron}{R} ")
    c = Cast("beamsig: install onto a Beam (short)", width=80, height=16)

    c.wait(0.7).prompt(laptop).type("./main.sh vapor-jet")
    c.wait(0.3)
    c.lines(f"""
{GREY}Setting up Beam: vapor-jet{R}
{GREY}SSH is ready. Packed 84 KB.{R}
{GREY}Running beamsig setup on the Beam...{R}
""", pause=0.4)
    c.wait(0.3).line()
    c.line(f"  {GREY}dependencies, Teleport CA pinned, ~/.gitconfig written{R}")
    c.wait(0.7).line()
    c.line("Verifying end to end...").wait(0.9)
    c.line(f"{GREEN}Signed and verified as beam-8bba9461-\u2026{R}")
    c.wait(0.4).line()
    c.line(f"{BOLD}{GREEN}beamsig is ready.{R}")
    c.wait(1.2)

    c.prompt(laptop).type("tsh beams ssh vapor-jet")
    c.wait(0.9)
    c.line(f"{GREY}Connected to vapor-jet.{R}")
    c.wait(0.5)
    c.prompt(beam).type("git config --global gpg.ssh.program")
    c.wait(0.4)
    c.line(f"{BOLD}{GREEN}~/.beamsig/bin/git-beamsig-keygen{R}")
    c.wait(0.6)
    c.prompt(beam)
    c.wait(2.2)
    return c


BUILDERS = {
    "install": build_install,
    "install-short": build_install_short,
    "commit": build_commit,
}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--outdir", default=os.path.dirname(os.path.abspath(__file__)))
    p.add_argument("--play", choices=sorted(BUILDERS))
    p.add_argument("--ascii", action="store_true",
                   help="use '$' rather than a chevron in the prompt")
    a = p.parse_args()

    if a.play:
        BUILDERS[a.play](a.ascii).play()
        return 0

    os.makedirs(a.outdir, exist_ok=True)
    for name, build in sorted(BUILDERS.items()):
        cast = build(a.ascii)
        path = os.path.join(a.outdir, f"beamsig-{name}.cast")
        cast.dump(path)
        dur = cast.events[-1][0] if cast.events else 0
        print(f"wrote {path}  ({len(cast.events)} events, {dur:.1f}s)")
    print("\npreview:  ./record-demo.py --play install")
    print("gif:      agg --theme asciinema beamsig-install.cast beamsig-install.gif")
    return 0


if __name__ == "__main__":
    sys.exit(main())
