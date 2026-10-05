"""Regenerate extension/test/avatar-golden.json from teleport_avatar.py.

    python3 extension/tools/avatar/make-golden.py

The JS port in src/lib/avatar.js must reproduce these SVGs byte-for-byte.
"""
import json
import random
import sys
import uuid
from pathlib import Path

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import teleport_avatar as ta  # noqa: E402

rng = random.Random(7)
seeds = ["jeff@example.com", "  Jeff@Example.com ", "1786bcd6-0000-4000-8000-000000000000", "", "tomás@goteleport.com"]
seeds += [str(uuid.UUID(int=rng.getrandbits(128), version=4)) for _ in range(120)]

out = {"version": ta.VERSION, "cases": [{"seed": s, "svg": ta.avatar(s, 24)} for s in seeds]}
dest = here.parent.parent / "test" / "avatar-golden.json"
dest.write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n")
print(f"wrote {len(seeds)} cases to {dest}")
