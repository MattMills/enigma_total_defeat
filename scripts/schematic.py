#!/usr/bin/env python3
"""Print / export the schematic breakdown of rotor action.

Examples
--------
    # ASCII schematic for M3 rotors I-II-III, reflector B, first letter:
    python scripts/schematic.py --rotors I II III

    # Show a later position and dump the first 20 steps to JSON:
    python scripts/schematic.py --rotors II IV V --step 5 \
        --json out.json --length 20

    # M4 with a Greek rotor:
    python scripts/schematic.py --rotors I II III --reflector B-thin \
        --fourth Beta --fourth-pos A
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from enigma.schematic import Config, render_stage_table, to_dict


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rotors", nargs=3, metavar=("L", "M", "R"),
                    default=["I", "II", "III"],
                    help="left middle right rotor names (default I II III)")
    ap.add_argument("--reflector", default="B", help="reflector name (default B)")
    ap.add_argument("--rings", default="AAA", help="ring settings, 3 letters (default AAA)")
    ap.add_argument("--positions", default="AAA",
                    help="start positions, 3 letters (default AAA)")
    ap.add_argument("--step", type=int, default=0,
                    help="which encryption step to display (default 0)")
    ap.add_argument("--fourth", default=None, help="4th (Greek) rotor: Beta or Gamma")
    ap.add_argument("--fourth-pos", default="A", help="4th rotor position (default A)")
    ap.add_argument("--fourth-ring", default="A", help="4th rotor ring (default A)")
    ap.add_argument("--json", default=None, metavar="PATH",
                    help="also write a JSON dump to PATH")
    ap.add_argument("--length", type=int, default=1,
                    help="number of steps to include in the JSON dump (default 1)")
    args = ap.parse_args()

    cfg = Config.from_letters(
        rotor_names=tuple(args.rotors),
        reflector_name=args.reflector,
        rings=args.rings,
        positions=args.positions,
        fourth_rotor_name=args.fourth,
        fourth_position=args.fourth_pos,
        fourth_ring=args.fourth_ring,
    )

    print(render_stage_table(cfg, step=args.step))

    if args.json:
        data = to_dict(cfg, length=args.length)
        Path(args.json).write_text(json.dumps(data, indent=2))
        print(f"\nWrote {args.length}-step JSON dump to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
