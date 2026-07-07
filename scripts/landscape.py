#!/usr/bin/env python3
"""Demonstrate resolving the rotor configuration from operative-geometry evidence.

Two modes:

    # Crib mode (default): encrypt a plaintext with a hidden config (no
    # plugboard), then show the possibility landscape collapse as more crib
    # letters are used.
    python scripts/landscape.py --rotors III I IV --positions HCT \
        --plain DIEWEHRMACHTGREIFTAN

    # Geometry mode: build the full injective index for a reflector and
    # confirm zero collisions (this is the ~10^6-entry precompute; ~40s).
    python scripts/landscape.py --build-index --reflector B
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from enigma.landscape import (
    RotorLandscape,
    m3_triples,
    resolve_crib,
    resolution_curve,
    stepping_events,
    geometry_differential,
)
from enigma.schematic import Config
from enigma.simulator import Enigma


def _s(seq) -> str:
    return "".join(chr(x + 65) for x in seq)


def crib_demo(args) -> None:
    triple = tuple(args.rotors)
    start = tuple(ord(c) - 65 for c in args.positions.upper())
    machine = Enigma(rotor_names=triple, reflector_name=args.reflector,
                     positions=list(start), ring_settings=[0, 0, 0])
    plain = "".join(c for c in args.plain.upper() if "A" <= c <= "Z")
    if not plain:
        raise SystemExit("provide --plain with some A-Z letters")
    cipher = machine.encrypt(plain)

    print(f"Hidden config : rotors={'-'.join(triple)}  reflector={args.reflector}  "
          f"start={args.positions.upper()}  rings=AAA  plugboard=identity")
    print(f"Plaintext     : {plain}")
    print(f"Ciphertext    : {cipher}")
    print(f"Search space  : {len(m3_triples())} triples x 26^3 = "
          f"{len(m3_triples()) * 26**3:,} configs\n")

    print("Possibility-landscape collapse (survivors as crib grows):")
    print("  k   survivors")
    t0 = time.time()
    curve = resolution_curve(plain, cipher, reflector=args.reflector)
    for k, n in curve:
        print(f"  {k:2d}  {n:9,d}")
    print(f"  ({time.time() - t0:.1f}s)\n")

    final = resolve_crib(plain, cipher, reflector=args.reflector)
    if len(final) == 1:
        (tr, st), = final
        print(f"RESOLVED: rotors={'-'.join(tr)}  start={_s(st)}  "
              f"(matches hidden config: {tr == triple and st == start})")
    else:
        print(f"{len(final)} configs still consistent with the full crib "
              f"(need a turnover or more text to separate).")

    # Show how advancement imputes topology, for the true config.
    cfg = Config(rotor_names=triple, reflector_name=args.reflector,
                 start_positions=start)
    diff = geometry_differential(cfg, 8)
    print("\nGeometry differential (entries of E changing per step): "
          + " ".join(str(d) for d in diff[1:]))
    print("  -> ~26 every step: the right rotor conjugates the whole cascade.")
    evs = stepping_events(cfg, 8)
    print("Stepping:")
    for e in evs:
        tag = "  <-- middle turnover" if e["middle_stepped"] else ""
        print(f"  step {e['step']}: {e['positions']}  moved={''.join(sorted(e['moved']))}{tag}")


def build_index(args) -> None:
    print(f"Building injective landscape for reflector {args.reflector} "
          f"({len(m3_triples())} triples x 26^3)...")
    t0 = time.time()
    land = RotorLandscape(reflector=args.reflector).build()
    dt = time.time() - t0
    total = len(m3_triples()) * 26**3
    print(f"  configs enumerated : {total:,}")
    print(f"  distinct geometries: {len(land):,}")
    print(f"  collisions         : {land.collisions} "
          f"(cross-triple: {land.cross_triple_collisions})")
    print(f"  -> injective: {len(land) == total}   ({dt:.1f}s)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rotors", nargs=3, default=["III", "I", "IV"],
                    help="hidden rotor triple (default III I IV)")
    ap.add_argument("--reflector", default="B")
    ap.add_argument("--positions", default="HCT", help="hidden start positions")
    ap.add_argument("--plain", default="DIEWEHRMACHTGREIFTANMORGEN",
                    help="plaintext to encipher and then resolve")
    ap.add_argument("--build-index", action="store_true",
                    help="build the full injective geometry index and report collisions")
    args = ap.parse_args()

    if args.build_index:
        build_index(args)
    else:
        crib_demo(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
