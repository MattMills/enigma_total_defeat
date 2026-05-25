#!/usr/bin/env python3
"""Trace the full path topology of any Enigma configuration.

Usage:
  python scripts/trace_topology.py [OPTIONS] PLAINTEXT

Options:
  --rotors L,M,R         Rotor names (default: II,IV,V)
  --reflector NAME       Reflector (default: B)
  --positions LMR        Start positions as 3 letters (default: AAA)
  --rings LMR            Ring settings as 3 letters (default: AAA)
  --plugboard PAIRS      Space-separated pairs (default: none)
  --fourth ROTOR         Fourth rotor for M4 (Beta or Gamma)
  --fourth-pos P         Fourth rotor position letter (default: A)
  --fourth-ring R        Fourth rotor ring letter (default: A)
  --max N                Max positions to display (default: all)
  --compact              Compact output (signal flow matrix only)
  --historical MSG_ID    Use a historical message (barbarossa-1, etc.)

Examples:
  # Simple M3
  python scripts/trace_topology.py --rotors I,II,III --reflector B \
    --positions AAA HELLOWORLD

  # Barbarossa configuration (most secure M3)
  python scripts/trace_topology.py --rotors II,IV,V --reflector B \
    --positions BLA --rings BUL \
    --plugboard "AV BS CG DL FU HZ IN KM OW RX" \
    AUFKLXABTEILUNGXVONXKURTINOWAX

  # M4 Kriegsmarine (Scharnhorst key)
  python scripts/trace_topology.py --rotors II,IV,I --reflector B-thin \
    --positions JNA --rings AAV \
    --fourth Beta --fourth-pos V \
    --plugboard "AT BL DF GJ HM NW OP QY RZ VX" \
    VONVONJLOOKSJHFF

  # Historical message by ID
  python scripts/trace_topology.py --historical barbarossa-1

  # Compact mode for long messages
  python scripts/trace_topology.py --rotors II,IV,V --reflector B \
    --positions BLA --rings BUL --compact --max 20 \
    AUFKLXABTEILUNGXVONX
"""

import argparse
import sys

sys.path.insert(0, ".")

from enigma.path_topology import trace, render


def main():
    parser = argparse.ArgumentParser(
        description="Trace the full path topology of any Enigma configuration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("plaintext", nargs="?", default=None,
                        help="Plaintext to encrypt (A-Z only)")
    parser.add_argument("--rotors", default="II,IV,V",
                        help="Comma-separated rotor names L,M,R")
    parser.add_argument("--reflector", default="B",
                        help="Reflector name")
    parser.add_argument("--positions", default="AAA",
                        help="Start positions as letters")
    parser.add_argument("--rings", default="AAA",
                        help="Ring settings as letters")
    parser.add_argument("--plugboard", default="",
                        help="Space-separated plugboard pairs")
    parser.add_argument("--fourth", default=None,
                        help="Fourth rotor name (Beta/Gamma) for M4")
    parser.add_argument("--fourth-pos", default="A",
                        help="Fourth rotor position letter")
    parser.add_argument("--fourth-ring", default="A",
                        help="Fourth rotor ring letter")
    parser.add_argument("--max", type=int, default=None,
                        help="Max positions to display")
    parser.add_argument("--compact", action="store_true",
                        help="Compact output (matrix only)")
    parser.add_argument("--historical", default=None,
                        help="Use a historical message by ID")

    args = parser.parse_args()

    if args.historical:
        from enigma.messages import get_message
        msg = get_message(args.historical)
        if msg is None:
            from enigma.messages import MESSAGES
            ids = [m.id for m in MESSAGES]
            print(f"Unknown message ID: {args.historical}")
            print(f"Available: {', '.join(ids)}")
            sys.exit(1)

        if not msg.rotors:
            print(f"Message {msg.id} has no known key settings.")
            sys.exit(1)

        rotor_names = tuple(msg.rotors)
        reflector_name = msg.reflector
        positions = tuple(ord(c) - 65 for c in msg.initial_positions)
        ring_settings = tuple(ord(c) - 65 for c in msg.ring_settings)
        plug_pairs = msg.plugboard.split() if msg.plugboard else []
        fourth = msg.fourth_rotor or None
        fourth_pos = ord(msg.fourth_position) - 65 if msg.fourth_position else 0
        fourth_ring = 0

        if msg.known_plaintext:
            plaintext = "".join(c for c in msg.known_plaintext if "A" <= c <= "Z")
        else:
            ct = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
            print(f"No known plaintext for {msg.id}; tracing ciphertext as input")
            print(f"(decrypt mode: output will be the plaintext if key is correct)")
            plaintext = ct

        print(f"Historical message: {msg.id}")
        print(f"  Source: {msg.source}")
        print(f"  Date:   {msg.date}")
        print(f"  Type:   {msg.machine_type.value}")
        print()

    else:
        if args.plaintext is None:
            parser.print_help()
            sys.exit(1)

        plaintext = "".join(c for c in args.plaintext.upper() if "A" <= c <= "Z")
        if not plaintext:
            print("Error: plaintext must contain at least one letter A-Z")
            sys.exit(1)

        rotor_names = tuple(args.rotors.split(","))
        reflector_name = args.reflector
        positions = tuple(ord(c) - 65 for c in args.positions.upper())
        ring_settings = tuple(ord(c) - 65 for c in args.rings.upper())
        plug_pairs = args.plugboard.split() if args.plugboard else []
        fourth = args.fourth
        fourth_pos = ord(args.fourth_pos.upper()) - 65
        fourth_ring = ord(args.fourth_ring.upper()) - 65

    topo = trace(
        plaintext,
        rotor_names=rotor_names,
        reflector_name=reflector_name,
        positions=positions,
        ring_settings=ring_settings,
        plugboard_pairs=plug_pairs,
        fourth_rotor_name=fourth,
        fourth_position=fourth_pos,
        fourth_ring=fourth_ring,
    )

    if args.compact:
        layer_names = topo.layer_names()
        print(f"Machine: {'-'.join(rotor_names)} / {reflector_name}"
              f"{f' / {fourth}' if fourth else ''}")
        print(f"Positions: {''.join(chr(p+65) for p in positions)}  "
              f"Rings: {''.join(chr(r+65) for r in ring_settings)}  "
              f"Plugboard: {' '.join(plug_pairs) or '(none)'}")
        print(f"Plaintext:  {topo.plaintext[:70]}")
        print(f"Ciphertext: {topo.ciphertext[:70]}")
        print()

        n = args.max or topo.length
        header = "  t  PT  " + "  ".join(f"{ln[:7]:>7}" for ln in layer_names) + "  CT  step"
        print(header)
        print("  " + "-" * (len(header) - 2))
        for pos in topo.positions[:n]:
            pt = chr(pos.plaintext + 65)
            ct = chr(pos.ciphertext + 65)
            signals = "  ".join(f"{chr(ev.signal_out+65):>7}" for ev in pos.events)
            print(f"  {pos.t:2d}  {pt}   {signals}  {ct}  {pos.step.trigger}")
    else:
        print(render(topo, max_positions=args.max))


if __name__ == "__main__":
    main()
