#!/usr/bin/env python3
"""End-to-end ciphertext-only crack of the Operation Barbarossa message.

Restores the working attack (position + plugboard from ciphertext alone,
rotors/reflector/rings known) using enigma.defeat:

    Phase 1  IC filter over 26^3 positions -> top 600      (~31s)
    Phase 2  multi-start hill-climb identifies the trajectory (~9min)
    Phase 3  beam_swap recovers the full plugboard + plaintext (2s)

Run:  PYTHONPATH=. python scripts/crack_barbarossa.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from enigma.defeat import crack_ciphertext_only
from enigma.language import LanguageModel
from enigma.messages import get_message


def main() -> int:
    model = LanguageModel.german_military()
    msg = get_message("barbarossa-1")
    ct = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
    rotors = tuple(msg.rotors)
    reflector = msg.reflector
    rings = tuple(ord(c) - 65 for c in msg.ring_settings)

    print("=" * 70)
    print("ENIGMA TOTAL DEFEAT — Barbarossa, ciphertext-only")
    print("=" * 70)
    print(f"Message:  {msg.id} ({len(ct)} chars)")
    print(f"Known:    rotors {'-'.join(rotors)} / reflector {reflector} / "
          f"rings {msg.ring_settings}")
    print(f"Unknown:  position (17,576) + plugboard (10 pairs), from ciphertext only")
    print()

    result = crack_ciphertext_only(
        ct, rotors, reflector, rings, model=model,
        ic_survivors=600, hill_restarts=20, beam_rounds=10, beam_width=50,
    )

    true_pos = "".join(msg.initial_positions)
    got_pos = "".join(chr(p + 65) for p in result.position)
    print("=" * 70)
    print(f"RESULT ({result.elapsed:.0f}s)")
    print("=" * 70)
    print(f"Position:  {got_pos}  "
          f"({'CORRECT' if got_pos == true_pos else 'WRONG, true=' + true_pos})"
          f"  [IC rank #{(result.ic_rank or 0) + 1}]")
    print(f"Plugboard: {result.plug_str()}")
    if msg.plugboard:
        found = {(min(a, b), max(a, b)) for a, b in result.plug_pairs()}
        true = {(min(ord(p[0]) - 65, ord(p[1]) - 65),
                 max(ord(p[0]) - 65, ord(p[1]) - 65)) for p in msg.plugboard.split()}
        print(f"           ({len(found & true)}/{len(true)} correct, "
              f"true: {msg.plugboard})")
    print(f"Score:     {result.score:.4f}")
    print(f"\nPLAINTEXT:")
    for i in range(0, len(result.plaintext), 50):
        print(f"  {result.plaintext[i:i + 50]}")

    if msg.known_plaintext:
        known = "".join(c for c in msg.known_plaintext if "A" <= c <= "Z")
        match = sum(a == b for a, b in zip(result.plaintext, known))
        print(f"\nMatch: {match}/{len(known)} ({match * 100 // len(known)}%)")
        return 0 if match == len(known) else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
