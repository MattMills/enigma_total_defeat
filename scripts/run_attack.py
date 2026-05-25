#!/usr/bin/env python3
"""CI smoke test: verify the attack pipeline works end-to-end.

Test 1: No-plugboard key recovery (attack → top result = correct key)
Test 2: Plugboard recovery (beam_swap_search → correct plaintext)
"""

import sys
import time

from enigma.attack import attack, beam_swap_search
from enigma.language import LanguageModel
from enigma.simulator import Enigma, Plugboard, fast_trajectory


def main() -> int:
    model = LanguageModel.german_military()
    ok = True

    print("=== Test 1: No-plugboard key recovery ===")
    plaintext = "DASWETTERISTHEUTESEHRGUTSTOPENDE"
    enc = Enigma(
        rotor_names=("I", "II", "III"), reflector_name="B",
        positions=[7, 11, 19], ring_settings=[0, 0, 0],
    )
    ciphertext = enc.encrypt(plaintext)

    t0 = time.time()
    results = attack(
        ciphertext, rotor_pool=("I", "II", "III"),
        reflector_names=("B",), rings=((0, 0, 0),), top_k=5,
    )
    elapsed = time.time() - t0

    if results and results[0].plaintext == plaintext:
        print(f"  PASS ({elapsed:.1f}s)")
    else:
        print(f"  FAIL")
        ok = False

    print("=== Test 2: Plugboard recovery (beam swap) ===")
    plaintext2 = "DASWETTERISTHEUTESEHRGUTUNDDIEMASCHINEFUNKTIONIERT"
    plug = Plugboard.from_pairs(["AB", "CD", "EF"])
    enc2 = Enigma(
        rotor_names=("I", "II", "III"), reflector_name="B",
        positions=[7, 11, 19], ring_settings=[0, 0, 0],
        plugboard=Plugboard(mapping=list(plug.mapping)),
    )
    ciphertext2 = enc2.encrypt(plaintext2)
    cipher2 = [ord(c) - 65 for c in ciphertext2]
    traj = fast_trajectory(("I", "II", "III"), "B", (7, 11, 19), (0, 0, 0), len(cipher2))

    t0 = time.time()
    score, found_plug, dec = beam_swap_search(cipher2, traj, model, rounds=5)
    elapsed = time.time() - t0
    found_text = "".join(chr(p + 65) for p in dec)

    if found_text == plaintext2:
        pairs = [(a, found_plug[a]) for a in range(26) if found_plug[a] > a]
        print(f"  PASS ({elapsed:.1f}s) plugboard: {' '.join(chr(a+65)+chr(b+65) for a,b in pairs)}")
    else:
        print(f"  FAIL: got {found_text[:30]}")
        ok = False

    print(f"\n{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
