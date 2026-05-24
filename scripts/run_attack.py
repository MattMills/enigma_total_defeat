#!/usr/bin/env python3
"""Demo: encrypt a German message and recover the key from ciphertext alone.

Tests both no-plugboard attack (fast, direct) and plugboard attack
(beam swap search). Used by CI as a smoke test.
"""

from __future__ import annotations

import sys
import time

from enigma.attack import attack, beam_swap_search
from enigma.language import LanguageModel
from enigma.simulator import Enigma, Plugboard, fast_trajectory


def main() -> int:
    model = LanguageModel.german_military()
    ok = True

    # --- Test 1: no-plugboard recovery ---
    print("=== Test 1: No-plugboard key recovery ===")
    plaintext = "DASWETTERISTHEUTESEHRGUTSTOPENDE"
    cfg = dict(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=[7, 11, 19],
        ring_settings=[0, 0, 0],
    )
    enc = Enigma(**cfg)
    ciphertext = enc.encrypt(plaintext)
    print(f"plaintext  : {plaintext}")
    print(f"ciphertext : {ciphertext}")

    t0 = time.time()
    results = attack(
        ciphertext,
        rotor_pool=("I", "II", "III"),
        reflector_names=("B",),
        rings=((0, 0, 0),),
        top_k=5,
        early_prefix=8,
    )
    elapsed = time.time() - t0

    if results and results[0].plaintext == plaintext:
        print(f"PASS: recovered in {elapsed:.2f}s")
    else:
        print(f"FAIL: top result = {results[0].plaintext[:30] if results else 'none'}")
        ok = False

    # --- Test 2: plugboard recovery via beam swap ---
    print("\n=== Test 2: Plugboard recovery (beam swap) ===")
    plaintext2 = "DASWETTERISTHEUTESEHRGUTUNDDIEMASCHINEFUNKTIONIERT"
    plug = Plugboard.from_pairs(["AB", "CD", "EF"])
    enc2 = Enigma(
        plugboard=Plugboard(mapping=list(plug.mapping)), **cfg
    )
    ciphertext2 = enc2.encrypt(plaintext2)
    cipher2 = [ord(c) - 65 for c in ciphertext2]
    traj = fast_trajectory(("I", "II", "III"), "B", (7, 11, 19), (0, 0, 0), len(cipher2))

    t0 = time.time()
    score, found_plug, dec = beam_swap_search(cipher2, traj, model, rounds=5)
    elapsed = time.time() - t0
    found_text = "".join(chr(p + 65) for p in dec)

    if found_text == plaintext2:
        print(f"PASS: recovered plugboard in {elapsed:.2f}s")
        pairs = [(a, found_plug[a]) for a in range(26) if found_plug[a] > a]
        print(f"  plugboard: {' '.join(chr(a+65)+chr(b+65) for a,b in pairs)}")
    else:
        print(f"FAIL: got {found_text[:30]}")
        ok = False

    print(f"\n{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
