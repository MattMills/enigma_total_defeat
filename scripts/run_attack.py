#!/usr/bin/env python3
"""Demo: encrypt a German message and recover the key from ciphertext alone.

Used by CI to smoke-test the full pipeline end-to-end. Runs with a tightly
constrained rotor pool/reflector/ring to stay well under a minute.
"""

from __future__ import annotations

import sys
import time

from enigma.attack import attack
from enigma.simulator import Enigma


def main() -> int:
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
        top_k=20,
        early_prefix=8,
    )
    elapsed = time.time() - t0
    print(f"\nattack finished in {elapsed:.2f}s; returned {len(results)} candidates")
    if not results:
        print("FAIL: attack returned no candidates")
        return 1

    matched = [
        r for r in results
        if r.rotor_names == ("I", "II", "III")
        and r.reflector_name == "B"
        and tuple(r.positions) == (7, 11, 19)
    ]
    print(f"correct key in top-{len(results)}: {bool(matched)}")
    print("\nTop 5 results:")
    for r in results[:5]:
        print(" ", r)
    if not matched:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
