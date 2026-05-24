#!/usr/bin/env python3
"""End-to-end ciphertext-only crack of Operation Barbarossa.

Uses message database. Three phases:
  Phase 1: IC filter (17,576 → top 600 positions)
  Phase 2: beam swap plugboard search on each survivor
  Phase 3: report best result

Each phase uses proper library functions from enigma.attack.
"""

import time

from enigma.attack import beam_swap_search, _sorted_chi_squared
from enigma.language import LanguageModel, index_of_coincidence
from enigma.messages import get_message
from enigma.simulator import fast_trajectory


def main():
    model = LanguageModel.german_military()
    msg = get_message("barbarossa-1")
    ct_str = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
    cipher = [ord(c) - 65 for c in ct_str]
    L = len(cipher)

    rotor_names = tuple(msg.rotors)
    reflector = msg.reflector
    rings = tuple(ord(c) - 65 for c in msg.ring_settings)
    true_pos = tuple(ord(c) - 65 for c in msg.initial_positions)

    print("=" * 70)
    print("ENIGMA TOTAL DEFEAT — Barbarossa Ciphertext-Only Attack")
    print("=" * 70)
    print(f"Message:   {msg.id} ({L} chars)")
    print(f"Known:     rotors={'-'.join(rotor_names)}, refl={reflector}, rings={msg.ring_settings}")
    print(f"Unknown:   position (17,576), plugboard (10 pairs)")
    print()

    # === Phase 1: IC filter ===
    print("Phase 1: IC-filtered position search")
    t0 = time.time()
    ic_scores = []
    for pl in range(26):
        for pm in range(26):
            for pr in range(26):
                traj = fast_trajectory(rotor_names, reflector, (pl, pm, pr), rings, L)
                dec = [traj[t][cipher[t]] for t in range(L)]
                ic_scores.append((index_of_coincidence(dec), (pl, pm, pr)))
    ic_scores.sort(reverse=True)
    n_survivors = 600
    survivors = [pos for _, pos in ic_scores[:n_survivors]]
    phase1_time = time.time() - t0

    true_rank = next(i for i, (_, p) in enumerate(ic_scores) if p == true_pos)
    print(f"  {phase1_time:.1f}s — kept {n_survivors} of 17,576")
    print(f"  True position {msg.initial_positions}: rank #{true_rank + 1}")

    # === Phase 2: beam swap on each survivor ===
    print(f"\nPhase 2: Beam swap plugboard search ({len(survivors)} trajectories)")
    t0 = time.time()
    results = []

    for si, pos in enumerate(survivors):
        traj = fast_trajectory(rotor_names, reflector, pos, rings, L)
        score, plug, dec = beam_swap_search(
            cipher, traj, model, beam_width=50, rounds=3,
        )
        results.append((score, pos, plug, dec))

        if (si + 1) % 100 == 0:
            results.sort(reverse=True)
            elapsed = time.time() - t0
            best_pos = results[0][1]
            print(f"  {si+1}/{len(survivors)} ({elapsed:.0f}s) "
                  f"best={results[0][0]:.3f} pos={''.join(chr(p+65) for p in best_pos)}")

    results.sort(reverse=True)
    phase2_time = time.time() - t0
    print(f"  Phase 2: {phase2_time:.1f}s")

    # === Output ===
    best_score, best_pos, best_plug, best_dec = results[0]
    pairs = [(a, best_plug[a]) for a in range(26) if best_plug[a] > a]
    plaintext = "".join(chr(p + 65) for p in best_dec)
    total = phase1_time + phase2_time

    print(f"\n{'=' * 70}")
    print(f"RESULT ({total:.0f}s)")
    print(f"{'=' * 70}")
    print(f"Rotors:    {'-'.join(rotor_names)}")
    print(f"Reflector: {reflector}")
    print(f"Position:  {''.join(chr(p+65) for p in best_pos)} "
          f"({'CORRECT' if best_pos == true_pos else 'true=' + msg.initial_positions})")
    print(f"Rings:     {msg.ring_settings}")
    print(f"Plugboard: {' '.join(chr(a+65)+chr(b+65) for a,b in pairs)}")

    if msg.plugboard:
        true_set = set()
        for p in msg.plugboard.split():
            a, b = ord(p[0]) - 65, ord(p[1]) - 65
            true_set.add((min(a, b), max(a, b)))
        found_set = {(min(a, b), max(a, b)) for a, b in pairs}
        print(f"           ({len(found_set & true_set)}/{len(true_set)} correct)")

    print(f"Score:     {best_score:.3f}")
    print(f"\nPLAINTEXT:")
    for i in range(0, len(plaintext), 50):
        print(f"  {plaintext[i:i+50]}")

    if msg.known_plaintext:
        known = "".join(c for c in msg.known_plaintext if "A" <= c <= "Z")
        match = sum(a == b for a, b in zip(plaintext, known))
        print(f"\nMatch: {match}/{min(len(plaintext), len(known))} "
              f"({match * 100 // min(len(plaintext), len(known))}%)")


if __name__ == "__main__":
    main()
