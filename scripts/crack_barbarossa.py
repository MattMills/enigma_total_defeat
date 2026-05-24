#!/usr/bin/env python3
"""End-to-end ciphertext-only crack of Operation Barbarossa message.

Uses the message database — no inline ciphertext strings.
Three phases: IC filter → multi-start plugboard → pair-level repair.
"""

import math
import random
import time
from itertools import combinations

from enigma.language import LanguageModel, index_of_coincidence
from enigma.messages import get_message
from enigma.simulator import fast_trajectory


def decrypt(cipher, traj, plug):
    return [plug[traj[t][plug[cipher[t]]]] for t in range(len(cipher))]


def _pm(letters):
    """All perfect matchings of a list of letters."""
    if len(letters) == 0:
        yield []
        return
    if len(letters) == 2:
        yield [(letters[0], letters[1])]
        return
    first = letters[0]
    rest = letters[1:]
    for i, partner in enumerate(rest):
        remaining = rest[:i] + rest[i + 1:]
        for sub in _pm(remaining):
            yield [(first, partner)] + sub


def main():
    model = LanguageModel.german_military()
    msg = get_message("barbarossa-1")
    ct_str = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
    cipher = [ord(c) - 65 for c in ct_str]
    L = len(cipher)

    rotor_names = tuple(msg.rotors)
    reflector = msg.reflector
    rings = tuple(ord(c) - 65 for c in msg.ring_settings)

    print("=" * 70)
    print("ENIGMA TOTAL DEFEAT — Barbarossa Ciphertext-Only Attack")
    print("=" * 70)
    print(f"Message:   {msg.id} ({L} chars)")
    print(f"Known key: {'-'.join(rotor_names)} / {reflector} / rings={''.join(msg.ring_settings)}")
    print(f"Unknown:   position (17,576 options) + plugboard (10 pairs)")
    print()

    # === PHASE 1: IC filter ===
    print("--- Phase 1: IC-filtered position search ---")
    t0 = time.time()
    ic_scores = []
    for pl in range(26):
        for pm in range(26):
            for pr in range(26):
                traj = fast_trajectory(rotor_names, reflector, (pl, pm, pr), rings, L)
                dec = [traj[t][cipher[t]] for t in range(L)]
                ic = index_of_coincidence(dec)
                ic_scores.append((ic, (pl, pm, pr)))
    ic_scores.sort(reverse=True)
    survivors = [pos for _, pos in ic_scores[:600]]
    phase1_time = time.time() - t0

    true_pos = tuple(ord(c) - 65 for c in msg.initial_positions)
    true_rank = next(i for i, (_, p) in enumerate(ic_scores) if p == true_pos)
    print(f"  {phase1_time:.1f}s — top 600 of 17,576")
    print(f"  True position {msg.initial_positions} rank: #{true_rank + 1}")

    # === PHASE 2: Multi-start plugboard hill climb ===
    print(f"\n--- Phase 2: Multi-start plugboard ({len(survivors)} trajectories) ---")
    rng = random.Random(42)
    t0 = time.time()
    phase2_results = []

    for si, pos in enumerate(survivors):
        traj = fast_trajectory(rotor_names, reflector, pos, rings, L)
        best_score = float("-inf")
        best_plug = list(range(26))

        for _ in range(20):
            letters = list(range(26))
            rng.shuffle(letters)
            plug = list(range(26))
            for i in range(0, 2 * rng.randint(5, 13), 2):
                plug[letters[i]] = letters[i + 1]
                plug[letters[i + 1]] = letters[i]

            dec = decrypt(cipher, traj, plug)
            score = model.score(dec)

            improved = True
            while improved:
                improved = False
                for a in range(26):
                    for b in range(a + 1, 26):
                        np = list(plug)
                        oa, ob = plug[a], plug[b]
                        np[oa] = oa; np[ob] = ob; np[a] = a; np[b] = b
                        np[a] = b; np[b] = a
                        ns = model.score(decrypt(cipher, traj, np))
                        if ns > score + 0.001:
                            score = ns; plug = np; improved = True; break
                    if improved:
                        break

            if score > best_score:
                best_score = score
                best_plug = list(plug)

        phase2_results.append((best_score, pos, best_plug))
        if (si + 1) % 100 == 0:
            phase2_results.sort(reverse=True)
            print(f"  {si+1}/{len(survivors)} ({time.time()-t0:.0f}s) "
                  f"best={phase2_results[0][0]:.3f} "
                  f"pos={''.join(chr(p+65) for p in phase2_results[0][1])}")

    phase2_results.sort(reverse=True)
    phase2_time = time.time() - t0
    print(f"  Phase 2: {phase2_time:.1f}s")

    # === PHASE 3: Pair-level repair on top results ===
    print(f"\n--- Phase 3: Pair-level repair ---")
    t0 = time.time()
    final_best = float("-inf")
    final_result = None

    for ri, (p2_score, pos, plug) in enumerate(phase2_results[:5]):
        traj = fast_trajectory(rotor_names, reflector, pos, rings, L)
        pairs = [(a, plug[a]) for a in range(26) if plug[a] > a]

        # Try removing each pair individually, replacing with best alternative
        current_score = p2_score
        current_plug = list(plug)
        for _ in range(5):  # up to 5 repair rounds
            improved = False
            for remove_idx in range(len(pairs)):
                keep = [p for i, p in enumerate(pairs) if i != remove_idx]
                bp = list(range(26))
                for a, b in keep:
                    bp[a] = b; bp[b] = a
                freed = [a for a in range(26) if bp[a] == a]
                for a, b in combinations(freed, 2):
                    p = list(bp); p[a] = b; p[b] = a
                    s = model.score(decrypt(cipher, traj, p))
                    if s > current_score + 0.001:
                        current_score = s
                        current_plug = list(p)
                        pairs = [(x, p[x]) for x in range(26) if p[x] > x]
                        improved = True
                        break
                if improved:
                    break
            if not improved:
                break

        dec = decrypt(cipher, traj, current_plug)
        score = model.score(dec)
        if score > final_best:
            final_best = score
            final_result = (score, pos, current_plug, dec)

    phase3_time = time.time() - t0
    print(f"  Phase 3: {phase3_time:.1f}s")

    # === OUTPUT ===
    if final_result:
        score, pos, plug, dec = final_result
        pairs = [(a, plug[a]) for a in range(26) if plug[a] > a]
        plaintext = "".join(chr(p + 65) for p in dec)

        total = phase1_time + phase2_time + phase3_time
        print(f"\n{'=' * 70}")
        print(f"RESULT ({total:.0f}s total)")
        print(f"{'=' * 70}")
        print(f"Rotors:    {'-'.join(rotor_names)}")
        print(f"Reflector: {reflector}")
        print(f"Position:  {''.join(chr(p+65) for p in pos)} "
              f"({'CORRECT' if pos == true_pos else 'WRONG, true=' + msg.initial_positions})")
        print(f"Rings:     {''.join(chr(r+65) for r in rings)}")
        print(f"Plugboard: {' '.join(chr(a+65)+chr(b+65) for a,b in pairs)}")
        if msg.plugboard:
            true_set = set()
            for p in msg.plugboard.split():
                a, b = ord(p[0]) - 65, ord(p[1]) - 65
                true_set.add((min(a, b), max(a, b)))
            found_set = {(min(a, b), max(a, b)) for a, b in pairs}
            n_correct = len(found_set & true_set)
            print(f"           ({n_correct}/{len(true_set)} correct, true: {msg.plugboard})")
        print(f"Score:     {score:.3f}")
        print(f"\nPLAINTEXT:")
        for i in range(0, len(plaintext), 50):
            print(f"  {plaintext[i:i+50]}")

        if msg.known_plaintext:
            known = "".join(c for c in msg.known_plaintext if "A" <= c <= "Z")
            match = sum(a == b for a, b in zip(plaintext, known))
            print(f"\nMatch with known plaintext: {match}/{len(known)} ({match*100//len(known)}%)")


if __name__ == "__main__":
    main()
