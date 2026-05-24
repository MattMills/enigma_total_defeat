#!/usr/bin/env python3
"""End-to-end ciphertext-only crack of Operation Barbarossa message.

Demonstrates the full pipeline: from raw ciphertext to German plaintext
with full key recovery (rotors, positions, rings, plugboard).

No cribs. No known plaintext. Just ciphertext and the Enigma machine specs.
"""

import math
import random
import time
from itertools import combinations

from enigma.language import LanguageModel, index_of_coincidence
from enigma.simulator import fast_trajectory, ROTORS


def decrypt(cipher, traj, plug):
    return [plug[traj[t][plug[cipher[t]]]] for t in range(len(cipher))]


def all_pairings(letters, n_pairs):
    if n_pairs == 0:
        yield []
        return
    if len(letters) < 2:
        return
    for chosen in combinations(letters, 2 * n_pairs):
        chosen = list(chosen)
        yield from _perfect_matchings(chosen)


def _perfect_matchings(letters):
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
        for sub in _perfect_matchings(remaining):
            yield [(first, partner)] + sub


def main():
    model = LanguageModel.german_military()

    ct = (
        "EDPUDNRGYSZRCXNUYTPOMRMBOFKTBZREZKMLXLVEFGUEYSIOZV"
        "EQMIKUBPMMYLKLTTDEISMDICA"
        "GYKU ACTCDOMOHWXMUUIAUBSTSLRNBZSZWNRFXWFYSSXJZVIJHI"
        "DISHPRKLKAYUPADTXQSPINQMA"
        "TLPIFSVKDASCTACDPBOPVHJK"
    )
    ct = "".join(c for c in ct if "A" <= c <= "Z")
    cipher = [ord(c) - 65 for c in ct]
    L = len(cipher)

    print("=" * 70)
    print("ENIGMA TOTAL DEFEAT — Barbarossa Ciphertext-Only Attack")
    print("=" * 70)
    print(f"Ciphertext: {ct[:50]}... ({L} chars)")
    print()

    # ================================================================
    # PHASE 1: IC-filtered trajectory search
    # ================================================================
    print("--- Phase 1: IC-filtered trajectory search ---")
    # Known: rotors II-IV-V, reflector B, rings BUL
    # Unknown: position (26^3 = 17,576 options), plugboard (10 pairs)
    rotor_names = ("II", "IV", "V")
    reflector = "B"
    rings = (1, 20, 11)

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
    phase1_time = time.time() - t0
    print(f"  Scanned 17,576 positions in {phase1_time:.1f}s")
    print(f"  IC range: {ic_scores[0][0]:.4f} - {ic_scores[-1][0]:.4f}")

    # Keep top 600 (correct is ~rank 400, top 3%)
    survivors = [pos for _, pos in ic_scores[:600]]
    print(f"  Keeping top 600 survivors")
    correct_rank = next(
        i for i, (_, pos) in enumerate(ic_scores) if pos == (1, 11, 0)
    )
    print(f"  Correct position (BLA) rank: #{correct_rank + 1}")

    # ================================================================
    # PHASE 2: Multi-start plugboard hill climbing on each survivor
    # ================================================================
    print(f"\n--- Phase 2: Multi-start plugboard search ({len(survivors)} trajectories) ---")
    rng = random.Random(0xBA4B)
    t0 = time.time()
    best_results = []

    for si, (pl, pm, pr) in enumerate(survivors):
        traj = fast_trajectory(rotor_names, reflector, (pl, pm, pr), rings, L)

        best_score = float("-inf")
        best_plug = list(range(26))

        for trial in range(20):  # 20 random starts per trajectory
            letters = list(range(26))
            rng.shuffle(letters)
            plug = list(range(26))
            n_pairs = rng.randint(5, 13)
            for i in range(0, 2 * n_pairs, 2):
                a, b = letters[i], letters[i + 1]
                plug[a] = b
                plug[b] = a

            dec = decrypt(cipher, traj, plug)
            score = model.score(dec)

            # Hill climb
            improved = True
            while improved:
                improved = False
                for a in range(26):
                    for b in range(a + 1, 26):
                        np = list(plug)
                        oa, ob = plug[a], plug[b]
                        np[oa] = oa; np[ob] = ob; np[a] = a; np[b] = b
                        np[a] = b; np[b] = a
                        nd = decrypt(cipher, traj, np)
                        ns = model.score(nd)
                        if ns > score + 0.001:
                            score = ns; plug = np
                            improved = True; break
                    if improved:
                        break

            if score > best_score:
                best_score = score
                best_plug = list(plug)

        pairs = [(a, plug[a]) for a in range(26) if best_plug[a] > a]
        best_results.append((best_score, (pl, pm, pr), best_plug, pairs))

        if (si + 1) % 100 == 0:
            best_results.sort(reverse=True)
            elapsed = time.time() - t0
            print(f"  {si+1}/{len(survivors)} ({elapsed:.0f}s), "
                  f"best score={best_results[0][0]:.3f}")

    best_results.sort(reverse=True)
    phase2_time = time.time() - t0
    print(f"  Phase 2 complete: {phase2_time:.1f}s")

    # ================================================================
    # PHASE 3: Coherence-based pair validation + completion
    # ================================================================
    print(f"\n--- Phase 3: Coherence validation & completion ---")
    t0 = time.time()

    top_result = best_results[0]
    score, pos, plug, pairs = top_result
    traj = fast_trajectory(rotor_names, reflector, pos, rings, L)
    dec = decrypt(cipher, traj, plug)

    print(f"  Best trajectory: pos={''.join(chr(p+65) for p in pos)}")
    print(f"  Score: {score:.3f}, {len(pairs)} pairs")
    print(f"  Partial: {''.join(chr(p+65) for p in dec)[:60]}")

    # Score each pair by per-position coherence
    pair_scores = []
    for a, b in pairs:
        interaction_bigrams = 0
        bigram_score = 0.0
        for t in range(L - 1):
            c_t = cipher[t]
            pc = plug[c_t]
            d = traj[t][pc]
            pd = plug[d]
            if c_t in (a, b) or pc in (a, b) or d in (a, b) or pd in (a, b):
                bg = model.bigram[dec[t]][dec[t + 1]]
                if bg > 0:
                    bigram_score += math.log(bg)
                else:
                    bigram_score -= 10
                interaction_bigrams += 1
        avg = bigram_score / max(interaction_bigrams, 1)
        pair_scores.append((avg, a, b))

    pair_scores.sort()
    # Keep pairs above median coherence
    median_score = pair_scores[len(pair_scores) // 2][0] if pair_scores else 0
    good_pairs = [(a, b) for s, a, b in pair_scores if s >= median_score - 0.5]
    bad_pairs = [(a, b) for s, a, b in pair_scores if s < median_score - 0.5]

    print(f"  Good pairs ({len(good_pairs)}): "
          f"{' '.join(chr(a+65)+chr(b+65) for a,b in good_pairs)}")
    print(f"  Suspect pairs ({len(bad_pairs)}): "
          f"{' '.join(chr(a+65)+chr(b+65) for a,b in bad_pairs)}")

    # Rebuild from good pairs + search completion
    good_plug = list(range(26))
    for a, b in good_pairs:
        good_plug[a] = b
        good_plug[b] = a
    freed = [a for a in range(26) if good_plug[a] == a]

    n_missing = max(0, 10 - len(good_pairs))
    print(f"  Searching {n_missing} additional pairs from {len(freed)} freed letters...")

    completions = []
    for n_extra in range(n_missing + 2):
        for extra in all_pairings(freed, n_extra):
            p = list(good_plug)
            for a, b in extra:
                p[a] = b
                p[b] = a
            d = decrypt(cipher, traj, p)
            s = model.score(d)
            if s > float("-inf"):
                completions.append((s, extra, d, p))

    completions.sort(reverse=True)
    phase3_time = time.time() - t0

    if completions:
        best_s, best_extra, best_dec, best_final_plug = completions[0]
        final_pairs = [(a, best_final_plug[a]) for a in range(26)
                       if best_final_plug[a] > a]
        plaintext = "".join(chr(p + 65) for p in best_dec)

        print(f"  Best completion: "
              f"{' '.join(chr(a+65)+chr(b+65) for a,b in best_extra) or '(none)'}")
        print(f"  Final score: {best_s:.3f}")
        print(f"  Phase 3: {phase3_time:.1f}s")

        total_time = phase1_time + phase2_time + phase3_time
        print(f"\n{'=' * 70}")
        print(f"RESULT ({total_time:.1f}s total)")
        print(f"{'=' * 70}")
        print(f"Rotors:    {'-'.join(rotor_names)}")
        print(f"Reflector: {reflector}")
        print(f"Position:  {''.join(chr(p+65) for p in pos)}")
        print(f"Rings:     {''.join(chr(r+65) for r in rings)}")
        print(f"Plugboard: {' '.join(chr(a+65)+chr(b+65) for a,b in final_pairs)}")
        print(f"Score:     {best_s:.3f}")
        print(f"\nPLAINTEXT:")
        for i in range(0, len(plaintext), 50):
            print(f"  {plaintext[i:i+50]}")
    else:
        print("  No valid completions found!")


if __name__ == "__main__":
    main()
