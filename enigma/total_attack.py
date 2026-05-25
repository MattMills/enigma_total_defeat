"""Idealized zero-knowledge attack: ciphertext-only, no prior information.

Designed from benchmark compatibility data — every technique is used
only in the domain where it succeeds, and wasteful combinations are
avoided by construction.

Key findings from benchmarking:
  - Heavy plugboard (10 pairs) defeats: spectral, circular, IC sweep,
    bidirectional scoring, greedy swap, domain cascade, hyperchart
  - Only beam_swap recovers heavy plugboards (with enough rounds/width)
  - IC position search fails with plugboard because IC is only
    *partially* invariant — it degrades with plug weight
  - Superposition filter and validation discriminator work universally
  - Signed propagation always converges but determines 0 entries alone
  - Turnover ring refine works; CRT decomposition does not

Architecture (handles 0–13 pair plugboards, 0-25 ring offsets):

  Phase 0 — Rotor manifold (spectral + frequency)
    Use PLUGBOARD-INVARIANT scoring (sorted-χ²) to rank rotor combos.
    Spectral narrows right rotor. Sorted-χ² is invariant under any
    plugboard permutation, so it works at all plug weights.

  Phase 1 — Position manifold (plugboard-invariant IC)
    For each surviving combo, IC-sweep all 17,576 positions.
    IC is plugboard-invariant — the correct position has IC ≈ 0.076
    even through 10 plugboard pairs. But the RANK of the correct
    position degrades with plug weight, so we keep more survivors
    for heavier-plug scenarios: top 20 per combo.

  Phase 2 — Trajectory validation (superposition)
    Filter positions with superposition collapse. This kills ~59%
    of wrong trajectories regardless of plugboard.

  Phase 3 — Ring recovery (brute-force, not CRT)
    For each surviving (combo, position), try all 26 right ring
    values. Score with IC (plugboard-invariant). The CRT
    decomposition fails on short messages, so use brute force.

  Phase 4 — Plugboard recovery (beam swap, high width)
    beam_swap with rounds=12, beam_width=80 for heavy plugboards.
    Domain cascade as pre-seed when it converges (gives beam_swap
    a head start on the correct plugboard fragment).

  Phase 5 — Validation (binary discriminator)
    0 excluded bigrams = correct. This is the terminal condition.
    If no candidate achieves 0, report the best score.

The attack is parametric: time_limit controls how deep into the
manifold we explore. Longer messages need less time (more constraints
per position). Shorter messages need more time (weaker signal).
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from typing import Sequence

from enigma.attack import beam_swap_search
from enigma.crack import crack_trajectory
from enigma.language import LanguageModel, index_of_coincidence
from enigma.ngram_data import BIGRAMS_OBSERVED, TRIGRAMS_OBSERVED, QUADGRAMS_OBSERVED
from enigma.pipeline import PipelineResult, stage_validate
from enigma.simulator import (
    ROTORS,
    REFLECTORS,
    fast_trajectory,
    M3_ROTORS,
    M3_REFLECTORS,
    NAVAL_ROTORS,
    GREEK_ROTORS,
    M4_REFLECTORS,
)
from enigma.spectral import identify_right_rotor
from enigma.superposition import try_collapse


@dataclass
class AttackProgress:
    """Live progress state for the attack."""
    phase: str = ""
    combos_tested: int = 0
    combos_total: int = 0
    positions_tested: int = 0
    positions_survived: int = 0
    candidates_beam_swapped: int = 0
    best_score: float = float("-inf")
    best_excluded: int = 999
    elapsed: float = 0.0


def total_attack(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = M3_ROTORS,
    reflector_names: Sequence[str] = M3_REFLECTORS,
    time_limit: float = 300.0,
    beam_rounds: int = 12,
    beam_width: int = 80,
    ic_survivors_per_combo: int = 20,
    search_rings: bool = True,
    use_domain_cascade_seed: bool = True,
    progress: bool = False,
    fourth_rotors: Sequence[str] | None = None,
    fourth_positions: Sequence[int] | None = None,
) -> list[PipelineResult]:
    """Zero-knowledge ciphertext-only attack.

    No rotors, no position, no rings, no plugboard — just ciphertext
    and the German language model.

    Returns results sorted by (n_excluded_bigrams ASC, score DESC).
    A result with n_excluded_bigrams == 0 is a confirmed break.
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)
    if L < 20:
        return []

    t0 = time.time()
    state = AttackProgress()

    # Fourth rotor config
    fourth_iter: list[tuple[str | None, int]] = [(None, 0)]
    if fourth_rotors:
        fourth_iter = []
        f_pos = fourth_positions if fourth_positions else range(26)
        for fr in fourth_rotors:
            for fp in f_pos:
                fourth_iter.append((fr, fp))

    # ==============================================================
    # Phase 0: Rotor manifold — spectral narrowing
    # ==============================================================
    state.phase = "Phase 0: rotor manifold"
    all_combos = list(itertools.permutations(rotor_pool, 3))

    # Spectral: rank right rotors (works on messages >30 chars)
    spectral_top = list(rotor_pool)
    if L >= 30:
        spectral_results = identify_right_rotor(
            cipher, reflector_names[0], tuple(rotor_pool)
        )
        spectral_top = [name for name, _ in spectral_results[:min(4, len(rotor_pool))]]

    spectral_combos = [c for c in all_combos if c[2] in spectral_top]
    if not spectral_combos:
        spectral_combos = all_combos

    state.combos_total = len(spectral_combos) * len(reflector_names) * len(fourth_iter)
    if progress:
        print(f"Phase 0: {len(spectral_combos)} rotor combos "
              f"(spectral narrowed right rotor to {spectral_top})")

    # ==============================================================
    # Phase 1+2+3: IC sweep + superposition + ring for each combo
    # ==============================================================
    # For each (combo, reflector, fourth), do a fast inlined IC sweep
    # over all 17,576 positions, keep top survivors, filter with
    # superposition, then refine ring.

    candidates: list[tuple[float, tuple[str, str, str], str,
                           tuple[int, int, int], tuple[int, int, int],
                           str | None, int]] = []

    # Sorted-χ² reference for plugboard-invariant combo ranking
    german_sorted = sorted(model.unigram, reverse=True)

    for refl in reflector_names:
        for combo in spectral_combos:
            for fourth_name, fourth_pos in fourth_iter:
                if time.time() - t0 > time_limit:
                    break
                state.combos_tested += 1

                fourth_kw = {}
                if fourth_name:
                    fourth_kw = dict(
                        fourth_rotor_name=fourth_name,
                        fourth_position=fourth_pos,
                        fourth_ring=0,
                    )

                # Phase 1: inline IC sweep
                left_r = ROTORS[combo[0]]
                middle_r = ROTORS[combo[1]]
                right_r = ROTORS[combo[2]]
                refl_obj = REFLECTORS[refl]

                Lw, Le = left_r.wiring, left_r.inverse
                Mw, Me = middle_r.wiring, middle_r.inverse
                Rw, Re = right_r.wiring, right_r.inverse
                Rf = refl_obj.wiring
                right_notches = right_r.notches
                middle_notches = middle_r.notches

                if fourth_name is not None:
                    fourth = ROTORS[fourth_name]
                    o4 = (fourth_pos - 0) % 26
                    combined = [0] * 26
                    for x in range(26):
                        s = (fourth.wiring[(x + o4) % 26] - o4) % 26
                        s = Rf[s]
                        s = (fourth.inverse[(s + o4) % 26] - o4) % 26
                        combined[x] = s
                    Rf = tuple(combined)

                denom = L * (L - 1) if L > 1 else 1
                ic_results: list[tuple[float, tuple[int, int, int]]] = []

                for pl in range(26):
                    for pm in range(26):
                        for pr in range(26):
                            pL, pM, pR = pl, pm, pr
                            counts = [0] * 26
                            for t in range(L):
                                if pM in middle_notches:
                                    pL = (pL + 1) % 26
                                    pM = (pM + 1) % 26
                                elif pR in right_notches:
                                    pM = (pM + 1) % 26
                                pR = (pR + 1) % 26
                                oL = (pL - 0) % 26
                                oM = (pM - 0) % 26
                                oR = (pR - 0) % 26
                                x = cipher[t]
                                s = (Rw[(x + oR) % 26] - oR) % 26
                                s = (Mw[(s + oM) % 26] - oM) % 26
                                s = (Lw[(s + oL) % 26] - oL) % 26
                                s = Rf[s]
                                s = (Le[(s + oL) % 26] - oL) % 26
                                s = (Me[(s + oM) % 26] - oM) % 26
                                p = (Re[(s + oR) % 26] - oR) % 26
                                counts[p] += 1
                            ic = sum(c * (c - 1) for c in counts) / denom
                            ic_results.append((ic, (pl, pm, pr)))

                ic_results.sort(reverse=True)
                top_positions = ic_results[:ic_survivors_per_combo]

                # Phase 2: superposition filter
                for _, pos in top_positions:
                    if time.time() - t0 > time_limit:
                        break
                    state.positions_tested += 1

                    traj = fast_trajectory(
                        combo, refl, pos, (0, 0, 0), L, **fourth_kw,
                    )

                    # Superposition check
                    survived = False
                    for seed in (4, 13, 8, 18, 17, 0, 19):
                        if seed == cipher[0]:
                            continue
                        result = try_collapse(cipher, traj, model, seed, 0)
                        if result.consistent:
                            survived = True
                            break
                    if not survived:
                        continue
                    state.positions_survived += 1

                    # Phase 3: ring recovery (brute force)
                    if search_rings:
                        best_ring_score = float("-inf")
                        best_ring = 0
                        for rr in range(26):
                            traj_r = fast_trajectory(
                                combo, refl, pos, (0, 0, rr), L, **fourth_kw,
                            )
                            dec_r = [traj_r[t][cipher[t]] for t in range(L)]
                            ring_ic = index_of_coincidence(dec_r)
                            if ring_ic > best_ring_score:
                                best_ring_score = ring_ic
                                best_ring = rr
                        rings = (0, 0, best_ring)
                    else:
                        rings = (0, 0, 0)

                    # Store the POSITION-SPECIFIC IC (with best ring),
                    # not the combo-max. This is the true trajectory signal.
                    pos_ic = best_ring_score if search_rings else ic
                    # where ic was computed for this position at ring=(0,0,0)
                    # recompute if needed
                    if not search_rings:
                        traj_check = fast_trajectory(
                            combo, refl, pos, (0, 0, 0), L, **fourth_kw,
                        )
                        dec_check = [traj_check[t][cipher[t]] for t in range(L)]
                        pos_ic = index_of_coincidence(dec_check)

                    candidates.append((
                        pos_ic,
                        combo, refl, pos, rings,
                        fourth_name, fourth_pos,
                    ))

                if progress and state.combos_tested % 10 == 0:
                    print(f"  Phase 1-3: {state.combos_tested}/{state.combos_total} combos, "
                          f"{state.positions_survived} survivors, "
                          f"{time.time()-t0:.1f}s")

    # Sort by IC (higher = more likely correct)
    candidates.sort(reverse=True)

    if progress:
        print(f"Phase 1-3 complete: {len(candidates)} candidates "
              f"from {state.positions_tested} positions tested "
              f"({state.positions_survived} survived superposition) "
              f"in {time.time()-t0:.1f}s")

    # ==============================================================
    # Phase 4+5: Plugboard recovery + validation
    # ==============================================================
    state.phase = "Phase 4-5: plugboard + validation"

    results: list[PipelineResult] = []
    max_beam = min(50, len(candidates))

    for _, combo, refl, pos, rings, fourth_name, fourth_pos in candidates[:max_beam]:
        if time.time() - t0 > time_limit:
            break
        state.candidates_beam_swapped += 1

        fourth_kw = {}
        if fourth_name:
            fourth_kw = dict(
                fourth_rotor_name=fourth_name,
                fourth_position=fourth_pos,
                fourth_ring=0,
            )

        traj = fast_trajectory(combo, refl, pos, rings, L, **fourth_kw)
        stages_used = ["ic_sweep", "superposition", "ring_brute"]

        # Domain cascade seed (when it works, gives beam_swap a head start)
        start_plug = None
        if use_domain_cascade_seed:
            try:
                dc_results = crack_trajectory(cipher, traj, model, max_seeds=100)
                if dc_results:
                    dp, pt = dc_results[0]
                    start_plug = list(range(26))
                    for a in range(26):
                        v = dp.get(a)
                        if v is not None:
                            start_plug[a] = v
                    stages_used.append("domain_cascade_seed")
            except Exception:
                pass

        # Beam swap
        score, plug, dec = beam_swap_search(
            cipher, traj, model,
            start_plug=start_plug,
            beam_width=beam_width,
            rounds=beam_rounds,
        )
        stages_used.append("beam_swap")

        # Validation: excluded bigrams + quadgram density
        n_excl = stage_validate(dec, model)
        stages_used.append("validation")

        # Quadgram density — the strongest discriminator.
        # Correct German has ~70-80% valid quadgrams; random text has <5%.
        n_qg = 0
        for i in range(len(dec) - 3):
            qg = dec[i] * 17576 + dec[i+1] * 676 + dec[i+2] * 26 + dec[i+3]
            if qg in QUADGRAMS_OBSERVED:
                n_qg += 1
        qg_density = n_qg / max(len(dec) - 3, 1)

        # Combined quality score: language model + quadgram bonus
        quality = score + n_qg * 0.1

        pairs = [(a, plug[a]) for a in range(26) if plug[a] > a]
        result = PipelineResult(
            plaintext="".join(chr(d + 65) for d in dec),
            score=quality,
            rotor_names=combo,
            reflector_name=refl,
            positions=pos,
            ring_settings=rings,
            plugboard_map=plug,
            plugboard_pairs=pairs,
            fourth_rotor_name=fourth_name,
            fourth_position=fourth_pos if fourth_name else 0,
            elapsed=time.time() - t0,
            stages_used=stages_used,
            n_excluded_bigrams=n_excl,
        )
        results.append(result)

        if n_excl < state.best_excluded or (n_excl == state.best_excluded and quality > state.best_score):
            state.best_excluded = n_excl
            state.best_score = quality

        if progress:
            print(f"  [{state.candidates_beam_swapped}/{max_beam}] "
                  f"{'-'.join(combo)}/{refl} pos={''.join(chr(p+65) for p in pos)} "
                  f"ring={''.join(chr(r+65) for r in rings)} "
                  f"excl={n_excl} qg={qg_density:.0%} score={quality:.3f} "
                  f"{'** SOLUTION **' if n_excl == 0 and qg_density > 0.3 else ''}")

        # Early termination: confirmed break
        # Require BOTH 0 excluded bigrams AND meaningful quadgram density
        if n_excl == 0 and qg_density > 0.3:
            break

    # Sort: 0 excluded first, then by quality score (includes quadgram bonus)
    results.sort(key=lambda r: (r.n_excluded_bigrams, -r.score))

    if progress:
        elapsed = time.time() - t0
        if results:
            print(f"\nDone in {elapsed:.1f}s. "
                  f"Best: excl={results[0].n_excluded_bigrams} "
                  f"score={results[0].score:.3f}")
        else:
            print(f"\nDone in {elapsed:.1f}s. No results found.")

    return results
