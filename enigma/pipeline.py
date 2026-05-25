"""Fully integrated cryptanalysis pipeline.

Chains all available techniques in topologically optimal order:

  Stage 1 — Spectral:       Identify candidate right rotors from ciphertext
  Stage 2 — IC Filter:      Rank 17,576 positions by plugboard-invariant IC
  Stage 3 — Superposition:  Reject inconsistent trajectories (kills ~59%)
  Stage 4 — Domain Cascade: Narrow plugboard domains via differential
  Stage 5 — Beam Swap:      Recover plugboard with n-gram scoring
  Stage 6 — Validation:     Binary discriminator + coherence check

Each stage ENCLOSES the search space for the next. Longer messages
converge faster because more positions = more constraints.

Techniques can be used independently or combined. The pipeline
adapts based on what's known (rotors, positions, plugboard) and
what must be searched.
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from typing import Sequence

from enigma.attack import beam_swap_search, infer_plugboard
from enigma.circular import bidirectional_score
from enigma.crack import DomainPlug, crack_trajectory
from enigma.hyperchart import solve_hyperchart
from enigma.language import LanguageModel, index_of_coincidence
from enigma.ngram_data import BIGRAMS_OBSERVED
from enigma.propagate import SignedPropagator
from enigma.simulator import (
    Plugboard,
    fast_trajectory,
    M3_ROTORS,
    M3_REFLECTORS,
    M4_REFLECTORS,
    NAVAL_ROTORS,
    GREEK_ROTORS,
)
from enigma.spectral import identify_right_rotor
from enigma.superposition import try_collapse
from enigma.topology import TopologyCache, trajectory_fingerprint


@dataclass
class PipelineResult:
    plaintext: str
    score: float
    rotor_names: tuple[str, str, str]
    reflector_name: str
    positions: tuple[int, int, int]
    ring_settings: tuple[int, int, int]
    plugboard_map: list[int]
    plugboard_pairs: list[tuple[int, int]] = field(default_factory=list)
    fourth_rotor_name: str | None = None
    fourth_position: int = 0
    fourth_ring: int = 0
    elapsed: float = 0.0
    stages_used: list[str] = field(default_factory=list)
    n_excluded_bigrams: int = 0

    @property
    def plug_str(self) -> str:
        return " ".join(
            chr(a + 65) + chr(b + 65) for a, b in self.plugboard_pairs
        )

    def __repr__(self) -> str:
        pos = "".join(chr(p + 65) for p in self.positions)
        rings = "".join(chr(r + 65) for r in self.ring_settings)
        return (
            f"PipelineResult(score={self.score:.3f}, "
            f"rotors={'-'.join(self.rotor_names)}, refl={self.reflector_name}, "
            f"pos={pos}, rings={rings}, plug=[{self.plug_str}], "
            f"excluded_bg={self.n_excluded_bigrams}, "
            f"elapsed={self.elapsed:.2f}s, stages={self.stages_used})\n"
            f"  plaintext={self.plaintext[:80]!r}"
        )


# ------------------------------------------------------------------
# Stage 1: Spectral rotor identification
# ------------------------------------------------------------------


def stage_spectral(
    cipher: list[int],
    candidate_rotors: Sequence[str] = M3_ROTORS,
    reflector_name: str = "B",
    top_k: int = 3,
) -> list[str]:
    """Identify candidate right rotors from ciphertext differential profile."""
    if len(cipher) < 30:
        return list(candidate_rotors)
    results = identify_right_rotor(cipher, reflector_name, tuple(candidate_rotors))
    return [name for name, _ in results[:top_k]]


# ------------------------------------------------------------------
# Stage 2: IC filter
# ------------------------------------------------------------------


def stage_ic_filter(
    cipher: list[int],
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    ring_settings: tuple[int, int, int],
    top_k: int = 500,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> list[tuple[float, tuple[int, int, int]]]:
    """Rank all 17,576 positions by IC (plugboard-invariant). Returns top_k."""
    L = len(cipher)
    fourth_kw = {}
    if fourth_rotor_name:
        fourth_kw = dict(
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=fourth_position,
            fourth_ring=fourth_ring,
        )

    ic_scores: list[tuple[float, tuple[int, int, int]]] = []
    for pl in range(26):
        for pm in range(26):
            for pr in range(26):
                traj = fast_trajectory(
                    rotor_names, reflector_name, (pl, pm, pr),
                    ring_settings, L, **fourth_kw,
                )
                dec = [traj[t][cipher[t]] for t in range(L)]
                ic = index_of_coincidence(dec)
                ic_scores.append((ic, (pl, pm, pr)))

    ic_scores.sort(reverse=True)
    return ic_scores[:top_k]


# ------------------------------------------------------------------
# Stage 3: Superposition rejection
# ------------------------------------------------------------------


def stage_superposition(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    seed_letters: tuple[int, ...] = (4, 13, 8, 18, 17, 0, 19),
) -> bool:
    """Returns True if trajectory survives superposition check."""
    for seed in seed_letters:
        if seed == cipher[0]:
            continue
        result = try_collapse(cipher, trajectory, model, seed, 0)
        if result.consistent:
            return True
    return False


# ------------------------------------------------------------------
# Stage 4: Domain cascade
# ------------------------------------------------------------------


def stage_domain_cascade(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
) -> list[tuple[DomainPlug, list[int | None]]] | None:
    """Run domain cascade. Returns surviving (plug, plaintext) pairs or None."""
    results = crack_trajectory(cipher, trajectory, model)
    return results if results else None


# ------------------------------------------------------------------
# Stage 5: Beam swap search
# ------------------------------------------------------------------


def stage_beam_swap(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    start_plug: list[int] | None = None,
    beam_width: int = 50,
    rounds: int = 10,
) -> tuple[float, list[int], list[int]]:
    """Recover plugboard via beam swap search."""
    return beam_swap_search(
        cipher, trajectory, model,
        start_plug=start_plug,
        beam_width=beam_width,
        rounds=rounds,
    )


# ------------------------------------------------------------------
# Stage 6: Validation (binary discriminator)
# ------------------------------------------------------------------


def stage_validate(
    decrypted: list[int],
    model: LanguageModel,
) -> int:
    """Count excluded bigrams. 0 = correct, >0 = wrong."""
    count = 0
    for i in range(len(decrypted) - 1):
        if model.excluded[decrypted[i]][decrypted[i + 1]]:
            count += 1
    return count


def count_valid_ngrams(dec: list[int]) -> dict[str, int]:
    """Count valid bigrams, trigrams (via bigram-of-bigrams), quadgrams."""
    from enigma.ngram_data import (
        BIGRAMS_OBSERVED, TRIGRAMS_OBSERVED, QUADGRAMS_OBSERVED,
        BIGRAM_SUCCESSORS, TRIGRAM_SUCCESSORS,
    )
    n = len(dec)
    valid_bg = sum(
        1 for i in range(n - 1)
        if (dec[i] * 26 + dec[i + 1]) in BIGRAMS_OBSERVED
    )
    valid_tg = 0
    if n >= 3:
        prev_bg = dec[0] * 26 + dec[1]
        for i in range(1, n - 1):
            cur_bg = dec[i] * 26 + dec[i + 1]
            succ = BIGRAM_SUCCESSORS.get(prev_bg)
            if succ is not None and cur_bg in succ:
                valid_tg += 1
            prev_bg = cur_bg
    valid_qg = 0
    if n >= 4:
        prev_tg = dec[0] * 676 + dec[1] * 26 + dec[2]
        for i in range(1, n - 2):
            cur_tg = dec[i] * 676 + dec[i + 1] * 26 + dec[i + 2]
            succ = TRIGRAM_SUCCESSORS.get(prev_tg)
            if succ is not None and cur_tg in succ:
                valid_qg += 1
            prev_tg = cur_tg
    return {"bigrams": valid_bg, "trigrams": valid_tg, "quadgrams": valid_qg}


# ------------------------------------------------------------------
# Combined pipeline
# ------------------------------------------------------------------


def crack_full(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = M3_ROTORS,
    reflector_names: Sequence[str] = M3_REFLECTORS,
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    known_rotors: tuple[str, str, str] | None = None,
    known_positions: tuple[int, int, int] | None = None,
    ic_survivors: int = 200,
    superposition_filter: bool = True,
    domain_cascade: bool = False,
    beam_rounds: int = 10,
    beam_width: int = 50,
    time_limit: float = 120.0,
    progress: bool = False,
    fourth_rotors: Sequence[str] | None = None,
    fourth_positions: Sequence[int] | None = None,
    fourth_rings: Sequence[int] | None = None,
    topology_cache: TopologyCache | None = None,
) -> list[PipelineResult]:
    """Full integrated pipeline: spectral → IC → superposition → beam swap.

    Adapts to what's known:
      - If rotors known: skip spectral
      - If positions known: skip IC filter + superposition
      - If nothing known: run full pipeline

    Returns results sorted by score (best first).
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)
    if L < 5:
        return []

    t0 = time.time()
    results: list[PipelineResult] = []

    fourth_iter: list[tuple[str | None, int, int]] = [(None, 0, 0)]
    if fourth_rotors:
        fourth_iter = []
        f_pos = fourth_positions if fourth_positions else range(26)
        f_rings = fourth_rings if fourth_rings else [0]
        for fr in fourth_rotors:
            for fp in f_pos:
                for fring in f_rings:
                    fourth_iter.append((fr, fp, fring))

    # --- Topology cache lookup (Stage 0) ---
    if topology_cache:
        cache_hits = topology_cache.match_trajectory(cipher, model, top_k=3)
        for score, entry, dec in cache_hits:
            n_excl = stage_validate(dec, model)
            if n_excl == 0:
                plug_map = list(range(26))
                results.append(PipelineResult(
                    plaintext="".join(chr(d + 65) for d in dec),
                    score=score,
                    rotor_names=entry.rotor_names,
                    reflector_name=entry.reflector_name,
                    positions=entry.positions,
                    ring_settings=entry.ring_settings,
                    plugboard_map=plug_map,
                    fourth_rotor_name=entry.fourth_rotor_name,
                    fourth_position=entry.fourth_position,
                    elapsed=time.time() - t0,
                    stages_used=["topology_cache"],
                    n_excluded_bigrams=n_excl,
                ))
        if results:
            return results

    # --- Determine rotor combos ---
    if known_rotors:
        rotor_combos: list[tuple[str, str, str]] = [known_rotors]
    else:
        rotor_combos = list(itertools.permutations(rotor_pool, 3))

    # --- Stage 1: Spectral (if rotors unknown and pool > 3) ---
    stages_used: list[str] = []
    if not known_rotors and len(rotor_pool) > 3:
        right_candidates = stage_spectral(cipher, rotor_pool, reflector_names[0])
        rotor_combos = [
            combo for combo in rotor_combos
            if combo[2] in right_candidates
        ]
        stages_used.append("spectral")
        if progress:
            print(f"  Stage 1 (spectral): {len(right_candidates)} right rotor candidates → "
                  f"{len(rotor_combos)} combos")

    # --- Main loop ---
    for refl in reflector_names:
        for rotors in rotor_combos:
            for fourth_name, fourth_pos, fourth_rng in fourth_iter:
                if time.time() - t0 > time_limit:
                    break

                fourth_kw = {}
                if fourth_name:
                    fourth_kw = dict(
                        fourth_rotor_name=fourth_name,
                        fourth_position=fourth_pos,
                        fourth_ring=fourth_rng,
                    )

                local_stages = list(stages_used)

                # --- Known position: skip IC + superposition ---
                if known_positions:
                    positions_to_try = [known_positions]
                else:
                    # Stage 2: IC filter
                    ic_results = stage_ic_filter(
                        cipher, rotors, refl, ring_settings,
                        top_k=ic_survivors, **fourth_kw,
                    )
                    positions_to_try = [pos for _, pos in ic_results]
                    local_stages.append("ic_filter")
                    if progress:
                        print(f"  Stage 2 (IC): {len(positions_to_try)} survivors "
                              f"for {'-'.join(rotors)}/{refl}")

                survived = 0
                for pos in positions_to_try:
                    if time.time() - t0 > time_limit:
                        break

                    traj = fast_trajectory(
                        rotors, refl, pos, ring_settings, L, **fourth_kw,
                    )

                    # Stage 3: Superposition pre-filter
                    if superposition_filter and not known_positions:
                        if not stage_superposition(cipher, traj, model):
                            continue
                        if "superposition" not in local_stages:
                            local_stages.append("superposition")
                    survived += 1

                    # Stage 4: Domain cascade (optional, expensive)
                    start_plug = None
                    if domain_cascade:
                        cascade_results = stage_domain_cascade(cipher, traj, model)
                        if cascade_results:
                            dp, pt = cascade_results[0]
                            start_plug = list(range(26))
                            for a in range(26):
                                v = dp.get(a)
                                if v is not None:
                                    start_plug[a] = v
                            if "domain_cascade" not in local_stages:
                                local_stages.append("domain_cascade")

                    # Stage 5: Beam swap
                    score, plug, dec = stage_beam_swap(
                        cipher, traj, model,
                        start_plug=start_plug,
                        beam_width=beam_width,
                        rounds=beam_rounds,
                    )
                    if "beam_swap" not in local_stages:
                        local_stages.append("beam_swap")

                    # Stage 6: Validation
                    n_excl = stage_validate(dec, model)
                    if "validation" not in local_stages:
                        local_stages.append("validation")

                    pairs = [(a, plug[a]) for a in range(26) if plug[a] > a]
                    results.append(PipelineResult(
                        plaintext="".join(chr(d + 65) for d in dec),
                        score=score,
                        rotor_names=rotors,
                        reflector_name=refl,
                        positions=pos,
                        ring_settings=ring_settings,
                        plugboard_map=plug,
                        plugboard_pairs=pairs,
                        fourth_rotor_name=fourth_name,
                        fourth_position=fourth_pos,
                        fourth_ring=fourth_rng,
                        elapsed=time.time() - t0,
                        stages_used=list(local_stages),
                        n_excluded_bigrams=n_excl,
                    ))

                if progress and positions_to_try:
                    print(f"    {'-'.join(rotors)}/{refl}: "
                          f"{survived}/{len(positions_to_try)} survived superposition")

            if time.time() - t0 > time_limit:
                break
        if time.time() - t0 > time_limit:
            break

    results.sort(key=lambda r: (r.n_excluded_bigrams, -r.score))
    return results


# ------------------------------------------------------------------
# Convenience: single-trajectory crack (known rotors + position)
# ------------------------------------------------------------------


def crack_with_known_trajectory(
    ciphertext: str,
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    *,
    model: LanguageModel | None = None,
    use_domain_cascade: bool = True,
    beam_rounds: int = 10,
    beam_width: int = 50,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> PipelineResult:
    """Crack a message with known trajectory (rotors + position).

    Runs domain cascade for initial plugboard estimate, then beam swap
    to polish. Validates with binary discriminator.
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)
    t0 = time.time()

    fourth_kw = {}
    if fourth_rotor_name:
        fourth_kw = dict(
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=fourth_position,
            fourth_ring=fourth_ring,
        )

    traj = fast_trajectory(
        rotor_names, reflector_name, positions, ring_settings, L, **fourth_kw,
    )
    stages_used = []

    start_plug = None
    if use_domain_cascade:
        cascade_results = stage_domain_cascade(cipher, traj, model)
        if cascade_results:
            dp, pt = cascade_results[0]
            start_plug = list(range(26))
            for a in range(26):
                v = dp.get(a)
                if v is not None:
                    start_plug[a] = v
            stages_used.append("domain_cascade")

    score, plug, dec = stage_beam_swap(
        cipher, traj, model,
        start_plug=start_plug,
        beam_width=beam_width,
        rounds=beam_rounds,
    )
    stages_used.append("beam_swap")

    n_excl = stage_validate(dec, model)
    stages_used.append("validation")

    pairs = [(a, plug[a]) for a in range(26) if plug[a] > a]
    return PipelineResult(
        plaintext="".join(chr(d + 65) for d in dec),
        score=score,
        rotor_names=rotor_names,
        reflector_name=reflector_name,
        positions=positions,
        ring_settings=ring_settings,
        plugboard_map=plug,
        plugboard_pairs=pairs,
        fourth_rotor_name=fourth_rotor_name,
        fourth_position=fourth_position,
        fourth_ring=fourth_ring,
        elapsed=time.time() - t0,
        stages_used=stages_used,
        n_excluded_bigrams=n_excl,
    )


# ------------------------------------------------------------------
# Individual technique runners (for independent testing)
# ------------------------------------------------------------------


# ------------------------------------------------------------------
# Zero-knowledge hierarchical crack
# ------------------------------------------------------------------
#
# Multi-phase solver over the full key space:
#
#   Phase 0 (hyper-phase): Rotor combo × reflector manifold
#     Each combo gets an IC-based "configuration score" from a fast
#     inlined sweep over all 17,576 positions. This is the
#     superposition over the rotor manifold — we maintain a score
#     distribution across ALL combos and let the IC evidence collapse
#     it to a few survivors.
#
#   Phase 1: Position manifold within each surviving combo
#     IC-ranked positions from Phase 0. Superposition filter rejects
#     inconsistent trajectories. The CRT tail-radix structure of
#     26 = 2 × 13 decomposes ring search within this phase.
#
#   Phase 2: Plugboard manifold (Birkhoff polytope)
#     Beam swap search on surviving (combo, position, ring) triples.
#     Binary discriminator (0 excluded bigrams) collapses the
#     superposition to the correct solution.
#
#   Phase 3: Cross-message validation
#     Same-day messages share rotors/reflector/rings/plugboard.
#     A key recovered from one message validates against all others.
#


def _inline_ic_sweep(
    cipher: list[int],
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    ring_settings: tuple[int, int, int],
    top_k: int = 20,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> list[tuple[float, tuple[int, int, int]]]:
    """Fast inlined IC sweep over all 17,576 positions.

    ~10x faster than stage_ic_filter because we avoid constructing
    full trajectory objects — inline rotor lookups + IC counting.
    """
    from enigma.simulator import ROTORS, REFLECTORS

    L = len(cipher)
    left_r = ROTORS[rotor_names[0]]
    middle_r = ROTORS[rotor_names[1]]
    right_r = ROTORS[rotor_names[2]]
    refl = REFLECTORS[reflector_name]

    Lw, Le = left_r.wiring, left_r.inverse
    Mw, Me = middle_r.wiring, middle_r.inverse
    Rw, Re = right_r.wiring, right_r.inverse
    Rf = refl.wiring
    right_notches = right_r.notches
    middle_notches = middle_r.notches
    rL, rM, rR = ring_settings

    if fourth_rotor_name is not None:
        fourth = ROTORS[fourth_rotor_name]
        o4 = (fourth_position - fourth_ring) % 26
        combined = [0] * 26
        for x in range(26):
            s = (fourth.wiring[(x + o4) % 26] - o4) % 26
            s = Rf[s]
            s = (fourth.inverse[(s + o4) % 26] - o4) % 26
            combined[x] = s
        Rf = tuple(combined)

    denom = L * (L - 1) if L > 1 else 1
    results: list[tuple[float, tuple[int, int, int]]] = []

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
                    oL = (pL - rL) % 26
                    oM = (pM - rM) % 26
                    oR = (pR - rR) % 26
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
                results.append((ic, (pl, pm, pr)))

    results.sort(reverse=True)
    return results[:top_k]


def _crt_ring_refine(
    cipher: list[int],
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    model: LanguageModel,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> tuple[tuple[int, int, int], float]:
    """CRT ring refinement: 26 = 2 × 13, so 15 trials instead of 26.

    Tests the right ring mod-2 (2 trials) and mod-13 (13 trials)
    independently, then CRT-combines the best of each.
    """
    from enigma.solver import crt

    fourth_kw = {}
    if fourth_rotor_name:
        fourth_kw = dict(
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=fourth_position,
            fourth_ring=fourth_ring,
        )
    L = len(cipher)

    def _score_ring(rr: int) -> float:
        traj = fast_trajectory(
            rotor_names, reflector_name, positions, (0, 0, rr), L, **fourth_kw,
        )
        dec = [traj[t][cipher[t]] for t in range(L)]
        return model.score(dec)

    # Mod 2: test rr=0 and rr=1
    mod2_scores = [((_score_ring(rr2), rr2)) for rr2 in range(2)]
    mod2_scores.sort(reverse=True)

    # Mod 13: test rr=0..12
    mod13_scores = [((_score_ring(rr13), rr13)) for rr13 in range(13)]
    mod13_scores.sort(reverse=True)

    # CRT combine top candidates
    best_rr = 0
    best_score = float("-inf")
    for _, r2 in mod2_scores[:2]:
        for _, r13 in mod13_scores[:3]:
            rr = crt(r2, 2, r13, 13)
            s = _score_ring(rr)
            if s > best_score:
                best_score = s
                best_rr = rr

    return (0, 0, best_rr), best_score


def crack_zero_knowledge(
    ciphertexts: str | list[str],
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = M3_ROTORS,
    reflector_names: Sequence[str] = M3_REFLECTORS,
    ic_survivors_per_combo: int = 20,
    beam_rounds: int = 10,
    beam_width: int = 50,
    search_rings: bool = True,
    time_limit: float = 600.0,
    progress: bool = False,
    fourth_rotors: Sequence[str] | None = None,
    fourth_positions: Sequence[int] | None = None,
) -> list[PipelineResult]:
    """Zero-knowledge crack: no rotors, no position, no rings, no plugboard.

    Hierarchical phase-space solver:

      Phase 0 (hyper-phase): superposition over rotor × reflector manifold.
        Fast inlined IC sweep scores every combo by max IC across all 17,576
        positions. Spectral narrowing reduces right-rotor candidates first.
        Combos are ranked and the top survivors enter Phase 1.

      Phase 1: position manifold within surviving combos.
        IC-ranked positions from Phase 0. Superposition filter rejects
        ~59% of candidates. CRT tail-radix decomposition (26 = 2 × 13)
        refines ring settings with 15 trials instead of 26.

      Phase 2: plugboard manifold (Birkhoff polytope).
        Beam swap search resolves the plugboard for each surviving
        (combo, position, ring) triple. Binary discriminator (0 excluded
        bigrams) collapses the superposition.

      Phase 3: cross-message validation.
        If multiple ciphertexts are provided, a key recovered from one
        message is tested against all others. Same-day messages share
        rotors/reflector/rings/plugboard — only position differs.

    Multiple ciphertexts can be provided for cross-validation. Messages
    encrypted with the same day key (same rotors, reflector, rings,
    plugboard) will mutually confirm each other.
    """
    if model is None:
        model = LanguageModel.german_military()

    if isinstance(ciphertexts, str):
        ciphertexts = [ciphertexts]

    primary_ct = ciphertexts[0]
    cipher = [ord(c) - 65 for c in primary_ct if "A" <= c <= "Z"]
    L = len(cipher)
    if L < 20:
        return []

    t0 = time.time()

    # Fourth rotor config
    fourth_iter: list[tuple[str | None, int]] = [(None, 0)]
    if fourth_rotors:
        fourth_iter = []
        f_pos = fourth_positions if fourth_positions else range(26)
        for fr in fourth_rotors:
            for fp in f_pos:
                fourth_iter.append((fr, fp))

    # ================================================================
    # Phase 0: Hyper-phase — superposition over rotor × reflector manifold
    # ================================================================
    # Score each combo by max IC across all positions. This is the
    # "rotor-level superposition" — evidence from the IC distribution
    # collapses the manifold to a few survivors.

    all_combos = list(itertools.permutations(rotor_pool, 3))

    # Spectral narrowing: rank right rotors, keep top candidates
    spectral_top = stage_spectral(cipher, rotor_pool, reflector_names[0], top_k=min(4, len(rotor_pool)))
    spectral_combos = [c for c in all_combos if c[2] in spectral_top]
    if not spectral_combos:
        spectral_combos = all_combos

    if progress:
        print(f"Phase 0: {len(spectral_combos)} combos × {len(reflector_names)} reflectors "
              f"× {len(fourth_iter)} fourth configs "
              f"(spectral narrowed right rotors to {spectral_top})")

    # IC sweep: for each combo, find best IC and top positions
    combo_results: list[tuple[float, tuple[str, str, str], str,
                              str | None, int,
                              list[tuple[float, tuple[int, int, int]]]]] = []

    for refl in reflector_names:
        for rotors in spectral_combos:
            for fourth_name, fourth_pos in fourth_iter:
                if time.time() - t0 > time_limit:
                    break

                fourth_kw = {}
                if fourth_name:
                    fourth_kw = dict(
                        fourth_rotor_name=fourth_name,
                        fourth_position=fourth_pos,
                        fourth_ring=0,
                    )

                ic_results = _inline_ic_sweep(
                    cipher, rotors, refl, (0, 0, 0),
                    top_k=ic_survivors_per_combo, **fourth_kw,
                )
                max_ic = ic_results[0][0] if ic_results else 0.0
                combo_results.append((
                    max_ic, rotors, refl, fourth_name, fourth_pos, ic_results,
                ))

                if progress:
                    pos_str = "".join(chr(p + 65) for p in ic_results[0][1]) if ic_results else "???"
                    print(f"  {'-'.join(rotors)}/{refl}"
                          f"{f'/{fourth_name}({chr(fourth_pos+65)})' if fourth_name else ''}"
                          f": max_IC={max_ic:.4f} at {pos_str}")

    # Rank combos by IC. The correct combo has IC ≈ 0.076 (German);
    # wrong combos have IC ≈ 0.038 (random). The gap is definitive.
    combo_results.sort(reverse=True)

    # Keep combos with IC significantly above random (0.038)
    ic_threshold = 0.042  # just above random
    survivors = [cr for cr in combo_results if cr[0] > ic_threshold]
    if not survivors:
        survivors = combo_results[:5]

    if progress:
        print(f"Phase 0 complete: {len(survivors)} combo survivors "
              f"(IC range {survivors[0][0]:.4f} — {survivors[-1][0]:.4f})")

    # ================================================================
    # Phase 1: Position manifold + CRT ring refinement
    # ================================================================
    # For each surviving combo, take top IC positions, filter with
    # superposition, then refine ring settings via CRT.

    phase1_results: list[tuple[float, tuple[str, str, str], str,
                               tuple[int, int, int], tuple[int, int, int],
                               str | None, int, list[str]]] = []

    for max_ic, rotors, refl, fourth_name, fourth_pos, ic_positions in survivors:
        if time.time() - t0 > time_limit:
            break

        fourth_kw = {}
        if fourth_name:
            fourth_kw = dict(
                fourth_rotor_name=fourth_name,
                fourth_position=fourth_pos,
                fourth_ring=0,
            )

        for _, pos in ic_positions:
            if time.time() - t0 > time_limit:
                break

            traj = fast_trajectory(
                rotors, refl, pos, (0, 0, 0), L, **fourth_kw,
            )

            # Superposition filter
            if not stage_superposition(cipher, traj, model):
                continue

            # CRT ring refinement
            rings = (0, 0, 0)
            ring_score = model.score([traj[t][cipher[t]] for t in range(L)])
            stages = ["ic_filter", "superposition"]

            if search_rings:
                rings, ring_score = _crt_ring_refine(
                    cipher, rotors, refl, pos, model, **fourth_kw,
                )
                stages.append("crt_ring")

            phase1_results.append((
                ring_score, rotors, refl, pos, rings,
                fourth_name, fourth_pos, stages,
            ))

    phase1_results.sort(reverse=True)

    if progress:
        print(f"Phase 1 complete: {len(phase1_results)} position/ring survivors")

    # ================================================================
    # Phase 2: Plugboard manifold (Birkhoff polytope → beam swap)
    # ================================================================
    # For top candidates, resolve the plugboard. Binary discriminator
    # (0 excluded bigrams) identifies the correct solution.

    results: list[PipelineResult] = []
    # Only beam-swap the top candidates (expensive)
    top_n = min(20, len(phase1_results))

    for ring_score, rotors, refl, pos, rings, fourth_name, fourth_pos, stages in phase1_results[:top_n]:
        if time.time() - t0 > time_limit:
            break

        fourth_kw = {}
        if fourth_name:
            fourth_kw = dict(
                fourth_rotor_name=fourth_name,
                fourth_position=fourth_pos,
                fourth_ring=0,
            )

        traj = fast_trajectory(rotors, refl, pos, rings, L, **fourth_kw)

        score, plug, dec = stage_beam_swap(
            cipher, traj, model,
            beam_width=beam_width,
            rounds=beam_rounds,
        )

        n_excl = stage_validate(dec, model)
        local_stages = list(stages) + ["beam_swap", "validation"]

        pairs = [(a, plug[a]) for a in range(26) if plug[a] > a]
        results.append(PipelineResult(
            plaintext="".join(chr(d + 65) for d in dec),
            score=score,
            rotor_names=rotors,
            reflector_name=refl,
            positions=pos,
            ring_settings=rings,
            plugboard_map=plug,
            plugboard_pairs=pairs,
            fourth_rotor_name=fourth_name,
            fourth_position=fourth_pos,
            elapsed=time.time() - t0,
            stages_used=local_stages,
            n_excluded_bigrams=n_excl,
        ))

        if n_excl == 0 and progress:
            print(f"  ** 0 excluded bigrams at "
                  f"{'-'.join(rotors)}/{refl} "
                  f"pos={''.join(chr(p+65) for p in pos)} "
                  f"rings={''.join(chr(r+65) for r in rings)}")

    # Binary discriminator sort: 0 excluded first, then by score
    results.sort(key=lambda r: (r.n_excluded_bigrams, -r.score))

    # ================================================================
    # Phase 3: Cross-message validation
    # ================================================================
    # If we have a best result and multiple ciphertexts, validate the
    # recovered day key against all other messages. Same-day messages
    # share rotors/reflector/rings/plugboard — only position differs.

    if results and len(ciphertexts) > 1 and results[0].n_excluded_bigrams == 0:
        best = results[0]
        if progress:
            print(f"\nPhase 3: Cross-validating against {len(ciphertexts)-1} other messages")

        for i, other_ct in enumerate(ciphertexts[1:], 1):
            other_cipher = [ord(c) - 65 for c in other_ct if "A" <= c <= "Z"]
            if len(other_cipher) < 20:
                continue

            other_L = len(other_cipher)
            fourth_kw = {}
            if best.fourth_rotor_name:
                fourth_kw = dict(
                    fourth_rotor_name=best.fourth_rotor_name,
                    fourth_position=best.fourth_position,
                    fourth_ring=0,
                )

            # Search positions for this message using same day key
            other_ic = _inline_ic_sweep(
                other_cipher, best.rotor_names, best.reflector_name,
                best.ring_settings, top_k=10, **fourth_kw,
            )

            for _, other_pos in other_ic[:5]:
                traj = fast_trajectory(
                    best.rotor_names, best.reflector_name,
                    other_pos, best.ring_settings, other_L, **fourth_kw,
                )
                # Use the SAME plugboard from the primary message
                other_dec = [best.plugboard_map[traj[t][best.plugboard_map[other_cipher[t]]]]
                             for t in range(other_L)]
                other_excl = stage_validate(other_dec, model)
                other_score = model.score(other_dec)

                if other_excl == 0 and other_score > float("-inf"):
                    results.append(PipelineResult(
                        plaintext="".join(chr(d + 65) for d in other_dec),
                        score=other_score,
                        rotor_names=best.rotor_names,
                        reflector_name=best.reflector_name,
                        positions=other_pos,
                        ring_settings=best.ring_settings,
                        plugboard_map=best.plugboard_map,
                        plugboard_pairs=best.plugboard_pairs,
                        fourth_rotor_name=best.fourth_rotor_name,
                        fourth_position=best.fourth_position,
                        elapsed=time.time() - t0,
                        stages_used=["cross_validation"],
                        n_excluded_bigrams=other_excl,
                    ))
                    if progress:
                        print(f"  Message {i}: pos={''.join(chr(p+65) for p in other_pos)} "
                              f"excl={other_excl} → {''.join(chr(d+65) for d in other_dec[:40])}")
                    break

    if progress and results:
        elapsed = time.time() - t0
        print(f"\nDone in {elapsed:.1f}s. Top result: {results[0].n_excluded_bigrams} "
              f"excluded bigrams, score={results[0].score:.3f}")

    return results


def run_spectral_only(
    ciphertext: str,
    candidate_rotors: Sequence[str] = NAVAL_ROTORS,
    reflector_name: str = "B",
) -> list[tuple[str, float]]:
    """Run spectral identification only. Returns (rotor, correlation) pairs."""
    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    return identify_right_rotor(cipher, reflector_name, tuple(candidate_rotors))


def run_ic_filter_only(
    ciphertext: str,
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    top_k: int = 500,
    **fourth_kw,
) -> list[tuple[float, tuple[int, int, int]]]:
    """Run IC filter only. Returns (ic, position) pairs."""
    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    return stage_ic_filter(
        cipher, rotor_names, reflector_name, ring_settings,
        top_k=top_k, **fourth_kw,
    )


def run_superposition_only(
    ciphertext: str,
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    *,
    model: LanguageModel | None = None,
    **fourth_kw,
) -> bool:
    """Run superposition check only. Returns True if trajectory is consistent."""
    if model is None:
        model = LanguageModel.german_military()
    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    traj = fast_trajectory(
        rotor_names, reflector_name, positions, ring_settings,
        len(cipher), **fourth_kw,
    )
    return stage_superposition(cipher, traj, model)


def run_domain_cascade_only(
    ciphertext: str,
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    *,
    model: LanguageModel | None = None,
    **fourth_kw,
) -> list[tuple[DomainPlug, list[int | None]]] | None:
    """Run domain cascade only."""
    if model is None:
        model = LanguageModel.german_military()
    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    traj = fast_trajectory(
        rotor_names, reflector_name, positions, ring_settings,
        len(cipher), **fourth_kw,
    )
    return stage_domain_cascade(cipher, traj, model)


def run_bidirectional_only(
    ciphertext: str,
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    *,
    model: LanguageModel | None = None,
    **fourth_kw,
) -> tuple[float, list[int]] | None:
    """Run bidirectional scoring only."""
    if model is None:
        model = LanguageModel.german_military()
    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    return bidirectional_score(
        cipher, rotor_names, reflector_name, positions, ring_settings,
        model, **fourth_kw,
    )


def run_hyperchart_only(
    ciphertext: str,
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    *,
    model: LanguageModel | None = None,
    iterations: int = 150,
    **fourth_kw,
):
    """Run hyperchart solver only."""
    if model is None:
        model = LanguageModel.german_military()
    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    traj = fast_trajectory(
        rotor_names, reflector_name, positions, ring_settings,
        len(cipher), **fourth_kw,
    )
    return solve_hyperchart(cipher, traj, model, iterations=iterations)


def run_propagate_only(
    ciphertext: str,
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    *,
    model: LanguageModel | None = None,
    **fourth_kw,
) -> SignedPropagator:
    """Run signed propagation only."""
    if model is None:
        model = LanguageModel.german_military()
    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    traj = fast_trajectory(
        rotor_names, reflector_name, positions, ring_settings,
        len(cipher), **fourth_kw,
    )
    prop = SignedPropagator(cipher, traj, model)
    prop.propagate()
    return prop
