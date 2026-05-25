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
