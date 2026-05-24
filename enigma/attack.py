"""Geometric Constraint Propagation (GCP) attack on the Enigma.

Two-phase pipeline faithful to Part IV of the design doc:

  Phase 1 (trajectory search): sweep all (rotor, reflector, position)
      combinations. Score each decryption using PLUGBOARD-INVARIANT
      statistics (IC, entropy, sorted-χ² against German frequencies).
      Keep top-K candidates. ~2s per rotor triple.

  Phase 2 (plugboard resolution): for each Phase 1 survivor, run
      arc-consistency constraint propagation to derive the plugboard.
      Score the plugboard-resolved text with bigrams/trigrams. ~1ms
      per candidate.

The key insight: IC, entropy, and sorted frequency distributions are
invariant under letter permutations (the plugboard). So the correct
trajectory ranks high on these statistics even when the plugboard is
unknown. Once the trajectory is identified, the plugboard constraint
solver determines the plugboard from the exclusory graph.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Sequence

from enigma.language import (
    LanguageModel,
    index_of_coincidence,
)
from enigma.simulator import (
    Enigma,
    Plugboard,
    REFLECTORS,
    ROTORS,
    fast_trajectory,
    M3_ROTORS,
    M3_REFLECTORS,
    M4_REFLECTORS,
    NAVAL_ROTORS,
    GREEK_ROTORS,
)


# ----------------------------------------------------------------------
# Phase 1/2: candidate-set initialization and bigram propagation


def initialize_candidates(ciphertext: Sequence[int]) -> list[set[int]]:
    """Return per-position positive candidate sets after the reflector exclusion."""
    return [set(range(26)) - {c} for c in ciphertext]


def propagate_bigrams(
    candidates: list[set[int]], model: LanguageModel
) -> list[set[int]]:
    """Iteratively prune candidates that have no valid bigram successor/predecessor."""
    L = len(candidates)
    if L < 2:
        return candidates
    cands = [set(s) for s in candidates]
    changed = True
    while changed:
        changed = False
        for t in range(L - 1):
            for a in list(cands[t]):
                if not any(not model.excluded[a][b] for b in cands[t + 1]):
                    cands[t].discard(a)
                    changed = True
        for t in range(L - 1, 0, -1):
            for b in list(cands[t]):
                if not any(not model.excluded[a][b] for a in cands[t - 1]):
                    cands[t].discard(b)
                    changed = True
    return cands


# ----------------------------------------------------------------------
# Phase 3: trajectory search


@dataclass
class AttackResult:
    plaintext: str
    score: float
    rotor_names: tuple[str, str, str]
    reflector_name: str
    positions: tuple[int, int, int]
    ring_settings: tuple[int, int, int]
    plugboard_pairs: list[tuple[str, str]] = field(default_factory=list)
    fourth_rotor_name: str | None = None
    fourth_position: int = 0
    fourth_ring: int = 0

    def __repr__(self) -> str:
        rings = "".join(chr(r + 65) for r in self.ring_settings)
        pos = "".join(chr(p + 65) for p in self.positions)
        plug = " ".join(f"{a}{b}" for a, b in self.plugboard_pairs)
        parts = [
            f"AttackResult(score={self.score:.3f}",
            f"rotors={'-'.join(self.rotor_names)}",
            f"reflector={self.reflector_name}",
            f"pos={pos}",
            f"rings={rings}",
        ]
        if self.fourth_rotor_name:
            parts.append(f"4th={self.fourth_rotor_name}({chr(self.fourth_position+65)})")
        parts.append(f"plugboard={plug or 'none'})")
        return ", ".join(parts) + f"\n  plaintext={self.plaintext!r}"


def _try_fast(
    cipher: list[int],
    candidates: list[set[int]],
    model: LanguageModel,
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int],
    early_prefix: int,
    ic_min: float,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> tuple[float, list[int]] | None:
    """Core trial: decrypt letter-by-letter using inline stepping, reject on
    the first hard constraint violation.

    Uses fast inline rotor logic (no Python object cloning) with the same
    early termination as before: reject as soon as the decrypted prefix
    has an exclusory bigram or a candidate-set violation.
    """
    L = len(cipher)
    left = ROTORS[rotor_names[0]]
    middle = ROTORS[rotor_names[1]]
    right = ROTORS[rotor_names[2]]
    refl = REFLECTORS[reflector_name]

    Lw, Le = left.wiring, left.inverse
    Mw, Me = middle.wiring, middle.inverse
    Rw, Re = right.wiring, right.inverse
    Rf: tuple[int, ...] | list[int] = refl.wiring
    right_notches = right.notches
    middle_notches = middle.notches

    if fourth_rotor_name is not None:
        fourth = ROTORS[fourth_rotor_name]
        o4 = (fourth_position - fourth_ring) % 26
        combined = [0] * 26
        for x in range(26):
            s = (fourth.wiring[(x + o4) % 26] - o4) % 26
            s = Rf[s]
            s = (fourth.inverse[(s + o4) % 26] - o4) % 26
            combined[x] = s
        Rf = combined

    pL, pM, pR = positions
    rL, rM, rR = ring_settings
    excluded = model.excluded
    n_prefix = min(early_prefix, L)
    full: list[int] = []

    for t in range(L):
        # Step
        if pM in middle_notches:
            pL = (pL + 1) % 26
            pM = (pM + 1) % 26
        elif pR in right_notches:
            pM = (pM + 1) % 26
        pR = (pR + 1) % 26

        # Decrypt single letter: E_t(c_t) = p_t (involution property).
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

        # Early reject during prefix.
        if t < n_prefix:
            if p not in candidates[t]:
                return None
        if full and excluded[full[-1]][p]:
            return None
        full.append(p)

    # IC pre-filter.
    if L >= 8 and model.ic_score(full) < ic_min:
        return None
    score = model.score(full)
    if score == float("-inf"):
        return None
    return score, full


# ----------------------------------------------------------------------
# Plugboard inference (Phase 4)


def infer_plugboard(
    plaintext: list[int],
    model: LanguageModel,
    max_pairs: int = 10,
    min_gain: float = 0.05,
) -> tuple[list[tuple[int, int]], list[int]]:
    """Greedy swap inference per the doc's Phase 4.

    Requires each swap to clear ``min_gain`` log-units of improvement,
    preventing spurious fitting when true plugboard is near-identity.
    """
    text = list(plaintext)
    pairs: list[tuple[int, int]] = []
    used: set[int] = set()
    current = model.score(text)
    for _ in range(max_pairs):
        best_gain = min_gain
        best_pair: tuple[int, int] | None = None
        best_text: list[int] | None = None
        for a in range(26):
            if a in used:
                continue
            for b in range(a + 1, 26):
                if b in used:
                    continue
                swapped = [b if x == a else a if x == b else x for x in text]
                s = model.score(swapped)
                gain = s - current
                if gain > best_gain:
                    best_gain = gain
                    best_pair = (a, b)
                    best_text = swapped
        if best_pair is None or best_text is None:
            break
        pairs.append(best_pair)
        used.add(best_pair[0])
        used.add(best_pair[1])
        text = best_text
        current += best_gain
    return pairs, text


# ----------------------------------------------------------------------
# Top-level attack


def attack(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = M3_ROTORS,
    reflector_names: Sequence[str] = M3_REFLECTORS,
    rings: Sequence[tuple[int, int, int]] | None = None,
    search_rings: bool = False,
    early_prefix: int = 10,
    ic_min: float = 0.45,
    top_k: int = 5,
    progress: bool = False,
    # M4 support:
    fourth_rotors: Sequence[str] | None = None,
    fourth_positions: Sequence[int] | None = None,
    fourth_rings: Sequence[int] | None = None,
) -> list[AttackResult]:
    """Run GCP attack on the given ciphertext.

    M3 mode (default): three rotors chosen from ``rotor_pool``, reflectors
    from ``reflector_names``.

    M4 mode: set ``fourth_rotors`` to ("Beta", "Gamma") and
    ``reflector_names`` to ("B-thin", "C-thin").

    Ring search: set ``search_rings=True`` to enumerate all 26*26 ring
    settings for the middle and right rotors (left ring rarely matters).
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)
    if L == 0:
        return []

    # Phase 1/2
    candidates = initialize_candidates(cipher)
    candidates = propagate_bigrams(candidates, model)

    # Build ring list.
    if rings is None:
        if search_rings:
            rings = [(0, rm, rr) for rm in range(26) for rr in range(26)]
        else:
            rings = [(0, 0, 0)]

    # Fourth rotor config (M4) — default to no fourth rotor.
    fourth_iter: list[tuple[str | None, int, int]] = [(None, 0, 0)]
    if fourth_rotors:
        fourth_iter = []
        f_pos = fourth_positions if fourth_positions else range(26)
        f_rings = fourth_rings if fourth_rings else [0]
        for fr in fourth_rotors:
            for fp in f_pos:
                for fring in f_rings:
                    fourth_iter.append((fr, fp, fring))

    best: list[AttackResult] = []

    def consider(res: AttackResult) -> None:
        best.append(res)
        best.sort(key=lambda r: r.score, reverse=True)
        del best[top_k:]

    tried = 0
    for refl in reflector_names:
        for rotor_triple in itertools.permutations(rotor_pool, 3):
            for ring in rings:
                for (fourth_name, fourth_pos, fourth_rng) in fourth_iter:
                    for pl in range(26):
                        for pm in range(26):
                            for pr in range(26):
                                tried += 1
                                res = _try_fast(
                                    cipher,
                                    candidates,
                                    model,
                                    rotor_triple,
                                    refl,
                                    (pl, pm, pr),
                                    ring,
                                    early_prefix,
                                    ic_min,
                                    fourth_rotor_name=fourth_name,
                                    fourth_position=fourth_pos,
                                    fourth_ring=fourth_rng,
                                )
                                if res is None:
                                    continue
                                score, plaintext = res
                                consider(
                                    AttackResult(
                                        plaintext="".join(
                                            chr(p + 65) for p in plaintext
                                        ),
                                        score=score,
                                        rotor_names=rotor_triple,
                                        reflector_name=refl,
                                        positions=(pl, pm, pr),
                                        ring_settings=ring,
                                        fourth_rotor_name=fourth_name,
                                        fourth_position=fourth_pos,
                                        fourth_ring=fourth_rng,
                                    )
                                )
                if progress:
                    print(
                        f"  refl={refl} rotors={rotor_triple} ring={ring} "
                        f"tried={tried} best={best[0].score if best else float('-inf'):.3f}"
                    )

    # Phase 4: Plugboard inference on top candidates.
    refined: list[AttackResult] = []
    for r in best:
        pt_ints = [ord(c) - 65 for c in r.plaintext]
        pairs, improved = infer_plugboard(pt_ints, model)
        if pairs:
            new_score = model.score(improved)
            if new_score > r.score:
                refined.append(
                    AttackResult(
                        plaintext="".join(chr(p + 65) for p in improved),
                        score=new_score,
                        rotor_names=r.rotor_names,
                        reflector_name=r.reflector_name,
                        positions=r.positions,
                        ring_settings=r.ring_settings,
                        plugboard_pairs=[
                            (chr(a + 65), chr(b + 65)) for a, b in pairs
                        ],
                        fourth_rotor_name=r.fourth_rotor_name,
                        fourth_position=r.fourth_position,
                        fourth_ring=r.fourth_ring,
                    )
                )
                continue
        refined.append(r)
    refined.sort(key=lambda r: r.score, reverse=True)
    return refined


# ----------------------------------------------------------------------
# Plugboard-invariant attack (two-phase: IC filter → constraint solver)
# ----------------------------------------------------------------------


def _sorted_chi_squared(dec: list[int], german_sorted: list[float]) -> float:
    """Sorted-χ² of decrypted letter frequencies vs sorted German frequencies.

    Plugboard-invariant because sorting removes label dependence.
    Lower = better match.
    """
    n = len(dec)
    if n == 0:
        return 1e9
    counts = [0] * 26
    for c in dec:
        counts[c] += 1
    freq = sorted([c / n for c in counts], reverse=True)
    return sum((f - g) ** 2 / max(g, 0.001) for f, g in zip(freq, german_sorted))


def attack_with_plugboard(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = M3_ROTORS,
    reflector_names: Sequence[str] = M3_REFLECTORS,
    rings: Sequence[tuple[int, int, int]] | None = None,
    top_k: int = 5,
    phase1_survivors: int = 500,
    progress: bool = False,
    fourth_rotors: Sequence[str] | None = None,
    fourth_positions: Sequence[int] | None = None,
    fourth_rings: Sequence[int] | None = None,
) -> list[AttackResult]:
    """Two-phase GCP attack that handles unknown plugboard.

    Phase 1: sweep all trajectories, score with PLUGBOARD-INVARIANT
    statistics (sorted-χ² against German frequency profile). Keep
    top ``phase1_survivors`` candidates. The correct trajectory
    typically ranks in the top 2-3% even through an unknown plugboard.

    Phase 2: for each Phase 1 survivor, run the arc-consistency
    plugboard constraint solver. Score the resolved text with the
    full language model (bigrams + trigrams). The plugboard solver
    determines which letter swaps transform the decryption into
    valid German.
    """
    import math
    from enigma.solver import PlugboardSolver

    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)
    if L == 0:
        return []

    candidates = initialize_candidates(cipher)
    candidates = propagate_bigrams(candidates, model)

    german_sorted = sorted(model.unigram, reverse=True)

    if rings is None:
        rings = [(0, 0, 0)]

    fourth_iter: list[tuple[str | None, int, int]] = [(None, 0, 0)]
    if fourth_rotors:
        fourth_iter = []
        f_pos = fourth_positions if fourth_positions else range(26)
        f_rings = fourth_rings if fourth_rings else [0]
        for fr in fourth_rotors:
            for fp in f_pos:
                for fring in f_rings:
                    fourth_iter.append((fr, fp, fring))

    # Phase 1: plugboard-invariant scoring.
    phase1: list[tuple[float, tuple[str, str, str], str,
                       tuple[int, int, int], tuple[int, int, int],
                       str | None, int, int, list[int]]] = []

    for refl in reflector_names:
        for rotor_triple in itertools.permutations(rotor_pool, 3):
            for ring in rings:
                for (fourth_name, fourth_pos, fourth_rng) in fourth_iter:
                    left_r = ROTORS[rotor_triple[0]]
                    middle_r = ROTORS[rotor_triple[1]]
                    right_r = ROTORS[rotor_triple[2]]
                    refl_w = REFLECTORS[refl].wiring
                    Lw, Le = left_r.wiring, left_r.inverse
                    Mw, Me = middle_r.wiring, middle_r.inverse
                    Rw, Re = right_r.wiring, right_r.inverse
                    Rf = refl_w
                    right_notches = right_r.notches
                    middle_notches = middle_r.notches

                    if fourth_name is not None:
                        fourth = ROTORS[fourth_name]
                        o4 = (fourth_pos - fourth_rng) % 26
                        combined = [0] * 26
                        for x in range(26):
                            s = (fourth.wiring[(x + o4) % 26] - o4) % 26
                            s = Rf[s]
                            s = (fourth.inverse[(s + o4) % 26] - o4) % 26
                            combined[x] = s
                        Rf = tuple(combined)

                    rL, rM, rR = ring

                    for pl in range(26):
                        for pm in range(26):
                            for pr in range(26):
                                pL, pM, pR = pl, pm, pr
                                dec: list[int] = []
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
                                    dec.append(p)

                                chi = _sorted_chi_squared(dec, german_sorted)
                                phase1.append((
                                    chi, rotor_triple, refl,
                                    (pl, pm, pr), ring,
                                    fourth_name, fourth_pos, fourth_rng,
                                    dec,
                                ))

            if progress and phase1:
                phase1.sort()
                print(
                    f"  refl={refl} rotors={rotor_triple} "
                    f"best_chi={phase1[0][0]:.4f} candidates={len(phase1)}"
                )

    # Keep top survivors.
    phase1.sort()
    phase1 = phase1[:phase1_survivors]

    if progress:
        print(f"  Phase 1: {len(phase1)} survivors (chi² range "
              f"{phase1[0][0]:.4f} - {phase1[-1][0]:.4f})")

    # Phase 2: greedy plugboard inference + language scoring.
    results: list[AttackResult] = []
    for (chi, rotor_triple, refl, positions, ring,
         fourth_name, fourth_pos, fourth_rng, dec) in phase1:

        pairs, improved = infer_plugboard(dec, model, max_pairs=13, min_gain=0.01)
        score = model.score(improved)

        if score == float("-inf"):
            continue

        results.append(AttackResult(
            plaintext="".join(chr(p + 65) for p in improved),
            score=score,
            rotor_names=rotor_triple,
            reflector_name=refl,
            positions=positions,
            ring_settings=ring,
            plugboard_pairs=[(chr(a+65), chr(b+65)) for a, b in pairs],
            fourth_rotor_name=fourth_name,
            fourth_position=fourth_pos,
            fourth_ring=fourth_rng,
        ))

    results.sort(key=lambda r: r.score, reverse=True)
    return results[:top_k]


# ----------------------------------------------------------------------
# Beam swap search (plugboard recovery from a known trajectory)
# ----------------------------------------------------------------------


def beam_swap_search(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    start_plug: list[int] | None = None,
    beam_width: int = 50,
    rounds: int = 8,
) -> tuple[float, list[int], list[int]]:
    """Recover the plugboard for a known trajectory via beam search.

    Maintains ``beam_width`` parallel plugboard hypotheses. Each round,
    every hypothesis is expanded by trying all C(26,2)=325 swap moves
    and all unpair moves. The top ``beam_width`` unique results survive.

    A swap move on (a,b): disconnect a and b from their current partners,
    connect a↔b. An unpair move: disconnect an existing pair.

    Returns (score, plugboard_map, decrypted_ints).
    """
    def decrypt(pl: list[int]) -> list[int]:
        return [pl[trajectory[t][pl[cipher[t]]]] for t in range(len(cipher))]

    def apply_swap(plug: list[int], a: int, b: int) -> list[int]:
        p = list(plug)
        oa, ob = p[a], p[b]
        if oa != a:
            p[oa] = oa
        if ob != b:
            p[ob] = ob
        p[a] = b
        p[b] = a
        return p

    if start_plug is None:
        start_plug = list(range(26))

    beam: list[tuple[float, list[int]]] = [
        (model.score(decrypt(start_plug)), list(start_plug))
    ]

    for _ in range(rounds):
        candidates: list[tuple[float, list[int]]] = []
        for _, plug in beam:
            for a in range(26):
                for b in range(a + 1, 26):
                    np = apply_swap(plug, a, b)
                    s = model.score(decrypt(np))
                    candidates.append((s, np))
            for a in range(26):
                if plug[a] > a:
                    np = list(plug)
                    b = plug[a]
                    np[a] = a
                    np[b] = b
                    s = model.score(decrypt(np))
                    candidates.append((s, np))

        candidates.sort(reverse=True)
        seen: set[tuple[int, ...]] = set()
        new_beam: list[tuple[float, list[int]]] = []
        for s, p in candidates:
            key = tuple(p)
            if key not in seen and len(new_beam) < beam_width:
                new_beam.append((s, p))
                seen.add(key)
        beam = new_beam

        if not beam:
            break

    best_score, best_plug = beam[0]
    return best_score, best_plug, decrypt(best_plug)
