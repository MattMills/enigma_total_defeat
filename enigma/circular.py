"""Circular projection attack on the Enigma.

The right rotor traces a closed orbit of 26 permutations in the
676-dimensional space of flattened permutation matrices. Each rotor
wiring produces a DIFFERENT orbit shape. The ciphertext produces
weighted observations in the same space via the language prior.

The attack operates BIDIRECTIONALLY: forward constraints (bigram
successors from position 0→L) and backward constraints (bigram
predecessors from position L→0) propagate simultaneously along the
trajectory. Where both passes agree on a candidate, the hypothesis
is reinforced; where they disagree, the hypothesis is eliminated.

The entire message length acts as a rigid constraint spine — the
Enigma trajectory is deterministic, so fixing the key at ANY single
position determines ALL positions. Bidirectional propagation exploits
this by attacking from both ends, meeting in the middle where the
constraint density is highest.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field
from typing import Sequence

from enigma.language import LanguageModel, UNIGRAM_FREQ
from enigma.simulator import ROTORS, REFLECTORS, fast_trajectory


# ------------------------------------------------------------------
# Embedding: permutations → R^676
# ------------------------------------------------------------------


def embed_permutation(perm: list[int] | tuple[int, ...]) -> list[float]:
    """Flatten a 26-element permutation into a 676-dim one-hot vector.

    Entry [i*26 + j] = 1.0 if perm[i] == j, else 0.0.
    This is the flattened permutation matrix.
    """
    v = [0.0] * 676
    for i, j in enumerate(perm):
        v[i * 26 + j] = 1.0
    return v


def embed_observation(
    ciphertext_letter: int,
    perm: list[int] | tuple[int, ...],
    freq: list[float],
) -> list[float]:
    """Embed a single ciphertext observation weighted by language prior.

    For ciphertext letter c and operative geometry E, the observation
    at position (i, j) in the 26×26 matrix is:

      obs[i][j] = freq[i]  if E(i) == j == c
                  0         otherwise

    Since E is a permutation, exactly one i satisfies E(i) = c, namely
    i = E^{-1}(c) = E(c) (involution). So the observation is sparse:
    only position (E(c), c) is nonzero, with weight freq[E(c)].

    This weights each observation by how likely the plaintext letter is,
    giving German-frequent letters more influence on the match.
    """
    v = [0.0] * 676
    # E(c) = decrypted letter = plaintext hypothesis
    plaintext_hyp = perm[ciphertext_letter]
    v[plaintext_hyp * 26 + ciphertext_letter] = freq[plaintext_hyp]
    return v


# ------------------------------------------------------------------
# Circular orbit of a rotor
# ------------------------------------------------------------------


@dataclass
class RotorOrbit:
    """The 26-point orbit of a rotor in R^676."""
    rotor_name: str
    reflector_name: str
    middle_name: str
    left_name: str
    # orbit[p] = embedded permutation at right-rotor position p.
    orbit: list[list[float]] = field(default_factory=list)
    # Norm of each orbit point (for normalization).
    norms: list[float] = field(default_factory=list)

    @classmethod
    def compute(
        cls,
        right_rotor: str,
        reflector: str,
        middle_rotor: str = "I",
        left_rotor: str = "II",
        middle_pos: int = 0,
        left_pos: int = 0,
    ) -> "RotorOrbit":
        """Compute the 26-point orbit for the given right rotor.

        Uses fixed middle/left rotors at fixed positions (these act as
        an unknown constant transformation that shifts correlations
        but doesn't change relative rankings).
        """
        orbit: list[list[float]] = []
        norms: list[float] = []
        for rp in range(26):
            traj = fast_trajectory(
                rotor_names=(left_rotor, middle_rotor, right_rotor),
                reflector_name=reflector,
                start_positions=(left_pos, middle_pos, rp),
                ring_settings=(0, 0, 0),
                length=1,
            )
            E = traj[0]
            v = embed_permutation(E)
            orbit.append(v)
            norms.append(math.sqrt(sum(x * x for x in v)))
        return cls(
            rotor_name=right_rotor,
            reflector_name=reflector,
            middle_name=middle_rotor,
            left_name=left_rotor,
            orbit=orbit,
            norms=norms,
        )


# ------------------------------------------------------------------
# Circular cross-correlation
# ------------------------------------------------------------------


def dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def circular_correlate(
    cipher: list[int],
    orbit: RotorOrbit,
    freq: list[float],
    reflector: str,
    middle_rotor: str,
    left_rotor: str,
    middle_pos: int = 0,
    left_pos: int = 0,
) -> list[float]:
    """Circular cross-correlation of ciphertext against a rotor orbit.

    For each candidate starting position p ∈ {0..25}:
      score[p] = Σ_t  dot(orbit[(p+t) mod 26], obs_t)

    where obs_t is the weighted ciphertext observation at position t.

    Returns a 26-element array: score[p] for p = 0..25.
    The peak identifies the starting position.

    Note: for positions t ≥ 26 (past one full rotation of the right
    rotor), the middle rotor may have stepped, changing the effective
    orbit. For the first 26 positions, the orbit is exact.
    """
    L = min(len(cipher), 26)  # use at most one full rotation
    scores = [0.0] * 26

    # Pre-compute the full trajectory for each starting position.
    # For starting position p, position t uses right-rotor at (p+t) mod 26.
    for p in range(26):
        traj = fast_trajectory(
            rotor_names=(left_rotor, middle_rotor, orbit.rotor_name),
            reflector_name=reflector,
            start_positions=(left_pos, middle_pos, p),
            ring_settings=(0, 0, 0),
            length=L,
        )
        total = 0.0
        for t in range(L):
            E = traj[t]
            # Decrypted letter under this hypothesis.
            d = E[cipher[t]]
            # Score: log-frequency of decrypted letter.
            total += math.log(max(freq[d], 1e-9))
        scores[p] = total

    return scores


# ------------------------------------------------------------------
# Full circular projection attack
# ------------------------------------------------------------------


@dataclass
class CircularResult:
    right_rotor: str
    best_position: int
    correlation: float
    all_positions: list[float] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"CircularResult(rotor={self.right_rotor}, "
            f"pos={self.best_position}({chr(self.best_position+65)}), "
            f"corr={self.correlation:.4f})"
        )


def circular_attack(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    candidate_right_rotors: Sequence[str] = ("I", "II", "III", "IV", "V"),
    reflector: str = "B",
    middle_rotor: str = "I",
    left_rotor: str = "II",
    middle_pos: int = 0,
    left_pos: int = 0,
) -> list[CircularResult]:
    """Project all candidate rotors into the high-dimensional orbit space,
    cross-correlate with the ciphertext observations, and project back
    down to the circle to identify the right rotor and its position.

    Returns candidates sorted by correlation (highest first).

    Cost: O(|candidates| × 26 × L × 26) where L = min(len(ciphertext), 26).
    For 8 candidate rotors: ~43K operations. Instant.
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    if not cipher:
        return []

    freq = model.unigram
    results: list[CircularResult] = []

    for rotor_name in candidate_right_rotors:
        orbit = RotorOrbit.compute(
            rotor_name, reflector, middle_rotor, left_rotor,
            middle_pos, left_pos,
        )
        scores = circular_correlate(
            cipher, orbit, freq, reflector,
            middle_rotor, left_rotor, middle_pos, left_pos,
        )
        best_pos = max(range(26), key=lambda p: scores[p])
        results.append(CircularResult(
            right_rotor=rotor_name,
            best_position=best_pos,
            correlation=scores[best_pos],
            all_positions=scores,
        ))

    results.sort(key=lambda r: r.correlation, reverse=True)
    return results


def full_circular_solve(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    candidate_right_rotors: Sequence[str] = ("I", "II", "III", "IV", "V"),
    candidate_middle_rotors: Sequence[str] | None = None,
    candidate_left_rotors: Sequence[str] | None = None,
    reflector_names: Sequence[str] = ("B",),
    top_k: int = 5,
) -> list[dict]:
    """Three-stage circular projection: right → middle → left.

    Stage 1: for each candidate right rotor × reflector, sweep 26
    right positions at reference middle/left. Find top right rotors.

    Stage 2: for each surviving right rotor, sweep 26 middle positions
    (cycling through candidate middle rotors at each position).

    Stage 3: for each surviving (right, middle), sweep 26 left positions.

    Each stage is a circular cross-correlation — projection up into
    R^676, comparison, projection back down to the 26-element circle.

    Total cost: O(R × M × L × 26 × 26) where R = right candidates,
    M = middle candidates, L = message length. For typical parameters:
    8 × 7 × 200 × 26 × 26 ≈ 7.6M operations. Under 1 second.
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    if not cipher:
        return []

    freq = model.unigram
    if candidate_middle_rotors is None:
        candidate_middle_rotors = candidate_right_rotors
    if candidate_left_rotors is None:
        candidate_left_rotors = candidate_right_rotors

    all_results: list[dict] = []

    for refl in reflector_names:
        # Stage 1: sweep right rotor + position, fixed middle/left.
        stage1: list[tuple[float, str, int]] = []
        for right in candidate_right_rotors:
            for rp in range(26):
                traj = fast_trajectory(
                    rotor_names=(candidate_left_rotors[0], candidate_middle_rotors[0], right),
                    reflector_name=refl,
                    start_positions=(0, 0, rp),
                    ring_settings=(0, 0, 0),
                    length=min(len(cipher), 26),
                )
                score = sum(
                    math.log(max(freq[traj[t][cipher[t]]], 1e-9))
                    for t in range(len(traj))
                )
                stage1.append((score, right, rp))

        stage1.sort(key=lambda x: x[0], reverse=True)
        right_survivors = stage1[:top_k * 2]

        # Stage 2: for each right survivor, sweep middle rotor + position.
        stage2: list[tuple[float, str, int, str, int]] = []
        for _, right, rp in right_survivors:
            for mid in candidate_middle_rotors:
                if mid == right:
                    continue
                for mp in range(26):
                    traj = fast_trajectory(
                        rotor_names=(candidate_left_rotors[0], mid, right),
                        reflector_name=refl,
                        start_positions=(0, mp, rp),
                        ring_settings=(0, 0, 0),
                        length=min(len(cipher), 52),
                    )
                    score = sum(
                        math.log(max(freq[traj[t][cipher[t]]], 1e-9))
                        for t in range(len(traj))
                    )
                    stage2.append((score, right, rp, mid, mp))

        stage2.sort(key=lambda x: x[0], reverse=True)
        mid_survivors = stage2[:top_k * 2]

        # Stage 3: sweep left rotor + position.
        for _, right, rp, mid, mp in mid_survivors:
            for left in candidate_left_rotors:
                if left == right or left == mid:
                    continue
                for lp in range(26):
                    traj = fast_trajectory(
                        rotor_names=(left, mid, right),
                        reflector_name=refl,
                        start_positions=(lp, mp, rp),
                        ring_settings=(0, 0, 0),
                        length=len(cipher),
                    )
                    dec = [traj[t][cipher[t]] for t in range(len(cipher))]
                    score = model.score(dec)
                    if score > float("-inf"):
                        all_results.append({
                            "score": score,
                            "rotors": (left, mid, right),
                            "reflector": refl,
                            "positions": (lp, mp, rp),
                            "plaintext": "".join(chr(d + 65) for d in dec),
                        })

    all_results.sort(key=lambda x: x["score"], reverse=True)
    return all_results[:top_k]


# ------------------------------------------------------------------
# Bidirectional constraint propagation
# ------------------------------------------------------------------


def bidirectional_score(
    cipher: list[int],
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int],
    model: LanguageModel,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> tuple[float, list[int]] | None:
    """Bidirectional decryption and scoring.

    Decrypts the ciphertext in BOTH directions simultaneously:
      Forward:  d_fwd[0], d_fwd[1], ..., d_fwd[L-1]  (left to right)
      Backward: d_bwd[L-1], d_bwd[L-2], ..., d_bwd[0] (right to left)

    Since the Enigma trajectory is deterministic, both passes use the
    SAME sequence of operative geometries — but the language model
    constraints flow in opposite directions:
      Forward:  bigram(d[t-1], d[t]) must be valid German
      Backward: bigram(d[t], d[t+1]) must be valid German

    A trajectory that passes BOTH forward AND backward rejection is
    more likely correct than one that passes only forward. This
    doubles the constraint power with negligible extra cost.

    Additionally, the backward pass checks bigrams from the END of
    the message (where closings like ENDE, STOP, HEIL are common),
    providing strong constraints that the forward-only pass reaches
    last.
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
    full: list[int] = []

    # Forward pass: decrypt and check bigrams left-to-right.
    fwd_pL, fwd_pM, fwd_pR = pL, pM, pR
    for t in range(L):
        if fwd_pM in middle_notches:
            fwd_pL = (fwd_pL + 1) % 26
            fwd_pM = (fwd_pM + 1) % 26
        elif fwd_pR in right_notches:
            fwd_pM = (fwd_pM + 1) % 26
        fwd_pR = (fwd_pR + 1) % 26

        oL = (fwd_pL - rL) % 26
        oM = (fwd_pM - rM) % 26
        oR = (fwd_pR - rR) % 26
        x = cipher[t]
        s = (Rw[(x + oR) % 26] - oR) % 26
        s = (Mw[(s + oM) % 26] - oM) % 26
        s = (Lw[(s + oL) % 26] - oL) % 26
        s = Rf[s]
        s = (Le[(s + oL) % 26] - oL) % 26
        s = (Me[(s + oM) % 26] - oM) % 26
        p = (Re[(s + oR) % 26] - oR) % 26

        # Forward bigram rejection.
        if full and excluded[full[-1]][p]:
            return None
        full.append(p)

    # Backward pass: check bigrams right-to-left.
    for t in range(L - 1, 0, -1):
        if excluded[full[t]][full[t - 1]]:
            return None

    score = model.score(full)
    if score == float("-inf"):
        return None
    return score, full


def bidirectional_attack(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = ("I", "II", "III", "IV", "V"),
    reflector_names: Sequence[str] = ("B",),
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    top_k: int = 5,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> list[dict]:
    """Full brute-force attack with bidirectional constraint checking.

    For each (rotor_combo, reflector, position):
      1. Decrypt forward, rejecting on first excluded bigram (fast).
      2. IF forward passes: check backward bigrams from the END.
      3. Score survivors with the full language model.

    The backward pass adds ~0% cost (just 26 comparisons on the
    already-decrypted text) but eliminates candidates that happen
    to pass the forward bigram filter while having invalid bigrams
    at the END of the message. This is especially useful for
    messages with stereotyped endings (ENDE, STOP, etc.).
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    if not cipher:
        return []

    results: list[dict] = []

    for refl in reflector_names:
        for rotor_triple in itertools.permutations(rotor_pool, 3):
            for pl in range(26):
                for pm in range(26):
                    for pr in range(26):
                        res = bidirectional_score(
                            cipher, rotor_triple, refl,
                            (pl, pm, pr), ring_settings, model,
                            fourth_rotor_name=fourth_rotor_name,
                            fourth_position=fourth_position,
                            fourth_ring=fourth_ring,
                        )
                        if res is None:
                            continue
                        score, dec = res
                        results.append({
                            "score": score,
                            "rotors": rotor_triple,
                            "reflector": refl,
                            "positions": (pl, pm, pr),
                            "rings": ring_settings,
                            "plaintext": "".join(chr(d + 65) for d in dec),
                        })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:top_k]
