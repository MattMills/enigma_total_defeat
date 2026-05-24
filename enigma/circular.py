"""Circular projection attack on the Enigma.

The right rotor traces a closed orbit of 26 permutations in the
676-dimensional space of flattened permutation matrices. Each rotor
wiring produces a DIFFERENT orbit shape. The ciphertext produces
weighted observations in the same space via the language prior.

The attack:
  1. UP: embed each rotor's 26-position orbit into R^676.
  2. ACROSS: embed the ciphertext as weighted observations in R^676
     using German letter frequencies as soft plaintext hypotheses.
  3. DOWN: circular cross-correlation between orbit and observations
     → a function on the 26-element circle Z/26Z.
  4. CIRCLE: the peak of this function gives the starting position;
     the amplitude gives the rotor match quality.

This identifies the right rotor AND its starting position in one pass
over the ciphertext, without trying all 17,576 position combinations.
The middle/left rotors contribute a CONSTANT offset (for positions
before the first turnover) which shifts all correlations equally —
it doesn't change which rotor or which position wins.
"""

from __future__ import annotations

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
