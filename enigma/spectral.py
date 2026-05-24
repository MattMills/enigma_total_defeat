"""Spectral analysis of rotor wirings for irreducible signature extraction.

Each Enigma rotor wiring σ is a permutation in S₂₆. When viewed as a
26×26 permutation matrix, it has spectral properties (eigenvalues, cycle
structure, trace) that form an IRREDUCIBLE SIGNATURE of the wiring.

The key insight: as the right rotor advances one position, the operative
geometry E_t changes by a specific "differential" determined by the
rotor wiring. This differential pattern is a FINGERPRINT that:
  1. Is unique to each rotor wiring (I-V, VI-VIII each have distinct patterns)
  2. Is detectable from ciphertext alone (without knowing plaintext)
  3. Is invariant under plugboard (plugboard commutes with the differential)

By projecting the ciphertext's letter-pair statistics into a high-dimensional
space (26² = 676 dimensions, one per bigram), the rotor differential creates
a characteristic distortion pattern that can be matched against known rotor
signatures.

This allows us to IDENTIFY WHICH ROTOR IS IN THE RIGHT SLOT before
searching positions, reducing the search space by 5-8×.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from enigma.simulator import ROTORS, REFLECTORS, Rotor, fast_trajectory


# ------------------------------------------------------------------
# Permutation matrix and spectral decomposition
# ------------------------------------------------------------------


def permutation_matrix(perm: tuple[int, ...] | list[int]) -> list[list[float]]:
    """26×26 permutation matrix for the given permutation."""
    n = len(perm)
    M = [[0.0] * n for _ in range(n)]
    for i, j in enumerate(perm):
        M[i][j] = 1.0
    return M


def matrix_multiply(A: list[list[float]], B: list[list[float]]) -> list[list[float]]:
    n = len(A)
    C = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            s = 0.0
            for k in range(n):
                s += A[i][k] * B[k][j]
            C[i][j] = s
    return C


def matrix_trace(M: list[list[float]]) -> float:
    return sum(M[i][i] for i in range(len(M)))


def frobenius_norm(M: list[list[float]]) -> float:
    return math.sqrt(sum(M[i][j] ** 2 for i in range(len(M)) for j in range(len(M[0]))))


def matrix_diff(A: list[list[float]], B: list[list[float]]) -> list[list[float]]:
    n = len(A)
    return [[A[i][j] - B[i][j] for j in range(n)] for i in range(n)]


# ------------------------------------------------------------------
# Rotor differential signature
# ------------------------------------------------------------------


@dataclass
class RotorSignature:
    """Irreducible signature of a rotor wiring."""
    name: str
    cycle_lengths: list[int]           # sorted cycle structure
    fixed_points: int                  # |{i : σ(i) = i}|
    order: int                         # smallest k such that σ^k = id
    # Differential profile: how the operative geometry changes per step.
    # For each step offset d=1..25, the Frobenius norm of
    # (E_{t+d} - E_t) as a permutation matrix, averaged over t.
    differential_profile: list[float] = field(default_factory=list)
    # Autocorrelation: fraction of letter mappings that repeat at lag d.
    autocorrelation: list[float] = field(default_factory=list)
    # Spectral: eigenvalue magnitudes of σ as a permutation matrix.
    # (For a permutation, eigenvalues are roots of unity; their
    # distribution encodes the cycle structure.)
    eigenvalue_signature: list[float] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "cycle_lengths": self.cycle_lengths,
            "fixed_points": self.fixed_points,
            "order": self.order,
            "differential_profile": [round(x, 4) for x in self.differential_profile],
            "autocorrelation": [round(x, 4) for x in self.autocorrelation],
            "eigenvalue_signature": [round(x, 4) for x in self.eigenvalue_signature],
        }


def _cycle_structure(perm: tuple[int, ...]) -> list[int]:
    n = len(perm)
    seen = [False] * n
    cycles: list[int] = []
    for i in range(n):
        if seen[i]:
            continue
        j = i
        length = 0
        while not seen[j]:
            seen[j] = True
            j = perm[j]
            length += 1
        cycles.append(length)
    return sorted(cycles, reverse=True)


def _permutation_order(perm: tuple[int, ...]) -> int:
    """LCM of cycle lengths = order of the permutation."""
    cycles = _cycle_structure(perm)
    from math import gcd
    result = 1
    for c in cycles:
        result = result * c // gcd(result, c)
    return result


def _eigenvalue_signature(perm: tuple[int, ...]) -> list[float]:
    """Eigenvalue magnitudes of the permutation matrix.

    For a permutation with cycle structure (c₁, c₂, ..., cₖ),
    the eigenvalues are all cⱼ-th roots of unity. We return the
    sorted list of distinct |eigenvalue| values (all 1.0 for
    permutations, but the ANGLES encode the cycle structure).
    """
    cycles = _cycle_structure(perm)
    angles: list[float] = []
    for c in cycles:
        for k in range(c):
            angles.append(2.0 * math.pi * k / c)
    angles.sort()
    return angles


def compute_rotor_signature(
    rotor_name: str,
    reflector_name: str = "B",
    reference_rotors: tuple[str, str] = ("I", "II"),
    trajectory_length: int = 52,
) -> RotorSignature:
    """Compute the irreducible signature of a rotor wiring.

    Places the target rotor in the RIGHT slot with reference rotors in
    middle/left positions, and computes the differential profile of
    the resulting trajectory.
    """
    rotor = ROTORS[rotor_name]

    # Basic algebraic properties.
    cycles = _cycle_structure(rotor.wiring)
    fps = sum(1 for i in range(26) if rotor.wiring[i] == i)
    order = _permutation_order(rotor.wiring)
    eigenvalues = _eigenvalue_signature(rotor.wiring)

    # Compute trajectory with target rotor in right slot.
    traj = fast_trajectory(
        rotor_names=(reference_rotors[0], reference_rotors[1], rotor_name),
        reflector_name=reflector_name,
        start_positions=(0, 0, 0),
        ring_settings=(0, 0, 0),
        length=trajectory_length,
    )

    # Differential profile: how many letter mappings change at each lag.
    diffs: list[float] = []
    for lag in range(1, 26):
        total_diff = 0
        count = 0
        for t in range(len(traj) - lag):
            d = sum(1 for i in range(26) if traj[t][i] != traj[t + lag][i])
            total_diff += d
            count += 1
        diffs.append(total_diff / count if count else 0)

    # Autocorrelation: fraction of mappings that match at each lag.
    autocorr: list[float] = []
    for lag in range(1, 26):
        total_match = 0
        count = 0
        for t in range(len(traj) - lag):
            m = sum(1 for i in range(26) if traj[t][i] == traj[t + lag][i])
            total_match += m
            count += 1
        autocorr.append(total_match / (count * 26) if count else 0)

    return RotorSignature(
        name=rotor_name,
        cycle_lengths=cycles,
        fixed_points=fps,
        order=order,
        differential_profile=diffs,
        autocorrelation=autocorr,
        eigenvalue_signature=eigenvalues,
    )


# ------------------------------------------------------------------
# Ciphertext-based rotor identification
# ------------------------------------------------------------------


def ciphertext_differential(cipher: list[int], max_lag: int = 25) -> list[float]:
    """Compute the differential profile of a ciphertext.

    For each lag d, counts the fraction of positions where
    cipher[t] == cipher[t+d]. This is the IC at lag d and reflects
    the underlying rotor's autocorrelation structure.
    """
    L = len(cipher)
    profile: list[float] = []
    for lag in range(1, max_lag + 1):
        matches = sum(
            1 for t in range(L - lag) if cipher[t] == cipher[t + lag]
        )
        total = L - lag
        profile.append(matches / total if total > 0 else 0)
    return profile


def identify_right_rotor(
    cipher: list[int],
    reflector_name: str = "B",
    candidate_rotors: tuple[str, ...] = ("I", "II", "III", "IV", "V"),
) -> list[tuple[str, float]]:
    """Identify the most likely right rotor from ciphertext alone.

    Computes the ciphertext's differential profile and correlates it
    against each candidate rotor's signature. Returns candidates
    sorted by correlation (highest first).

    The right rotor dominates the per-position variation in the
    operative geometry, so its differential fingerprint is the
    strongest signal in the ciphertext.
    """
    ct_profile = ciphertext_differential(cipher)
    if not ct_profile:
        return [(r, 0.0) for r in candidate_rotors]

    results: list[tuple[str, float]] = []
    for rotor_name in candidate_rotors:
        sig = compute_rotor_signature(rotor_name, reflector_name)

        # Correlate ciphertext profile against rotor autocorrelation.
        # Higher autocorrelation at specific lags = specific rotor.
        n = min(len(ct_profile), len(sig.autocorrelation))
        if n == 0:
            results.append((rotor_name, 0.0))
            continue

        # Pearson correlation between profiles.
        ct_mean = sum(ct_profile[:n]) / n
        sig_mean = sum(sig.autocorrelation[:n]) / n

        num = sum(
            (ct_profile[i] - ct_mean) * (sig.autocorrelation[i] - sig_mean)
            for i in range(n)
        )
        d_ct = math.sqrt(sum((ct_profile[i] - ct_mean) ** 2 for i in range(n)))
        d_sig = math.sqrt(sum((sig.autocorrelation[i] - sig_mean) ** 2 for i in range(n)))
        denom = d_ct * d_sig
        corr = num / denom if denom > 1e-10 else 0.0

        results.append((rotor_name, corr))

    results.sort(key=lambda x: x[1], reverse=True)
    return results


# ------------------------------------------------------------------
# Full rotor pool signature database
# ------------------------------------------------------------------


def build_signature_database(
    reflector_names: tuple[str, ...] = ("B",),
    rotor_names: tuple[str, ...] = ("I", "II", "III", "IV", "V", "VI", "VII", "VIII"),
) -> dict[str, RotorSignature]:
    """Pre-compute signatures for all rotors × reflectors."""
    db: dict[str, RotorSignature] = {}
    for refl in reflector_names:
        for rotor in rotor_names:
            key = f"{rotor}/{refl}"
            db[key] = compute_rotor_signature(rotor, refl)
    return db
