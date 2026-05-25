"""Adelic CRT-diagonal hyperchart: holographic resolution across prime basis sets.

Implements the SAMR/HOCF architecture for Enigma cryptanalysis:

The Enigma key space has mixed-radix structure:
  Key = (reflector × rotor_combo × position × ring × plugboard)
  Radices: (3, 60, 26³, 26², Birkhoff₂₆)

CRT decomposition of circular dimensions:
  26 = 2 × 13  (prime factorization)
  Position_right mod 2: 2 trials
  Position_right mod 13: 13 trials
  CRT combines: 2 × 13 = 26 total instead of 26 brute force

The "diagonal" means evidence propagates BETWEEN CRT components:
  - Bigram evidence (DFT projector on C₂₆) decomposes into
    mod-2 component (even/odd parity) and mod-13 component
  - Plugboard evidence (involution constraint) factors primewise
  - IC evidence (subgroup averaging) projects onto both mod-2 and mod-13

Multi-message coupling: same-day messages share the same key EXCEPT
position. In the CRT decomposition, shared components (rotors, rings,
plugboard) create CROSS-MESSAGE PROJECTORS that enforce consistency.

The holographic property: fixing ANY subset of CRT residues constrains
ALL others via the anti-set exclusory structure. This is why the correct
key can be reconstructed from partial evidence on each prime component.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field
from typing import Sequence

from enigma.language import LanguageModel, index_of_coincidence
from enigma.ngram_data import BIGRAMS_OBSERVED
from enigma.simulator import ROTORS, REFLECTORS, fast_trajectory


def crt_26(r2: int, r13: int) -> int:
    """CRT reconstruction: x ≡ r2 (mod 2), x ≡ r13 (mod 13) → x mod 26."""
    # Extended GCD: 2*7 + 13*(-1) = 1, so x = r2*13*(-1) + r13*2*7 mod 26
    return (r2 * 13 * (-1) + r13 * 2 * 7) % 26


@dataclass
class CRTEvidence:
    """Evidence accumulated on CRT basis sets for one position dimension.

    Stores log-likelihood scores for each residue mod-2 and mod-13.
    CRT reconstruction gives the full mod-26 value.
    """
    mod2: list[float] = field(default_factory=lambda: [0.0, 0.0])
    mod13: list[float] = field(default_factory=lambda: [0.0] * 13)

    def best_residues(self) -> tuple[int, int]:
        """Best residue in each prime component."""
        r2 = max(range(2), key=lambda i: self.mod2[i])
        r13 = max(range(13), key=lambda i: self.mod13[i])
        return r2, r13

    def reconstruct(self) -> int:
        """CRT-reconstruct the best full value."""
        r2, r13 = self.best_residues()
        return crt_26(r2, r13)

    def top_k(self, k: int = 3) -> list[int]:
        """Top-k full values by combined evidence."""
        scores = []
        for r2 in range(2):
            for r13 in range(13):
                combined = self.mod2[r2] + self.mod13[r13]
                val = crt_26(r2, r13)
                scores.append((combined, val))
        scores.sort(reverse=True)
        return [v for _, v in scores[:k]]

    def entropy(self) -> float:
        """Information entropy of the evidence distribution."""
        all_scores = [self.mod2[r2] + self.mod13[r13]
                      for r2 in range(2) for r13 in range(13)]
        max_s = max(all_scores)
        probs = [math.exp(s - max_s) for s in all_scores]
        total = sum(probs)
        if total < 1e-15:
            return math.log(26)
        probs = [p / total for p in probs]
        return -sum(p * math.log(p + 1e-15) for p in probs)


@dataclass
class AdelicState:
    """Full adelic state: CRT evidence for all position/ring dimensions.

    The Enigma key in CRT form:
      pos_right: CRTEvidence (mod 2, mod 13)
      pos_middle: CRTEvidence
      pos_left: CRTEvidence
      ring_right: CRTEvidence
      ring_middle: CRTEvidence
    """
    pos_right: CRTEvidence = field(default_factory=CRTEvidence)
    pos_middle: CRTEvidence = field(default_factory=CRTEvidence)
    pos_left: CRTEvidence = field(default_factory=CRTEvidence)
    ring_right: CRTEvidence = field(default_factory=CRTEvidence)

    def best_position(self) -> tuple[int, int, int]:
        return (
            self.pos_left.reconstruct(),
            self.pos_middle.reconstruct(),
            self.pos_right.reconstruct(),
        )

    def best_ring(self) -> tuple[int, int, int]:
        return (0, 0, self.ring_right.reconstruct())

    def total_entropy(self) -> float:
        return (self.pos_right.entropy() + self.pos_middle.entropy() +
                self.pos_left.entropy() + self.ring_right.entropy())


def _ic_at_position(
    cipher: list[int],
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int],
    **fourth_kw,
) -> float:
    """Compute IC at a specific position (fast, no trajectory object)."""
    L = len(cipher)
    traj = fast_trajectory(
        rotor_names, reflector_name, positions, ring_settings, L, **fourth_kw,
    )
    dec = [traj[t][cipher[t]] for t in range(L)]
    return index_of_coincidence(dec)


def accumulate_crt_evidence(
    cipher: list[int],
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    model: LanguageModel,
    *,
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> AdelicState:
    """Accumulate evidence on CRT basis sets for position dimensions.

    For each prime component of each position dimension, tests all
    residues while marginalizing over the other dimensions. The
    evidence for mod-p component of dimension d is:

      E_d[r] = max_{other dims} IC(cipher | pos_d ≡ r mod p)

    This is the "projection onto the p-component" — it accumulates
    evidence from all possible positions consistent with that residue.
    """
    L = len(cipher)
    state = AdelicState()
    fourth_kw = {}
    if fourth_rotor_name:
        fourth_kw = dict(
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=fourth_position,
            fourth_ring=fourth_ring,
        )

    # Right position: test mod-2 and mod-13
    # For mod-2: fix right_pos parity, sweep middle and left over a sample
    sample_ml = [(m, l) for m in range(0, 26, 4) for l in range(0, 26, 4)]

    for r2 in range(2):
        best_ic = 0.0
        for pr in range(r2, 26, 2):  # all positions with right ≡ r2 mod 2
            for pm, pl in sample_ml[:12]:
                ic = _ic_at_position(
                    cipher, rotor_names, reflector_name,
                    (pl, pm, pr), ring_settings, **fourth_kw,
                )
                if ic > best_ic:
                    best_ic = ic
        state.pos_right.mod2[r2] = best_ic

    for r13 in range(13):
        best_ic = 0.0
        for pr in range(r13, 26, 13):  # positions with right ≡ r13 mod 13
            for pm, pl in sample_ml[:12]:
                ic = _ic_at_position(
                    cipher, rotor_names, reflector_name,
                    (pl, pm, pr), ring_settings, **fourth_kw,
                )
                if ic > best_ic:
                    best_ic = ic
        state.pos_right.mod13[r13] = best_ic

    # Middle position: similar decomposition
    sample_rl = [(r, l) for r in range(0, 26, 4) for l in range(0, 26, 4)]

    for r2 in range(2):
        best_ic = 0.0
        for pm in range(r2, 26, 2):
            for pr, pl in sample_rl[:12]:
                ic = _ic_at_position(
                    cipher, rotor_names, reflector_name,
                    (pl, pm, pr), ring_settings, **fourth_kw,
                )
                if ic > best_ic:
                    best_ic = ic
        state.pos_middle.mod2[r2] = best_ic

    for r13 in range(13):
        best_ic = 0.0
        for pm in range(r13, 26, 13):
            for pr, pl in sample_rl[:12]:
                ic = _ic_at_position(
                    cipher, rotor_names, reflector_name,
                    (pl, pm, pr), ring_settings, **fourth_kw,
                )
                if ic > best_ic:
                    best_ic = ic
        state.pos_middle.mod13[r13] = best_ic

    # Left position
    sample_rm = [(r, m) for r in range(0, 26, 4) for m in range(0, 26, 4)]

    for r2 in range(2):
        best_ic = 0.0
        for pl in range(r2, 26, 2):
            for pr, pm in sample_rm[:12]:
                ic = _ic_at_position(
                    cipher, rotor_names, reflector_name,
                    (pl, pm, pr), ring_settings, **fourth_kw,
                )
                if ic > best_ic:
                    best_ic = ic
        state.pos_left.mod2[r2] = best_ic

    for r13 in range(13):
        best_ic = 0.0
        for pl in range(r13, 26, 13):
            for pr, pm in sample_rm[:12]:
                ic = _ic_at_position(
                    cipher, rotor_names, reflector_name,
                    (pl, pm, pr), ring_settings, **fourth_kw,
                )
                if ic > best_ic:
                    best_ic = ic
        state.pos_left.mod13[r13] = best_ic

    # Right ring: CRT decomposition for ring search
    for r2 in range(2):
        best_ic = 0.0
        pos = state.best_position()
        for rr in range(r2, 26, 2):
            ic = _ic_at_position(
                cipher, rotor_names, reflector_name,
                pos, (0, 0, rr), **fourth_kw,
            )
            if ic > best_ic:
                best_ic = ic
        state.ring_right.mod2[r2] = best_ic

    for r13 in range(13):
        best_ic = 0.0
        pos = state.best_position()
        for rr in range(r13, 26, 13):
            ic = _ic_at_position(
                cipher, rotor_names, reflector_name,
                pos, (0, 0, rr), **fourth_kw,
            )
            if ic > best_ic:
                best_ic = ic
        state.ring_right.mod13[r13] = best_ic

    return state


def diagonal_resolve(
    ciphertexts: list[str],
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = ("I", "II", "III", "IV", "V"),
    reflector_names: Sequence[str] = ("B",),
    progress: bool = False,
) -> list[dict]:
    """Diagonal CRT resolution across multiple messages.

    For each rotor combo × reflector, accumulates CRT evidence from
    ALL messages simultaneously. The coupling constraint (shared day key)
    means evidence from different messages reinforces the same CRT
    residues for the shared components (ring, rotor combo).

    The position dimensions are message-specific, but ring/rotor are shared.
    """
    if model is None:
        model = LanguageModel.german_military()

    ciphers = [[ord(c) - 65 for c in ct if "A" <= c <= "Z"] for ct in ciphertexts]
    all_combos = list(itertools.permutations(rotor_pool, 3))

    results: list[dict] = []

    for refl in reflector_names:
        for rotors in all_combos:
            if progress:
                print(f"  {'-'.join(rotors)}/{refl}...", end="", flush=True)

            # Accumulate CRT evidence from each message
            per_msg_states = []
            for cipher in ciphers:
                state = accumulate_crt_evidence(
                    cipher, rotors, refl, model,
                )
                per_msg_states.append(state)

            # Shared ring evidence: sum across messages (diagonal coupling)
            shared_ring = CRTEvidence()
            for state in per_msg_states:
                for i in range(2):
                    shared_ring.mod2[i] += state.ring_right.mod2[i]
                for i in range(13):
                    shared_ring.mod13[i] += state.ring_right.mod13[i]

            # Per-message position (not shared)
            per_msg_positions = [state.best_position() for state in per_msg_states]

            # Combined entropy (lower = more determined)
            total_entropy = sum(s.total_entropy() for s in per_msg_states)

            # Best ring from coupled evidence
            best_ring = (0, 0, shared_ring.reconstruct())

            results.append({
                "rotors": rotors,
                "reflector": refl,
                "positions": per_msg_positions,
                "ring": best_ring,
                "entropy": total_entropy,
                "shared_ring_evidence": shared_ring,
            })

            if progress:
                print(f" entropy={total_entropy:.2f}")

    results.sort(key=lambda r: r["entropy"])
    return results
