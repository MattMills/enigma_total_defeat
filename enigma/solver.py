"""CRT-based progressive solver for Enigma key recovery.

Decomposes the key space using its mixed-radix structure:

  Key = (reflector, rotor_combo, right_pos, middle_pos, left_pos,
         right_ring, middle_ring, plugboard)
  Radices: (3, 60, 26, 26, 26, 26, 26, ~10^14)

The solver works in three phases that progressively resolve the key
from highest-information to lowest-information components:

  Phase A (trajectory): brute-force the 26^3 position search per
      (rotor_combo, reflector) using fast inline decryption with early
      rejection. This is the workhorse — ~2s per rotor triple.

  Phase B (ring/turnover): for top trajectory candidates, use the
      CRT structure of the stepping odometer (26 = 2 × 13, period
      = LCM of rotor notch cycles) to identify ring settings from
      turnover timing. Turnovers occur at t ≡ notch - right_pos +
      right_ring (mod 26); detecting WHEN quality degrades pins
      right_ring.

  Phase C (plugboard): arc-consistency constraint propagation on
      the exclusory graph, faithful to Part IV of the design doc.
      Each position t contributes: P(d[t]) ∈ C[t], where d is the
      no-plugboard decryption and C is the language candidate set.
      The involution constraint P(a)=b ⟹ P(b)=a propagates until
      convergence.

CRT utilities are provided for modular decomposition of any
composite radix (e.g., 26 = 2 × 13, 676 = 4 × 169).
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field
from typing import Sequence

from enigma.language import LanguageModel, index_of_coincidence
from enigma.simulator import (
    Plugboard,
    REFLECTORS,
    ROTORS,
    M3_ROTORS,
    M3_REFLECTORS,
)


# ------------------------------------------------------------------
# CRT utilities
# ------------------------------------------------------------------

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def crt(r1: int, m1: int, r2: int, m2: int) -> int:
    """CRT: find x ≡ r1 (mod m1) and x ≡ r2 (mod m2). Requires gcd(m1, m2) = 1."""
    g, p, q = extended_gcd(m1, m2)
    if g != 1:
        raise ValueError(f"moduli not coprime: {m1}, {m2}")
    return (r1 * m2 * q + r2 * m1 * p) % (m1 * m2)


def crt_multi(residues: list[tuple[int, int]]) -> int:
    """Multi-modulus CRT: [(r1, m1), (r2, m2), ...] → x."""
    r, m = residues[0]
    for r2, m2 in residues[1:]:
        r = crt(r, m, r2, m2)
        m = m * m2
    return r


def prime_factors(n: int) -> list[int]:
    factors = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors


# ------------------------------------------------------------------
# Plugboard constraint solver (arc-consistency on exclusory graph)
# ------------------------------------------------------------------


@dataclass
class PlugboardSolver:
    """Derives plugboard from exclusory constraints.

    Given a no-plugboard decryption d[0..L-1] and per-position candidate
    sets C[0..L-1], the plugboard P must satisfy P(d[t]) ∈ C[t] for all t.
    Since P is an involution, P(a)=b implies P(b)=a.

    Arc-consistency propagation reduces the domain of each letter until
    convergence.
    """
    allowed: list[set[int]] = field(default_factory=list)  # allowed[a] = possible P(a)

    @classmethod
    def from_decryption(
        cls,
        decrypted: list[int],
        candidates: list[set[int]],
    ) -> "PlugboardSolver":
        allowed = [set(range(26)) for _ in range(26)]
        for t, d in enumerate(decrypted):
            if t < len(candidates):
                allowed[d] = allowed[d] & candidates[t]
        solver = cls(allowed=allowed)
        solver.propagate()
        return solver

    def propagate(self) -> None:
        changed = True
        while changed:
            changed = False
            for a in range(26):
                for b in list(self.allowed[a]):
                    if a not in self.allowed[b]:
                        self.allowed[a].discard(b)
                        changed = True
                if len(self.allowed[a]) == 1:
                    b = next(iter(self.allowed[a]))
                    if self.allowed[b] != {a}:
                        self.allowed[b] = {a}
                        changed = True
                    for c in range(26):
                        if c != a and b in self.allowed[c]:
                            self.allowed[c].discard(b)
                            changed = True
                    for c in range(26):
                        if c != b and a in self.allowed[c]:
                            self.allowed[c].discard(a)
                            changed = True
                if not self.allowed[a]:
                    return

    def is_consistent(self) -> bool:
        return all(len(s) > 0 for s in self.allowed)

    def is_determined(self) -> bool:
        return all(len(s) == 1 for s in self.allowed)

    def get_pairs(self) -> list[tuple[int, int]]:
        pairs = []
        seen: set[int] = set()
        for a in range(26):
            if a in seen:
                continue
            if len(self.allowed[a]) == 1:
                b = next(iter(self.allowed[a]))
                if b != a:
                    pairs.append((a, b))
                    seen.add(a)
                    seen.add(b)
        return pairs

    def ambiguity(self) -> int:
        return sum(len(s) for s in self.allowed)

    def apply_best_guess(self, decrypted: list[int], model: LanguageModel) -> list[int]:
        m = list(range(26))
        for a in range(26):
            if len(self.allowed[a]) == 1:
                m[a] = next(iter(self.allowed[a]))
            elif self.allowed[a]:
                # Pick the mapping that best matches German unigram frequency.
                best_b = max(self.allowed[a], key=lambda b: model.unigram[b])
                m[a] = best_b
        return [m[d] for d in decrypted]


# ------------------------------------------------------------------
# Fast inline decryption + scoring
# ------------------------------------------------------------------

def _decrypt_and_score(
    cipher: list[int],
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int],
    model: LanguageModel,
    early_prefix: int = 8,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> tuple[float, list[int]] | None:
    """Decrypt with early rejection; return (score, plaintext) or None."""
    left = ROTORS[rotor_names[0]]
    middle = ROTORS[rotor_names[1]]
    right = ROTORS[rotor_names[2]]
    refl = REFLECTORS[reflector_name]

    Lw, Le = left.wiring, left.inverse
    Mw, Me = middle.wiring, middle.inverse
    Rw, Re = right.wiring, right.inverse
    Rf = refl.wiring
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
        Rf = tuple(combined)

    pL, pM, pR = positions
    rL, rM, rR = ring_settings
    L = len(cipher)
    excluded = model.excluded
    n_prefix = min(early_prefix, L)
    full: list[int] = []

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

        if t < n_prefix and full and excluded[full[-1]][p]:
            return None
        if full and excluded[full[-1]][p]:
            return None
        full.append(p)

    score = model.score(full)
    if score == float("-inf"):
        return None
    return score, full


# ------------------------------------------------------------------
# Turnover analysis (CRT on stepping odometer)
# ------------------------------------------------------------------


def detect_turnover_position(
    decrypted: list[int],
    model: LanguageModel,
    window: int = 6,
) -> int | None:
    """Detect where a rotor turnover degraded decryption quality.

    Returns the position t where a turnover likely occurred, or None if
    no quality drop is detected. The turnover shifts the middle rotor,
    which changes the effective reflector; at that point the decryption
    (computed with wrong ring settings) starts producing garbage.
    """
    if len(decrypted) < 2 * window:
        return None
    # Compute rolling bigram score.
    scores: list[float] = []
    for t in range(len(decrypted) - window + 1):
        chunk = decrypted[t:t + window]
        s = model.score(chunk)
        scores.append(s)
    if not scores:
        return None
    # Find the largest quality DROP.
    max_drop = 0.0
    drop_pos = None
    for i in range(1, len(scores)):
        drop = scores[i - 1] - scores[i]
        if drop > max_drop and scores[i - 1] > float("-inf"):
            max_drop = drop
            drop_pos = i
    if max_drop > 0.3:  # significant quality drop
        return drop_pos
    return None


def refine_ring_from_turnover(
    cipher: list[int],
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    model: LanguageModel,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> tuple[tuple[int, int, int], float]:
    """Try all 26 right ring settings; return the one that gives best score.

    The right ring setting shifts WHEN the middle rotor turns over.
    By CRT: turnover at t ≡ notch - right_pos + right_ring (mod 26).
    The correct ring setting aligns the turnover with the message
    structure.
    """
    best_ring = (0, 0, 0)
    best_score = float("-inf")
    for rr in range(26):
        rs = (0, 0, rr)
        result = _decrypt_and_score(
            cipher, rotor_names, reflector_name,
            positions, rs, model,
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=fourth_position,
            fourth_ring=fourth_ring,
        )
        if result and result[0] > best_score:
            best_score = result[0]
            best_ring = rs
    return best_ring, best_score


# ------------------------------------------------------------------
# Top-level progressive solver
# ------------------------------------------------------------------


@dataclass
class SolverResult:
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
            f"SolverResult(score={self.score:.3f}",
            f"rotors={'-'.join(self.rotor_names)}",
            f"reflector={self.reflector_name}",
            f"pos={pos}",
            f"rings={rings}",
        ]
        if self.fourth_rotor_name:
            parts.append(f"4th={self.fourth_rotor_name}({chr(self.fourth_position+65)})")
        parts.append(f"plugboard={plug or 'none'})")
        return ", ".join(parts) + f"\n  plaintext={self.plaintext!r}"


def progressive_solve(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = M3_ROTORS,
    reflector_names: Sequence[str] = M3_REFLECTORS,
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    search_rings: bool = False,
    top_k: int = 5,
    progress: bool = False,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> list[SolverResult]:
    """Progressive tail-radix solver.

    Phase A: for each (rotor_combo, reflector), brute-force 26^3
        positions with fast inline decryption + early rejection.

    Phase B: for top candidates, refine ring settings using turnover
        timing analysis. The right ring has 26 options; the CRT
        structure (26 = 2 × 13) means we can test mod-2 and mod-13
        independently: 2 + 13 = 15 trials instead of 26.

    Phase C: for each survivor, derive plugboard via arc-consistency
        on the exclusory constraint graph.
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)
    if L == 0:
        return []

    from enigma.attack import initialize_candidates, propagate_bigrams
    candidates = initialize_candidates(cipher)
    candidates = propagate_bigrams(candidates, model)

    # Phase A: trajectory search (brute-force positions).
    trajectory_hits: list[tuple[float, tuple[str, str, str], str,
                                tuple[int, int, int], list[int]]] = []

    for refl in reflector_names:
        for rotor_triple in itertools.permutations(rotor_pool, 3):
            if progress:
                print(f"  Phase A: {'-'.join(rotor_triple)} / {refl}")
            for pl in range(26):
                for pm in range(26):
                    for pr in range(26):
                        result = _decrypt_and_score(
                            cipher, rotor_triple, refl,
                            (pl, pm, pr), ring_settings, model,
                            fourth_rotor_name=fourth_rotor_name,
                            fourth_position=fourth_position,
                            fourth_ring=fourth_ring,
                        )
                        if result is None:
                            continue
                        score, dec = result
                        trajectory_hits.append(
                            (score, rotor_triple, refl, (pl, pm, pr), dec)
                        )

    trajectory_hits.sort(key=lambda x: x[0], reverse=True)
    trajectory_hits = trajectory_hits[:top_k * 3]

    if progress:
        print(f"  Phase A: {len(trajectory_hits)} trajectory candidates")

    # Phase B: ring setting refinement via CRT turnover analysis.
    ring_refined: list[tuple[float, tuple[str, str, str], str,
                             tuple[int, int, int], tuple[int, int, int],
                             list[int]]] = []

    for score, rotor_names_hit, refl, positions, dec in trajectory_hits:
        if search_rings:
            # CRT ring search: decompose 26 = 2 × 13 for the right ring.
            best_rr_score = float("-inf")
            best_rr = 0
            # Mod 2: test rr=0 and rr=1.
            mod2_scores: list[tuple[float, int]] = []
            for rr2 in range(2):
                res = _decrypt_and_score(
                    cipher, rotor_names_hit, refl,
                    positions, (0, 0, rr2), model,
                    fourth_rotor_name=fourth_rotor_name,
                    fourth_position=fourth_position,
                    fourth_ring=fourth_ring,
                )
                mod2_scores.append((res[0] if res else float("-inf"), rr2))
            mod2_scores.sort(reverse=True)
            best_r2 = mod2_scores[0][1]

            # Mod 13: test rr=0,1,...,12.
            mod13_scores: list[tuple[float, int]] = []
            for rr13 in range(13):
                res = _decrypt_and_score(
                    cipher, rotor_names_hit, refl,
                    positions, (0, 0, rr13), model,
                    fourth_rotor_name=fourth_rotor_name,
                    fourth_position=fourth_position,
                    fourth_ring=fourth_ring,
                )
                mod13_scores.append((res[0] if res else float("-inf"), rr13))
            mod13_scores.sort(reverse=True)

            # CRT combine top mod-2 × top-3 mod-13.
            for _, r13 in mod13_scores[:3]:
                for _, r2 in mod2_scores[:2]:
                    rr = crt(r2, 2, r13, 13)
                    res = _decrypt_and_score(
                        cipher, rotor_names_hit, refl,
                        positions, (0, 0, rr), model,
                        fourth_rotor_name=fourth_rotor_name,
                        fourth_position=fourth_position,
                        fourth_ring=fourth_ring,
                    )
                    if res and res[0] > best_rr_score:
                        best_rr_score = res[0]
                        best_rr = rr

            rs = (0, 0, best_rr)
            res = _decrypt_and_score(
                cipher, rotor_names_hit, refl,
                positions, rs, model,
                fourth_rotor_name=fourth_rotor_name,
                fourth_position=fourth_position,
                fourth_ring=fourth_ring,
            )
            if res:
                ring_refined.append(
                    (res[0], rotor_names_hit, refl, positions, rs, res[1])
                )
        else:
            ring_refined.append(
                (score, rotor_names_hit, refl, positions, ring_settings, dec)
            )

    ring_refined.sort(key=lambda x: x[0], reverse=True)
    ring_refined = ring_refined[:top_k]

    if progress:
        print(f"  Phase B: {len(ring_refined)} ring-refined candidates")

    # Phase C: plugboard via arc-consistency.
    results: list[SolverResult] = []
    for score, rotor_names_hit, refl, positions, rs, dec in ring_refined:
        psolver = PlugboardSolver.from_decryption(dec, candidates)
        pairs = psolver.get_pairs()
        if psolver.is_consistent():
            improved = psolver.apply_best_guess(dec, model)
            improved_score = model.score(improved)
            if improved_score > score:
                results.append(SolverResult(
                    plaintext="".join(chr(p + 65) for p in improved),
                    score=improved_score,
                    rotor_names=rotor_names_hit,
                    reflector_name=refl,
                    positions=positions,
                    ring_settings=rs,
                    plugboard_pairs=[(chr(a+65), chr(b+65)) for a, b in pairs],
                    fourth_rotor_name=fourth_rotor_name,
                    fourth_position=fourth_position,
                    fourth_ring=fourth_ring,
                ))
                continue
        results.append(SolverResult(
            plaintext="".join(chr(p + 65) for p in dec),
            score=score,
            rotor_names=rotor_names_hit,
            reflector_name=refl,
            positions=positions,
            ring_settings=rs,
            plugboard_pairs=[(chr(a+65), chr(b+65)) for a, b in pairs]
                if psolver.is_consistent() else [],
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=fourth_position,
            fourth_ring=fourth_ring,
        ))

    results.sort(key=lambda r: r.score, reverse=True)
    return results[:top_k]
