"""Hyperchart solver: projective multi-peak resolution on the Birkhoff polytope.

Each position t defines an INDIVIDUAL GEOMETRY: a 26×26 evidence tensor
T_t[a][b] encoding how strongly position t supports the hypothesis P(a)=b.

The UNIFIED GEOMETRY is the pointwise PRODUCT of all individual tensors:
  M[a][b] = Π_t T_t[a][b]

Multiplication (not addition) is critical: it SHARPENS peaks rather than
averaging them. A correct plugboard entry (a,b) gets multiplied by
evidence > 1 at every position where a appears as plaintext (~11 positions
for typical frequency), while wrong entries get multiplied by evidence < 1
at conflicting positions. The product diverges exponentially between
correct and incorrect entries.

Temperature annealing ensures multi-peak exploration:
  - High T: M is close to uniform (all vertices equally weighted).
    All peaks are represented in the superposition.
  - Low T: M concentrates on the strongest peak (correct plugboard).

The individual→unified projection is:
  T_t[a][b] = freq[a] · M[E_t(b)][c_t]  if a ≠ c_t
  T_t[a][b] = 1  otherwise (neutral)

This COUPLES two plugboard entries simultaneously: P(a)=b AND P(E_t(b))=c_t.
The coupling creates positive feedback — correct entries reinforce each
other across positions, driving the multi-peak landscape toward the
correct vertex.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from enigma.language import LanguageModel
from enigma.simulator import ROTORS, REFLECTORS, fast_trajectory


@dataclass
class HyperchartResult:
    plugboard_matrix: list[list[float]]
    plugboard_map: list[int]
    plugboard_pairs: list[tuple[int, int]]
    plaintext: str
    score: float
    convergence: list[float]

    def plug_str(self) -> str:
        return " ".join(chr(a+65) + chr(b+65) for a, b in self.plugboard_pairs)


def solve_hyperchart(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    iterations: int = 150,
    temp_start: float = 5.0,
    temp_end: float = 0.05,
) -> HyperchartResult:
    """Projective multi-peak resolution with temperature annealing.

    Each iteration:
      1. Compute per-position evidence tensors T_t (individual geometries).
      2. Accumulate the log-product Σ_t log T_t (unified geometry).
      3. Apply temperature: M[a][b] ∝ exp(unified[a][b] / T).
      4. Sinkhorn project to doubly-stochastic (Birkhoff polytope).
      5. Symmetrize (involution constraint P = P^{-1}).

    Temperature cools from temp_start to temp_end, ensuring all peaks
    are explored before collapsing to the strongest one.
    """
    L = len(cipher)
    freq = model.unigram

    # M: current estimate on the Birkhoff polytope.
    M = [[1.0 / 26] * 26 for _ in range(26)]

    convergence: list[float] = []

    for it in range(iterations):
        T = temp_start * (temp_end / temp_start) ** (it / max(iterations - 1, 1))

        # Accumulate unified evidence in log-space.
        log_evidence = [[0.0] * 26 for _ in range(26)]

        for t in range(L):
            c = cipher[t]
            E = trajectory[t]

            for a in range(26):
                if a == c:
                    continue
                w = freq[a]
                for b in range(26):
                    y = E[b]
                    # Evidence that P(a) = b at position t:
                    # If a is the plaintext at t, then P(a)=b and P(y)=c must hold.
                    # M[y][c] is the current belief that P(y) = c.
                    ev = w * M[y][c]
                    if ev > 1e-15:
                        log_evidence[a][b] += math.log(1.0 + ev)

            # Also accumulate evidence for the cipher letter constraint:
            # Position t requires P(y) = c for SOME y = E(P(p_t)).
            # This strengthens entries M[y][c] for valid y values.
            for b in range(26):
                y = E[b]
                # For any plaintext p where P(p)=b:
                total_p_weight = sum(freq[p] * M[p][b] for p in range(26) if p != c)
                if total_p_weight > 1e-15:
                    log_evidence[y][c] += math.log(1.0 + total_p_weight)

        # Apply temperature: M[a][b] ∝ exp(log_evidence[a][b] / T).
        max_le = max(log_evidence[a][b] for a in range(26) for b in range(26))
        for a in range(26):
            for b in range(26):
                M[a][b] = math.exp((log_evidence[a][b] - max_le) / T)

        # Symmetrize (involution: P = P^{-1}).
        for a in range(26):
            for b in range(a + 1, 26):
                avg = (M[a][b] + M[b][a]) / 2
                M[a][b] = avg
                M[b][a] = avg

        # Sinkhorn projection to doubly-stochastic.
        for _ in range(20):
            for a in range(26):
                rs = sum(M[a]) or 1e-12
                for b in range(26):
                    M[a][b] /= rs
            for b in range(26):
                cs = sum(M[a][b] for a in range(26)) or 1e-12
                for a in range(26):
                    M[a][b] /= cs

        # Track convergence: compute objective (sum of max per row).
        obj = sum(max(M[a]) for a in range(26))
        convergence.append(obj)

    # Round to nearest involution permutation.
    plug_map = _round_to_involution(M)

    pairs = []
    seen: set[int] = set()
    for a in range(26):
        b = plug_map[a]
        if a not in seen and b != a:
            pairs.append((min(a, b), max(a, b)))
            seen.add(a)
            seen.add(b)
    pairs.sort()

    # Decrypt with recovered plugboard.
    plaintext_ints: list[int] = []
    for t in range(L):
        c = cipher[t]
        E = trajectory[t]
        pc = plug_map[c]
        d = E[pc]
        p = plug_map[d]
        plaintext_ints.append(p)

    score = model.score(plaintext_ints)
    plaintext = "".join(chr(p + 65) for p in plaintext_ints)

    return HyperchartResult(
        plugboard_matrix=M,
        plugboard_map=plug_map,
        plugboard_pairs=pairs,
        plaintext=plaintext,
        score=score,
        convergence=convergence,
    )


def _round_to_involution(M: list[list[float]]) -> list[int]:
    """Round a symmetric doubly-stochastic matrix to an involution permutation.

    Greedily assigns the strongest off-diagonal pair as a plugboard pair.
    Remaining letters map to themselves.
    """
    n = len(M)
    result = list(range(n))  # start with identity
    used: set[int] = set()

    # Collect all off-diagonal entries.
    entries: list[tuple[float, int, int]] = []
    for a in range(n):
        for b in range(a + 1, n):
            entries.append((M[a][b] + M[b][a], a, b))
    entries.sort(reverse=True)

    # Greedily assign pairs (at most 13).
    n_pairs = 0
    for strength, a, b in entries:
        if n_pairs >= 13:
            break
        if a in used or b in used:
            continue
        # Only pair if off-diagonal is stronger than diagonal.
        if strength > M[a][a] + M[b][b]:
            result[a] = b
            result[b] = a
            used.add(a)
            used.add(b)
            n_pairs += 1

    return result


def hyperchart_attack(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_names: tuple[str, str, str] = ("II", "IV", "V"),
    reflector_name: str = "B",
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    top_k: int = 5,
    ic_survivors: int = 500,
    iterations: int = 150,
    progress: bool = False,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> list[dict]:
    """IC pre-filter → projective multi-peak resolution."""
    from enigma.language import index_of_coincidence

    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)
    if L == 0:
        return []

    ic_scores: list[tuple[float, tuple[int, int, int]]] = []
    for pl in range(26):
        for pm in range(26):
            for pr in range(26):
                traj = fast_trajectory(
                    rotor_names=rotor_names,
                    reflector_name=reflector_name,
                    start_positions=(pl, pm, pr),
                    ring_settings=ring_settings,
                    length=L,
                    fourth_rotor_name=fourth_rotor_name,
                    fourth_position=fourth_position,
                    fourth_ring=fourth_ring,
                )
                dec = [traj[t][cipher[t]] for t in range(L)]
                ic = index_of_coincidence(dec)
                ic_scores.append((ic, (pl, pm, pr)))

    ic_scores.sort(reverse=True)
    survivors = [pos for _, pos in ic_scores[:ic_survivors]]

    if progress:
        print(f"  Phase 1: {len(survivors)} IC survivors")

    results: list[dict] = []
    for i, (pl, pm, pr) in enumerate(survivors):
        traj = fast_trajectory(
            rotor_names=rotor_names,
            reflector_name=reflector_name,
            start_positions=(pl, pm, pr),
            ring_settings=ring_settings,
            length=L,
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=fourth_position,
            fourth_ring=fourth_ring,
        )
        hr = solve_hyperchart(cipher, traj, model, iterations=iterations)
        results.append({
            "positions": (pl, pm, pr),
            "plaintext": hr.plaintext,
            "score": hr.score,
            "plug_pairs": hr.plugboard_pairs,
            "n_pairs": len(hr.plugboard_pairs),
            "convergence_final": hr.convergence[-1] if hr.convergence else 0,
        })

        if progress and (i + 1) % 50 == 0:
            results.sort(key=lambda r: r["score"], reverse=True)
            best = results[0]
            print(f"  Phase 2: {i+1}/{len(survivors)}, "
                  f"best={best['score']:.3f} at "
                  f"{''.join(chr(p+65) for p in best['positions'])}")

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top_k]
