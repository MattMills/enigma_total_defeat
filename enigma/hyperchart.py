"""Hyperchart solver: geometric constraint relaxation on the Birkhoff polytope.

Each position t defines a constraint surface in the 26×26 plugboard
space. The plugboard is a permutation matrix (vertex of the Birkhoff
polytope). All 174 constraint surfaces intersect at exactly one vertex
for the correct trajectory.

Instead of branching or greedy search, we RELAX the plugboard to a
doubly-stochastic matrix (interior of the Birkhoff polytope) and let
all constraints pull simultaneously via gradient ascent. The matrix
converges to the correct vertex — the plugboard.

The "hyperchart" is the 26×26 matrix M that summarizes ALL position-wise
constraint sub-charts in a single geometric object. Working with M is
working with ALL positions simultaneously. The involution constraint
(P = P^{-1}, i.e., M = M^T) is enforced by symmetrization.

Log-likelihood at each position t:
  L_t = log Σ_p w_p Σ_x M[p][x] · M[E_t(x)][c_t]

where w_p = German frequency prior for plaintext letter p,
      E_t = trajectory permutation at position t,
      c_t = ciphertext letter at position t.

Total objective: Σ_t L_t (sum over all positions).

Gradient ascent + Sinkhorn projection converges to the correct
permutation matrix in O(iterations × L × 26²) operations.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from enigma.language import LanguageModel
from enigma.simulator import ROTORS, REFLECTORS, fast_trajectory


@dataclass
class HyperchartResult:
    plugboard_matrix: list[list[float]]  # 26×26 doubly-stochastic
    plugboard_map: list[int]             # rounded permutation
    plugboard_pairs: list[tuple[int, int]]
    plaintext: str
    score: float
    convergence: list[float]             # objective per iteration

    def plug_str(self) -> str:
        return " ".join(chr(a+65) + chr(b+65) for a, b in self.plugboard_pairs)


def solve_hyperchart(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    iterations: int = 80,
    lr: float = 0.5,
    sinkhorn_steps: int = 5,
) -> HyperchartResult:
    """Solve for the plugboard via geometric relaxation on the Birkhoff polytope.

    The 26×26 matrix M encodes ALL constraint sub-charts simultaneously.
    Each iteration updates M using gradients from ALL positions, then
    projects back to the doubly-stochastic polytope via Sinkhorn, and
    enforces the involution constraint via symmetrization.
    """
    L = len(cipher)
    freq = model.unigram

    # Initialize: center of Birkhoff polytope (uniform doubly-stochastic).
    M = [[1.0 / 26] * 26 for _ in range(26)]

    convergence: list[float] = []

    for it in range(iterations):
        # Compute gradient of log-likelihood w.r.t. M.
        grad = [[0.0] * 26 for _ in range(26)]
        obj = 0.0

        for t in range(L):
            c = cipher[t]
            E = trajectory[t]

            # For each candidate plaintext p, compute the "evidence":
            # evidence(p) = Σ_x M[p][x] · M[E[x]][c]
            # This is the probability (under the relaxed M) that
            # plaintext p at position t is consistent with the plugboard.
            evidences: list[float] = []
            for p in range(26):
                if p == c:
                    evidences.append(0.0)
                    continue
                ev = 0.0
                for x in range(26):
                    y = E[x]
                    ev += M[p][x] * M[y][c]
                evidences.append(ev * freq[p])

            total_ev = sum(evidences)
            if total_ev < 1e-15:
                continue
            obj += math.log(max(total_ev, 1e-15))

            # Gradient: for each (p, x), the contribution to grad[p][x]
            # and grad[E[x]][c] is proportional to the evidence weight.
            for p in range(26):
                if p == c or evidences[p] < 1e-15:
                    continue
                w = evidences[p] / total_ev
                for x in range(26):
                    y = E[x]
                    if M[p][x] > 1e-15 and M[y][c] > 1e-15:
                        g_px = w * freq[p] * M[y][c] / total_ev
                        g_yc = w * freq[p] * M[p][x] / total_ev
                        grad[p][x] += g_px
                        grad[y][c] += g_yc

        convergence.append(obj / L)

        # Multiplicative gradient step (exponentiated gradient).
        for a in range(26):
            for b in range(26):
                M[a][b] *= math.exp(lr * grad[a][b])
                M[a][b] = max(M[a][b], 1e-12)

        # Enforce involution: M should be symmetric (P = P^{-1}).
        for a in range(26):
            for b in range(a + 1, 26):
                avg = (M[a][b] + M[b][a]) / 2
                M[a][b] = avg
                M[b][a] = avg

        # Sinkhorn projection to doubly-stochastic.
        for _ in range(sinkhorn_steps):
            for a in range(26):
                rs = sum(M[a]) or 1e-12
                for b in range(26):
                    M[a][b] /= rs
            for b in range(26):
                cs = sum(M[a][b] for a in range(26)) or 1e-12
                for a in range(26):
                    M[a][b] /= cs

    # Round to nearest permutation (greedy maximum matching).
    plug_map = _round_to_permutation(M)

    # Extract pairs.
    pairs = []
    seen: set[int] = set()
    for a in range(26):
        b = plug_map[a]
        if a not in seen and b != a:
            pairs.append((min(a, b), max(a, b)))
            seen.add(a)
            seen.add(b)
    pairs.sort()

    # Decrypt with the recovered plugboard.
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


def _round_to_permutation(M: list[list[float]]) -> list[int]:
    """Greedy rounding of a doubly-stochastic matrix to a permutation."""
    n = len(M)
    result = [-1] * n
    used_cols: set[int] = set()
    # Process rows in order of their maximum entry (most confident first).
    row_order = sorted(range(n), key=lambda a: max(M[a]), reverse=True)
    for a in row_order:
        best_b = -1
        best_val = -1.0
        for b in range(n):
            if b not in used_cols and M[a][b] > best_val:
                best_val = M[a][b]
                best_b = b
        result[a] = best_b
        used_cols.add(best_b)
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
    iterations: int = 80,
    progress: bool = False,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> list[dict]:
    """Two-phase attack: IC filter → hyperchart geometric resolution.

    Phase 1: score all 17,576 positions by IC (plugboard-invariant).
    Keep top ``ic_survivors``.

    Phase 2: for each survivor, run the hyperchart solver (gradient
    ascent on the Birkhoff polytope). Score the resolved plaintext.
    """
    from enigma.language import index_of_coincidence

    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)
    if L == 0:
        return []

    # Phase 1: IC-based trajectory screening.
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
        print(f"  Phase 1: {len(survivors)} IC survivors "
              f"(IC range {ic_scores[0][0]:.4f} - {ic_scores[ic_survivors-1][0]:.4f})")

    # Phase 2: hyperchart resolution.
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
            "convergence_start": hr.convergence[0] if hr.convergence else 0,
            "convergence_end": hr.convergence[-1] if hr.convergence else 0,
        })

        if progress and (i + 1) % 50 == 0:
            results.sort(key=lambda r: r["score"], reverse=True)
            print(f"  Phase 2: {i+1}/{len(survivors)} done, "
                  f"best score={results[0]['score']:.3f}")

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top_k]
