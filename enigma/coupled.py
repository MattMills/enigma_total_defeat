"""Multi-message coupled hyperchart: simultaneous superposition across all key dimensions.

The Birkhoff polytope solver operates on a 26×26 doubly-stochastic matrix for
the plugboard. This module extends that idea to a TENSOR PRODUCT of manifolds:

  Manifold 0: Rotor combo (discrete, 60 elements for M3)
  Manifold 1: Position × Ring (discrete, 26^3 × 26^2 = 11.88M elements)
  Manifold 2: Plugboard (continuous, Birkhoff polytope of 26×26)

The key insight for heavy-plugboard messages: IC alone cannot distinguish the
correct trajectory from noise (IC = 0.042 vs random 0.038 with 10-pair plugboard).
BUT: multiple same-day messages share the SAME plugboard/rotors/rings and differ
only in position. This creates a coupling:

  M_plug[a][b] = Π_msg Π_t T_msg,t[a][b]

The product over MULTIPLE MESSAGES on the same day key is the "phase of phase"
structure — the plugboard manifold receives evidence from ALL messages
simultaneously, dramatically sharpening the peaks.

The CRT tail-radix decomposition structures the position search:
  position = (left, middle, right)
  right: cycles with period 26, turnover depends on ring
  middle: cycles with period 26, turnover depends on right ring

  26 = 2 × 13 (prime factorization)
  So ring_right has CRT structure: test mod-2 (2 trials) and mod-13 (13 trials)
  independently, then combine.

For each ring hypothesis, the hyperchart accumulates evidence from ALL positions
in ALL messages. Temperature annealing collapses the superposition.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from enigma.language import LanguageModel, index_of_coincidence
from enigma.simulator import ROTORS, REFLECTORS, fast_trajectory


@dataclass
class MultiMessageResult:
    """Result from multi-message coupled hyperchart."""
    rotor_names: tuple[str, str, str]
    reflector_name: str
    ring_settings: tuple[int, int, int]
    plugboard_matrix: list[list[float]]
    plugboard_map: list[int]
    plugboard_pairs: list[tuple[int, int]]
    per_message: list[dict]  # position + plaintext per message
    coupling_score: float  # how strongly the messages agree
    iterations: int = 0

    @property
    def plug_str(self) -> str:
        return " ".join(chr(a + 65) + chr(b + 65) for a, b in self.plugboard_pairs)


def coupled_hyperchart(
    ciphers: list[list[int]],
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions_per_msg: list[tuple[int, int, int]],
    ring_settings: tuple[int, int, int],
    model: LanguageModel,
    *,
    iterations: int = 200,
    temp_start: float = 5.0,
    temp_end: float = 0.02,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> MultiMessageResult:
    """Coupled hyperchart: simultaneous plugboard resolution from multiple messages.

    All messages share the SAME plugboard. Each message has its own trajectory
    (different position). The plugboard matrix receives evidence from ALL
    messages simultaneously — the product over messages sharpens peaks
    exponentially.

    This is the "phase of phase" structure:
      - Outer phase: plugboard (shared across messages)
      - Inner phase: per-message trajectory (different positions)
      - Coupling: P(a)=b must be consistent across ALL messages
    """
    n_msgs = len(ciphers)
    freq = model.unigram

    fourth_kw = {}
    if fourth_rotor_name:
        fourth_kw = dict(
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=fourth_position,
            fourth_ring=fourth_ring,
        )

    # Compute trajectories for all messages
    trajectories = []
    for i in range(n_msgs):
        traj = fast_trajectory(
            rotor_names, reflector_name, positions_per_msg[i],
            ring_settings, len(ciphers[i]), **fourth_kw,
        )
        trajectories.append(traj)

    # M: plugboard belief on the Birkhoff polytope (shared across messages)
    M = [[1.0 / 26] * 26 for _ in range(26)]

    for it in range(iterations):
        T = temp_start * (temp_end / temp_start) ** (it / max(iterations - 1, 1))

        # Accumulate unified evidence from ALL messages in log-space
        log_evidence = [[0.0] * 26 for _ in range(26)]

        for msg_idx in range(n_msgs):
            cipher = ciphers[msg_idx]
            traj = trajectories[msg_idx]
            L = len(cipher)

            for t in range(L):
                c = cipher[t]
                E = traj[t]

                for a in range(26):
                    if a == c:
                        continue
                    w = freq[a]
                    for b in range(26):
                        y = E[b]
                        ev = w * M[y][c]
                        if ev > 1e-15:
                            log_evidence[a][b] += math.log(1.0 + ev)

                for b in range(26):
                    y = E[b]
                    total_p = sum(freq[p] * M[p][b] for p in range(26) if p != c)
                    if total_p > 1e-15:
                        log_evidence[y][c] += math.log(1.0 + total_p)

        # Apply temperature
        max_le = max(log_evidence[a][b] for a in range(26) for b in range(26))
        for a in range(26):
            for b in range(26):
                M[a][b] = math.exp((log_evidence[a][b] - max_le) / T)

        # Symmetrize (involution)
        for a in range(26):
            for b in range(a + 1, 26):
                avg = (M[a][b] + M[b][a]) / 2
                M[a][b] = avg
                M[b][a] = avg

        # Sinkhorn projection
        for _ in range(20):
            for a in range(26):
                rs = sum(M[a]) or 1e-12
                for b in range(26):
                    M[a][b] /= rs
            for b in range(26):
                cs = sum(M[a][b] for a in range(26)) or 1e-12
                for a in range(26):
                    M[a][b] /= cs

    # Round to involution
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

    # Decrypt each message with recovered plugboard
    per_message = []
    for msg_idx in range(n_msgs):
        cipher = ciphers[msg_idx]
        traj = trajectories[msg_idx]
        L = len(cipher)
        dec = [plug_map[traj[t][plug_map[cipher[t]]]] for t in range(L)]
        score = model.score(dec)
        n_excl = sum(
            1 for i in range(L - 1) if model.excluded[dec[i]][dec[i + 1]]
        )
        per_message.append({
            "position": positions_per_msg[msg_idx],
            "plaintext": "".join(chr(d + 65) for d in dec),
            "score": score,
            "n_excluded_bigrams": n_excl,
        })

    # Coupling score: how many messages have 0 excluded bigrams
    coupling_score = sum(1 for m in per_message if m["n_excluded_bigrams"] == 0) / n_msgs

    return MultiMessageResult(
        rotor_names=rotor_names,
        reflector_name=reflector_name,
        ring_settings=ring_settings,
        plugboard_matrix=M,
        plugboard_map=plug_map,
        plugboard_pairs=pairs,
        per_message=per_message,
        coupling_score=coupling_score,
        iterations=iterations,
    )


def _round_to_involution(M: list[list[float]]) -> list[int]:
    """Round symmetric doubly-stochastic matrix to involution permutation."""
    n = len(M)
    result = list(range(n))
    used: set[int] = set()

    entries: list[tuple[float, int, int]] = []
    for a in range(n):
        for b in range(a + 1, n):
            entries.append((M[a][b] + M[b][a], a, b))
    entries.sort(reverse=True)

    n_pairs = 0
    for strength, a, b in entries:
        if n_pairs >= 13:
            break
        if a in used or b in used:
            continue
        if strength > M[a][a] + M[b][b]:
            result[a] = b
            result[b] = a
            used.add(a)
            used.add(b)
            n_pairs += 1

    return result


def multi_message_attack(
    ciphertexts: list[str],
    *,
    model: LanguageModel | None = None,
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    ic_survivors: int = 10,
    iterations: int = 200,
    progress: bool = False,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> list[MultiMessageResult]:
    """Multi-message coupled attack: find shared plugboard across messages.

    Given multiple messages encrypted with the SAME day key (rotors,
    reflector, rings, plugboard) but DIFFERENT positions, simultaneously
    resolves the shared plugboard using evidence from all messages.

    Steps:
      1. For each message, IC-rank positions independently
      2. Try all combinations of top positions across messages
      3. For each combo, run coupled_hyperchart
      4. Score by coupling (mutual consistency)
    """
    if model is None:
        model = LanguageModel.german_military()

    ciphers = [[ord(c) - 65 for c in ct if "A" <= c <= "Z"] for ct in ciphertexts]
    n_msgs = len(ciphers)

    fourth_kw = {}
    if fourth_rotor_name:
        fourth_kw = dict(
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=fourth_position,
            fourth_ring=fourth_ring,
        )

    # IC-rank positions for each message independently
    all_positions: list[list[tuple[int, int, int]]] = []
    for cipher in ciphers:
        L = len(cipher)
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
        all_positions.append([pos for _, pos in ic_scores[:ic_survivors]])

    if progress:
        for i, positions in enumerate(all_positions):
            print(f"  Message {i}: top IC positions = "
                  f"{[''.join(chr(p+65) for p in pos) for pos in positions[:3]]}")

    # Try combinations of top positions
    from itertools import product as cartesian
    results: list[MultiMessageResult] = []

    for pos_combo in cartesian(*all_positions):
        result = coupled_hyperchart(
            ciphers, rotor_names, reflector_name,
            list(pos_combo), ring_settings, model,
            iterations=iterations, **fourth_kw,
        )
        results.append(result)

    results.sort(key=lambda r: (-r.coupling_score, -sum(
        m["score"] for m in r.per_message if m["score"] > float("-inf")
    )))

    return results
