"""Adelic CRT-diagonal hyperchart with per-position Gold-coded interference.

Every position t in the message produces MULTIPLE signals, each Gold-coded
into the shared interference space:

  Per position t, signals:
    - c_t:           ciphertext letter (data, fixed)
    - E_t:           trajectory permutation (depends on structural manifolds)
    - E_t(c_t):      no-plug decryption (structural only)
    - P(c_t):        plugboard application to ciphertext (plug manifold for c_t)
    - E_t(P(c_t)):   trajectory applied to plugged ciphertext
    - P(E_t(P(c_t))): full decryption (depends on TWO plug manifolds)
    - bigram(t-1,t): relationship to previous position

Each of these is independently Gold-coded and projected into the
interference space. With L=174 positions × 7 transforms = ~1200 signals,
the interference space sees the FULL SEQUENTIAL STRUCTURE of the
decryption — not just aggregate statistics.

The period-26 structure of the right rotor becomes visible as
REPEATING PATTERNS in the per-position signals at stride 26.
Turnover kicks appear as DISRUPTIONS in that pattern.
Bigram chains propagate constraint SEQUENTIALLY through adjacent positions.

Architecture:
  - 33 manifolds (structural + plugboard) with Gold codes
  - L × k per-position signal channels in interference space
  - Signals encode: current position state for each component
  - Coherence = all signals reinforcing = correct key
  - Incoherence = signals cancelling = wrong key
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field
from typing import Sequence

from enigma.language import LanguageModel, index_of_coincidence
from enigma.ngram_data import BIGRAMS_OBSERVED, BIGRAM_SUCCESSORS
from enigma.simulator import ROTORS, REFLECTORS, fast_trajectory, M3_ROTORS, M3_REFLECTORS


# ------------------------------------------------------------------
# Gold codes (n=5, length 31, family 33)
# ------------------------------------------------------------------

def _lfsr(taps: list[int], state: int, n: int, length: int) -> list[int]:
    seq = []
    for _ in range(length):
        bit = state & 1
        seq.append(1 if bit else -1)
        fb = 0
        for t in taps:
            fb ^= (state >> t) & 1
        state = ((state >> 1) | (fb << (n - 1))) & ((1 << n) - 1)
    return seq


def _generate_gold_family(n: int = 5) -> list[list[int]]:
    length = (1 << n) - 1
    seq1 = _lfsr([0, 2], 1, n, length)
    seq2 = _lfsr([0, 1, 3, 4], 1, n, length)
    family = [seq1, seq2]
    for shift in range(length):
        gold = [seq1[i] * seq2[(i + shift) % length] for i in range(length)]
        family.append(gold)
    return family[:33]


GOLD_CODES = _generate_gold_family(5)
GOLD_LEN = 31

# Layer 2: Value codes (for parallel evaluation of all residues simultaneously)
# Use a different preferred pair to get an independent family
def _generate_gold_family_2(n: int = 5) -> list[list[int]]:
    length = (1 << n) - 1
    seq1 = _lfsr([0, 3], 1, n, length)  # different taps
    seq2 = _lfsr([0, 2, 3, 4], 1, n, length)
    family = [seq1, seq2]
    for shift in range(length):
        gold = [seq1[i] * seq2[(i + shift) % length] for i in range(length)]
        family.append(gold)
    return family[:33]

VALUE_CODES = _generate_gold_family_2(5)


def parallel_evaluate(scores: list[float]) -> list[float]:
    """Spread N scores with value codes, extract via correlation.

    Input: scores[i] = evidence for value i
    Output: recovered[i] = correlation-extracted score for value i
    (Includes diagonal interference from other values)
    """
    n = len(scores)
    # Spread into shared space
    shared = [0.0] * GOLD_LEN
    for val in range(n):
        code = VALUE_CODES[val % 33]
        for chip in range(GOLD_LEN):
            shared[chip] += scores[val] * code[chip]
    # Extract each value
    recovered = []
    for val in range(n):
        code = VALUE_CODES[val % 33]
        corr = sum(shared[i] * code[i] for i in range(GOLD_LEN)) / GOLD_LEN
        recovered.append(corr)
    return recovered


# ------------------------------------------------------------------
# Per-position signal encoding
# ------------------------------------------------------------------


@dataclass
class PositionSignal:
    """All intermediate values at one message position, Gold-coded."""
    t: int                    # position index
    ct: int                   # ciphertext letter (fixed data)
    et_ct: int = -1           # E_t(c_t): no-plug decrypt
    p_ct: int = -1            # P(c_t): plug applied to ciphertext
    et_p_ct: int = -1         # E_t(P(c_t)): trajectory of plugged ct
    full_dec: int = -1        # P(E_t(P(c_t))): full decryption
    bigram_valid: bool = False  # is bigram with previous valid?
    trigram_valid: bool = False  # is trigram with prev two valid?

    def coherence_vector(self) -> list[float]:
        """Encode this position's state as a coherence signal.

        Each intermediate value contributes to a length-31 vector
        using phase encoding: value → phase → cos/sin at each chip.
        """
        signal = [0.0] * GOLD_LEN
        values = [self.ct, self.et_ct, self.p_ct, self.et_p_ct, self.full_dec]
        for k, val in enumerate(values):
            if val < 0:
                continue
            phase = 2 * math.pi * val / 26
            amp = 1.0
            for chip in range(GOLD_LEN):
                chip_phase = 2 * math.pi * chip * (k + 1) / GOLD_LEN
                signal[chip] += amp * math.cos(phase + chip_phase)
        # Bigram/trigram validity as amplitude boost
        if self.bigram_valid:
            for chip in range(GOLD_LEN):
                signal[chip] += 2.0 * GOLD_CODES[self.t % 33][chip]
        if self.trigram_valid:
            for chip in range(GOLD_LEN):
                signal[chip] += 4.0 * GOLD_CODES[self.t % 33][chip]
        return signal


def compute_position_signals(
    cipher: list[int],
    traj: list[list[int]],
    plug_map: list[int],
) -> list[PositionSignal]:
    """Compute ALL intermediate values at every position."""
    L = len(cipher)
    signals = []
    prev_dec = -1
    prev_prev_dec = -1

    for t in range(L):
        ct = cipher[t]
        et_ct = traj[t][ct]  # no-plug decrypt
        p_ct = plug_map[ct]  # plug applied to ciphertext
        et_p_ct = traj[t][p_ct]  # trajectory of plugged ct
        full_dec = plug_map[et_p_ct]  # full decryption

        bg_valid = False
        tg_valid = False
        if prev_dec >= 0:
            bg_valid = (prev_dec * 26 + full_dec) in BIGRAMS_OBSERVED
        if prev_prev_dec >= 0 and prev_dec >= 0:
            succ = BIGRAM_SUCCESSORS.get(prev_prev_dec * 26 + prev_dec)
            if succ is not None:
                tg_valid = (prev_dec * 26 + full_dec) in succ

        signals.append(PositionSignal(
            t=t, ct=ct, et_ct=et_ct, p_ct=p_ct,
            et_p_ct=et_p_ct, full_dec=full_dec,
            bigram_valid=bg_valid, trigram_valid=tg_valid,
        ))
        prev_prev_dec = prev_dec
        prev_dec = full_dec

    return signals


def total_coherence(signals: list[PositionSignal]) -> float:
    """Total coherence: sum of all position signals' energy.

    High coherence = all positions producing valid n-grams = correct key.
    Low coherence = positions producing garbage = wrong key.
    """
    total = 0.0
    for sig in signals:
        total += 1.0 if sig.bigram_valid else 0.0
        total += 3.0 if sig.trigram_valid else 0.0
    return total


def interference_from_signals(
    signals: list[PositionSignal],
    manifold_code: list[int],
) -> float:
    """Extract interference signal relevant to a specific manifold.

    Correlates all position signals against the manifold's Gold code.
    Positions where the decryption is coherent (valid bigrams) contribute
    positive correlation; incoherent positions contribute negative.
    """
    accumulated = [0.0] * GOLD_LEN
    for sig in signals:
        cv = sig.coherence_vector()
        for i in range(GOLD_LEN):
            accumulated[i] += cv[i]
    # Correlate with manifold's Gold code
    return sum(accumulated[i] * manifold_code[i] for i in range(GOLD_LEN)) / GOLD_LEN


# ------------------------------------------------------------------
# Manifold system
# ------------------------------------------------------------------


@dataclass
class Manifold:
    """One manifold with Gold code and belief state."""
    name: str
    size: int
    code_idx: int
    belief: list[float] = field(default_factory=list)

    def __post_init__(self):
        if not self.belief:
            self.belief = [1.0 / self.size] * self.size

    @property
    def code(self) -> list[int]:
        return GOLD_CODES[self.code_idx]

    def best(self) -> int:
        return max(range(self.size), key=lambda i: self.belief[i])

    def entropy(self) -> float:
        total = sum(self.belief)
        if total < 1e-15:
            return math.log(self.size)
        probs = [b / total for b in self.belief]
        return -sum(p * math.log(p + 1e-15) for p in probs if p > 0)

    def accumulate(self, evidence: list[float], temperature: float):
        max_e = max(evidence) if evidence else 0
        for i in range(self.size):
            self.belief[i] *= math.exp((evidence[i] - max_e) / temperature)
        total = sum(self.belief) or 1e-12
        self.belief = [b / total for b in self.belief]


def run_adelic(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = M3_ROTORS,
    reflector_pool: Sequence[str] = M3_REFLECTORS,
    cycles: int = 25,
    temp_start: float = 5.0,
    temp_end: float = 0.05,
    progress: bool = False,
) -> dict:
    """Full adelic system: per-position signals feed all manifolds.

    Each cycle:
      1. Compute trajectory from current structural beliefs
      2. Compute ALL position signals (ct, E_t(ct), P(ct), E_t(P(ct)), P(E_t(P(ct))))
      3. Each signal Gold-coded into interference space
      4. For each manifold: compute evidence by testing alternatives,
         measuring how they change the TOTAL COHERENCE of all position signals
      5. Extract interference from shared space (Gold correlation)
      6. Update manifold beliefs
      7. Sinkhorn plugboard constraint
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)

    all_combos = list(itertools.permutations(rotor_pool, 3))

    # 7 structural manifolds only — plugboard is DERIVED, not searched.
    # It falls out path-topologically from trajectory + German constraint.
    m_combo = Manifold("combo", len(all_combos), 0)
    m_refl = Manifold("refl", len(reflector_pool), 1)
    m_pos_L = Manifold("pos_L", 26, 2)
    m_pos_M = Manifold("pos_M", 26, 3)
    m_pos_R = Manifold("pos_R", 26, 4)
    m_ring_M = Manifold("ring_M", 26, 5)
    m_ring_R = Manifold("ring_R", 26, 6)

    structural = [m_combo, m_refl, m_pos_L, m_pos_M, m_pos_R, m_ring_M, m_ring_R]
    all_manifolds = structural

    for cycle in range(cycles):
        T = temp_start * (temp_end / temp_start) ** (cycle / max(cycles - 1, 1))

        # Current state (7 structural manifolds only)
        ci = m_combo.best()
        ri = m_refl.best()
        pL, pM, pR = m_pos_L.best(), m_pos_M.best(), m_pos_R.best()
        rM, rR = m_ring_M.best(), m_ring_R.best()

        combo = all_combos[ci]
        refl = reflector_pool[ri]
        pos = (pL, pM, pR)
        ring = (0, rM, rR)

        # Plugboard derived from trajectory (not searched)
        traj = fast_trajectory(combo, refl, pos, ring, L)
        plug_map = list(range(26))  # start identity, let coherence scoring handle it

        # Current coherence (identity plug — the structural probes use IC which is plug-invariant)
        current_signals = compute_position_signals(cipher, traj, plug_map)
        current_coherence = total_coherence(current_signals)

        # === DUAL COHERENCE: random samples + structured probes ===
        # Signal 1 (full coherence): bigram/trigram validity — needs all 5D correct
        # Signal 2 (structural probes): patterned samples that fire on PARTIAL alignment
        #   - Period-26 probes: test each combo's rotor fingerprint
        #   - IC probes: plugboard-invariant, responds to 3D (combo+pos) alone
        #   - Differential probes: test rotor step patterns in ciphertext
        # The structural probes break the 5D coupling by providing per-dimension evidence.
        import random

        N_RANDOM = 500   # random samples for full coherence
        samples: list[tuple[int, int, int, int, int, float]] = []

        def _sample_manifold(m: Manifold) -> int:
            ent = m.entropy()
            max_ent = math.log(m.size)
            ratio = min(ent / max_ent, 1.0) if max_ent > 0 else 1.0
            if ratio > 0.7:
                return random.randint(0, m.size - 1)
            else:
                return random.choices(range(m.size), weights=m.belief)[0]

        # --- Signal 2: STRUCTURAL PROBES (per-dimension, don't need all 5D) ---
        # For each combo: compute IC at sampled positions (IC is plugboard-invariant,
        # responds to combo+position being correct even with wrong ring/plug)
        combo_structural_ev = [0.0] * len(all_combos)
        for ci_test in range(len(all_combos)):
            c_test = all_combos[ci_test]
            best_ic = 0.0
            # Sample positions for this combo (entropy-driven width)
            for _ in range(20):
                pl_s = _sample_manifold(m_pos_L)
                pm_s = _sample_manifold(m_pos_M)
                pr_s = _sample_manifold(m_pos_R)
                rr_s = _sample_manifold(m_ring_R)
                t2 = fast_trajectory(c_test, refl, (pl_s, pm_s, pr_s), (0, rM, rr_s), L)
                dec = [t2[t][cipher[t]] for t in range(L)]
                ic = index_of_coincidence(dec)
                if ic > best_ic:
                    best_ic = ic
            combo_structural_ev[ci_test] = best_ic * 1000

        # pos_R structural: for best combo, IC across pos_R values
        # (fixes combo, sweeps pos_R with random pos_M/pos_L — IC still responds)
        pos_r_structural_ev = [0.0] * 26
        best_combo_idx = max(range(len(all_combos)), key=lambda i: combo_structural_ev[i])
        c_best = all_combos[best_combo_idx]
        for pr_test in range(26):
            best_ic = 0.0
            for _ in range(8):
                pl_s = _sample_manifold(m_pos_L)
                pm_s = _sample_manifold(m_pos_M)
                rr_s = _sample_manifold(m_ring_R)
                t2 = fast_trajectory(c_best, refl, (pl_s, pm_s, pr_test), (0, rM, rr_s), L)
                dec = [t2[t][cipher[t]] for t in range(L)]
                ic = index_of_coincidence(dec)
                if ic > best_ic:
                    best_ic = ic
            pos_r_structural_ev[pr_test] = best_ic * 1000

        # pos_M structural
        pos_m_structural_ev = [0.0] * 26
        best_pr = max(range(26), key=lambda i: pos_r_structural_ev[i])
        for pm_test in range(26):
            best_ic = 0.0
            for _ in range(8):
                pl_s = _sample_manifold(m_pos_L)
                rr_s = _sample_manifold(m_ring_R)
                t2 = fast_trajectory(c_best, refl, (pl_s, pm_test, best_pr), (0, rM, rr_s), L)
                dec = [t2[t][cipher[t]] for t in range(L)]
                ic = index_of_coincidence(dec)
                if ic > best_ic:
                    best_ic = ic
            pos_m_structural_ev[pm_test] = best_ic * 1000

        # pos_L structural
        pos_l_structural_ev = [0.0] * 26
        best_pm = max(range(26), key=lambda i: pos_m_structural_ev[i])
        for pl_test in range(26):
            rr_s = _sample_manifold(m_ring_R)
            t2 = fast_trajectory(c_best, refl, (pl_test, best_pm, best_pr), (0, rM, rr_s), L)
            dec = [t2[t][cipher[t]] for t in range(L)]
            pos_l_structural_ev[pl_test] = index_of_coincidence(dec) * 1000

        # --- Signal 1: RANDOM SAMPLES for full coherence ---
        for _ in range(N_RANDOM):
            ci_s = _sample_manifold(m_combo)
            pl_s = _sample_manifold(m_pos_L)
            pm_s = _sample_manifold(m_pos_M)
            pr_s = _sample_manifold(m_pos_R)
            rr_s = _sample_manifold(m_ring_R)

            c_s = all_combos[ci_s]
            t2 = fast_trajectory(c_s, refl, (pl_s, pm_s, pr_s), (0, rM, rr_s), L)
            sigs = compute_position_signals(cipher, t2, plug_map)
            coh = total_coherence(sigs)
            samples.append((ci_s, pl_s, pm_s, pr_s, rr_s, coh))

        # === COMBINE both signals: structural probes + random coherence ===
        # Structural (Signal 2) provides per-dimension evidence (partial alignment)
        # Random (Signal 1) provides full-coherence evidence (all-dimension alignment)
        # Weight structural more when entropy is high (exploring),
        # weight random more when entropy is low (exploiting).

        struct_weight = sum(m.entropy() for m in [m_combo, m_pos_R, m_pos_M, m_pos_L]) / (4 * math.log(26))
        rand_weight = 1.0 - struct_weight

        # Random coherence: accumulate from samples
        combo_rand = [0.0] * len(all_combos)
        combo_counts = [0] * len(all_combos)
        pos_r_rand = [0.0] * 26
        pos_r_counts = [0] * 26
        pos_m_rand = [0.0] * 26
        pos_m_counts = [0] * 26
        pos_l_rand = [0.0] * 26
        pos_l_counts = [0] * 26
        ring_r_rand = [0.0] * 26
        ring_r_counts = [0] * 26

        for ci_s, pl_s, pm_s, pr_s, rr_s, coh in samples:
            combo_rand[ci_s] += coh; combo_counts[ci_s] += 1
            pos_r_rand[pr_s] += coh; pos_r_counts[pr_s] += 1
            pos_m_rand[pm_s] += coh; pos_m_counts[pm_s] += 1
            pos_l_rand[pl_s] += coh; pos_l_counts[pl_s] += 1
            ring_r_rand[rr_s] += coh; ring_r_counts[rr_s] += 1

        combo_rand = [combo_rand[i] / max(combo_counts[i], 1) for i in range(len(all_combos))]
        pos_r_rand = [pos_r_rand[i] / max(pos_r_counts[i], 1) for i in range(26)]
        pos_m_rand = [pos_m_rand[i] / max(pos_m_counts[i], 1) for i in range(26)]
        pos_l_rand = [pos_l_rand[i] / max(pos_l_counts[i], 1) for i in range(26)]
        ring_r_rand = [ring_r_rand[i] / max(ring_r_counts[i], 1) for i in range(26)]

        # Blend: structural × struct_weight + random × rand_weight
        combo_ev = [struct_weight * combo_structural_ev[i] + rand_weight * combo_rand[i]
                    for i in range(len(all_combos))]
        pos_r_ev = [struct_weight * pos_r_structural_ev[i] + rand_weight * pos_r_rand[i]
                    for i in range(26)]
        pos_m_ev = [struct_weight * pos_m_structural_ev[i] + rand_weight * pos_m_rand[i]
                    for i in range(26)]
        pos_l_ev = [struct_weight * pos_l_structural_ev[i] + rand_weight * pos_l_rand[i]
                    for i in range(26)]
        ring_r_ev = [rand_weight * ring_r_rand[i] for i in range(26)]

        # Gold code interference
        combo_ev = parallel_evaluate(combo_ev)
        pos_r_ev = parallel_evaluate(pos_r_ev)
        pos_m_ev = parallel_evaluate(pos_m_ev)
        pos_l_ev = parallel_evaluate(pos_l_ev)
        ring_r_ev = parallel_evaluate(ring_r_ev)

        # Update all structural manifolds
        m_combo.accumulate(combo_ev, T)
        m_pos_R.accumulate(pos_r_ev, T)
        m_pos_M.accumulate(pos_m_ev, T)
        m_pos_L.accumulate(pos_l_ev, T)
        m_ring_R.accumulate(ring_r_ev, T)

        combo = all_combos[m_combo.best()]
        pR = m_pos_R.best()
        pM = m_pos_M.best()
        pL = m_pos_L.best()
        rR = m_ring_R.best()
        pos = (pL, pM, pR)
        ring = (0, rM, rR)

        # Reflector: use best (combo, pos_R) from joint
        refl_ev = [0.0] * len(reflector_pool)
        for ri_test in range(len(reflector_pool)):
            t2 = fast_trajectory(combo, reflector_pool[ri_test], (pL, pM, pR), ring, L)
            sigs = compute_position_signals(cipher, t2, plug_map)
            refl_ev[ri_test] = total_coherence(sigs)
        m_refl.accumulate(refl_ev, T)
        refl = reflector_pool[m_refl.best()]

        # Position M: sweep with best combo and pos_R locked
        pos_m_ev = [0.0] * 26
        for pm_test in range(26):
            t2 = fast_trajectory(combo, refl, (pL, pm_test, pR), ring, L)
            sigs = compute_position_signals(cipher, t2, plug_map)
            pos_m_ev[pm_test] = total_coherence(sigs)
        pos_m_ev = parallel_evaluate(pos_m_ev)
        m_pos_M.accumulate(pos_m_ev, T)
        pM = m_pos_M.best()

        # Position L: sweep with best combo, pos_R, pos_M locked
        pos_l_ev = [0.0] * 26
        for pl_test in range(26):
            t2 = fast_trajectory(combo, refl, (pl_test, pM, pR), ring, L)
            sigs = compute_position_signals(cipher, t2, plug_map)
            pos_l_ev[pl_test] = total_coherence(sigs)
        pos_l_ev = parallel_evaluate(pos_l_ev)
        m_pos_L.accumulate(pos_l_ev, T)
        pL = m_pos_L.best()
        pos = (pL, pM, pR)

        # Ring R: sweep
        ring_r_ev = [0.0] * 26
        for rr_test in range(26):
            t2 = fast_trajectory(combo, refl, pos, (0, rM, rr_test), L)
            sigs = compute_position_signals(cipher, t2, plug_map)
            ring_r_ev[rr_test] = total_coherence(sigs)
        ring_r_ev = parallel_evaluate(ring_r_ev)
        m_ring_R.accumulate(ring_r_ev, T)
        rR = m_ring_R.best()

        # Ring M: sweep
        ring_m_ev = [0.0] * 26
        for rm_test in range(26):
            t2 = fast_trajectory(combo, refl, pos, (0, rm_test, rR), L)
            sigs = compute_position_signals(cipher, t2, plug_map)
            ring_m_ev[rm_test] = total_coherence(sigs)
        ring_m_ev = parallel_evaluate(ring_m_ev)
        m_ring_M.accumulate(ring_m_ev, T)
        rM = m_ring_M.best()
        ring = (0, rM, rR)

        # Plugboard: DERIVED (not searched). Done at end via beam_swap.

        if progress and cycle % 3 == 0:
            combo = all_combos[m_combo.best()]
            refl = reflector_pool[m_refl.best()]
            pos = (m_pos_L.best(), m_pos_M.best(), m_pos_R.best())
            ring = (0, m_ring_M.best(), m_ring_R.best())
            struct_ent = sum(m.entropy() for m in structural)
            print(f"  cycle {cycle:2d} T={T:.2f} | "
                  f"{'-'.join(combo)}/{refl} "
                  f"pos={''.join(chr(p+65) for p in pos)} "
                  f"ring={''.join(chr(r+65) for r in ring)} "
                  f"coh={current_coherence:.0f} "
                  f"H_struct={struct_ent:.1f}")

    # === Final reconstruction ===
    combo = all_combos[m_combo.best()]
    refl = reflector_pool[m_refl.best()]
    pos = (m_pos_L.best(), m_pos_M.best(), m_pos_R.best())
    ring = (0, m_ring_M.best(), m_ring_R.best())
    # Plugboard derived via beam swap on the recovered trajectory
    from enigma.attack import beam_swap_search
    traj = fast_trajectory(combo, refl, pos, ring, L)
    score, final_plug, dec = beam_swap_search(cipher, traj, model, rounds=10, beam_width=50)

    n_excl = sum(1 for i in range(L - 1) if model.excluded[dec[i]][dec[i + 1]])
    pairs = [(a, final_plug[a]) for a in range(26) if final_plug[a] > a]

    return {
        "rotors": combo,
        "reflector": refl,
        "positions": pos,
        "ring_settings": ring,
        "plugboard_map": final_plug,
        "plugboard_pairs": pairs,
        "plaintext": "".join(chr(d + 65) for d in dec),
        "score": score,
        "n_excluded_bigrams": n_excl,
        "final_coherence": total_coherence(compute_position_signals(cipher, traj, final_plug)),
    }
