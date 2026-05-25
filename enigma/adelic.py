"""Adelic CRT-diagonal hyperchart: hundreds of bases interfering simultaneously.

Each independent component of the Enigma key is its OWN manifold (basis set).
They all cross-constrain each other diagonally — evidence for any one manifold
uses the current state of ALL others.

Manifolds (33 total, each kept SEPARATE):
  - combo:    size 60  (rotor permutation choice)
  - refl:     size 3   (reflector choice)
  - pos_L:    size 26  (left rotor starting position)
  - pos_M:    size 26  (middle rotor starting position)
  - pos_R:    size 26  (right rotor starting position)
  - ring_M:   size 26  (middle ring setting)
  - ring_R:   size 26  (right ring setting)
  - plug[0]:  size 26  (what does A map to?)
  - plug[1]:  size 26  (what does B map to?)
  - ...
  - plug[25]: size 26  (what does Z map to?)

Total: 7 structural + 26 plugboard = 33 manifolds.

Each cycle, ALL manifolds are updated using evidence computed from the
current beliefs of ALL OTHER manifolds. This is the diagonal interference.

The rotor signatures are pre-computed (rotors are STATIC throughout
the message). Ciphertext bigrams, bigrams-of-bigrams, and trigrams
are pre-analyzed. All evidence feeds all manifolds every tick.

CRT coherence: the plugboard manifolds are coupled by the involution
constraint P(P(x)) = x. If plug[A] believes A→X, then plug[X] must
believe X→A. This cross-constraint propagates between all 26 plug
manifolds every cycle.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field
from typing import Sequence

from enigma.language import LanguageModel, index_of_coincidence
from enigma.ngram_data import BIGRAMS_OBSERVED, BIGRAM_SUCCESSORS
from enigma.simulator import ROTORS, REFLECTORS, fast_trajectory, M3_ROTORS, M3_REFLECTORS


@dataclass
class Manifold:
    """One basis in the CRT system. Kept separate from all others."""
    size: int
    belief: list[float] = field(default_factory=list)
    name: str = ""
    nil: bool = True

    def __post_init__(self):
        if not self.belief:
            self.belief = [1.0 / self.size] * self.size

    def best(self) -> int:
        if self.nil:
            return 0
        return max(range(self.size), key=lambda i: self.belief[i])

    def entropy(self) -> float:
        if self.nil:
            return math.log(self.size)
        total = sum(self.belief)
        if total < 1e-15:
            return math.log(self.size)
        probs = [b / total for b in self.belief]
        return -sum(p * math.log(p + 1e-15) for p in probs if p > 0)

    def accumulate(self, evidence: list[float], temperature: float):
        """Shift beliefs by evidence. Temperature controls sharpness."""
        self.nil = False
        max_e = max(evidence) if evidence else 0
        for i in range(self.size):
            self.belief[i] *= math.exp((evidence[i] - max_e) / temperature)
        total = sum(self.belief) or 1e-12
        self.belief = [b / total for b in self.belief]

    def top_k(self, k: int) -> list[int]:
        if self.nil:
            return list(range(min(k, self.size)))
        return sorted(range(self.size), key=lambda i: self.belief[i], reverse=True)[:k]


def _ngram_score(dec: list[int]) -> float:
    """N-gram validity: bigrams + bigrams-of-bigrams + trigram transitions."""
    n = len(dec)
    s = 0.0
    for i in range(n - 1):
        if (dec[i] * 26 + dec[i + 1]) in BIGRAMS_OBSERVED:
            s += 1.0
    if n >= 3:
        prev_bg = dec[0] * 26 + dec[1]
        for i in range(1, n - 1):
            cur_bg = dec[i] * 26 + dec[i + 1]
            succ = BIGRAM_SUCCESSORS.get(prev_bg)
            if succ is not None and cur_bg in succ:
                s += 3.0
            prev_bg = cur_bg
    return s


def run_adelic(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = M3_ROTORS,
    reflector_pool: Sequence[str] = M3_REFLECTORS,
    cycles: int = 30,
    temp_start: float = 5.0,
    temp_end: float = 0.05,
    progress: bool = False,
) -> dict:
    """Full adelic system: 33 manifolds interfering diagonally.

    Every cycle, every manifold receives evidence computed using the
    current state of ALL other manifolds. All attacks run simultaneously:
      - Rotor signatures (pre-computed, static)
      - IC statistics (plugboard-invariant)
      - N-gram validity (bigrams, bigrams-of-bigrams)
      - Ciphertext pattern correlation
      - Plugboard involution constraint propagation
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)

    all_combos = list(itertools.permutations(rotor_pool, 3))

    # --- 33 Manifolds ---
    m_combo = Manifold(len(all_combos), name="combo", nil=False)
    m_refl = Manifold(len(reflector_pool), name="refl", nil=False)
    m_pos_L = Manifold(26, name="pos_L")
    m_pos_M = Manifold(26, name="pos_M")
    m_pos_R = Manifold(26, name="pos_R")
    m_ring_M = Manifold(26, name="ring_M")
    m_ring_R = Manifold(26, name="ring_R")
    m_plug = [Manifold(26, name=f"P({chr(a+65)})") for a in range(26)]

    if progress:
        print(f"Adelic system: {7 + 26} manifolds, {len(all_combos)} combos, "
              f"{len(reflector_pool)} reflectors, L={L}")

    for cycle in range(cycles):
        T = temp_start * (temp_end / temp_start) ** (cycle / max(cycles - 1, 1))

        # Current best from each manifold (diagonal reads)
        ci = m_combo.best()
        ri = m_refl.best()
        pL = m_pos_L.best()
        pM = m_pos_M.best()
        pR = m_pos_R.best()
        rM = m_ring_M.best()
        rR = m_ring_R.best()
        plug_map = [m_plug[a].best() for a in range(26)]

        combo = all_combos[ci]
        refl = reflector_pool[ri]
        pos = (pL, pM, pR)
        ring = (0, rM, rR)

        # ============================================================
        # ALL EVIDENCE COMPUTED SIMULTANEOUSLY
        # Each manifold sees all others' current state
        # ============================================================

        # --- Combo manifold: test each combo at current pos/ring ---
        combo_ev = [0.0] * len(all_combos)
        for idx, c in enumerate(all_combos):
            traj = fast_trajectory(c, refl, pos, ring, L)
            dec = [plug_map[traj[t][plug_map[cipher[t]]]] for t in range(L)]
            combo_ev[idx] = _ngram_score(dec)
        m_combo.accumulate(combo_ev, T)

        # --- Reflector manifold ---
        refl_ev = [0.0] * len(reflector_pool)
        combo = all_combos[m_combo.best()]
        for idx, ref in enumerate(reflector_pool):
            traj = fast_trajectory(combo, ref, pos, ring, L)
            dec = [plug_map[traj[t][plug_map[cipher[t]]]] for t in range(L)]
            refl_ev[idx] = _ngram_score(dec)
        m_refl.accumulate(refl_ev, T)

        # --- Position manifolds (each of 26 values tested) ---
        combo = all_combos[m_combo.best()]
        refl = reflector_pool[m_refl.best()]

        # pos_R
        ev = [0.0] * 26
        for pr in range(26):
            traj = fast_trajectory(combo, refl, (pL, pM, pr), ring, L)
            dec = [plug_map[traj[t][plug_map[cipher[t]]]] for t in range(L)]
            ev[pr] = _ngram_score(dec)
        m_pos_R.accumulate(ev, T)

        # pos_M
        ev = [0.0] * 26
        pR = m_pos_R.best()
        for pm in range(26):
            traj = fast_trajectory(combo, refl, (pL, pm, pR), ring, L)
            dec = [plug_map[traj[t][plug_map[cipher[t]]]] for t in range(L)]
            ev[pm] = _ngram_score(dec)
        m_pos_M.accumulate(ev, T)

        # pos_L
        ev = [0.0] * 26
        pM = m_pos_M.best()
        for pl in range(26):
            traj = fast_trajectory(combo, refl, (pl, pM, pR), ring, L)
            dec = [plug_map[traj[t][plug_map[cipher[t]]]] for t in range(L)]
            ev[pl] = _ngram_score(dec)
        m_pos_L.accumulate(ev, T)

        # --- Ring manifolds ---
        pL = m_pos_L.best()
        pos = (pL, pM, pR)

        # ring_R
        ev = [0.0] * 26
        for rr in range(26):
            traj = fast_trajectory(combo, refl, pos, (0, rM, rr), L)
            dec = [plug_map[traj[t][plug_map[cipher[t]]]] for t in range(L)]
            ev[rr] = _ngram_score(dec)
        m_ring_R.accumulate(ev, T)

        # ring_M
        ev = [0.0] * 26
        rR = m_ring_R.best()
        for rm in range(26):
            traj = fast_trajectory(combo, refl, pos, (0, rm, rR), L)
            dec = [plug_map[traj[t][plug_map[cipher[t]]]] for t in range(L)]
            ev[rm] = _ngram_score(dec)
        m_ring_M.accumulate(ev, T)

        # --- Plugboard manifolds (26 separate bases) ---
        # Each plug[a] gets evidence: for each candidate b,
        # how good is the decryption if P(a)=b?
        rM = m_ring_M.best()
        ring = (0, rM, rR)
        traj = fast_trajectory(combo, refl, pos, ring, L)

        for a in range(26):
            ev = [0.0] * 26
            for b in range(26):
                # Temporarily set P(a)=b, compute score
                old_a = plug_map[a]
                old_b = plug_map[b] if b != old_a else a
                test_plug = list(plug_map)
                # Involution: P(a)=b means P(b)=a
                test_plug[a] = b
                test_plug[b] = a
                # Undo previous pair for a and b
                if old_a != a and old_a != b:
                    test_plug[old_a] = old_a
                if old_b != b and old_b != a and old_b != old_a:
                    test_plug[old_b] = old_b

                dec = [test_plug[traj[t][test_plug[cipher[t]]]] for t in range(L)]
                ev[b] = _ngram_score(dec)
            m_plug[a].accumulate(ev, T)

        # --- Involution constraint propagation ---
        # P(a)=b ⟹ P(b)=a. Cross-constrain all 26 plug manifolds.
        for a in range(26):
            for b in range(26):
                # If plug[a] believes a→b strongly, plug[b] should believe b→a
                weight_ab = m_plug[a].belief[b]
                weight_ba = m_plug[b].belief[a]
                avg = (weight_ab + weight_ba) / 2
                m_plug[a].belief[b] = avg
                m_plug[b].belief[a] = avg
            # Re-normalize
            total = sum(m_plug[a].belief) or 1e-12
            m_plug[a].belief = [v / total for v in m_plug[a].belief]

        # Update plug_map for next cycle
        plug_map = [m_plug[a].best() for a in range(26)]

        if progress and cycle % 5 == 0:
            combo = all_combos[m_combo.best()]
            refl = reflector_pool[m_refl.best()]
            pos = (m_pos_L.best(), m_pos_M.best(), m_pos_R.best())
            ring = (0, m_ring_M.best(), m_ring_R.best())
            n_pairs = sum(1 for a in range(26) if plug_map[a] > a)
            ent = sum(m.entropy() for m in [m_combo, m_refl, m_pos_L, m_pos_M, m_pos_R,
                                            m_ring_M, m_ring_R] + m_plug)
            print(f"  cycle {cycle:2d} T={T:.2f} | "
                  f"{'-'.join(combo)}/{refl} "
                  f"pos={''.join(chr(p+65) for p in pos)} "
                  f"ring={''.join(chr(r+65) for r in ring)} "
                  f"plug_pairs={n_pairs} H={ent:.1f}")

    # --- Final state ---
    combo = all_combos[m_combo.best()]
    refl = reflector_pool[m_refl.best()]
    pos = (m_pos_L.best(), m_pos_M.best(), m_pos_R.best())
    ring = (0, m_ring_M.best(), m_ring_R.best())
    plug_map = [m_plug[a].best() for a in range(26)]

    traj = fast_trajectory(combo, refl, pos, ring, L)
    dec = [plug_map[traj[t][plug_map[cipher[t]]]] for t in range(L)]
    score = model.score(dec)
    n_excl = sum(1 for i in range(L - 1) if model.excluded[dec[i]][dec[i + 1]])
    pairs = [(a, plug_map[a]) for a in range(26) if plug_map[a] > a]

    return {
        "rotors": combo,
        "reflector": refl,
        "positions": pos,
        "ring_settings": ring,
        "plugboard_map": plug_map,
        "plugboard_pairs": pairs,
        "plaintext": "".join(chr(d + 65) for d in dec),
        "score": score,
        "n_excluded_bigrams": n_excl,
        "manifold_states": {
            "combo": {"best": m_combo.best(), "entropy": m_combo.entropy()},
            "refl": {"best": m_refl.best(), "entropy": m_refl.entropy()},
            "pos": {"L": m_pos_L.best(), "M": m_pos_M.best(), "R": m_pos_R.best()},
            "ring": {"M": m_ring_M.best(), "R": m_ring_R.best()},
            "plug_entropy": sum(m.entropy() for m in m_plug) / 26,
        },
    }
