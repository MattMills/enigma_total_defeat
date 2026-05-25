"""Adelic CRT-diagonal hyperchart with Gold-code interference.

Architecture:
  1. Each manifold stores state as vector across prime bases
     (size-26 → size-2 × size-13; size-60 → size-4 × size-3 × size-5)
  2. These prime-base vectors form a matrix: manifolds × prime-components
  3. Gold codes (length 31, family 33) spread each manifold into a shared
     interference space where they cross-interfere diagonally
  4. FEC-style entropy layer packages each manifold's state for consistent
     cross-interference into the global solve

Gold code properties (n=5):
  - Code length: 31 chips
  - Family size: 33 codes (exactly our manifold count!)
  - Auto-correlation: 31 (full signal extraction)
  - Cross-correlation: bounded ±9 (controlled diagonal leak)
  - The cross-correlation IS the interference signal between manifolds

The "diagonal" emerges naturally: manifolds sharing a prime base
(e.g., all size-26 manifolds share mod-2 and mod-13 structure)
interfere more strongly because their Gold code cross-correlation
encodes this shared structure.
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
# Gold code generation (n=5, length 31, family size 33)
# ------------------------------------------------------------------


def _lfsr(taps: list[int], state: int, n: int, length: int) -> list[int]:
    """Generate m-sequence from LFSR with given taps."""
    seq = []
    for _ in range(length):
        bit = state & 1
        seq.append(1 if bit else -1)  # bipolar: 0→-1, 1→+1
        fb = 0
        for t in taps:
            fb ^= (state >> t) & 1
        state = ((state >> 1) | (fb << (n - 1))) & ((1 << n) - 1)
    return seq


def generate_gold_family(n: int = 5) -> list[list[int]]:
    """Generate Gold code family for n=5 (length 31, family size 33).

    Uses preferred pair of m-sequences with good cross-correlation.
    Taps for n=5 preferred pair: [4,2,0] and [4,3,2,1,0] (or equivalent).
    """
    length = (1 << n) - 1  # 31

    # Preferred pair taps for n=5
    # poly1: x^5 + x^2 + 1 → taps at positions 0, 2 (feedback from bits 0 and 2)
    # poly2: x^5 + x^4 + x^3 + x + 1 → taps at positions 0, 1, 3, 4
    seq1 = _lfsr([0, 2], 1, n, length)
    seq2 = _lfsr([0, 1, 3, 4], 1, n, length)

    family = [seq1, seq2]  # First two codes are the m-sequences themselves
    for shift in range(length):
        # XOR (multiply in bipolar: 1*1=1, 1*-1=-1, -1*-1=1)
        gold = [seq1[i] * seq2[(i + shift) % length] for i in range(length)]
        family.append(gold)

    return family[:33]  # Exactly 33 codes


GOLD_CODES = generate_gold_family(5)
GOLD_LENGTH = 31


def gold_correlate(signal: list[float], code: list[int]) -> float:
    """Correlate a signal with a Gold code. Returns correlation value."""
    n = min(len(signal), len(code))
    return sum(signal[i] * code[i] for i in range(n)) / n


# ------------------------------------------------------------------
# Prime-base decomposition of manifold state
# ------------------------------------------------------------------


def factorize(n: int) -> list[tuple[int, int]]:
    """Return prime factorization as [(p, k), ...]."""
    factors = []
    d = 2
    while d * d <= n:
        k = 0
        while n % d == 0:
            k += 1
            n //= d
        if k > 0:
            factors.append((d, k))
        d += 1
    if n > 1:
        factors.append((n, 1))
    return factors


@dataclass
class PrimeBaseVector:
    """State vector decomposed across prime bases.

    A size-N manifold with N = p1^k1 * p2^k2 * ... gets one sub-vector
    per prime power component. These are the CRT "lanes."
    """
    total_size: int
    components: dict[int, list[float]] = field(default_factory=dict)  # base → belief vector
    factors: list[tuple[int, int]] = field(default_factory=list)

    @classmethod
    def create(cls, size: int) -> "PrimeBaseVector":
        factors = factorize(size)
        components = {}
        for p, k in factors:
            pk = p ** k
            components[pk] = [1.0 / pk] * pk  # uniform prior
        return cls(total_size=size, components=components, factors=factors)

    def best_per_base(self) -> dict[int, int]:
        """Best residue in each prime-power base."""
        return {base: max(range(len(vec)), key=lambda i: vec[i])
                for base, vec in self.components.items()}

    def entropy_per_base(self) -> dict[int, float]:
        """Entropy in each prime-power base."""
        result = {}
        for base, vec in self.components.items():
            total = sum(vec)
            if total < 1e-15:
                result[base] = math.log(base)
                continue
            probs = [v / total for v in vec]
            result[base] = -sum(p * math.log(p + 1e-15) for p in probs if p > 0)
        return result

    def total_entropy(self) -> float:
        return sum(self.entropy_per_base().values())

    def accumulate_base(self, base: int, evidence: list[float], temperature: float):
        """Accumulate evidence on one prime-power base."""
        vec = self.components[base]
        max_e = max(evidence)
        for i in range(len(vec)):
            vec[i] *= math.exp((evidence[i] - max_e) / temperature)
        total = sum(vec) or 1e-12
        self.components[base] = [v / total for v in vec]

    def full_belief(self) -> list[float]:
        """CRT-reconstruct full belief vector from prime-base components.

        For each value v in [0, total_size), decompose into prime residues
        and multiply the beliefs from each component.
        """
        belief = [1.0] * self.total_size
        for v in range(self.total_size):
            for base, vec in self.components.items():
                r = v % base
                belief[v] *= vec[r]
        total = sum(belief) or 1e-12
        return [b / total for b in belief]

    def best(self) -> int:
        """Best value from CRT reconstruction."""
        fb = self.full_belief()
        return max(range(self.total_size), key=lambda i: fb[i])

    def spread(self, code: list[int]) -> list[float]:
        """Spread the state into interference space using Gold code.

        Encodes the entropy of each prime-base component as signal amplitude,
        spread by the Gold code chips.
        """
        signal = [0.0] * GOLD_LENGTH
        # Signal amplitude = 1 - normalized_entropy (more certain = stronger signal)
        for base, vec in self.components.items():
            total = sum(vec)
            if total < 1e-15:
                continue
            probs = [v / total for v in vec]
            ent = -sum(p * math.log(p + 1e-15) for p in probs if p > 0)
            max_ent = math.log(base)
            certainty = 1.0 - (ent / max_ent) if max_ent > 0 else 0.0
            # Amplitude encodes certainty, phase encodes best value
            best_r = max(range(base), key=lambda i: vec[i])
            phase = 2 * math.pi * best_r / base
            for chip in range(GOLD_LENGTH):
                signal[chip] += certainty * code[chip] * math.cos(phase + 2*math.pi*chip/GOLD_LENGTH)
        return signal


# ------------------------------------------------------------------
# Interference space and FEC
# ------------------------------------------------------------------


@dataclass
class InterferenceSpace:
    """Shared space where all manifolds project and extract signals.

    Gold codes provide CDMA-like separation:
      - Auto-correlation (own code): full signal extraction
      - Cross-correlation (other codes): bounded diagonal leak

    The interference IS the information flow between manifolds.
    """
    accumulator: list[float] = field(default_factory=lambda: [0.0] * GOLD_LENGTH)
    n_contributions: int = 0

    def clear(self):
        self.accumulator = [0.0] * GOLD_LENGTH
        self.n_contributions = 0

    def project(self, signal: list[float]):
        """Add a manifold's spread signal to the shared space."""
        for i in range(GOLD_LENGTH):
            self.accumulator[i] += signal[i]
        self.n_contributions += 1

    def extract(self, code: list[int]) -> float:
        """Extract one manifold's signal via correlation with its Gold code.

        Returns: correlation value (high = strong agreement with own signal,
        plus bounded interference from other manifolds).
        """
        return gold_correlate(self.accumulator, code)

    def extract_vector(self, code: list[int], n_phases: int) -> list[float]:
        """Extract phase-resolved signal for a manifold.

        Returns evidence vector of length n_phases, where each element
        is the correlation at that phase offset.
        """
        evidence = []
        for phase_idx in range(n_phases):
            phase = 2 * math.pi * phase_idx / n_phases
            rotated = [
                self.accumulator[i] * math.cos(phase + 2*math.pi*i/GOLD_LENGTH)
                for i in range(GOLD_LENGTH)
            ]
            corr = gold_correlate(rotated, code)
            evidence.append(corr)
        return evidence

    def entropy_check(self) -> float:
        """FEC-style check: total energy in the interference space.

        Low energy = manifolds are inconsistent (cancelling each other).
        High energy = manifolds are coherent (reinforcing).
        """
        energy = sum(x * x for x in self.accumulator)
        max_energy = GOLD_LENGTH * self.n_contributions ** 2
        return energy / max_energy if max_energy > 0 else 0.0


# ------------------------------------------------------------------
# Full adelic system with Gold-code interference
# ------------------------------------------------------------------


@dataclass
class Manifold:
    """One manifold in the system: state + Gold code + prime decomposition."""
    name: str
    size: int
    code_idx: int
    state: PrimeBaseVector = field(default=None)

    def __post_init__(self):
        if self.state is None:
            self.state = PrimeBaseVector.create(self.size)

    @property
    def code(self) -> list[int]:
        return GOLD_CODES[self.code_idx]

    def spread(self) -> list[float]:
        return self.state.spread(self.code)

    def best(self) -> int:
        return self.state.best()

    def entropy(self) -> float:
        return self.state.total_entropy()


def build_manifold_system(
    rotor_pool: Sequence[str] = M3_ROTORS,
    reflector_pool: Sequence[str] = M3_REFLECTORS,
) -> tuple[list[Manifold], list[tuple[str, str, str]]]:
    """Build the 33-manifold system with Gold code assignments."""
    all_combos = list(itertools.permutations(rotor_pool, 3))

    manifolds = []
    idx = 0

    # Structural manifolds
    manifolds.append(Manifold("combo", len(all_combos), idx)); idx += 1
    manifolds.append(Manifold("refl", len(reflector_pool), idx)); idx += 1
    manifolds.append(Manifold("pos_L", 26, idx)); idx += 1
    manifolds.append(Manifold("pos_M", 26, idx)); idx += 1
    manifolds.append(Manifold("pos_R", 26, idx)); idx += 1
    manifolds.append(Manifold("ring_M", 26, idx)); idx += 1
    manifolds.append(Manifold("ring_R", 26, idx)); idx += 1

    # Plugboard manifolds (26 separate)
    for a in range(26):
        manifolds.append(Manifold(f"P({chr(a+65)})", 26, idx)); idx += 1

    return manifolds, all_combos


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
    """Full adelic system with Gold-code interference between manifolds.

    Each cycle:
      1. All manifolds spread their state into interference space
      2. Compute direct evidence for each manifold (trajectory-based)
      3. Extract interference signal from shared space (Gold correlation)
      4. Combine direct evidence + interference → update beliefs
      5. FEC check: verify coherence (energy in interference space)
      6. Involution constraint propagation on plug manifolds
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)

    manifolds, all_combos = build_manifold_system(rotor_pool, reflector_pool)
    space = InterferenceSpace()

    # Named references for convenience
    m_combo = manifolds[0]
    m_refl = manifolds[1]
    m_pos_L = manifolds[2]
    m_pos_M = manifolds[3]
    m_pos_R = manifolds[4]
    m_ring_M = manifolds[5]
    m_ring_R = manifolds[6]
    m_plug = manifolds[7:33]  # 26 plug manifolds

    for cycle in range(cycles):
        T = temp_start * (temp_end / temp_start) ** (cycle / max(cycles - 1, 1))

        # === Phase 1: All manifolds spread into interference space ===
        space.clear()
        for m in manifolds:
            space.project(m.spread())

        # === Phase 2: Compute direct evidence using current beliefs ===
        # Read current best from all manifolds
        ci = m_combo.best()
        ri = m_refl.best()
        pL = m_pos_L.best()
        pM = m_pos_M.best()
        pR = m_pos_R.best()
        rM = m_ring_M.best()
        rR = m_ring_R.best()
        plug_map = [m_plug[a].best() for a in range(26)]

        combo = all_combos[ci % len(all_combos)]
        refl = reflector_pool[ri % len(reflector_pool)]
        pos = (pL % 26, pM % 26, pR % 26)
        ring = (0, rM % 26, rR % 26)

        # Get trajectory at current best config
        traj = fast_trajectory(combo, refl, pos, ring, L)

        # Decrypt with current plug beliefs
        dec = [plug_map[traj[t][plug_map[cipher[t]]]] for t in range(L)]
        base_score = _ngram_score(dec)

        # --- Combo evidence ---
        combo_ev = [0.0] * len(all_combos)
        for idx, c in enumerate(all_combos):
            t2 = fast_trajectory(c, refl, pos, ring, L)
            d2 = [plug_map[t2[t][plug_map[cipher[t]]]] for t in range(L)]
            combo_ev[idx] = _ngram_score(d2)
        # Add interference signal from shared space
        interference = space.extract(m_combo.code)
        combo_ev = [e + interference * 0.1 for e in combo_ev]
        m_combo.state.accumulate_base(
            list(m_combo.state.components.keys())[0],
            combo_ev[:list(m_combo.state.components.keys())[0]],
            T,
        )

        # --- Position R evidence (26 values) ---
        pos_r_ev = [0.0] * 26
        for pr in range(26):
            t2 = fast_trajectory(combo, refl, (pL, pM, pr), ring, L)
            d2 = [plug_map[t2[t][plug_map[cipher[t]]]] for t in range(L)]
            pos_r_ev[pr] = _ngram_score(d2)
        # Add interference
        interference_r = space.extract(m_pos_R.code)
        pos_r_ev = [e + interference_r * 0.1 for e in pos_r_ev]
        # Update each prime base
        for base in m_pos_R.state.components:
            base_ev = [0.0] * base
            for r in range(base):
                # Average evidence across all values with this residue
                vals_with_r = [v for v in range(26) if v % base == r]
                base_ev[r] = max(pos_r_ev[v] for v in vals_with_r) if vals_with_r else 0
            m_pos_R.state.accumulate_base(base, base_ev, T)

        # --- Position M evidence ---
        pos_m_ev = [0.0] * 26
        pR = m_pos_R.best()
        for pm in range(26):
            t2 = fast_trajectory(combo, refl, (pL, pm, pR), ring, L)
            d2 = [plug_map[t2[t][plug_map[cipher[t]]]] for t in range(L)]
            pos_m_ev[pm] = _ngram_score(d2)
        for base in m_pos_M.state.components:
            base_ev = [0.0] * base
            for r in range(base):
                vals = [v for v in range(26) if v % base == r]
                base_ev[r] = max(pos_m_ev[v] for v in vals) if vals else 0
            m_pos_M.state.accumulate_base(base, base_ev, T)

        # --- Position L evidence ---
        pos_l_ev = [0.0] * 26
        pM = m_pos_M.best()
        for pl in range(26):
            t2 = fast_trajectory(combo, refl, (pl, pM, pR), ring, L)
            d2 = [plug_map[t2[t][plug_map[cipher[t]]]] for t in range(L)]
            pos_l_ev[pl] = _ngram_score(d2)
        for base in m_pos_L.state.components:
            base_ev = [0.0] * base
            for r in range(base):
                vals = [v for v in range(26) if v % base == r]
                base_ev[r] = max(pos_l_ev[v] for v in vals) if vals else 0
            m_pos_L.state.accumulate_base(base, base_ev, T)

        # --- Ring R evidence ---
        pL = m_pos_L.best()
        pos = (pL, pM, pR)
        ring_r_ev = [0.0] * 26
        for rr in range(26):
            t2 = fast_trajectory(combo, refl, pos, (0, rM, rr), L)
            d2 = [plug_map[t2[t][plug_map[cipher[t]]]] for t in range(L)]
            ring_r_ev[rr] = _ngram_score(d2)
        for base in m_ring_R.state.components:
            base_ev = [0.0] * base
            for r in range(base):
                vals = [v for v in range(26) if v % base == r]
                base_ev[r] = max(ring_r_ev[v] for v in vals) if vals else 0
            m_ring_R.state.accumulate_base(base, base_ev, T)

        # --- Plug manifolds ---
        rR = m_ring_R.best()
        ring = (0, rM, rR)
        traj = fast_trajectory(combo, refl, pos, ring, L)

        for a in range(26):
            plug_ev = [0.0] * 26
            for b in range(26):
                test_plug = list(plug_map)
                old_pa = test_plug[a]
                old_pb = test_plug[b]
                test_plug[a] = b
                test_plug[b] = a
                if old_pa != a and old_pa != b:
                    test_plug[old_pa] = old_pa
                if old_pb != b and old_pb != a and old_pb != old_pa:
                    test_plug[old_pb] = old_pb
                d2 = [test_plug[traj[t][test_plug[cipher[t]]]] for t in range(L)]
                plug_ev[b] = _ngram_score(d2)
            # Add interference from other plug manifolds
            plug_interference = space.extract(m_plug[a].code)
            plug_ev = [e + plug_interference * 0.05 for e in plug_ev]
            for base in m_plug[a].state.components:
                base_ev = [0.0] * base
                for r in range(base):
                    vals = [v for v in range(26) if v % base == r]
                    base_ev[r] = max(plug_ev[v] for v in vals) if vals else 0
                m_plug[a].state.accumulate_base(base, base_ev, T)

        # === Phase 3: Involution constraint propagation ===
        for a in range(26):
            for b in range(26):
                fb_a = m_plug[a].state.full_belief()
                fb_b = m_plug[b].state.full_belief()
                # Symmetrize: P(a)=b ⟹ P(b)=a
                avg = (fb_a[b] + fb_b[a]) / 2
                # Push back into prime bases
                for base, vec in m_plug[a].state.components.items():
                    r = b % base
                    vec[r] = (vec[r] + avg) / 2
                for base, vec in m_plug[b].state.components.items():
                    r = a % base
                    vec[r] = (vec[r] + avg) / 2
            # Renormalize
            for base, vec in m_plug[a].state.components.items():
                total = sum(vec) or 1e-12
                m_plug[a].state.components[base] = [v / total for v in vec]

        # === Phase 4: FEC coherence check ===
        coherence = space.entropy_check()

        if progress and cycle % 5 == 0:
            total_ent = sum(m.entropy() for m in manifolds)
            plug_map = [m_plug[a].best() for a in range(26)]
            n_pairs = sum(1 for a in range(26) if plug_map[a] > a)
            combo = all_combos[m_combo.best() % len(all_combos)]
            refl = reflector_pool[m_refl.best() % len(reflector_pool)]
            pos = (m_pos_L.best(), m_pos_M.best(), m_pos_R.best())
            ring = (0, m_ring_M.best(), m_ring_R.best())
            print(f"  cycle {cycle:2d} T={T:.2f} | "
                  f"{'-'.join(combo)}/{refl} "
                  f"pos={''.join(chr(p%26+65) for p in pos)} "
                  f"ring={''.join(chr(r%26+65) for r in ring)} "
                  f"pairs={n_pairs} coh={coherence:.3f} H={total_ent:.1f}")

    # === Final reconstruction ===
    combo = all_combos[m_combo.best() % len(all_combos)]
    refl = reflector_pool[m_refl.best() % len(reflector_pool)]
    pos = (m_pos_L.best() % 26, m_pos_M.best() % 26, m_pos_R.best() % 26)
    ring = (0, m_ring_M.best() % 26, m_ring_R.best() % 26)
    plug_map = [m_plug[a].best() % 26 for a in range(26)]

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
        "coherence": space.entropy_check(),
        "total_entropy": sum(m.entropy() for m in manifolds),
    }


def _ngram_score(dec: list[int]) -> float:
    """N-gram validity score."""
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
