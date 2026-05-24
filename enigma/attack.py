"""Geometric Constraint Propagation (GCP) attack on the Enigma.

Implements the algorithm described in
``geometric_enigma_cryptanalysis.md`` Part IV/V:

  1. Initialize per-position candidate sets using the reflector exclusion.
  2. Propagate German bigram exclusions to prune candidates.
  3. Sweep over (reflector, rotor selection/order, initial positions, rings)
     and for each trajectory decrypt the ciphertext, reject early on
     exclusory bigrams, and score against the language model.
  4. Infer plugboard swaps from residual frequency deviation.

The implementation is intended to be correct first and fast second; the
trajectory loop is deliberately structured to make early termination cheap
so that the inner search remains tractable.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from enigma.language import LanguageModel, UNIGRAM_FREQ
from enigma.simulator import (
    Enigma,
    Plugboard,
    REFLECTORS,
    ROTORS,
)


# ----------------------------------------------------------------------
# Phase 1/2: candidate-set initialization and bigram propagation


def initialize_candidates(ciphertext: Sequence[int]) -> list[set[int]]:
    """Return per-position positive candidate sets after the reflector exclusion."""
    return [set(range(26)) - {c} for c in ciphertext]


def propagate_bigrams(
    candidates: list[set[int]], model: LanguageModel
) -> list[set[int]]:
    """Iteratively prune candidates that have no valid bigram successor/predecessor."""
    L = len(candidates)
    if L < 2:
        return candidates
    cands = [set(s) for s in candidates]
    changed = True
    while changed:
        changed = False
        # Forward
        for t in range(L - 1):
            for a in list(cands[t]):
                if not any(not model.excluded[a][b] for b in cands[t + 1]):
                    cands[t].discard(a)
                    changed = True
        # Backward
        for t in range(L - 1, 0, -1):
            for b in list(cands[t]):
                if not any(not model.excluded[a][b] for a in cands[t - 1]):
                    cands[t].discard(b)
                    changed = True
    return cands


# ----------------------------------------------------------------------
# Phase 3: trajectory search


@dataclass
class AttackResult:
    plaintext: str
    score: float
    rotor_names: tuple[str, str, str]
    reflector_name: str
    positions: tuple[int, int, int]
    ring_settings: tuple[int, int, int]
    plugboard_pairs: list[tuple[str, str]] = field(default_factory=list)

    def __repr__(self) -> str:
        rings = "".join(chr(r + 65) for r in self.ring_settings)
        pos = "".join(chr(p + 65) for p in self.positions)
        plug = " ".join(f"{a}{b}" for a, b in self.plugboard_pairs)
        return (
            f"AttackResult(score={self.score:.3f}, "
            f"rotors={'-'.join(self.rotor_names)}, "
            f"reflector={self.reflector_name}, pos={pos}, rings={rings}, "
            f"plugboard={plug or 'none'})\n  plaintext={self.plaintext!r}"
        )


def _decrypt_with_machine(
    machine: Enigma, ciphertext: Sequence[int]
) -> list[int]:
    out: list[int] = []
    for c in ciphertext:
        out.append(machine.encrypt_letter(c))
    return out


def _early_reject(
    plaintext: list[int],
    candidates: list[set[int]],
    model: LanguageModel,
) -> bool:
    """Return True if the partial plaintext violates a hard constraint."""
    for t, p in enumerate(plaintext):
        if p not in candidates[t]:
            return True
        if t > 0 and model.excluded[plaintext[t - 1]][p]:
            return True
    return False


def _try_trajectory(
    ciphertext: Sequence[int],
    candidates: list[set[int]],
    model: LanguageModel,
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int],
    early_prefix: int,
) -> tuple[float, list[int]] | None:
    machine = Enigma(
        rotor_names=rotor_names,
        reflector_name=reflector_name,
        positions=list(positions),
        ring_settings=list(ring_settings),
        plugboard=Plugboard.identity(),
    )
    # Short pre-check: decrypt the prefix; reject if any hard violation.
    prefix: list[int] = []
    cipher_list = list(ciphertext)
    n_prefix = min(early_prefix, len(cipher_list))
    for t in range(n_prefix):
        p = machine.encrypt_letter(cipher_list[t])
        if p not in candidates[t]:
            return None
        if t > 0 and model.excluded[prefix[t - 1]][p]:
            return None
        prefix.append(p)
    # Continue full decryption from current state.
    full = list(prefix)
    for t in range(n_prefix, len(cipher_list)):
        p = machine.encrypt_letter(cipher_list[t])
        if model.excluded[full[-1]][p] if full else False:
            return None
        full.append(p)
    score = model.score(full)
    if score == float("-inf"):
        return None
    return score, full


# ----------------------------------------------------------------------
# Plugboard inference (Phase 4)


def infer_plugboard(
    plaintext: list[int], model: LanguageModel, max_pairs: int = 10
) -> tuple[list[tuple[int, int]], list[int]]:
    """Greedy swap inference. Returns (pairs, improved_plaintext)."""
    text = list(plaintext)
    pairs: list[tuple[int, int]] = []
    used: set[int] = set()

    def score(t: list[int]) -> float:
        return model.score(t)

    current = score(text)
    for _ in range(max_pairs):
        best_gain = 0.0
        best_pair: tuple[int, int] | None = None
        best_text: list[int] | None = None
        for a in range(26):
            if a in used:
                continue
            for b in range(a + 1, 26):
                if b in used:
                    continue
                swapped = [b if x == a else a if x == b else x for x in text]
                s = score(swapped)
                gain = s - current
                if gain > best_gain:
                    best_gain = gain
                    best_pair = (a, b)
                    best_text = swapped
        if best_pair is None or best_text is None:
            break
        pairs.append(best_pair)
        used.add(best_pair[0])
        used.add(best_pair[1])
        text = best_text
        current += best_gain
    return pairs, text


# ----------------------------------------------------------------------
# Top-level attack


def attack(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = ("I", "II", "III", "IV", "V"),
    reflector_names: Sequence[str] = ("A", "B", "C"),
    rings: Sequence[tuple[int, int, int]] = ((0, 0, 0),),
    early_prefix: int = 10,
    top_k: int = 5,
    progress: bool = False,
) -> list[AttackResult]:
    """Run GCP attack on the given ciphertext.

    This is intentionally a focused, programmable search. To keep runtime
    bounded for unit tests, callers can restrict the rotor pool, reflector
    list, and ring settings. The pure-language pre-pruning still applies.
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)
    if L == 0:
        return []

    # Phase 1/2
    candidates = initialize_candidates(cipher)
    candidates = propagate_bigrams(candidates, model)

    best: list[AttackResult] = []

    def consider(res: AttackResult) -> None:
        best.append(res)
        best.sort(key=lambda r: r.score, reverse=True)
        del best[top_k:]

    # Phase 3
    tried = 0
    for refl in reflector_names:
        for rotor_triple in itertools.permutations(rotor_pool, 3):
            for ring in rings:
                for pl in range(26):
                    for pm in range(26):
                        for pr in range(26):
                            tried += 1
                            res = _try_trajectory(
                                cipher,
                                candidates,
                                model,
                                rotor_triple,
                                refl,
                                (pl, pm, pr),
                                ring,
                                early_prefix,
                            )
                            if res is None:
                                continue
                            score, plaintext = res
                            # Optional plugboard inference for top candidates.
                            consider(
                                AttackResult(
                                    plaintext="".join(
                                        chr(p + 65) for p in plaintext
                                    ),
                                    score=score,
                                    rotor_names=rotor_triple,
                                    reflector_name=refl,
                                    positions=(pl, pm, pr),
                                    ring_settings=ring,
                                )
                            )
                if progress:
                    print(
                        f"  reflector={refl} rotors={rotor_triple} ring={ring} "
                        f"tried={tried} best_score={best[0].score if best else float('-inf'):.3f}"
                    )

    # Refine top candidates with plugboard inference.
    refined: list[AttackResult] = []
    for r in best:
        pt_ints = [ord(c) - 65 for c in r.plaintext]
        pairs, improved = infer_plugboard(pt_ints, model)
        if pairs:
            new_score = model.score(improved)
            if new_score > r.score:
                refined.append(
                    AttackResult(
                        plaintext="".join(chr(p + 65) for p in improved),
                        score=new_score,
                        rotor_names=r.rotor_names,
                        reflector_name=r.reflector_name,
                        positions=r.positions,
                        ring_settings=r.ring_settings,
                        plugboard_pairs=[
                            (chr(a + 65), chr(b + 65)) for a, b in pairs
                        ],
                    )
                )
                continue
        refined.append(r)
    refined.sort(key=lambda r: r.score, reverse=True)
    return refined
