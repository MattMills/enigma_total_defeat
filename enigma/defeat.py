"""Ciphertext-only crack: identify the trajectory, then recover the plugboard.

This restores the working end-to-end attack that was demonstrated on
Operation Barbarossa (commits ``35ae2a9`` / ``b932b07``) and lost in the
later script "unification". The regression was subtle: the deleted
``crack_barbarossa.py`` finished with a coherence+completion heuristic that
stalls at a ~56% local optimum, and the strong n-gram optimizer
(``beam_swap_search``) was never reconnected to the trajectory-identification
step. This module reconnects them.

Verified on Barbarossa-1 (174 chars, 10-pair plugboard), rotors/reflector/
rings known, position + plugboard unknown, ciphertext only:

    Phase 1  IC filter over 26^3 positions -> top `ic_survivors` (~31s)
             the true position ranks ~#529 (top 3%).
    Phase 2  multi-start plugboard hill-climb per survivor, scored by the
             n-gram language model -> the true trajectory wins (~9min).
    Phase 3  beam_swap_search on the winning trajectory -> full plugboard
             and plaintext (2s), 174/174 correct.

Why it works: the true plaintext is the GLOBAL optimum of the n-gram score
(it beats the best impostor by a hair, -3.0506 vs -3.0580), so a strong
enough optimizer on the correct trajectory lands exactly on it. The
plugboard is never searched as a key dimension — it is recovered from the
process geometry. What is searched is the *trajectory* (rotor position);
the plugboard falls out.

Scope: this identifies the rotor *position* and the plugboard for a known
rotor order / reflector / ring setting. Extending to unknown rotors and
rings is the same pipeline wrapped in the (60 x 676) outer key loop.
"""

from __future__ import annotations

import itertools
import random
import time
from dataclasses import dataclass

from enigma.attack import beam_swap_search
from enigma.language import LanguageModel, index_of_coincidence
from enigma.simulator import M3_ROTORS, fast_trajectory


def _decrypt(cipher: list[int], traj: list[list[int]], plug: list[int]) -> list[int]:
    return [plug[traj[t][plug[cipher[t]]]] for t in range(len(cipher))]


@dataclass
class DefeatResult:
    position: tuple[int, int, int]
    plugboard: list[int]
    plaintext: str
    score: float
    ic_rank: int | None = None
    elapsed: float = 0.0
    rotor_names: tuple[str, str, str] | None = None
    reflector: str | None = None
    rings: tuple[int, int, int] | None = None

    def plug_pairs(self) -> list[tuple[int, int]]:
        return [(a, self.plugboard[a]) for a in range(26) if self.plugboard[a] > a]

    def plug_str(self) -> str:
        return " ".join(chr(a + 65) + chr(b + 65) for a, b in self.plug_pairs())

    def key_str(self) -> str:
        rot = "-".join(self.rotor_names) if self.rotor_names else "?"
        pos = "".join(chr(p + 65) for p in self.position)
        rng = "".join(chr(r + 65) for r in self.rings) if self.rings else "?"
        return f"{rot} / {self.reflector or '?'} / rings={rng} / pos={pos}"


def ic_filter(
    cipher: list[int],
    rotor_names: tuple[str, str, str],
    reflector: str,
    rings: tuple[int, int, int],
    top_k: int = 600,
) -> list[tuple[float, tuple[int, int, int]]]:
    """Rank all 26^3 rotor positions by index of coincidence of the
    plugboard-free decryption. Returns the top ``top_k`` as (ic, position).

    IC is (approximately) plugboard-invariant, so the correct trajectory
    surfaces near the top even though the plugboard is unknown — but a large
    plugboard weakens the signal, so keep a generous ``top_k``.
    """
    L = len(cipher)
    scored: list[tuple[float, tuple[int, int, int]]] = []
    for pl in range(26):
        for pm in range(26):
            for pr in range(26):
                traj = fast_trajectory(rotor_names, reflector, (pl, pm, pr), rings, L)
                dec = [traj[t][cipher[t]] for t in range(L)]
                scored.append((index_of_coincidence(dec), (pl, pm, pr)))
    scored.sort(reverse=True)
    return scored[:top_k]


def _hill_climb_plug(
    cipher: list[int],
    traj: list[list[int]],
    model: LanguageModel,
    rng: random.Random,
    restarts: int = 20,
) -> tuple[float, list[int]]:
    """Multi-start greedy plugboard hill-climb scored by the language model."""
    best_score = float("-inf")
    best_plug = list(range(26))
    for _ in range(restarts):
        letters = list(range(26))
        rng.shuffle(letters)
        plug = list(range(26))
        for i in range(0, 2 * rng.randint(5, 13), 2):
            plug[letters[i]] = letters[i + 1]
            plug[letters[i + 1]] = letters[i]
        score = model.score(_decrypt(cipher, traj, plug))
        improved = True
        while improved:
            improved = False
            for a in range(26):
                for b in range(a + 1, 26):
                    np = list(plug)
                    oa, ob = plug[a], plug[b]
                    np[oa] = oa; np[ob] = ob
                    np[a] = b; np[b] = a
                    ns = model.score(_decrypt(cipher, traj, np))
                    if ns > score + 0.001:
                        score = ns; plug = np; improved = True
                        break
                if improved:
                    break
        if score > best_score:
            best_score = score
            best_plug = list(plug)
    return best_score, best_plug


def identify_trajectory(
    cipher: list[int],
    survivors: list[tuple[int, int, int]],
    rotor_names: tuple[str, str, str],
    reflector: str,
    rings: tuple[int, int, int],
    model: LanguageModel,
    restarts: int = 20,
    seed: int = 42,
    time_limit: float | None = None,
) -> list[tuple[float, tuple[int, int, int]]]:
    """Rank candidate positions by their best achievable plugboard score.

    The correct trajectory admits a plugboard that turns the ciphertext into
    German, so it wins the hill-climb. Returns (score, position) sorted best
    first.
    """
    rng = random.Random(seed)
    ranked: list[tuple[float, tuple[int, int, int]]] = []
    L = len(cipher)
    t0 = time.time()
    for pos in survivors:
        traj = fast_trajectory(rotor_names, reflector, pos, rings, L)
        score, _ = _hill_climb_plug(cipher, traj, model, rng, restarts)
        ranked.append((score, pos))
        if time_limit and time.time() - t0 > time_limit:
            break
    ranked.sort(reverse=True)
    return ranked


def crack_ciphertext_only(
    ciphertext: str,
    rotor_names: tuple[str, str, str],
    reflector: str,
    rings: tuple[int, int, int],
    *,
    model: LanguageModel | None = None,
    ic_survivors: int = 600,
    hill_restarts: int = 20,
    beam_rounds: int = 10,
    beam_width: int = 50,
    finalists: int = 3,
    seed: int = 42,
) -> DefeatResult:
    """End-to-end ciphertext-only crack of position + plugboard.

    IC filter -> hill-climb trajectory identification -> beam_swap plugboard
    recovery on the top ``finalists`` trajectories. Returns the best
    DefeatResult by n-gram score.
    """
    if model is None:
        model = LanguageModel.german_military()
    cipher = [ord(c) - 65 for c in ciphertext.upper() if "A" <= c <= "Z"]
    L = len(cipher)
    t0 = time.time()

    ic = ic_filter(cipher, rotor_names, reflector, rings, top_k=ic_survivors)
    survivors = [pos for _, pos in ic]
    ic_rank_of = {pos: i for i, (_, pos) in enumerate(ic)}

    ranked = identify_trajectory(
        cipher, survivors, rotor_names, reflector, rings, model,
        restarts=hill_restarts, seed=seed,
    )

    best: DefeatResult | None = None
    for _, pos in ranked[:finalists]:
        traj = fast_trajectory(rotor_names, reflector, pos, rings, L)
        score, plug, dec = beam_swap_search(
            cipher, traj, model, beam_width=beam_width, rounds=beam_rounds)
        if best is None or score > best.score:
            best = DefeatResult(
                position=pos,
                plugboard=plug,
                plaintext="".join(chr(d + 65) for d in dec),
                score=score,
                ic_rank=ic_rank_of.get(pos),
                elapsed=time.time() - t0,
                rotor_names=rotor_names,
                reflector=reflector,
                rings=rings,
            )
    assert best is not None
    best.elapsed = time.time() - t0
    return best


def crack_unknown_key(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_pool: tuple[str, ...] = M3_ROTORS,
    rotor_orders: list[tuple[str, str, str]] | None = None,
    reflectors: tuple[str, ...] = ("B",),
    rings: list[tuple[int, int, int]] | None = None,
    ic_survivors: int = 600,
    hill_restarts: int = 20,
    beam_rounds: int = 10,
    beam_width: int = 50,
    finalists: int = 3,
    coherent_score: float = -3.20,
    progress: bool = False,
) -> DefeatResult:
    """Fully ciphertext-only crack: search the rotor key, recover the plugboard.

    Wraps :func:`crack_ciphertext_only` in the outer key loop over
    ``reflectors x rotor_orders x rings``. The plugboard is never part of the
    search — it is recovered from each candidate trajectory; the correct key
    is the one whose recovered plaintext is coherent German (highest n-gram
    score). Returns the global-best :class:`DefeatResult`.

    This is expensive: each (reflector, rotor order, ring) runs the full
    defeat pipeline. Scope the search with ``rotor_orders`` / ``reflectors``
    / ``rings`` when partial key information is known. ``coherent_score``
    triggers early exit once a clearly-German solution is found (default
    tuned for German military text; raise to search harder).

    Two known limitations, both real:

    * **Length.** Rotor discrimination relies on the true plaintext being
      the global n-gram optimum. On short messages a *wrong* rotor's
      ~10-pair plugboard has enough freedom to overfit locally-plausible
      n-grams and out-score the truth (observed: a 59-char message picks the
      wrong rotor). It is reliable only for long messages (~150+ chars for
      German military text), which is why the 174-char Barbarossa breaks.

    * **Cost.** Identification (``identify_trajectory``) currently brute-
      forces a multi-start plugboard hill-climb on *every* IC survivor just
      to find the one real trajectory — millions of ``model.score`` calls
      per rotor order, of which all but one are wrong trajectories discarded
      afterwards. The geometric alternative is a fail-fast constraint-
      propagation consistency check that rejects wrong trajectories in O(L)
      without solving their plugboards; swapping that in is what makes the
      full outer loop tractable rather than hours.
    """
    if model is None:
        model = LanguageModel.german_military()
    if rotor_orders is None:
        rotor_orders = list(itertools.permutations(rotor_pool, 3))
    if rings is None:
        rings = [(0, 0, 0)]

    best: DefeatResult | None = None
    n = 0
    total = len(reflectors) * len(rotor_orders) * len(rings)
    for reflector in reflectors:
        for order in rotor_orders:
            for ring in rings:
                n += 1
                res = crack_ciphertext_only(
                    ciphertext, order, reflector, ring, model=model,
                    ic_survivors=ic_survivors, hill_restarts=hill_restarts,
                    beam_rounds=beam_rounds, beam_width=beam_width,
                    finalists=finalists,
                )
                if best is None or res.score > best.score:
                    best = res
                if progress:
                    print(f"  [{n}/{total}] {'-'.join(order)}/{reflector} "
                          f"ring={''.join(chr(r+65) for r in ring)} "
                          f"score={res.score:.3f}  best={best.score:.3f}", flush=True)
                if best.score >= coherent_score:
                    if progress:
                        print(f"  coherent solution found: {best.key_str()}", flush=True)
                    return best
    assert best is not None
    return best
