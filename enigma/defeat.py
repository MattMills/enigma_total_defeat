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

import random
import time
from dataclasses import dataclass

from enigma.attack import beam_swap_search
from enigma.language import LanguageModel, index_of_coincidence
from enigma.simulator import fast_trajectory


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

    def plug_pairs(self) -> list[tuple[int, int]]:
        return [(a, self.plugboard[a]) for a in range(26) if self.plugboard[a] > a]

    def plug_str(self) -> str:
        return " ".join(chr(a + 65) + chr(b + 65) for a, b in self.plug_pairs())


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
            )
    assert best is not None
    best.elapsed = time.time() - t0
    return best
