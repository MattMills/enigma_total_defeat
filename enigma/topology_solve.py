"""Topological solver: forward-backward constraint closure.

The Enigma's path topology is bidirectional: encrypt and decrypt are
the same operation. This means we can:

1. FORWARD: For a hypothesized trajectory, compute what each ciphertext
   letter decrypts to (without plugboard). This gives us 26 possible
   "inner values" per position (one per plugboard mapping of c_t).

2. BACKWARD: From the ciphertext, constrain which inner values are
   GLOBALLY consistent. At each position, the plugboard maps c_t to
   some letter q_t, the trajectory maps q_t to some letter r_t, and
   the plugboard maps r_t to the plaintext p_t. The plugboard is a
   SINGLE static involution P across ALL positions. So P(c_t) and P(r_t)
   at every position must be mutually consistent.

3. CLOSURE: The set of globally consistent (trajectory, plugboard)
   pairs is the solution space. For the correct trajectory, there is
   exactly one consistent plugboard. For wrong trajectories, the
   constraints contradict and the solution space is empty.

The "X-pattern" is a special case: if we KNOW p_t = X at some positions,
then P(r_t) = X at those positions, which forces P(23) = r_t. But we
can generalize beyond X: ANY repeated plaintext letter at known positions
creates the same constraint.

The topological insight: we don't need to know WHICH positions have X.
Instead, for each position t, the ciphertext c_t and trajectory E_t
define a PAIR of plugboard entries: P(c_t) = q_t and P(E_t(q_t)) = p_t.
These pairs must be globally consistent across ALL L positions.
For the wrong trajectory, they aren't.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Sequence

from enigma.language import LanguageModel, index_of_coincidence
from enigma.simulator import (
    ROTORS,
    REFLECTORS,
    fast_trajectory,
    M3_ROTORS,
    M3_REFLECTORS,
)


@dataclass
class PlugConstraint:
    """A plugboard constraint: P(a) could be any value in `domain`."""
    domains: list[set[int]]  # domains[a] = possible values of P(a)

    @classmethod
    def unconstrained(cls) -> "PlugConstraint":
        return cls(domains=[set(range(26)) for _ in range(26)])

    def set_pair(self, a: int, b: int) -> bool:
        if b not in self.domains[a] or a not in self.domains[b]:
            return False
        self.domains[a] = {b}
        self.domains[b] = {a}
        return True

    def exclude(self, a: int, b: int) -> None:
        self.domains[a].discard(b)
        self.domains[b].discard(a)

    def propagate(self) -> bool:
        changed = True
        while changed:
            changed = False
            for a in range(26):
                if not self.domains[a]:
                    return False
                for b in list(self.domains[a]):
                    if a not in self.domains[b]:
                        self.domains[a].discard(b)
                        changed = True
                if len(self.domains[a]) == 1:
                    b = next(iter(self.domains[a]))
                    if self.domains[b] != {a}:
                        self.domains[b] = {a}
                        changed = True
                    for c in range(26):
                        if c != a and b in self.domains[c]:
                            self.domains[c].discard(b)
                            changed = True
                        if c != b and a in self.domains[c]:
                            self.domains[c].discard(a)
                            changed = True
        return all(len(d) > 0 for d in self.domains)

    def is_determined(self) -> bool:
        return all(len(d) == 1 for d in self.domains)

    def n_determined(self) -> int:
        return sum(1 for d in self.domains if len(d) == 1)

    def ambiguity(self) -> int:
        return sum(len(d) for d in self.domains)

    def get_map(self) -> list[int]:
        result = list(range(26))
        for a in range(26):
            if len(self.domains[a]) == 1:
                result[a] = next(iter(self.domains[a]))
        return result

    def copy(self) -> "PlugConstraint":
        return PlugConstraint(domains=[set(d) for d in self.domains])


def forward_backward_constrain(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
) -> PlugConstraint | None:
    """Derive plugboard constraints from trajectory + ciphertext + language.

    For each position t:
      c_t is the ciphertext (known)
      E_t is the operative geometry (from trajectory)

      The cipher equation: c_t = P(E_t(P(p_t)))
      Equivalently: P(c_t) = q_t, E_t(q_t) = r_t, P(r_t) = p_t

    For each position, E_t maps every possible q_t to a specific r_t.
    The constraint is: P(c_t) = q_t AND P(r_t) = p_t, and p_t != c_t
    (fixed-point-free).

    Additionally, bigram constraints: if p_t and p_{t+1} form an
    excluded bigram, that combination is impossible.

    The GLOBAL constraint: P must be consistent across ALL positions.
    """
    L = len(cipher)
    pc = PlugConstraint.unconstrained()

    # Forward pass: for each position, the cipher equation constrains P
    # P(c_t) = q_t means c_t maps to SOME q_t
    # E_t(q_t) = r_t, and P(r_t) = p_t (the plaintext)
    # p_t != c_t (fixed-point-free on the FULL machine, including plugboard)

    # First: exclude self-mappings at the full-machine level
    # The full machine maps plaintext to ciphertext, and p_t != c_t.
    # But P(c_t) CAN equal c_t (that just means c_t is unplugged).

    # For each position, enumerate the valid (q_t, r_t, p_t) triples
    # and intersect the P constraints across all positions.

    # Build per-position constraints on P(c_t)
    for t in range(L):
        c = cipher[t]
        E = trajectory[t]

        # P(c) = q  =>  E(q) = r  =>  P(r) = p  =>  p != c
        # For each candidate q in domains[c]:
        valid_q = set()
        for q in list(pc.domains[c]):
            r = E[q]
            # P(r) must have at least one value p where p != c
            possible_p = pc.domains[r] - {c}
            if not possible_p:
                continue
            # Also check involution: P(q) must include c
            if c not in pc.domains[q]:
                continue
            # And P(r) = p => P(p) = r, so r must be in domains[p]
            has_valid = False
            for p in possible_p:
                if r in pc.domains[p]:
                    has_valid = True
                    break
            if has_valid:
                valid_q.add(q)

        # Narrow P(c) to only valid q values
        pc.domains[c] = pc.domains[c] & valid_q
        if not pc.domains[c]:
            return None

    if not pc.propagate():
        return None

    # Bigram pass: if p_t and p_{t+1} must not be an excluded bigram,
    # then for each pair of adjacent positions, the plaintext values
    # are constrained by the language model.
    excluded = model.excluded
    for _ in range(3):  # iterate for convergence
        changed = False
        for t in range(L - 1):
            c1, c2 = cipher[t], cipher[t + 1]
            E1, E2 = trajectory[t], trajectory[t + 1]

            for q1 in list(pc.domains[c1]):
                r1 = E1[q1]
                possible_p1 = pc.domains[r1] - {c1}
                if not possible_p1:
                    pc.domains[c1].discard(q1)
                    changed = True
                    continue

                has_valid_successor = False
                for p1 in possible_p1:
                    for q2 in pc.domains[c2]:
                        r2 = E2[q2]
                        possible_p2 = pc.domains[r2] - {c2}
                        for p2 in possible_p2:
                            if not excluded[p1][p2]:
                                has_valid_successor = True
                                break
                        if has_valid_successor:
                            break
                    if has_valid_successor:
                        break

                if not has_valid_successor:
                    pc.domains[c1].discard(q1)
                    changed = True

            if not pc.domains[c1]:
                return None

        if not pc.propagate():
            return None
        if not changed:
            break

    return pc


def count_solution_space(pc: PlugConstraint) -> int:
    """Count the number of valid involutions consistent with the constraints.

    This is the size of the global solution space — the number of
    plugboard configurations that are topologically consistent with
    the trajectory and ciphertext.
    """
    if pc.is_determined():
        return 1

    # Simple upper bound: product of domain sizes / 2 (involution pairing)
    # Exact count requires backtracking
    determined = pc.n_determined()
    free = 26 - determined
    if free == 0:
        return 1

    # Backtracking count
    return _count_involutions(pc, 0)


def _count_involutions(pc: PlugConstraint, start: int) -> int:
    """Count valid involutions by backtracking from letter `start`."""
    # Find first undetermined letter
    a = -1
    for i in range(start, 26):
        if len(pc.domains[i]) > 1:
            a = i
            break
    if a == -1:
        return 1  # all determined

    count = 0
    for b in sorted(pc.domains[a]):
        trial = pc.copy()
        if not trial.set_pair(a, b):
            continue
        if not trial.propagate():
            continue
        count += _count_involutions(trial, a + 1)

    return count


def topology_solve(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_pool: Sequence[str] = M3_ROTORS,
    reflector_names: Sequence[str] = M3_REFLECTORS,
    ic_survivors: int = 20,
    time_limit: float = 300.0,
    search_rings: bool = True,
    progress: bool = False,
) -> list[dict]:
    """Topological solver: forward-backward constraint closure.

    For each candidate trajectory:
      1. FORWARD: compute plugboard constraints from cipher equation
      2. BACKWARD: propagate involution + bigram constraints
      3. COUNT: size of the global solution space
      4. If solution space = 1: we have the answer

    The correct trajectory produces solution space = 1.
    Wrong trajectories produce solution space = 0 (contradiction).
    """
    import itertools
    from enigma.attack import beam_swap_search
    from enigma.pipeline import stage_validate
    from enigma.spectral import identify_right_rotor

    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)
    if L < 30:
        return []

    t0 = time.time()

    # Spectral narrowing
    all_combos = list(itertools.permutations(rotor_pool, 3))
    spectral_results = identify_right_rotor(cipher, reflector_names[0], tuple(rotor_pool))
    spectral_top = [name for name, _ in spectral_results[:min(4, len(rotor_pool))]]
    combos = [c for c in all_combos if c[2] in spectral_top] or all_combos

    if progress:
        print(f"Phase 0: {len(combos)} combos × {len(reflector_names)} reflectors")

    results: list[dict] = []
    tested = 0
    survived = 0

    for refl in reflector_names:
        for combo in combos:
            if time.time() - t0 > time_limit:
                break

            # IC sweep
            ic_results: list[tuple[float, tuple[int, int, int]]] = []
            for pl in range(26):
                for pm in range(26):
                    for pr in range(26):
                        traj = fast_trajectory(combo, refl, (pl, pm, pr), (0, 0, 0), L)
                        dec = [traj[t][cipher[t]] for t in range(L)]
                        ic = index_of_coincidence(dec)
                        ic_results.append((ic, (pl, pm, pr)))
            ic_results.sort(reverse=True)

            for _, pos in ic_results[:ic_survivors]:
                if time.time() - t0 > time_limit:
                    break

                ring_range = range(26) if search_rings else [0]
                for rr in ring_range:
                    if time.time() - t0 > time_limit:
                        break
                    tested += 1
                    rings = (0, 0, rr)
                    traj = fast_trajectory(combo, refl, pos, rings, L)

                    # FORWARD-BACKWARD CONSTRAINT CLOSURE
                    pc = forward_backward_constrain(cipher, traj, model)
                    if pc is None:
                        continue  # contradiction — wrong trajectory

                    survived += 1
                    n_det = pc.n_determined()
                    ambig = pc.ambiguity()

                    # Count solution space (only if mostly determined)
                    sol_count = -1
                    if ambig <= 52:  # at most 2 choices per free letter
                        sol_count = count_solution_space(pc)

                    if progress and (n_det >= 20 or sol_count == 1):
                        print(f"  {'-'.join(combo)}/{refl} "
                              f"pos={''.join(chr(p+65) for p in pos)} "
                              f"ring={''.join(chr(r+65) for r in rings)} "
                              f"det={n_det}/26 ambig={ambig} "
                              f"sol={'?' if sol_count < 0 else sol_count}"
                              f"{'  ** UNIQUE **' if sol_count == 1 else ''}")

                    if sol_count == 1 or n_det >= 24:
                        plug_map = pc.get_map()
                        dec = [plug_map[traj[t][plug_map[cipher[t]]]] for t in range(L)]

                        # If not fully determined, polish with beam swap
                        if n_det < 26:
                            score, plug_map, dec = beam_swap_search(
                                cipher, traj, model,
                                start_plug=plug_map,
                                beam_width=80, rounds=8,
                            )
                        else:
                            score = model.score(dec)

                        n_excl = stage_validate(dec, model)
                        plaintext = "".join(chr(d + 65) for d in dec)
                        pairs = [(a, plug_map[a]) for a in range(26) if plug_map[a] > a]

                        results.append({
                            "rotors": combo,
                            "reflector": refl,
                            "positions": pos,
                            "rings": rings,
                            "plug_map": plug_map,
                            "plug_pairs": pairs,
                            "plaintext": plaintext,
                            "score": score,
                            "n_excluded": n_excl,
                            "n_determined": n_det,
                            "ambiguity": ambig,
                            "solution_count": sol_count,
                            "elapsed": time.time() - t0,
                        })

                        if n_excl == 0 and sol_count == 1:
                            if progress:
                                print(f"  ** SOLVED ** {tested} tested, {survived} survived")
                            return results

            if progress and tested % 500 == 0:
                print(f"  [{tested} tested, {survived} survived, {time.time()-t0:.1f}s]")

    if progress:
        print(f"Done: {tested} tested, {survived} survived, {len(results)} candidates")

    results.sort(key=lambda r: (r["n_excluded"], -r["score"]))
    return results
