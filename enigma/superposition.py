"""Superposition solver: constructive constraint propagation.

The plugboard starts EMPTY and is progressively populated with entries
that MUST exist because the cipher equation at each position requires
them. Forward propagation (position 0→L) builds requirements left to
right; backward propagation (position L→0) builds them right to left.

At each position t, the cipher equation c_t = P(E_t(P(p_t))) requires:
  P(p_t) = x  (some x)
  E_t(x) = y
  P(y) = c_t

This establishes plugboard fragments: {p_t↔x, y↔c_t}. Fragments from
different positions must be MUTUALLY CONSISTENT (no letter maps to two
different targets). Inconsistent fragments are eliminated.

For the CORRECT trajectory: fragments from all positions converge to
the unique true plugboard. Mutual consistency across 50+ positions
is essentially impossible by chance — only the true plugboard survives.

For WRONG trajectories: fragments from different positions contradict
each other within the first few positions, and the hypothesis dies.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from enigma.language import LanguageModel
from enigma.simulator import ROTORS, REFLECTORS, fast_trajectory


@dataclass
class CollapseResult:
    consistent: bool
    plugboard: dict[int, int]     # determined P(a) = b entries
    plaintext: list[int | None]   # determined or None per position
    n_plug_determined: int = 0
    n_pt_determined: int = 0

    def plaintext_str(self) -> str:
        return "".join(
            chr(p + 65) if p is not None else "?"
            for p in self.plaintext
        )

    def plug_pairs(self) -> list[tuple[int, int]]:
        pairs = []
        seen: set[int] = set()
        for a, b in self.plugboard.items():
            if a in seen:
                continue
            if b != a:
                pairs.append((min(a, b), max(a, b)))
                seen.add(a)
                seen.add(b)
        return sorted(pairs)


def try_collapse(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    seed_letter: int,
    seed_position: int = 0,
) -> CollapseResult:
    """Try to collapse the superposition by seeding with a specific
    plaintext letter at a specific position, then propagating forward
    and backward constructively.

    The seed fixes p[seed_position] = seed_letter. The cipher equation
    at that position requires P(seed_letter) = x for some x. We try
    EACH possible x and propagate. For the correct (trajectory, seed,
    x), the constraints cascade and determine the full plugboard.
    For wrong combinations, contradictions appear quickly.
    """
    L = len(cipher)
    c0 = cipher[seed_position]
    E0 = trajectory[seed_position]

    if seed_letter == c0:
        return CollapseResult(False, {}, [None] * L)

    best = CollapseResult(False, {}, [None] * L)

    for x0 in range(26):
        y0 = E0[x0]
        # Fragment from seed position: P(seed_letter)=x0, P(x0)=seed_letter,
        # P(y0)=c0, P(c0)=y0.
        plug: dict[int, int] = {}

        # Check self-consistency of the four assignments.
        assignments = [
            (seed_letter, x0), (x0, seed_letter), (y0, c0), (c0, y0)
        ]
        ok = True
        for a, b in assignments:
            if a in plug and plug[a] != b:
                ok = False
                break
            plug[a] = b
        if not ok:
            continue

        # Now propagate forward and backward from the seed, building
        # the plugboard constructively.
        plaintext: list[int | None] = [None] * L
        plaintext[seed_position] = seed_letter

        ok = _propagate_constructive(
            cipher, trajectory, model, plug, plaintext, seed_position
        )
        if not ok:
            continue

        n_plug = len(plug)
        n_pt = sum(1 for p in plaintext if p is not None)

        if n_pt > best.n_pt_determined or (
            n_pt == best.n_pt_determined and n_plug > best.n_plug_determined
        ):
            best = CollapseResult(
                consistent=True,
                plugboard=dict(plug),
                plaintext=list(plaintext),
                n_plug_determined=n_plug,
                n_pt_determined=n_pt,
            )

    return best


def _propagate_constructive(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    plug: dict[int, int],
    plaintext: list[int | None],
    seed_pos: int,
) -> bool:
    """Propagate constraints forward and backward from determined positions.

    Returns False if a contradiction is found.
    """
    L = len(cipher)
    excluded = model.excluded
    queue: list[int] = [seed_pos]
    visited: set[int] = set()

    while queue:
        t = queue.pop(0)
        if t in visited:
            continue
        visited.add(t)

        p_t = plaintext[t]
        if p_t is None:
            continue

        c_t = cipher[t]
        E_t = trajectory[t]

        # p_t is known. Derive plugboard entries.
        if p_t in plug:
            x = plug[p_t]
        else:
            # p_t not yet in plugboard — it maps to itself (unplugged).
            x = p_t

        y = E_t[x]

        # Check P(y) = c_t
        if y in plug:
            if plug[y] != c_t:
                return False
        else:
            plug[y] = c_t
        if c_t in plug:
            if plug[c_t] != y:
                return False
        else:
            plug[c_t] = y

        # Involution: P(x) = p_t
        if x in plug:
            if plug[x] != p_t:
                return False
        else:
            plug[x] = p_t

        # Now try to determine adjacent positions using language + plugboard.
        for dt in [1, -1]:
            t2 = t + dt
            if t2 < 0 or t2 >= L or plaintext[t2] is not None:
                continue

            c2 = cipher[t2]
            E2 = trajectory[t2]

            # Try each candidate plaintext letter at t2.
            valid_p2: list[int] = []
            for p2 in range(26):
                if p2 == c2:
                    continue
                # Bigram check.
                if dt == 1 and excluded[p_t][p2]:
                    continue
                if dt == -1 and excluded[p2][p_t]:
                    continue

                # Check cipher equation consistency with current plugboard.
                if p2 in plug:
                    x2 = plug[p2]
                else:
                    x2 = p2  # assume unplugged
                y2 = E2[x2]

                # P(y2) should be c2
                if y2 in plug:
                    if plug[y2] != c2:
                        continue
                elif c2 in plug:
                    if plug[c2] != y2:
                        continue

                # P(x2) should be p2
                if x2 in plug:
                    if plug[x2] != p2:
                        continue

                valid_p2.append(p2)

            if len(valid_p2) == 0:
                return False
            if len(valid_p2) == 1:
                plaintext[t2] = valid_p2[0]
                # Add plugboard entries for this determined position.
                p2 = valid_p2[0]
                if p2 in plug:
                    x2 = plug[p2]
                else:
                    x2 = p2
                    plug[p2] = x2
                    plug[x2] = p2
                y2 = E2[x2]
                if y2 not in plug:
                    plug[y2] = c2
                elif plug[y2] != c2:
                    return False
                if c2 not in plug:
                    plug[c2] = y2
                elif plug[c2] != y2:
                    return False
                queue.append(t2)

    # Greedy extension: when no singletons, try the most likely
    # German letter at the next undetermined position and continue.
    freq_order = sorted(range(26), key=lambda x: model.unigram[x], reverse=True)
    for _ in range(L):
        # Find the first undetermined position adjacent to a determined one.
        next_t = None
        for t in range(L):
            if plaintext[t] is not None:
                continue
            # Check if adjacent to a determined position.
            if (t > 0 and plaintext[t - 1] is not None) or \
               (t < L - 1 and plaintext[t + 1] is not None):
                next_t = t
                break
        if next_t is None:
            break

        c_t = cipher[next_t]
        E_t = trajectory[next_t]
        branched = False
        for p_try in freq_order:
            if p_try == c_t:
                continue
            # Bigram check with determined neighbors.
            if next_t > 0 and plaintext[next_t - 1] is not None:
                if excluded[plaintext[next_t - 1]][p_try]:
                    continue
            if next_t < L - 1 and plaintext[next_t + 1] is not None:
                if excluded[p_try][plaintext[next_t + 1]]:
                    continue

            # Cipher equation check.
            if p_try in plug:
                x_t = plug[p_try]
            else:
                x_t = p_try
            y_t = E_t[x_t]
            if y_t in plug and plug[y_t] != c_t:
                continue
            if c_t in plug and plug[c_t] != y_t:
                continue
            if x_t in plug and plug[x_t] != p_try:
                continue

            # Try this assignment.
            plug_backup = dict(plug)
            plaintext[next_t] = p_try
            if p_try not in plug:
                plug[p_try] = x_t
                plug[x_t] = p_try
            if y_t not in plug:
                plug[y_t] = c_t
                plug[c_t] = y_t

            # Propagate from this new position.
            queue.append(next_t)
            branched = True
            break

        if not branched:
            return False

        # Re-propagate from queue.
        while queue:
            t = queue.pop(0)
            if t in visited:
                continue
            visited.add(t)
            p_t = plaintext[t]
            if p_t is None:
                continue
            c_tt = cipher[t]
            E_tt = trajectory[t]
            if p_t in plug:
                x = plug[p_t]
            else:
                x = p_t
            y = E_tt[x]
            if y in plug:
                if plug[y] != c_tt:
                    return False
            else:
                plug[y] = c_tt
            if c_tt in plug:
                if plug[c_tt] != y:
                    return False
            else:
                plug[c_tt] = y
            if x in plug:
                if plug[x] != p_t:
                    return False
            else:
                plug[x] = p_t

            for dt in [1, -1]:
                t2 = t + dt
                if t2 < 0 or t2 >= L or plaintext[t2] is not None:
                    continue
                c2 = cipher[t2]
                E2 = trajectory[t2]
                valid_p2: list[int] = []
                for p2 in range(26):
                    if p2 == c2:
                        continue
                    if dt == 1 and excluded[p_t][p2]:
                        continue
                    if dt == -1 and excluded[p2][p_t]:
                        continue
                    if p2 in plug:
                        x2 = plug[p2]
                    else:
                        x2 = p2
                    y2 = E2[x2]
                    if y2 in plug and plug[y2] != c2:
                        continue
                    if c2 in plug and plug[c2] != y2:
                        continue
                    if x2 in plug and plug[x2] != p2:
                        continue
                    valid_p2.append(p2)
                if len(valid_p2) == 0:
                    return False
                if len(valid_p2) == 1:
                    plaintext[t2] = valid_p2[0]
                    p2 = valid_p2[0]
                    if p2 not in plug:
                        plug[p2] = p2
                    x2 = plug[p2]
                    y2 = E2[x2]
                    if y2 not in plug:
                        plug[y2] = c2
                    elif plug[y2] != c2:
                        return False
                    if c2 not in plug:
                        plug[c2] = y2
                    elif plug[c2] != y2:
                        return False
                    queue.append(t2)

    return True


def collapse_attack(
    ciphertext: str,
    *,
    model: LanguageModel | None = None,
    rotor_names: tuple[str, str, str] = ("I", "II", "III"),
    reflector_name: str = "B",
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    top_k: int = 5,
    seed_letters: tuple[int, ...] = (4, 13, 8, 18, 17, 0, 19),  # E N I S R A T
    progress: bool = False,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> list[dict]:
    """Full attack: for each of 17,576 positions, try seeding with
    common German letters and propagate. Correct trajectory collapses;
    wrong trajectories contradict.
    """
    if model is None:
        model = LanguageModel.german_military()

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    L = len(cipher)
    if L == 0:
        return []

    results: list[dict] = []
    tested = 0

    for pl in range(26):
        for pm in range(26):
            for pr in range(26):
                tested += 1
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

                for seed in seed_letters:
                    if seed == cipher[0]:
                        continue
                    result = try_collapse(cipher, traj, model, seed, 0)
                    if not result.consistent:
                        continue
                    if result.n_pt_determined < 5:
                        continue

                    pt_ints = [p if p is not None else 0 for p in result.plaintext]
                    score = model.score(pt_ints)
                    results.append({
                        "positions": (pl, pm, pr),
                        "plaintext": result.plaintext_str(),
                        "score": score,
                        "plug_pairs": result.plug_pairs(),
                        "plug_determined": result.n_plug_determined,
                        "pt_determined": result.n_pt_determined,
                        "seed": chr(seed + 65),
                    })

        if progress and pl % 5 == 0:
            print(f"  left={pl}/25 tested={tested} hits={len(results)}")

    results.sort(key=lambda r: (-r["pt_determined"], -r["score"]))
    return results[:top_k]
