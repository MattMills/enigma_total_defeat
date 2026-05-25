"""Core cracking engine: domain-based cascade with back-propagation.

Combines three mechanisms:
  1. CASCADE: each determined plug entry triggers processing of all
     positions that touch that letter, which produces new entries,
     which triggers more processing.
  2. DOMAINS: undetermined plug entries carry a SET of possible values
     (not just a single value). Each position narrows the domain.
     When a domain becomes singleton, it's determined → cascade fires.
  3. BACK-PROPAGATION: new entries retroactively constrain previous
     positions. Bigram exclusions between adjacent resolved positions
     kill inconsistent states.

Binary discriminator: correct plugboard → 0 excluded bigrams.
Wrong plugboard → 1-5 excluded bigrams → state dies.
"""

from __future__ import annotations

from enigma.language import LanguageModel


class DomainPlug:
    """Plugboard with domain tracking per letter.

    plug_domain[a] = set of values P(a) could be.
    When |domain| == 1: determined.
    When |domain| == 0: contradiction → dead.
    """

    __slots__ = ("domains",)

    def __init__(self):
        self.domains: list[set[int]] = [set(range(26)) for _ in range(26)]

    def copy(self) -> "DomainPlug":
        dp = DomainPlug.__new__(DomainPlug)
        dp.domains = [set(s) for s in self.domains]
        return dp

    def is_determined(self, a: int) -> bool:
        return len(self.domains[a]) == 1

    def get(self, a: int) -> int | None:
        if len(self.domains[a]) == 1:
            return next(iter(self.domains[a]))
        return None

    def dead(self) -> bool:
        return any(len(d) == 0 for d in self.domains)

    def n_determined(self) -> int:
        return sum(1 for d in self.domains if len(d) == 1)

    def set_value(self, a: int, b: int) -> bool:
        """Set P(a) = b. Returns False if contradiction."""
        if b not in self.domains[a]:
            return False
        if len(self.domains[a]) == 1:
            return self.domains[a] == {b}
        self.domains[a] = {b}
        return True

    def exclude(self, a: int, b: int) -> bool:
        """Remove b from domain of a. Returns False if domain empties."""
        self.domains[a].discard(b)
        return len(self.domains[a]) > 0

    def propagate_involution(self) -> bool:
        """Enforce P(a)=b ⟹ P(b)=a. Returns False on contradiction."""
        changed = True
        while changed:
            changed = False
            for a in range(26):
                for b in list(self.domains[a]):
                    if a not in self.domains[b]:
                        self.domains[a].discard(b)
                        changed = True
                if len(self.domains[a]) == 0:
                    return False
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
        return True

    def fingerprint(self) -> tuple:
        return tuple(frozenset(d) for d in self.domains)

    def pairs(self) -> list[tuple[int, int]]:
        result = []
        seen: set[int] = set()
        for a in range(26):
            if a in seen or not self.is_determined(a):
                continue
            b = next(iter(self.domains[a]))
            if b != a:
                result.append((min(a, b), max(a, b)))
                seen.add(a)
                seen.add(b)
        return sorted(result)


def crack_trajectory(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    max_seeds: int = 650,
) -> list[tuple[DomainPlug, list[int | None]]]:
    """Find all plugboards consistent with this trajectory.

    Seeds from position 0 (all plaintext × all P(p) values).
    For each seed, cascades through all positions using domain
    propagation. Returns surviving (DomainPlug, plaintext) pairs.
    """
    L = len(cipher)
    excluded = model.excluded
    results: list[tuple[DomainPlug, list[int | None]]] = []

    c0 = cipher[0]
    E0 = trajectory[0]

    for seed_p in range(26):
        if seed_p == c0:
            continue
        for seed_x in range(26):
            y0 = E0[seed_x]

            dp = DomainPlug()
            # Set P(seed_p) = seed_x, P(seed_x) = seed_p
            # Set P(y0) = c0, P(c0) = y0
            ok = (
                dp.set_value(seed_p, seed_x)
                and dp.set_value(seed_x, seed_p)
                and dp.set_value(y0, c0)
                and dp.set_value(c0, y0)
            )
            if not ok:
                continue
            if not dp.propagate_involution():
                continue

            # Cascade: process all positions, narrow domains.
            plaintext: list[int | None] = [None] * L
            plaintext[0] = seed_p

            alive = _cascade(cipher, trajectory, model, dp, plaintext)
            if alive and not dp.dead():
                results.append((dp, plaintext))

    return results


def _cascade(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    dp: DomainPlug,
    plaintext: list[int | None],
) -> bool:
    """Cascade constraint propagation through ALL positions.

    For each position t:
      - If P(c_t) is determined: compute x_t, narrow P(x_t) domain.
      - If P(x_t) becomes determined: plaintext[t] is known.
      - If plaintext[t] and plaintext[t±1] are both known: check bigram.
      - New determined entries → re-process all positions.

    Returns False on contradiction.
    """
    L = len(cipher)
    excluded = model.excluded

    from collections import defaultdict
    ct_positions: dict[int, list[int]] = defaultdict(list)
    for t in range(L):
        ct_positions[cipher[t]].append(t)

    # Run differential + involution + cascade in a unified loop.
    for _round in range(50):
        prev_fingerprint = dp.fingerprint()

        # DIFFERENTIAL: narrow P(c) using all positions where c appears.
        for c_letter, positions in ct_positions.items():
            for a in list(dp.domains[c_letter]):
                if c_letter not in dp.domains[a]:
                    dp.domains[c_letter].discard(a)
                    continue
                ok = True
                for t in positions:
                    x = trajectory[t][a]
                    valid_p = dp.domains[x] - {cipher[t]}
                    if not valid_p:
                        ok = False; break
                if not ok:
                    dp.domains[c_letter].discard(a)
            if dp.dead():
                return False

        # PER-POSITION: narrow domain(c_t) via cipher equation.
        for t in range(L):
            ct = cipher[t]
            Et = trajectory[t]
            for a in list(dp.domains[ct]):
                x = Et[a]
                if not (dp.domains[x] - {ct}):
                    dp.domains[ct].discard(a)
            if dp.dead():
                return False

        if not dp.propagate_involution():
            return False

        if dp.fingerprint() == prev_fingerprint:
            break
        changed = False
        for t in range(L):
            ct = cipher[t]
            Et = trajectory[t]

            c_val = dp.get(ct)
            if c_val is not None:
                y = c_val
                x = Et[y]
                # Reflector: plaintext ≠ ciphertext.
                if ct in dp.domains[x]:
                    dp.domains[x].discard(ct)
                    changed = True
                if dp.dead():
                    return False

                # Bigram narrowing: domain(x) = possible P(x) = possible
                # plaintext[t]. Exclude values that create bad bigrams
                # with determined neighbors.
                if t > 0 and plaintext[t - 1] is not None:
                    prev = plaintext[t - 1]
                    for v in list(dp.domains[x]):
                        if excluded[prev][v]:
                            dp.domains[x].discard(v)
                            changed = True
                if t < L - 1 and plaintext[t + 1] is not None:
                    nxt = plaintext[t + 1]
                    for v in list(dp.domains[x]):
                        if excluded[v][nxt]:
                            dp.domains[x].discard(v)
                            changed = True
                if dp.dead():
                    return False

                x_val = dp.get(x)
                if x_val is not None and plaintext[t] is None:
                    plaintext[t] = x_val
                    changed = True
                    if not dp.set_value(x_val, x):
                        return False
                    if not dp.set_value(x, x_val):
                        return False

            if plaintext[t] is not None:
                pt = plaintext[t]
                pt_val = dp.get(pt)
                if pt_val is not None:
                    x = pt_val
                    y = Et[x]
                    old_y = dp.get(y)
                    old_c = dp.get(ct)
                    if old_y is None or old_y != ct:
                        if not dp.set_value(y, ct):
                            return False
                        changed = True
                    if old_c is None or old_c != y:
                        if not dp.set_value(ct, y):
                            return False
                        changed = True
                else:
                    for x_cand in list(dp.domains[pt]):
                        y_cand = Et[x_cand]
                        if ct not in dp.domains[y_cand]:
                            dp.domains[pt].discard(x_cand)
                            changed = True
                    if dp.dead():
                        return False

            if plaintext[t] is not None:
                if t > 0 and plaintext[t - 1] is not None:
                    if excluded[plaintext[t - 1]][plaintext[t]]:
                        return False
                if t < L - 1 and plaintext[t + 1] is not None:
                    if excluded[plaintext[t]][plaintext[t + 1]]:
                        return False

        if not dp.propagate_involution():
            return False
        if not changed:
            break

    return True


def crack_message(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
) -> tuple[float, list[int], list[int]] | None:
    """Crack a message given its trajectory.

    Returns (score, plug_map, full_decryption) or None.
    """
    results = crack_trajectory(cipher, trajectory, model)
    if not results:
        return None

    best_score = float("-inf")
    best_result = None
    for dp, pt in results:
        plug_map = list(range(26))
        for a in range(26):
            v = dp.get(a)
            if v is not None:
                plug_map[a] = v
        dec = [plug_map[trajectory[t][plug_map[cipher[t]]]] for t in range(len(cipher))]
        score = model.score(dec)
        if score > best_score:
            best_score = score
            best_result = (score, plug_map, dec)

    return best_result
