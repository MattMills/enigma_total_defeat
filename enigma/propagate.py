"""Simultaneous constraint propagation with signed sets.

Every position propagates to every neighbor. Every solved position
constrains the plugboard globally. The plugboard constrains every
position. This runs until convergence.

Signed sets from the design doc:
  positive[t] = letters that COULD be plaintext at position t
  negative[t] = letters that CANNOT be plaintext at position t (NIL)

  plug_pos[a] = values P(a) could be
  plug_neg[a] = values P(a) cannot be

When positive[t] becomes a singleton: position t is SOLVED.
A solved position's plugboard implications flow to ALL positions.

When plug_pos[a] becomes a singleton: plugboard entry P(a) is DETERMINED.
A determined plugboard entry constrains ALL positions where a appears.

Propagation order: every position, every direction, every step.
Convergence: when no set changes.
"""

from __future__ import annotations

from enigma.language import LanguageModel
from enigma.simulator import fast_trajectory


class SignedPropagator:
    """Simultaneous constraint propagation on plaintext + plugboard."""

    def __init__(
        self,
        cipher: list[int],
        trajectory: list[list[int]],
        model: LanguageModel,
    ):
        self.cipher = cipher
        self.traj = trajectory
        self.model = model
        self.L = len(cipher)

        # Per-position signed sets.
        # positive[t] = candidate plaintext letters.
        # negative[t] = excluded plaintext letters.
        self.positive: list[set[int]] = []
        self.negative: list[set[int]] = []
        for t in range(self.L):
            pos = set(range(26)) - {cipher[t]}  # reflector exclusion
            self.positive.append(pos)
            self.negative.append({cipher[t]})

        # Plugboard signed sets.
        # plug_pos[a] = possible values of P(a).
        # plug_neg[a] = excluded values of P(a).
        self.plug_pos: list[set[int]] = [set(range(26)) for _ in range(26)]
        self.plug_neg: list[set[int]] = [set() for _ in range(26)]

    def propagate(self, max_rounds: int = 50) -> bool:
        """Run until convergence. Returns True if consistent."""
        for _ in range(max_rounds):
            changed = False
            changed |= self._prop_bigrams()
            changed |= self._prop_cipher_to_plug()
            changed |= self._prop_plug_involution()
            changed |= self._prop_plug_to_cipher()
            changed |= self._prop_plug_singletons()
            if not self._check_consistent():
                return False
            if not changed:
                break
        return True

    def _prop_bigrams(self) -> bool:
        """Bigram exclusion: forward and backward."""
        changed = False
        excluded = self.model.excluded
        for t in range(self.L - 1):
            for a in list(self.positive[t]):
                if not any(not excluded[a][b] for b in self.positive[t + 1]):
                    self.positive[t].discard(a)
                    self.negative[t].add(a)
                    changed = True
            for b in list(self.positive[t + 1]):
                if not any(not excluded[a][b] for a in self.positive[t]):
                    self.positive[t + 1].discard(b)
                    self.negative[t + 1].add(b)
                    changed = True
        return changed

    def _prop_cipher_to_plug(self) -> bool:
        """Cipher equation → plugboard constraints.

        At each position t where plaintext is determined (singleton):
          p = the plaintext letter
          c = cipher[t]
          E = traj[t]
          P(p) = x → E(x) = y → P(y) = c

        If plug_pos[p] is already singleton {x}: determine y = E(x),
        then plug_pos[y] ∩= {c} and plug_pos[c] ∩= {y}.

        If plug_pos[c] is singleton {y}: x = E(y), then
        plug_pos[p] ∩= {x} and plug_pos[x] ∩= {p}.
        """
        changed = False
        for t in range(self.L):
            if len(self.positive[t]) != 1:
                continue
            p = next(iter(self.positive[t]))
            c = self.cipher[t]
            E = self.traj[t]

            if len(self.plug_pos[p]) == 1:
                x = next(iter(self.plug_pos[p]))
                y = E[x]
                for a, b in [(y, c), (c, y), (x, p)]:
                    if b not in self.plug_pos[a]:
                        continue
                    if len(self.plug_pos[a]) > 1:
                        self.plug_pos[a] = {b}
                        changed = True

            if len(self.plug_pos[c]) == 1:
                y = next(iter(self.plug_pos[c]))
                x = E[y]
                for a, b in [(p, x), (x, p)]:
                    if b not in self.plug_pos[a]:
                        continue
                    if len(self.plug_pos[a]) > 1:
                        self.plug_pos[a] = {b}
                        changed = True

            # Even if plug isn't singleton, we can EXCLUDE values.
            # For each candidate x in plug_pos[p]:
            #   y = E(x). If c is NOT in plug_pos[y], then x is invalid.
            for x in list(self.plug_pos[p]):
                y = E[x]
                if c not in self.plug_pos[y]:
                    self.plug_pos[p].discard(x)
                    self.plug_neg[p].add(x)
                    changed = True
                # Also: P(x) = p, so p must be in plug_pos[x].
                if p not in self.plug_pos[x]:
                    self.plug_pos[p].discard(x)
                    self.plug_neg[p].add(x)
                    changed = True

        return changed

    def _prop_plug_involution(self) -> bool:
        """Involution: P(a)=b ⟹ P(b)=a. Remove asymmetric entries."""
        changed = False
        for a in range(26):
            for b in list(self.plug_pos[a]):
                if a not in self.plug_pos[b]:
                    self.plug_pos[a].discard(b)
                    self.plug_neg[a].add(b)
                    changed = True
        return changed

    def _prop_plug_to_cipher(self) -> bool:
        """Determined plugboard entries → constrain plaintext candidates.

        If plug_pos[c] is singleton {y} at position t where cipher=c:
          then x = E(y), P(x) = p. If plug_pos[x] is singleton {p}:
          then positive[t] ∩= {p}.
        """
        changed = False
        for t in range(self.L):
            c = self.cipher[t]
            E = self.traj[t]

            if len(self.plug_pos[c]) == 1:
                y = next(iter(self.plug_pos[c]))
                x = E[y]
                if len(self.plug_pos[x]) == 1:
                    p = next(iter(self.plug_pos[x]))
                    if p in self.positive[t] and len(self.positive[t]) > 1:
                        self.positive[t] = {p}
                        changed = True

            # Exclude plaintext candidates that conflict with plugboard.
            for p in list(self.positive[t]):
                # For p to be valid at position t: there must exist x in
                # plug_pos[p] such that E(x) = y and c in plug_pos[y].
                has_valid = False
                for x in self.plug_pos[p]:
                    y = E[x]
                    if c in self.plug_pos[y]:
                        has_valid = True
                        break
                if not has_valid:
                    self.positive[t].discard(p)
                    self.negative[t].add(p)
                    changed = True

        return changed

    def _prop_plug_singletons(self) -> bool:
        """Singleton propagation: determined P(a)=b excludes b from others."""
        changed = False
        for a in range(26):
            if len(self.plug_pos[a]) == 1:
                b = next(iter(self.plug_pos[a]))
                # P(b) = a (involution).
                if self.plug_pos[b] != {a}:
                    self.plug_pos[b] = {a}
                    changed = True
                # b is taken: remove from all other domains.
                for c in range(26):
                    if c != a and b in self.plug_pos[c]:
                        self.plug_pos[c].discard(b)
                        self.plug_neg[c].add(b)
                        changed = True
                    if c != b and a in self.plug_pos[c]:
                        self.plug_pos[c].discard(a)
                        self.plug_neg[c].add(a)
                        changed = True
        return changed

    def _check_consistent(self) -> bool:
        for t in range(self.L):
            if not self.positive[t]:
                return False
        for a in range(26):
            if not self.plug_pos[a]:
                return False
        return True

    def n_determined_positions(self) -> int:
        return sum(1 for t in range(self.L) if len(self.positive[t]) == 1)

    def n_determined_plug(self) -> int:
        return sum(1 for a in range(26) if len(self.plug_pos[a]) == 1)

    def plug_pairs(self) -> list[tuple[int, int]]:
        pairs = []
        seen: set[int] = set()
        for a in range(26):
            if a in seen or len(self.plug_pos[a]) != 1:
                continue
            b = next(iter(self.plug_pos[a]))
            if b != a:
                pairs.append((min(a, b), max(a, b)))
                seen.add(a)
                seen.add(b)
        return sorted(pairs)

    def get_plugboard(self) -> list[int]:
        plug = list(range(26))
        for a in range(26):
            if len(self.plug_pos[a]) == 1:
                plug[a] = next(iter(self.plug_pos[a]))
        return plug

    def decrypt_best(self) -> list[int]:
        plug = self.get_plugboard()
        return [plug[self.traj[t][plug[self.cipher[t]]]] for t in range(self.L)]

    def plaintext_str(self) -> str:
        out = []
        for t in range(self.L):
            if len(self.positive[t]) == 1:
                out.append(chr(next(iter(self.positive[t])) + 65))
            else:
                out.append("?")
        return "".join(out)

    def summary(self) -> str:
        return (
            f"pos_det={self.n_determined_positions()}/{self.L} "
            f"plug_det={self.n_determined_plug()}/26 "
            f"avg_candidates={sum(len(s) for s in self.positive)/self.L:.1f}"
        )
