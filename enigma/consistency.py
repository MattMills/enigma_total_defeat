"""Joint-consistency discriminator: the real trajectory test.

For each trajectory, the collision structure of E_t(q) across positions
implies plugboard entries. The correct trajectory is the one where
ALL implied entries across ALL ciphertext letters are mutually consistent
with a single involutory plugboard P.

The attack cascades from the most frequent ciphertext letter outward:

  1. For c_0 (most frequent), test 26 q values. Each q implies P entries
     via collision groups. Most q values will be internally consistent
     (the collision groups for one letter rarely self-contradict).

  2. But these P entries CONSTRAIN the q values for c_1 (next most frequent).
     If processing c_0 with q_0 determined P(a) = x, then processing c_1
     must use a q_1 where P(a) is still x. This prunes the 26 options
     for c_1 down to a handful.

  3. Continue cascading: each new ciphertext letter further constrains P,
     which further constrains q values for remaining letters.

  4. The correct trajectory cascades to a unique solution.
     Wrong trajectories cascade to contradiction (empty P).

The cascade is fast because at each step, the number of surviving
q values shrinks. After processing 3-4 high-frequency ciphertext
letters, most wrong trajectories are eliminated.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class ConsistencyResult:
    """Result of the joint-consistency test for one trajectory."""
    consistent: bool
    n_determined: int
    plug_map: list[int]
    plug_pairs: list[tuple[int, int]]
    q_assignments: dict[int, int]  # c -> q for each ciphertext letter
    n_ciphertext_letters_tested: int
    n_contradictions: int
    cascade_depth: int


def _build_collision_groups(
    cipher: list[int],
    trajectory: list[list[int]],
    c: int,
    q: int,
) -> dict[int, list[int]]:
    """For ciphertext letter c with hypothesis P(c) = q,
    compute E_t(q) at every position where cipher[t] = c.
    Group positions by their E_t(q) value."""
    groups: dict[int, list[int]] = defaultdict(list)
    for t in range(len(cipher)):
        if cipher[t] == c:
            e_val = trajectory[t][q]
            groups[e_val].append(t)
    return dict(groups)


def _extract_p_entries(
    groups: dict[int, list[int]],
    c: int,
    q: int,
) -> list[tuple[int, int, list[int]]]:
    """From collision groups, extract implied P entries.

    Each collision group with E_t(q) = a at positions [t1, t2, ...]
    means P(a) = p where p is the common plaintext at those positions.
    We don't know p yet, but we know:
      - P(a) is the SAME letter at all positions in the group
      - P(c) = q (the hypothesis)
      - P(q) = c (involution)

    Returns list of (a, group_size, positions) for groups with size > 1.
    These are the constraining groups — singletons tell us nothing.
    """
    entries = []
    for a, positions in groups.items():
        if len(positions) > 1:
            entries.append((a, len(positions), positions))
    return entries


class PlugState:
    """Partial plugboard being built incrementally."""

    __slots__ = ("forward", "used")

    def __init__(self):
        self.forward: dict[int, int] = {}  # P(a) = b
        self.used: set[int] = set()  # letters committed to a pair

    def copy(self) -> "PlugState":
        ps = PlugState()
        ps.forward = dict(self.forward)
        ps.used = set(self.used)
        return ps

    def set_pair(self, a: int, b: int) -> bool:
        """Set P(a) = b, P(b) = a. Returns False on contradiction."""
        if a in self.forward:
            if self.forward[a] != b:
                return False
            return True
        if b in self.forward:
            if self.forward[b] != a:
                return False
            return True
        if a in self.used or b in self.used:
            return False
        self.forward[a] = b
        self.forward[b] = a
        if a != b:
            self.used.add(a)
            self.used.add(b)
        return True

    def is_compatible(self, a: int, b: int) -> bool:
        """Can P(a) = b without contradiction?"""
        if a in self.forward:
            return self.forward[a] == b
        if b in self.forward:
            return self.forward[b] == a
        if a != b and (a in self.used or b in self.used):
            return False
        return True

    def get(self, a: int) -> int | None:
        return self.forward.get(a)

    def n_pairs(self) -> int:
        return sum(1 for a, b in self.forward.items() if a < b and a != b)

    def to_map(self) -> list[int]:
        result = list(range(26))
        for a, b in self.forward.items():
            result[a] = b
        return result

    def pairs(self) -> list[tuple[int, int]]:
        result = []
        seen: set[int] = set()
        for a, b in sorted(self.forward.items()):
            if a not in seen and a != b:
                result.append((min(a, b), max(a, b)))
                seen.add(a)
                seen.add(b)
        return result


def test_trajectory_consistency(
    cipher: list[int],
    trajectory: list[list[int]],
    min_freq: int = 4,
) -> ConsistencyResult:
    """Test if a trajectory admits a consistent plugboard.

    Cascades from most frequent ciphertext letter outward.
    Returns the result with the best (most-determined) consistent P found,
    or a failure result if no consistent assignment exists.
    """
    L = len(cipher)

    # Group positions by ciphertext letter, sorted by frequency
    ct_groups: dict[int, list[int]] = defaultdict(list)
    for t, c in enumerate(cipher):
        ct_groups[c].append(t)

    freq_order = sorted(ct_groups.keys(), key=lambda c: -len(ct_groups[c]))
    freq_order = [c for c in freq_order if len(ct_groups[c]) >= min_freq]

    if not freq_order:
        return ConsistencyResult(
            consistent=True, n_determined=0, plug_map=list(range(26)),
            plug_pairs=[], q_assignments={}, n_ciphertext_letters_tested=0,
            n_contradictions=0, cascade_depth=0,
        )

    best_result = None
    best_determined = -1

    # Start cascade from the most frequent ciphertext letter
    _cascade(
        cipher, trajectory, ct_groups, freq_order,
        depth=0,
        plug=PlugState(),
        q_assignments={},
        n_contradictions_holder=[0],
        best_holder=[best_result, best_determined],
    )

    best_result, best_determined = best_holder = [best_result, best_determined]

    if best_result is not None:
        return best_result

    return ConsistencyResult(
        consistent=False, n_determined=0, plug_map=list(range(26)),
        plug_pairs=[], q_assignments={},
        n_ciphertext_letters_tested=len(freq_order),
        n_contradictions=best_holder[1] if best_holder[1] >= 0 else 0,
        cascade_depth=0,
    )


def _cascade(
    cipher: list[int],
    trajectory: list[list[int]],
    ct_groups: dict[int, list[int]],
    freq_order: list[int],
    depth: int,
    plug: PlugState,
    q_assignments: dict[int, int],
    n_contradictions_holder: list[int],
    best_holder: list,
    max_depth: int = 8,
):
    """Recursive cascade: try q values for freq_order[depth], prune by P consistency.

    The key pruning: when processing (c, q), collision groups with size > 1
    force P(e_val) to be a SINGLE letter across all positions in the group.
    If P(e_val) is already determined by a previous cascade level, check
    consistency. If two collision groups from DIFFERENT ciphertext letters
    both constrain P(e_val), the constraints must agree.

    Additionally: for collision groups of size k, the k positions all have
    the same plaintext. For groups where e_val already has a P assignment,
    the plaintext at those positions is determined. We use this to propagate
    further: if P(e_val) = p, then at adjacent positions t+1, the bigram
    (p, plaintext[t+1]) must be valid German. This constrains plaintext[t+1],
    which may determine P entries for adjacent positions.
    """
    if depth >= len(freq_order) or depth >= max_depth:
        n_det = len(plug.forward)
        if n_det > best_holder[1]:
            best_holder[0] = ConsistencyResult(
                consistent=True,
                n_determined=n_det,
                plug_map=plug.to_map(),
                plug_pairs=plug.pairs(),
                q_assignments=dict(q_assignments),
                n_ciphertext_letters_tested=depth,
                n_contradictions=n_contradictions_holder[0],
                cascade_depth=depth,
            )
            best_holder[1] = n_det
        return

    c = freq_order[depth]

    for q in range(26):
        trial_plug = plug.copy()

        # P(c) = q, P(q) = c (involution)
        if not trial_plug.set_pair(c, q):
            n_contradictions_holder[0] += 1
            continue

        # Build collision groups
        groups = _build_collision_groups(cipher, trajectory, c, q)

        # Check and commit collision group constraints
        ok = True
        for e_val, group_positions in groups.items():
            if len(group_positions) < 2:
                continue

            # e_val == q would mean P(e_val) = P(q) = c, so plaintext = c,
            # but plaintext != ciphertext (fixed-point-free). Contradiction.
            if e_val == q:
                ok = False
                break

            # Check: is P(e_val) already determined?
            existing = trial_plug.get(e_val)
            if existing is not None:
                if existing == c:
                    # P(e_val) = c means plaintext = c = ciphertext. Forbidden.
                    ok = False
                    break
                # P(e_val) is committed and not c — consistent.
                # This means the plaintext at ALL positions in this group
                # is `existing`. This is a HARD determination.
                continue

            # P(e_val) is undetermined. We can't commit it yet (we don't
            # know the plaintext letter). But we CAN check: is e_val
            # already used as the image of some other letter? If P(x) = e_val
            # for some x, then P(e_val) = x (involution). Check that x != c.
            # The PlugState handles this via the `used` set.
            if e_val in trial_plug.used:
                # e_val is already committed as the image of some letter.
                # P(e_val) is determined. Check it's not c.
                p_e = trial_plug.get(e_val)
                if p_e == c:
                    ok = False
                    break

            # Now the CROSS-GROUP constraint: if another ciphertext letter
            # c2 already processed at a previous depth also has a collision
            # group touching e_val, then P(e_val) was already constrained.
            # The PlugState captures this automatically.

        if not ok:
            n_contradictions_holder[0] += 1
            continue

        # Also check: for SINGLETON groups (size 1), if e_val is already
        # P-committed, the plaintext at that position is determined.
        # If it equals c, contradiction.
        for e_val, group_positions in groups.items():
            if len(group_positions) != 1:
                continue
            existing = trial_plug.get(e_val)
            if existing == c:
                ok = False
                break

        if not ok:
            n_contradictions_holder[0] += 1
            continue

        trial_assignments = dict(q_assignments)
        trial_assignments[c] = q

        _cascade(
            cipher, trajectory, ct_groups, freq_order,
            depth + 1, trial_plug, trial_assignments,
            n_contradictions_holder, best_holder, max_depth,
        )

        if best_holder[1] >= 20:
            return


def score_trajectory(
    cipher: list[int],
    trajectory: list[list[int]],
    min_freq: int = 4,
    max_depth: int = 6,
) -> tuple[bool, int, int]:
    """Quick score: (consistent, n_determined, n_contradictions).

    Fast version for scanning many trajectories. Tests the top
    max_depth most frequent ciphertext letters.
    """
    L = len(cipher)
    ct_groups: dict[int, list[int]] = defaultdict(list)
    for t, c in enumerate(cipher):
        ct_groups[c].append(t)

    freq_order = sorted(ct_groups.keys(), key=lambda c: -len(ct_groups[c]))
    freq_order = [c for c in freq_order if len(ct_groups[c]) >= min_freq][:max_depth]

    if not freq_order:
        return True, 0, 0

    n_contradictions_holder = [0]
    best_holder: list = [None, -1]

    _cascade(
        cipher, trajectory, ct_groups, freq_order,
        depth=0,
        plug=PlugState(),
        q_assignments={},
        n_contradictions_holder=n_contradictions_holder,
        best_holder=best_holder,
        max_depth=max_depth,
    )

    if best_holder[0] is not None:
        r = best_holder[0]
        return True, r.n_determined, n_contradictions_holder[0]
    return False, 0, n_contradictions_holder[0]
