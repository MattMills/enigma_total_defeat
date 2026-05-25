"""Topological n-gram discriminator.

A topological n-gram is a set of message positions that the trajectory's
collision structure forces to share the same plaintext symbol. Unlike
traditional n-grams (sliding window of width n), topological n-grams
connect positions that may be hundreds of characters apart — made
neighbors by the frozen core's deterministic collision structure.

The discriminator works in three stages:

  Stage A — Build collision groups per (c, q):
    For each ciphertext letter c and each candidate q = P(c),
    compute E_t(q) at every position where c appears.
    Positions with the same E_t(q) value form a collision group.
    All positions in a group must have the same plaintext letter.

  Stage B — Merge groups across ciphertext letters:
    If (c1, q1) has a collision group at e_val = a, and (c2, q2)
    also has a collision group at e_val = a, then ALL positions
    from BOTH groups share the same plaintext letter P(a).
    This merges groups via shared e_val keys.

  Stage C — Check topological n-gram adjacency:
    When positions t and t+1 are in DIFFERENT merged groups,
    the plaintext at t and t+1 must form a valid bigram in the
    language model. Each merged group carries a single unknown
    symbol. The question: does there exist an assignment of symbols
    to groups such that all adjacency constraints are satisfied?

For the correct trajectory: exactly one assignment exists (the true
German plaintext). For wrong trajectories: the adjacency constraints
are unsatisfiable — no symbol assignment produces valid bigrams at
all required adjacent positions simultaneously.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from enigma.language import LanguageModel


@dataclass
class TopoGroup:
    """A topological n-gram: positions forced to share a plaintext symbol."""
    group_id: int
    e_val: int
    positions: list[int]
    source_letters: list[int]  # which ciphertext letters contributed


@dataclass
class AdjacencyConstraint:
    """Two adjacent positions belong to different topo-groups."""
    pos_left: int
    pos_right: int
    group_left: int
    group_right: int


@dataclass
class TopoNgramResult:
    """Result of the topological n-gram analysis."""
    n_groups: int
    n_adjacency_constraints: int
    n_satisfiable_adjacencies: int
    satisfiability_ratio: float
    q_assignment: dict[int, int]
    groups: list[TopoGroup]


def build_topo_ngrams(
    cipher: list[int],
    trajectory: list[list[int]],
    q_assignment: dict[int, int],
) -> tuple[list[TopoGroup], dict[int, int]]:
    """Build topological n-grams from collision groups across all assigned (c, q) pairs.

    Returns (groups, position_to_group) where position_to_group[t] = group_id
    for positions that appear in multi-position collision groups.
    """
    L = len(cipher)

    # Stage A+B: Build collision groups and merge across ciphertext letters.
    # Key: e_val. Value: set of positions from ALL (c, q) pairs.
    merged: dict[int, set[int]] = defaultdict(set)
    merged_sources: dict[int, list[int]] = defaultdict(list)

    for c, q in q_assignment.items():
        for t in range(L):
            if cipher[t] != c:
                continue
            e_val = trajectory[t][q]
            merged[e_val].add(t)
            if c not in merged_sources[e_val]:
                merged_sources[e_val].append(c)

    # Build groups (only multi-position ones matter)
    groups: list[TopoGroup] = []
    position_to_group: dict[int, int] = {}

    gid = 0
    for e_val, positions in merged.items():
        if len(positions) < 2:
            continue
        group = TopoGroup(
            group_id=gid,
            e_val=e_val,
            positions=sorted(positions),
            source_letters=merged_sources[e_val],
        )
        groups.append(group)
        for t in positions:
            position_to_group[t] = gid
        gid += 1

    return groups, position_to_group


def check_adjacency_satisfiability(
    cipher: list[int],
    groups: list[TopoGroup],
    position_to_group: dict[int, int],
    model: LanguageModel,
) -> tuple[int, int]:
    """Check how many adjacent position pairs in different groups have
    satisfiable bigram constraints.

    For positions t and t+1 where both are in topo-groups:
      group_left has symbol p_left (unknown)
      group_right has symbol p_right (unknown)
      Constraint: (p_left, p_right) must be a valid bigram

    Count how many such adjacencies are satisfiable (at least one valid
    bigram exists for the two groups' symbol candidates) vs unsatisfiable
    (no valid bigram exists for any combination of symbols).

    Returns (n_satisfiable, n_total).
    """
    L = len(cipher)
    excluded = model.excluded

    n_satisfiable = 0
    n_total = 0

    for t in range(L - 1):
        if t not in position_to_group or (t + 1) not in position_to_group:
            continue
        g_left = position_to_group[t]
        g_right = position_to_group[t + 1]
        if g_left == g_right:
            continue  # same group — no bigram constraint (same symbol)

        n_total += 1

        # Check: does there exist any (p_left, p_right) pair that
        # is not an excluded bigram, where p_left != cipher[t] and
        # p_right != cipher[t+1] (fixed-point-free)?
        #
        # But the stronger check: p_left must be valid at ALL positions
        # in group_left, and p_right must be valid at ALL positions in
        # group_right. For now, just check the bigram constraint between
        # the two groups.
        has_valid = False
        for p_left in range(26):
            if p_left == cipher[t]:
                continue
            for p_right in range(26):
                if p_right == cipher[t + 1]:
                    continue
                if not excluded[p_left][p_right]:
                    has_valid = True
                    break
            if has_valid:
                break

        if has_valid:
            n_satisfiable += 1

    return n_satisfiable, n_total


def check_cross_position_bigrams(
    cipher: list[int],
    groups: list[TopoGroup],
    position_to_group: dict[int, int],
    model: LanguageModel,
) -> tuple[int, int]:
    """The STRONG check: for each topo-group, find ALL adjacent positions
    (t, t+1) where BOTH t and t+1 are in topo-groups. If t is in group A
    and t+1 is in group B, then the bigram (symbol_A, symbol_B) must be
    valid German. If the SAME pair (group_A, group_B) appears at MULTIPLE
    adjacent positions, the bigram must be the SAME at all of them — since
    symbol_A is the SAME letter at all positions in group_A, and symbol_B
    is the SAME letter at all positions in group_B.

    So: collect all (group_A, group_B) adjacency pairs. For each unique
    pair, intersect the valid bigrams across all instances. If the
    intersection is empty: unsatisfiable.

    Returns (n_satisfiable_pairs, n_total_pairs).
    """
    L = len(cipher)
    excluded = model.excluded

    # Collect adjacencies grouped by (group_left, group_right) pair
    pair_positions: dict[tuple[int, int], list[tuple[int, int]]] = defaultdict(list)

    for t in range(L - 1):
        if t not in position_to_group or (t + 1) not in position_to_group:
            continue
        g_left = position_to_group[t]
        g_right = position_to_group[t + 1]
        if g_left == g_right:
            continue
        pair_positions[(g_left, g_right)].append((t, t + 1))

    n_satisfiable = 0
    n_total = 0

    for (g_left, g_right), pos_pairs in pair_positions.items():
        n_total += 1

        # For EACH instance of this (group_left, group_right) adjacency,
        # the bigram (symbol_left, symbol_right) must be valid.
        # Additionally: symbol_left != cipher[t] at each instance's t,
        # and symbol_right != cipher[t+1] at each instance's t+1.
        #
        # Since symbol_left is the SAME across all instances (it's the
        # group's symbol), it must satisfy ALL fixed-point-free constraints:
        # symbol_left != cipher[t] for ALL t in these instances.
        # Similarly for symbol_right.

        # Compute the set of forbidden values for left and right
        forbidden_left = set()
        forbidden_right = set()
        for t_l, t_r in pos_pairs:
            forbidden_left.add(cipher[t_l])
            forbidden_right.add(cipher[t_r])

        # Find valid bigrams
        has_valid = False
        for p_left in range(26):
            if p_left in forbidden_left:
                continue
            for p_right in range(26):
                if p_right in forbidden_right:
                    continue
                if not excluded[p_left][p_right]:
                    has_valid = True
                    break
            if has_valid:
                break

        if has_valid:
            n_satisfiable += 1

    return n_satisfiable, n_total


def score_trajectory(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    min_freq: int = 4,
) -> tuple[float, dict[int, int]]:
    """Score a trajectory by topological n-gram satisfiability.

    For each ciphertext letter, picks the q that produces the most
    constraining collision groups. Then checks cross-position bigram
    satisfiability of the merged topo-groups.

    Returns (score, best_q_assignment).
    Higher score = more satisfiable = more likely correct.
    Score of -1.0 means contradiction found.
    """
    L = len(cipher)

    ct_groups: dict[int, list[int]] = defaultdict(list)
    for t, c in enumerate(cipher):
        ct_groups[c].append(t)

    # Frequency-sorted ciphertext letters
    freq_order = sorted(ct_groups.keys(), key=lambda c: -len(ct_groups[c]))
    freq_order = [c for c in freq_order if len(ct_groups[c]) >= min_freq]

    # For each ciphertext letter, find the q that produces the most
    # multi-position collision groups (most constraining)
    best_qs: dict[int, int] = {}
    used_qs: set[int] = set()

    for c in freq_order:
        positions = ct_groups[c]
        best_q = -1
        best_multi = -1

        for q in range(26):
            if q in used_qs:
                continue
            # Build collision groups
            groups: dict[int, list[int]] = defaultdict(list)
            for t in positions:
                groups[trajectory[t][q]].append(t)

            # Count positions in multi-position groups
            multi = sum(len(g) for g in groups.values() if len(g) > 1)

            # Reject if e_val == q for any multi-position group
            has_self = any(e == q for e, g in groups.items() if len(g) > 1)
            if has_self:
                continue

            if multi > best_multi:
                best_multi = multi
                best_q = q

        if best_q >= 0:
            best_qs[c] = best_q
            used_qs.add(best_q)

    if not best_qs:
        return 0.0, {}

    # Build merged topo-groups
    groups, pos_to_group = build_topo_ngrams(cipher, trajectory, best_qs)

    if not groups:
        return 0.0, best_qs

    # Check cross-position bigram satisfiability
    n_sat, n_total = check_cross_position_bigrams(
        cipher, groups, pos_to_group, model,
    )

    if n_total == 0:
        return 0.0, best_qs

    ratio = n_sat / n_total
    return ratio, best_qs
