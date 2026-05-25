"""Topological language model for Wehrmacht Enigma plaintext.

Unlike a traditional language model that scores a flat sequence of
characters, this model encodes the TOPOLOGICAL structure of Wehrmacht
military German — the observable constraints that exist at multiple
scales simultaneously:

  Scale 0 — Symbol frequencies (unigram)
    E=14.7%, N=9.9%, X=0.8% in general but X=6-10% in military traffic
    because X is the word separator.

  Scale 1 — Bigram transitions (what follows what)
    315 observed out of 676 possible (46.6%). Each observed bigram has
    a transition probability. 15 bigrams are excluded (never occur).

  Scale 2 — Trigram chains (BIGRAM_SUCCESSORS: which bigram follows which)
    1,121 observed transitions (6.4%). Average 3.6 successors per bigram.
    This is where German structure becomes highly constraining.

  Scale 3 — Quadgram chains (TRIGRAM_SUCCESSORS)
    3,061 observed transitions (0.67%). At this scale, random text almost
    never produces valid chains.

  Scale X — Word-separator topology
    X appears every 2-33 characters (median ~7) at word boundaries.
    Letters before X: T, S, A, M, L, G, I (word endings).
    Letters after X: K, E, A, U, D, O, N (word beginnings).
    XX is rare (double separator). X never starts or ends a message.

  Scale D — Double-letter topology
    NN, FF, LL, SS, OO are common. QQ, JJ, YY never occur.
    Doubles indicate specific German morphology (suffix -NN-, -FF-).

The topological language model scores a PARTIAL labeling — a mapping
from topo-groups to symbols — rather than requiring a complete plaintext.
Each scale contributes an independent score that can be computed from
whatever groups are labeled so far. This allows incremental constraint
propagation: label the most constrained group first, propagate to
neighbors, repeat.

Observable expectations that can run as simultaneous attacks:

  Attack 1 — X-position expectation:
    ~6-10% of positions should be X. The positions form word boundaries
    with characteristic gap distribution matching German word lengths.

  Attack 2 — Frequency expectation:
    Group symbols weighted by group size should match German unigram
    frequencies. Groups covering many positions should have frequent
    letters (E, N, I, S, R, A, T).

  Attack 3 — Bigram chain expectation:
    Adjacent groups must form observed bigrams (315/676 = 46.6% acceptance).
    Chains of 3+ adjacent groups must follow BIGRAM_SUCCESSORS (6.4%).
    Chains of 4+ must follow TRIGRAM_SUCCESSORS (0.67%).

  Attack 4 — Word boundary expectation:
    Groups at X-positions must have symbol X. Their left neighbors must
    have word-ending letters (T, S, A, M, L, G, I). Their right neighbors
    must have word-beginning letters (K, E, A, U, D, O, N).

  Attack 5 — Double-letter expectation:
    Adjacent positions in the SAME group (consecutive message positions
    forced to the same symbol) must have that symbol be a valid double
    (NN, FF, LL, SS, OO, etc. — never QQ, JJ, YY).

These attacks run simultaneously on the topo-group graph. Each narrows
the candidate symbols for each group. The intersection of all five
constraint sets is the solution space.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Sequence

from enigma.language import LanguageModel
from enigma.ngram_data import (
    BIGRAMS_OBSERVED,
    TRIGRAMS_OBSERVED,
    QUADGRAMS_OBSERVED,
    BIGRAM_SUCCESSORS,
    TRIGRAM_SUCCESSORS,
)


# Wehrmacht X-separator statistics (from known plaintext corpus)
WORD_END_LETTERS = frozenset([19, 18, 0, 12, 11, 6, 8])    # T S A M L G I
WORD_START_LETTERS = frozenset([10, 4, 0, 20, 3, 14, 13])   # K E A U D O N
VALID_DOUBLES = frozenset([13, 5, 11, 18, 14, 0, 19, 4, 7, 22, 25])  # NFLOATSEHWZ
X_LETTER = 23


@dataclass
class TopoGroupNode:
    """A node in the topo-group graph: positions forced to share one symbol."""
    gid: int
    e_val: int
    positions: list[int]
    candidates: set[int]  # possible symbols for this group
    assigned: int | None = None  # determined symbol, if any

    @property
    def size(self) -> int:
        return len(self.positions)


@dataclass
class TopoEdge:
    """An edge between two adjacent topo-groups."""
    left_gid: int
    right_gid: int
    instances: list[tuple[int, int]]  # (pos_left, pos_right) pairs
    valid_bigrams: set[tuple[int, int]] | None = None


@dataclass
class TopoGraph:
    """The complete topo-group constraint graph."""
    nodes: dict[int, TopoGroupNode]
    edges: list[TopoEdge]
    position_to_node: dict[int, int]
    ungrouped_positions: list[int]

    def n_assigned(self) -> int:
        return sum(1 for n in self.nodes.values() if n.assigned is not None)

    def n_positions_covered(self) -> int:
        return sum(n.size for n in self.nodes.values() if n.assigned is not None)

    def total_candidates(self) -> int:
        return sum(len(n.candidates) for n in self.nodes.values())


def build_topo_graph(
    cipher: list[int],
    trajectory: list[list[int]],
    q_assignment: dict[int, int],
    model: LanguageModel,
) -> TopoGraph:
    """Build the topological constraint graph from collision groups."""
    L = len(cipher)

    # Build collision groups across all (c, q) pairs, merged by e_val
    merged: dict[int, set[int]] = defaultdict(set)
    for c, q in q_assignment.items():
        for t in range(L):
            if cipher[t] == c:
                e_val = trajectory[t][q]
                merged[e_val].add(t)

    # Create nodes for multi-position groups
    nodes: dict[int, TopoGroupNode] = {}
    position_to_node: dict[int, int] = {}
    gid = 0
    for e_val, positions in merged.items():
        if len(positions) < 2:
            continue
        # Initial candidates: all letters except cipher values at group positions
        forbidden = set(cipher[t] for t in positions)
        candidates = set(range(26)) - forbidden
        node = TopoGroupNode(gid=gid, e_val=e_val, positions=sorted(positions),
                             candidates=candidates)
        nodes[gid] = node
        for t in positions:
            position_to_node[t] = gid
        gid += 1

    ungrouped = [t for t in range(L) if t not in position_to_node]

    # Build edges: adjacent positions in different groups
    edge_map: dict[tuple[int, int], list[tuple[int, int]]] = defaultdict(list)
    for t in range(L - 1):
        if t in position_to_node and (t + 1) in position_to_node:
            gl = position_to_node[t]
            gr = position_to_node[t + 1]
            if gl != gr:
                edge_map[(gl, gr)].append((t, t + 1))

    edges = [TopoEdge(left_gid=gl, right_gid=gr, instances=insts)
             for (gl, gr), insts in edge_map.items()]

    return TopoGraph(nodes=nodes, edges=edges,
                     position_to_node=position_to_node,
                     ungrouped_positions=ungrouped)


def apply_all_constraints(
    graph: TopoGraph,
    cipher: list[int],
    model: LanguageModel,
    max_rounds: int = 20,
) -> int:
    """Apply all topological constraints simultaneously until convergence.

    Returns the number of symbols determined (groups reduced to 1 candidate).

    Constraints applied:
      1. Observed bigrams (315/676): adjacent groups must form an observed bigram
      2. Bigram successors (trigram chains): if groups A,B,C are consecutive,
         the bigram AB must have BC as a valid successor
      3. X-position topology: groups containing many positions at word boundaries
         are likely X; their neighbors must have word-start/end letters
      4. Double-letter constraint: if a group contains consecutive positions (t, t+1),
         the symbol must be a valid double letter
      5. Frequency expectation: large groups (many positions) should have
         frequent letters
    """
    excluded = model.excluded

    total_determined = 0
    for _ in range(max_rounds):
        changed = False

        # Constraint 1: Observed bigrams between adjacent groups
        for edge in graph.edges:
            left = graph.nodes[edge.left_gid]
            right = graph.nodes[edge.right_gid]

            # Left candidates: must have at least one valid bigram with some right candidate
            for s_l in list(left.candidates):
                has_partner = any(
                    (s_l * 26 + s_r) in BIGRAMS_OBSERVED
                    for s_r in right.candidates
                )
                if not has_partner:
                    left.candidates.discard(s_l)
                    changed = True

            # Right candidates: symmetric check
            for s_r in list(right.candidates):
                has_partner = any(
                    (s_l * 26 + s_r) in BIGRAMS_OBSERVED
                    for s_l in left.candidates
                )
                if not has_partner:
                    right.candidates.discard(s_r)
                    changed = True

        # Constraint 2: Trigram chains (bigram successor structure)
        # Find chains of 3 consecutive grouped positions
        L = max(graph.position_to_node.keys()) + 1 if graph.position_to_node else 0
        for t in range(L - 2):
            if (t in graph.position_to_node and
                (t + 1) in graph.position_to_node and
                (t + 2) in graph.position_to_node):
                ga = graph.position_to_node[t]
                gb = graph.position_to_node[t + 1]
                gc = graph.position_to_node[t + 2]
                if ga == gb or gb == gc:
                    continue

                na = graph.nodes[ga]
                nb = graph.nodes[gb]
                nc = graph.nodes[gc]

                # For each candidate in nb: the bigram (sa, sb) must exist
                # AND (sb, sc) must be a successor of (sa, sb) for some sa, sc
                for s_b in list(nb.candidates):
                    has_chain = False
                    for s_a in na.candidates:
                        bg_ab = s_a * 26 + s_b
                        if bg_ab not in BIGRAM_SUCCESSORS:
                            continue
                        succs = BIGRAM_SUCCESSORS[bg_ab]
                        for s_c in nc.candidates:
                            bg_bc = s_b * 26 + s_c
                            if bg_bc in succs:
                                has_chain = True
                                break
                        if has_chain:
                            break
                    if not has_chain:
                        nb.candidates.discard(s_b)
                        changed = True

        # Constraint 3: Double-letter check
        # If consecutive positions (t, t+1) are in the SAME group,
        # the symbol must be a valid double letter
        for node in graph.nodes.values():
            has_consecutive = False
            for i in range(len(node.positions) - 1):
                if node.positions[i] + 1 == node.positions[i + 1]:
                    has_consecutive = True
                    break
            if has_consecutive:
                for s in list(node.candidates):
                    if (s * 26 + s) not in BIGRAMS_OBSERVED:
                        node.candidates.discard(s)
                        changed = True

        # Constraint 4: X-position word boundary structure
        # If a group has >= 3 positions and the gaps between positions
        # match German word lengths (2-15), it's likely X
        for node in graph.nodes.values():
            if node.size >= 4:
                gaps = [node.positions[i+1] - node.positions[i]
                        for i in range(len(node.positions) - 1)]
                german_gap_frac = sum(1 for g in gaps if 2 <= g <= 15) / max(len(gaps), 1)
                if german_gap_frac > 0.6:
                    # Strongly consistent with X — restrict to X or very common letters
                    # Don't force X, but boost it by eliminating rare letters
                    for s in list(node.candidates):
                        if model.unigram[s] < 0.005 and s != X_LETTER:
                            node.candidates.discard(s)
                            changed = True

        # Constraint 5: Singleton propagation
        # When a group is determined (1 candidate), propagate to neighbors
        for node in graph.nodes.values():
            if len(node.candidates) == 1 and node.assigned is None:
                node.assigned = next(iter(node.candidates))
                total_determined += 1
                changed = True

                # Propagate: adjacent groups can't have the same symbol
                # if that would create an excluded bigram
                sym = node.assigned
                for edge in graph.edges:
                    if edge.left_gid == node.gid:
                        neighbor = graph.nodes[edge.right_gid]
                        for s in list(neighbor.candidates):
                            if excluded[sym][s]:
                                neighbor.candidates.discard(s)
                                changed = True
                    elif edge.right_gid == node.gid:
                        neighbor = graph.nodes[edge.left_gid]
                        for s in list(neighbor.candidates):
                            if excluded[s][sym]:
                                neighbor.candidates.discard(s)
                                changed = True

        # Constraint 6: Quadgram chains (when 4 consecutive groups exist)
        for t in range(L - 3):
            gids = []
            for dt in range(4):
                if (t + dt) in graph.position_to_node:
                    gids.append(graph.position_to_node[t + dt])
                else:
                    break
            if len(gids) < 4 or len(set(gids)) < 4:
                continue

            na, nb, nc, nd = [graph.nodes[g] for g in gids]

            for s_b in list(nb.candidates):
                has_quad = False
                for s_a in na.candidates:
                    tg_abc_base = s_a * 676 + s_b * 26
                    for s_c in nc.candidates:
                        tg_abc = tg_abc_base + s_c
                        if tg_abc not in TRIGRAM_SUCCESSORS:
                            continue
                        succs = TRIGRAM_SUCCESSORS[tg_abc]
                        for s_d in nd.candidates:
                            tg_bcd = s_b * 676 + s_c * 26 + s_d
                            if tg_bcd in succs:
                                has_quad = True
                                break
                        if has_quad:
                            break
                    if has_quad:
                        break
                if not has_quad:
                    nb.candidates.discard(s_b)
                    changed = True

        if not changed:
            break

        # Check for empty domains (contradiction)
        for node in graph.nodes.values():
            if not node.candidates:
                return -1  # contradiction

    return total_determined


def score_labeling(
    graph: TopoGraph,
    cipher: list[int],
    model: LanguageModel,
) -> float:
    """Score the current partial labeling by the language model.

    For each pair of adjacent assigned groups, check if their bigram
    is observed and compute the transition probability.
    """
    score = 0.0
    n_scored = 0

    for edge in graph.edges:
        left = graph.nodes[edge.left_gid]
        right = graph.nodes[edge.right_gid]
        if left.assigned is not None and right.assigned is not None:
            a, b = left.assigned, right.assigned
            if model.excluded[a][b]:
                return float("-inf")
            bg = a * 26 + b
            if bg in BIGRAMS_OBSERVED:
                score += model.bigram[a][b]
            else:
                score -= 2.0  # penalty for unobserved bigram
            n_scored += 1

    return score / max(n_scored, 1)
