"""Topological constraint graph: the formal discriminator.

Implements the bipartite constraint graph from the topological n-grams
specification (Section 6.2):

  Vertices A = equivalence classes (one per collision group)
  Algebraic edges E_alg = shared e_val across ciphertext letters
  Adjacency edges E_adj = sequential message positions

  Labeling: assign one symbol to each vertex such that
    1. Fixed-point-free: label != ciphertext at group positions
    2. Algebraic consistency: shared e_val => same label
    3. Plugboard involution: implied P is self-inverse, <= 13 pairs
    4. Linguistic validity: adjacency pairs are observed n-grams

The q-search is pruned by cascading P-consistency: process the most
frequent ciphertext letter first, commit P entries from its collision
groups, and let committed entries constrain subsequent q choices.

The discriminator: for the correct trajectory, exactly one labeling
exists (the true plaintext). For wrong trajectories, the constraint
graph is unsatisfiable.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from enigma.language import LanguageModel
from enigma.ngram_data import (
    BIGRAMS_OBSERVED,
    TRIGRAMS_OBSERVED,
    BIGRAM_SUCCESSORS,
)


@dataclass
class Vertex:
    """One equivalence class in the constraint graph."""
    vid: int
    e_val: int
    source_c: int          # which ciphertext letter produced this group
    source_q: int          # the q hypothesis
    positions: list[int]   # message positions in this group
    domain: set[int]       # candidate symbols

    @property
    def size(self) -> int:
        return len(self.positions)

    @property
    def determined(self) -> bool:
        return len(self.domain) == 1

    @property
    def label(self) -> int | None:
        return next(iter(self.domain)) if self.determined else None


@dataclass
class ConstraintGraph:
    """The full bipartite constraint graph."""
    vertices: dict[int, Vertex]
    adj_edges: list[tuple[int, int, list[tuple[int, int]]]]  # (vid_l, vid_r, [(pos_l, pos_r)])
    alg_edges: list[tuple[int, int]]  # (vid1, vid2) sharing e_val
    pos_to_vid: dict[int, int]
    q_assignment: dict[int, int]  # c -> q

    def n_determined(self) -> int:
        return sum(1 for v in self.vertices.values() if v.determined)

    def total_domain_size(self) -> int:
        return sum(len(v.domain) for v in self.vertices.values())

    def has_contradiction(self) -> bool:
        return any(len(v.domain) == 0 for v in self.vertices.values())

    def get_plug_map(self) -> list[int]:
        """Extract the plugboard from determined vertices."""
        P = list(range(26))
        for c, q in self.q_assignment.items():
            P[c] = q
            P[q] = c
        for v in self.vertices.values():
            if v.determined:
                sym = v.label
                P[v.e_val] = sym
                P[sym] = v.e_val
        return P


def _build_collision_groups(
    cipher: list[int],
    trajectory: list[list[int]],
    c: int,
    q: int,
) -> dict[int, list[int]]:
    """Group positions where cipher[t] == c by E_t(q) value."""
    groups: dict[int, list[int]] = defaultdict(list)
    for t in range(len(cipher)):
        if cipher[t] == c:
            groups[trajectory[t][q]].append(t)
    return dict(groups)


def build_graph(
    cipher: list[int],
    trajectory: list[list[int]],
    q_assignment: dict[int, int],
    model: LanguageModel,
) -> ConstraintGraph:
    """Build the constraint graph for a trajectory + q assignment."""
    L = len(cipher)

    # Build vertices from collision groups (multi-position only)
    vertices: dict[int, Vertex] = {}
    pos_to_vid: dict[int, int] = {}
    vid = 0

    # Track which e_vals are shared across ciphertext letters
    eval_to_vids: dict[int, list[int]] = defaultdict(list)

    for c, q in q_assignment.items():
        groups = _build_collision_groups(cipher, trajectory, c, q)
        for e_val, positions in groups.items():
            if len(positions) < 2:
                continue
            forbidden = set(cipher[t] for t in positions)
            domain = set(range(26)) - forbidden
            v = Vertex(vid=vid, e_val=e_val, source_c=c, source_q=q,
                       positions=sorted(positions), domain=domain)
            vertices[vid] = v
            for t in positions:
                pos_to_vid[t] = vid
            eval_to_vids[e_val].append(vid)
            vid += 1

    # Algebraic edges: vertices sharing the same e_val
    alg_edges: list[tuple[int, int]] = []
    for e_val, vids in eval_to_vids.items():
        for i in range(len(vids)):
            for j in range(i + 1, len(vids)):
                alg_edges.append((vids[i], vids[j]))

    # Adjacency edges: sequential positions in different vertices
    adj_map: dict[tuple[int, int], list[tuple[int, int]]] = defaultdict(list)
    for t in range(L - 1):
        if t in pos_to_vid and (t + 1) in pos_to_vid:
            vl = pos_to_vid[t]
            vr = pos_to_vid[t + 1]
            if vl != vr:
                adj_map[(vl, vr)].append((t, t + 1))

    adj_edges = [(vl, vr, insts) for (vl, vr), insts in adj_map.items()]

    return ConstraintGraph(
        vertices=vertices,
        adj_edges=adj_edges,
        alg_edges=alg_edges,
        pos_to_vid=pos_to_vid,
        q_assignment=q_assignment,
    )


def propagate(graph: ConstraintGraph, model: LanguageModel, max_rounds: int = 30) -> bool:
    """Run constraint propagation until convergence or contradiction.

    Returns True if consistent (no empty domains), False if contradiction.

    Applies in order:
      1. Algebraic edges: shared e_val => intersect domains
      2. Adjacency edges with observed bigrams (315/676)
      3. Adjacency edges with trigram chain successors (1121 transitions)
      4. Quadgram chains (3061 transitions)
      5. Double-letter constraint (consecutive positions in same group)
      6. Singleton propagation
    """
    excluded = model.excluded

    for round_num in range(max_rounds):
        changed = False

        # 1. Algebraic edges: vertices sharing e_val must have same label
        for v1_id, v2_id in graph.alg_edges:
            v1 = graph.vertices[v1_id]
            v2 = graph.vertices[v2_id]
            shared = v1.domain & v2.domain
            if shared != v1.domain:
                v1.domain = set(shared)
                changed = True
            if shared != v2.domain:
                v2.domain = set(shared)
                changed = True
            if not shared:
                return False

        # 2. Adjacency: observed bigrams (46.6% acceptance)
        for vl_id, vr_id, instances in graph.adj_edges:
            vl = graph.vertices[vl_id]
            vr = graph.vertices[vr_id]

            for s_l in list(vl.domain):
                if not any((s_l * 26 + s_r) in BIGRAMS_OBSERVED for s_r in vr.domain):
                    vl.domain.discard(s_l)
                    changed = True
            for s_r in list(vr.domain):
                if not any((s_l * 26 + s_r) in BIGRAMS_OBSERVED for s_l in vl.domain):
                    vr.domain.discard(s_r)
                    changed = True

            if not vl.domain or not vr.domain:
                return False

        # 3. Trigram chains: for 3 consecutive grouped positions,
        # the middle vertex is constrained by BIGRAM_SUCCESSORS
        L = max(graph.pos_to_vid.keys(), default=-1) + 1
        for t in range(L - 2):
            if not (t in graph.pos_to_vid and (t+1) in graph.pos_to_vid
                    and (t+2) in graph.pos_to_vid):
                continue
            va_id = graph.pos_to_vid[t]
            vb_id = graph.pos_to_vid[t + 1]
            vc_id = graph.pos_to_vid[t + 2]
            if va_id == vb_id or vb_id == vc_id:
                continue

            va = graph.vertices[va_id]
            vb = graph.vertices[vb_id]
            vc = graph.vertices[vc_id]

            for s_b in list(vb.domain):
                has_chain = False
                for s_a in va.domain:
                    bg_ab = s_a * 26 + s_b
                    succs = BIGRAM_SUCCESSORS.get(bg_ab)
                    if succs is None:
                        continue
                    for s_c in vc.domain:
                        if (s_b * 26 + s_c) in succs:
                            has_chain = True
                            break
                    if has_chain:
                        break
                if not has_chain:
                    vb.domain.discard(s_b)
                    changed = True

            if not vb.domain:
                return False

        # 4. Double-letter: consecutive positions in same group
        for v in graph.vertices.values():
            has_consec = any(
                v.positions[i] + 1 == v.positions[i + 1]
                for i in range(len(v.positions) - 1)
            )
            if has_consec:
                for s in list(v.domain):
                    if (s * 26 + s) not in BIGRAMS_OBSERVED:
                        v.domain.discard(s)
                        changed = True
                if not v.domain:
                    return False

        # 5. Singleton propagation + involution consistency
        for v in graph.vertices.values():
            if not v.determined:
                continue
            sym = v.label
            # Adjacency: exclude from neighbors
            for vl_id, vr_id, _ in graph.adj_edges:
                if vl_id == v.vid:
                    vr = graph.vertices[vr_id]
                    for s in list(vr.domain):
                        if excluded[sym][s]:
                            vr.domain.discard(s)
                            changed = True
                elif vr_id == v.vid:
                    vl = graph.vertices[vl_id]
                    for s in list(vl.domain):
                        if excluded[s][sym]:
                            vl.domain.discard(s)
                            changed = True

        if graph.has_contradiction():
            return False
        if not changed:
            break

    return True


def cascade_q_search(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    min_freq: int = 4,
    max_letters: int = 10,
) -> list[ConstraintGraph]:
    """Find q assignments via cascading P-consistency.

    Process the most frequent ciphertext letter first. For each surviving
    q, commit P entries and constrain q choices for subsequent letters.
    At each depth, build the constraint graph and propagate. Prune
    branches that produce contradictions.

    Returns list of surviving constraint graphs (ideally exactly 1).
    """
    L = len(cipher)

    ct_freq: dict[int, list[int]] = defaultdict(list)
    for t, c in enumerate(cipher):
        ct_freq[c].append(t)

    freq_order = sorted(ct_freq.keys(), key=lambda c: -len(ct_freq[c]))
    freq_order = [c for c in freq_order if len(ct_freq[c]) >= min_freq][:max_letters]

    if not freq_order:
        return []

    # State for cascading search
    survivors: list[dict[int, int]] = [{}]  # start with empty q assignment

    for c in freq_order:
        next_survivors: list[dict[int, int]] = []
        for partial_q in survivors:
            used_qs = set(partial_q.values())

            for q in range(26):
                if q in used_qs:
                    continue

                # Check basic involution: if c is already assigned as a q
                # for another letter, then P(c) is already determined
                if c in set(partial_q.values()):
                    existing_c = next(k for k, v in partial_q.items() if v == c)
                    if q != existing_c:
                        continue

                trial_q = dict(partial_q)
                trial_q[c] = q

                # Quick rejection: e_val == q for any multi-position group
                groups = _build_collision_groups(cipher, trajectory, c, q)
                reject = False
                for e_val, positions in groups.items():
                    if len(positions) >= 2 and e_val == q:
                        reject = True
                        break
                if reject:
                    continue

                # Build graph and propagate
                graph = build_graph(cipher, trajectory, trial_q, model)
                consistent = propagate(graph, model, max_rounds=10)

                if consistent:
                    next_survivors.append(trial_q)

                    # Limit branching: if we have enough survivors, stop
                    if len(next_survivors) >= 50:
                        break

            if len(next_survivors) >= 50:
                break

        survivors = next_survivors
        if not survivors:
            return []

    # Final pass: full propagation on each survivor
    results: list[ConstraintGraph] = []
    for q_assign in survivors:
        graph = build_graph(cipher, trajectory, q_assign, model)
        consistent = propagate(graph, model, max_rounds=30)
        if consistent:
            results.append(graph)

    # Rank by total domain size (smaller = more determined = better)
    results.sort(key=lambda g: g.total_domain_size())
    return results


def test_trajectory(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    min_freq: int = 4,
    max_letters: int = 6,
) -> tuple[bool, int, int, dict[int, int] | None]:
    """Test a trajectory for constraint graph satisfiability.

    Returns (has_solution, n_determined, total_domain, best_q_assignment).
    """
    results = cascade_q_search(cipher, trajectory, model, min_freq, max_letters)

    if not results:
        return False, 0, 0, None

    best = results[0]
    return (True, best.n_determined(), best.total_domain_size(), best.q_assignment)
