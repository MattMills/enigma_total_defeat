"""Total defeat: the complete topological constraint solver.

Merges algebraic-edge-linked collision groups into super-vertices,
then propagates the full n-gram chain hierarchy through the adjacency
graph. The super-vertex merge is what closes the gap: it forces the
cross-letter P-consistency that the per-letter cascade couldn't enforce.

A super-vertex is a set of positions from MULTIPLE ciphertext letters
that all share the same e_val in their collision groups. Since P(e_val)
must be a single letter, all these positions must have the same plaintext
— regardless of which ciphertext letter they came from. The adjacency
constraints between super-vertices then apply the language model at
the intersection of algebraic necessity and linguistic validity.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from enigma.language import LanguageModel
from enigma.ngram_data import (
    BIGRAMS_OBSERVED,
    BIGRAM_SUCCESSORS,
    TRIGRAM_SUCCESSORS,
)
from enigma.simulator import fast_trajectory


@dataclass
class SuperVertex:
    """Positions merged by shared e_val across ciphertext letters."""
    svid: int
    e_val: int
    positions: list[int]
    domain: set[int]
    sources: list[tuple[int, int]]  # (ciphertext_letter, q) pairs that contributed

    @property
    def determined(self) -> bool:
        return len(self.domain) == 1

    @property
    def label(self) -> int | None:
        return next(iter(self.domain)) if self.determined else None


def _merge_groups(
    cipher: list[int],
    trajectory: list[list[int]],
    q_assignment: dict[int, int],
) -> tuple[list[SuperVertex], dict[int, int]]:
    """Build super-vertices by merging collision groups with shared e_val."""
    L = len(cipher)

    # Collect ALL collision groups across all (c, q) pairs, keyed by e_val
    eval_data: dict[int, dict] = defaultdict(lambda: {"positions": set(), "sources": []})

    for c, q in q_assignment.items():
        for t in range(L):
            if cipher[t] != c:
                continue
            e_val = trajectory[t][q]
            eval_data[e_val]["positions"].add(t)
            src = (c, q)
            if src not in eval_data[e_val]["sources"]:
                eval_data[e_val]["sources"].append(src)

    # Build super-vertices from multi-position e_val groups
    svs: list[SuperVertex] = []
    pos_to_sv: dict[int, int] = {}
    svid = 0

    for e_val, data in eval_data.items():
        positions = sorted(data["positions"])
        if len(positions) < 2:
            continue

        # Domain: all letters except ciphertext letters at these positions
        forbidden = set(cipher[t] for t in positions)
        domain = set(range(26)) - forbidden

        # Also: e_val == q for any contributing (c, q) would mean P(e_val) = c,
        # but then plaintext = c = ciphertext at those c-positions. Fixed-point-free
        # violation. Exclude those ciphertext letters from the domain.
        for c, q in data["sources"]:
            if e_val == q:
                domain.discard(c)

        sv = SuperVertex(svid=svid, e_val=e_val, positions=positions,
                         domain=domain, sources=data["sources"])
        svs.append(sv)
        for t in positions:
            pos_to_sv[t] = svid
        svid += 1

    return svs, pos_to_sv


def _propagate(
    svs: list[SuperVertex],
    pos_to_sv: dict[int, int],
    cipher: list[int],
    model: LanguageModel,
    max_rounds: int = 40,
) -> bool:
    """Full n-gram chain propagation on super-vertices. Returns False on contradiction."""
    L = max(pos_to_sv.keys(), default=-1) + 1
    if not svs:
        return True

    sv_by_id = {sv.svid: sv for sv in svs}

    # Build adjacency map: (sv_left, sv_right) -> [(t, t+1), ...]
    adj: dict[tuple[int, int], list[tuple[int, int]]] = defaultdict(list)
    for t in range(L - 1):
        if t in pos_to_sv and (t + 1) in pos_to_sv:
            sl = pos_to_sv[t]
            sr = pos_to_sv[t + 1]
            if sl != sr:
                adj[(sl, sr)].append((t, t + 1))

    for _ in range(max_rounds):
        changed = False

        # 1. Observed bigram arc consistency (315/676 = 46.6%)
        for (sl, sr), instances in adj.items():
            svl = sv_by_id[sl]
            svr = sv_by_id[sr]

            for s_l in list(svl.domain):
                if not any((s_l * 26 + s_r) in BIGRAMS_OBSERVED for s_r in svr.domain):
                    svl.domain.discard(s_l)
                    changed = True
            for s_r in list(svr.domain):
                if not any((s_l * 26 + s_r) in BIGRAMS_OBSERVED for s_l in svl.domain):
                    svr.domain.discard(s_r)
                    changed = True

            if not svl.domain or not svr.domain:
                return False

        # 2. Trigram chain arc consistency (6.4%)
        for t in range(L - 2):
            if not (t in pos_to_sv and (t+1) in pos_to_sv and (t+2) in pos_to_sv):
                continue
            sa, sb, sc = pos_to_sv[t], pos_to_sv[t+1], pos_to_sv[t+2]
            if sa == sb or sb == sc:
                continue
            sva, svb, svc = sv_by_id[sa], sv_by_id[sb], sv_by_id[sc]

            for s_b in list(svb.domain):
                has_chain = False
                for s_a in sva.domain:
                    bg = s_a * 26 + s_b
                    succs = BIGRAM_SUCCESSORS.get(bg)
                    if succs is None:
                        continue
                    for s_c in svc.domain:
                        if (s_b * 26 + s_c) in succs:
                            has_chain = True
                            break
                    if has_chain:
                        break
                if not has_chain:
                    svb.domain.discard(s_b)
                    changed = True

            if not svb.domain:
                return False

        # 3. Quadgram chain arc consistency (0.67%)
        for t in range(L - 3):
            gids = []
            for dt in range(4):
                if (t + dt) in pos_to_sv:
                    gids.append(pos_to_sv[t + dt])
                else:
                    break
            if len(gids) < 4 or len(set(gids)) < 4:
                continue
            sva, svb, svc, svd = [sv_by_id[g] for g in gids]

            for s_b in list(svb.domain):
                has_quad = False
                for s_a in sva.domain:
                    tg = s_a * 676 + s_b * 26
                    for s_c in svc.domain:
                        tg_abc = tg + s_c
                        succs = TRIGRAM_SUCCESSORS.get(tg_abc)
                        if succs is None:
                            continue
                        for s_d in svd.domain:
                            if (s_b * 676 + s_c * 26 + s_d) in succs:
                                has_quad = True
                                break
                        if has_quad:
                            break
                    if has_quad:
                        break
                if not has_quad:
                    svb.domain.discard(s_b)
                    changed = True

            if not svb.domain:
                return False

        # 4. Double-letter: consecutive positions in same super-vertex
        for sv in svs:
            has_consec = any(
                sv.positions[i] + 1 == sv.positions[i + 1]
                for i in range(len(sv.positions) - 1)
            )
            if has_consec:
                for s in list(sv.domain):
                    if (s * 26 + s) not in BIGRAMS_OBSERVED:
                        sv.domain.discard(s)
                        changed = True
                if not sv.domain:
                    return False

        # 5. Singleton propagation
        excluded = model.excluded
        for sv in svs:
            if not sv.determined:
                continue
            sym = sv.label
            for (sl, sr), _ in adj.items():
                if sl == sv.svid:
                    svr = sv_by_id[sr]
                    for s in list(svr.domain):
                        if excluded[sym][s]:
                            svr.domain.discard(s)
                            changed = True
                elif sr == sv.svid:
                    svl = sv_by_id[sl]
                    for s in list(svl.domain):
                        if excluded[s][sym]:
                            svl.domain.discard(s)
                            changed = True

        if any(not sv.domain for sv in svs):
            return False
        if not changed:
            break

    return True


def solve(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    min_freq: int = 4,
    max_letters: int = 12,
) -> tuple[bool, int, int, dict[int, int] | None]:
    """Test a trajectory: cascade q-search with super-vertex merge + propagation.

    Returns (has_solution, n_super_vertices_determined, total_domain, best_q_assignment).
    False means the trajectory is rejected (no consistent q assignment exists).
    """
    L = len(cipher)
    ct_freq: dict[int, list[int]] = defaultdict(list)
    for t, c in enumerate(cipher):
        ct_freq[c].append(t)

    freq_order = sorted(ct_freq.keys(), key=lambda c: -len(ct_freq[c]))
    freq_order = [c for c in freq_order if len(ct_freq[c]) >= min_freq][:max_letters]

    if not freq_order:
        return True, 0, 0, None

    # Cascade: add one ciphertext letter at a time.
    # Keep the top N branches ranked by tightest total domain (most constrained
    # = most information extracted = most likely correct).
    # At each depth, try all 26 qs for the new letter, rebuild and propagate,
    # keep only consistent branches, rank by domain size, prune to top N.

    beam_width = 500
    # Each branch: (total_domain, q_assignment)
    beam: list[tuple[int, dict[int, int]]] = [(0, {})]

    for c in freq_order:
        candidates: list[tuple[int, dict[int, int]]] = []

        for _, partial_q in beam:
            used_qs = set(partial_q.values())

            for q in range(26):
                if q in used_qs:
                    continue
                # Involution check: if q is already a key in partial_q,
                # then P(q) = partial_q[q]. We want P(c) = q => P(q) = c.
                # So partial_q[q] must equal c.
                if q in partial_q and partial_q[q] != c:
                    continue
                # If c is already a value in partial_q, then some c' has P(c') = c.
                # Involution: P(c) = c'. So q must be c'.
                c_as_val = [k for k, v in partial_q.items() if v == c]
                if c_as_val and q != c_as_val[0]:
                    continue

                trial_q = dict(partial_q)
                trial_q[c] = q

                svs, pos_to_sv = _merge_groups(cipher, trajectory, trial_q)
                consistent = _propagate(svs, pos_to_sv, cipher, model)

                if consistent:
                    total_dom = sum(len(sv.domain) for sv in svs)
                    candidates.append((total_dom, trial_q))

        if not candidates:
            return False, 0, 0, None

        # Keep the tightest (smallest total domain = most constrained)
        candidates.sort(key=lambda x: x[0])
        beam = candidates[:beam_width]

    # Final: pick the best survivor (most determined, smallest domain)
    best = None
    best_score = (0, 999999)

    for _, q_assign in beam:
        svs, pos_to_sv = _merge_groups(cipher, trajectory, q_assign)
        consistent = _propagate(svs, pos_to_sv, cipher, model, max_rounds=40)
        if not consistent:
            continue
        n_det = sum(1 for sv in svs if sv.determined)
        total_dom = sum(len(sv.domain) for sv in svs)
        score = (n_det, -total_dom)
        if score > best_score:
            best_score = score
            best = (True, n_det, total_dom, q_assign)

    if best is None:
        return False, 0, 0, None
    return best
