"""Bidirectional constraint unwinding for plugboard + plaintext recovery.

Each position adds constraints on the plugboard. On the correct path,
constraints accumulate without conflict. On wrong paths, conflicts
kill the path quickly. Longer messages kill wrong paths FASTER.

The algorithm propagates from BOTH ends simultaneously:
  Forward:  position 0, 1, 2, ... building plugboard entries
  Backward: position L-1, L-2, ... building plugboard entries

Both directions produce partial plugboards. The INTERSECTION of
forward and backward constraints determines the full plugboard.
Paths that are consistent in both directions are correct.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from enigma.language import LanguageModel


@dataclass
class UnwindPath:
    plug: dict[int, int]
    plaintext: list[int]
    score: float = 0.0


def _try_add_entries(
    plug: dict[int, int],
    entries: list[tuple[int, int]],
) -> dict[int, int] | None:
    """Try adding plugboard entries. Returns new dict or None on conflict."""
    new = dict(plug)
    for a, b in entries:
        if a in new:
            if new[a] != b:
                return None
        else:
            new[a] = b
    return new


def unwind_forward(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    beam_width: int = 200,
    n_positions: int | None = None,
) -> list[UnwindPath]:
    """Forward unwind: position 0 → n_positions."""
    L = n_positions or len(cipher)
    L = min(L, len(cipher))
    excluded = model.excluded

    # Position 0: try all (plaintext, P(p)=x) combinations.
    paths: list[UnwindPath] = []
    c0 = cipher[0]
    E0 = trajectory[0]
    for p in range(26):
        if p == c0:
            continue
        for x in range(26):
            y = E0[x]
            entries = [(p, x), (x, p), (y, c0), (c0, y)]
            plug = _try_add_entries({}, entries)
            if plug is not None:
                paths.append(UnwindPath(plug=plug, plaintext=[p], score=model.unigram[p]))

    # Beam prune initial set.
    paths.sort(key=lambda p: p.score, reverse=True)
    paths = paths[:beam_width]

    for t in range(1, L):
        ct = cipher[t]
        Et = trajectory[t]
        new_paths: list[UnwindPath] = []

        for path in paths:
            for p in range(26):
                if p == ct:
                    continue
                if excluded[path.plaintext[-1]][p]:
                    continue

                # Determine x = P(p) from existing plug or cipher equation.
                if p in path.plug:
                    # P(p) already known.
                    x = path.plug[p]
                    y = Et[x]
                    entries = [(y, ct), (ct, y)]
                    new_plug = _try_add_entries(path.plug, entries)
                elif ct in path.plug:
                    # P(ct) known → y = plug[ct], x = E(y).
                    y = path.plug[ct]
                    x = Et[y]  # E is involution
                    entries = [(p, x), (x, p)]
                    new_plug = _try_add_entries(path.plug, entries)
                else:
                    # Neither determined. Default to unplugged (x=p).
                    x = p
                    y = Et[x]
                    entries = [(p, x), (x, p), (y, ct), (ct, y)]
                    new_plug = _try_add_entries(path.plug, entries)

                if new_plug is None:
                    continue

                new_paths.append(UnwindPath(
                    plug=new_plug,
                    plaintext=path.plaintext + [p],
                    score=path.score + model.unigram[p],
                ))

        new_paths.sort(key=lambda p: p.score, reverse=True)
        paths = new_paths[:beam_width]
        if not paths:
            break

    return paths


def unwind_backward(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    beam_width: int = 200,
    n_positions: int | None = None,
) -> list[UnwindPath]:
    """Backward unwind: position L-1 → L-1-n_positions."""
    L = len(cipher)
    n = n_positions or L
    n = min(n, L)
    excluded = model.excluded

    start = L - 1
    paths: list[UnwindPath] = []
    c0 = cipher[start]
    E0 = trajectory[start]
    for p in range(26):
        if p == c0:
            continue
        for x in range(26):
            y = E0[x]
            entries = [(p, x), (x, p), (y, c0), (c0, y)]
            plug = _try_add_entries({}, entries)
            if plug is not None:
                paths.append(UnwindPath(plug=plug, plaintext=[p], score=model.unigram[p]))

    paths.sort(key=lambda p: p.score, reverse=True)
    paths = paths[:beam_width]

    for i in range(1, n):
        t = start - i
        if t < 0:
            break
        ct = cipher[t]
        Et = trajectory[t]
        new_paths: list[UnwindPath] = []

        for path in paths:
            for p in range(26):
                if p == ct:
                    continue
                # Backward bigram: p is BEFORE the last plaintext letter.
                if excluded[p][path.plaintext[-1]]:
                    continue

                if p in path.plug:
                    x = path.plug[p]
                    y = Et[x]
                    entries = [(y, ct), (ct, y)]
                    new_plug = _try_add_entries(path.plug, entries)
                elif ct in path.plug:
                    y = path.plug[ct]
                    x = Et[y]
                    entries = [(p, x), (x, p)]
                    new_plug = _try_add_entries(path.plug, entries)
                else:
                    x = p
                    y = Et[x]
                    entries = [(p, x), (x, p), (y, ct), (ct, y)]
                    new_plug = _try_add_entries(path.plug, entries)

                if new_plug is None:
                    continue

                new_paths.append(UnwindPath(
                    plug=new_plug,
                    plaintext=path.plaintext + [p],
                    score=path.score + model.unigram[p],
                ))

        new_paths.sort(key=lambda p: p.score, reverse=True)
        paths = new_paths[:beam_width]
        if not paths:
            break

    return paths


def unwind_bidirectional(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    beam_width: int = 200,
    n_positions: int = 20,
) -> list[UnwindPath]:
    """Bidirectional unwind: forward and backward, then intersect.

    Runs forward from position 0 for n_positions steps, and backward
    from position L-1 for n_positions steps. Then finds paths whose
    plugboard entries are mutually consistent.
    """
    fwd = unwind_forward(cipher, trajectory, model, beam_width, n_positions)
    bwd = unwind_backward(cipher, trajectory, model, beam_width, n_positions)

    if not fwd or not bwd:
        return fwd or bwd or []

    # Intersect: find (fwd, bwd) pairs with consistent plugboards.
    results: list[UnwindPath] = []
    for fp in fwd[:50]:  # limit to top-50 each direction
        for bp in bwd[:50]:
            merged = _try_add_entries(fp.plug, list(bp.plug.items()))
            if merged is not None:
                results.append(UnwindPath(
                    plug=merged,
                    plaintext=fp.plaintext,  # forward plaintext
                    score=fp.score + bp.score,
                ))

    results.sort(key=lambda p: (-len(p.plug), p.score), reverse=True)
    return results[:beam_width]


def unwind_attack(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    beam_width: int = 200,
) -> tuple[float, list[int], list[int]] | None:
    """Full unwind attack. Returns (score, plug_map, full_decryption) or None."""
    paths = unwind_bidirectional(cipher, trajectory, model, beam_width)
    if not paths:
        return None

    best = paths[0]
    plug_map = list(range(26))
    for a, b in best.plug.items():
        plug_map[a] = b

    dec = [plug_map[trajectory[t][plug_map[cipher[t]]]] for t in range(len(cipher))]
    score = model.score(dec)
    return score, plug_map, dec
