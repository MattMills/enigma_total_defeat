"""Core cracking engine: constraint propagation with back-propagation.

The correct plugboard produces 0 excluded bigrams. Wrong plugboards
produce conflicts. The discriminator is BINARY, not probabilistic.

States are keyed by plugboard dict. At each new position:
  1. FORWARD: expand states with candidates at position t.
  2. BACKWARD: for each surviving state, verify ALL previously
     processed positions are still consistent. Kill states that
     now conflict due to new plug entries.

This backward propagation prevents state explosion: new plug entries
from position t retroactively kill states that were valid at t-1
but conflict with the new entries.

The trajectory differential E_t(P(c_t)) encodes the geometric
relationship between ciphertext and plaintext. Positions sharing
the same plaintext letter must produce the same differential —
this constrains P directly from the ciphertext structure.
"""

from __future__ import annotations

from enigma.language import LanguageModel
from enigma.simulator import fast_trajectory


def crack_trajectory(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    max_states: int = 5000,
) -> list[tuple[dict[int, int], list[int]]]:
    """Find all plugboards consistent with this trajectory + ciphertext.

    Returns list of (plug_dict, plaintext_list), possibly empty.

    At each position:
      1. Expand: try all plaintext candidates. For determined positions
         (p or c in plug), x is forced. For free positions, try all x.
      2. Prune: kill states with plugboard conflicts.
      3. Back-propagate: verify the new plug entries don't invalidate
         any previously determined plaintext (excluded bigrams between
         now-resolved adjacent positions).
    """
    L = len(cipher)
    excluded = model.excluded

    # State: plug_dict -> (plaintext_list)
    # Dedup by plug dict since plaintext is determined by plug + trajectory.
    states: dict[tuple[tuple[int, int], ...], list[int]] = {}

    # Position 0: seed
    c0 = cipher[0]
    E0 = trajectory[0]
    for p in range(26):
        if p == c0:
            continue
        for x in range(26):
            y = E0[x]
            plug: dict[int, int] = {}
            entries = [(p, x), (x, p), (y, c0), (c0, y)]
            ok = True
            for k, v in entries:
                if k in plug and plug[k] != v:
                    ok = False
                    break
                plug[k] = v
            if ok:
                key = tuple(sorted(plug.items()))
                if key not in states:
                    states[key] = [p]

    # Process remaining positions with back-propagation.
    for t in range(1, L):
        ct = cipher[t]
        Et = trajectory[t]
        new_states: dict[tuple[tuple[int, int], ...], list[int]] = {}

        for frozen_plug, pt_list in states.items():
            plug = dict(frozen_plug)
            last_p = pt_list[-1]

            for p in range(26):
                if p == ct:
                    continue
                if excluded[last_p][p]:
                    continue

                # Determine x candidates.
                if p in plug:
                    xs = [plug[p]]
                elif ct in plug:
                    xs = [Et[plug[ct]]]
                else:
                    xs = range(26)

                for x in xs:
                    y = Et[x]
                    entries = [(p, x), (x, p), (y, ct), (ct, y)]
                    new_plug = dict(plug)
                    ok = True
                    for k, v in entries:
                        if k in new_plug and new_plug[k] != v:
                            ok = False
                            break
                        new_plug[k] = v
                    if not ok:
                        continue

                    # BACK-PROPAGATION: the new plug entries might now
                    # determine plaintext at PREVIOUS positions that were
                    # previously free. Recompute those and check bigrams.
                    new_pt = pt_list + [p]
                    back_ok = True
                    for prev_t in range(t):
                        prev_c = cipher[prev_t]
                        prev_E = trajectory[prev_t]
                        prev_p_stored = new_pt[prev_t]
                        # Recompute what plaintext SHOULD be with new plug.
                        if prev_p_stored in new_plug:
                            prev_x = new_plug[prev_p_stored]
                            prev_y = prev_E[prev_x]
                            if prev_y in new_plug and new_plug[prev_y] != prev_c:
                                back_ok = False
                                break
                            if prev_c in new_plug and new_plug[prev_c] != prev_y:
                                back_ok = False
                                break
                    if not back_ok:
                        continue

                    key = tuple(sorted(new_plug.items()))
                    if key not in new_states:
                        new_states[key] = new_pt

        # Cap states to prevent explosion.
        if len(new_states) > max_states:
            # Keep states with most plug entries (most constrained).
            ranked = sorted(new_states.items(), key=lambda x: len(x[0]), reverse=True)
            new_states = dict(ranked[:max_states])

        states = new_states
        if not states:
            break

    # Build results.
    results = []
    for frozen_plug, pt_list in states.items():
        results.append((dict(frozen_plug), pt_list))
    return results


def crack_message(
    cipher: list[int],
    trajectory: list[list[int]],
    model: LanguageModel,
    max_states: int = 5000,
) -> tuple[float, list[int], list[int]] | None:
    """Crack a message given its trajectory. Returns (score, plug_map, decrypted)."""
    results = crack_trajectory(cipher, trajectory, model, max_states)
    if not results:
        return None

    best_score = float("-inf")
    best_result = None
    for plug_dict, pt_list in results:
        plug_map = list(range(26))
        for a, b in plug_dict.items():
            plug_map[a] = b
        dec = [plug_map[trajectory[t][plug_map[cipher[t]]]] for t in range(len(cipher))]
        score = model.score(dec)
        if score > best_score:
            best_score = score
            best_result = (score, plug_map, dec)

    return best_result
