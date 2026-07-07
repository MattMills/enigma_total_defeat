"""Tests for the restored ciphertext-only defeat pipeline.

The full pipeline is ~10 minutes (IC sweep + hill-climb over 600
trajectories), so the unit tests exercise the two pieces that regressed:
the trajectory-identification ranking and the beam_swap endgame that
recovers the full plugboard on the identified trajectory.
"""

from enigma.defeat import (
    crack_ciphertext_only,
    identify_trajectory,
)
from enigma.attack import beam_swap_search
from enigma.language import LanguageModel
from enigma.messages import get_message
from enigma.simulator import fast_trajectory


def _barb():
    msg = get_message("barbarossa-1")
    CT = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
    cipher = [ord(c) - 65 for c in CT]
    rings = tuple(ord(c) - 65 for c in msg.ring_settings)
    pos = tuple(ord(c) - 65 for c in msg.initial_positions)
    known = "".join(c for c in msg.known_plaintext if "A" <= c <= "Z")
    return msg, cipher, tuple(msg.rotors), msg.reflector, rings, pos, known


def test_beam_finish_recovers_full_plaintext_on_true_trajectory():
    """The endgame fix: beam_swap on the identified trajectory -> 174/174.

    This is the step the deleted pipeline lost. On the correct trajectory it
    must recover the exact plugboard and plaintext.
    """
    msg, cipher, rotors, refl, rings, pos, known = _barb()
    model = LanguageModel.german_military()
    traj = fast_trajectory(rotors, refl, pos, rings, len(cipher))
    score, plug, dec = beam_swap_search(cipher, traj, model, rounds=10, beam_width=50)
    plaintext = "".join(chr(d + 65) for d in dec)
    assert plaintext == known, plaintext[:40]
    # exact 10-pair plugboard
    pairs = {(min(a, b), max(a, b)) for a in range(26) if plug[a] != a for b in [plug[a]]}
    true = {(min(ord(p[0]) - 65, ord(p[1]) - 65), max(ord(p[0]) - 65, ord(p[1]) - 65))
            for p in msg.plugboard.split()}
    assert pairs == true


def test_identify_trajectory_ranks_true_position_first():
    """Hill-climb identification must rank the true trajectory above impostors."""
    msg, cipher, rotors, refl, rings, pos, known = _barb()
    model = LanguageModel.german_military()
    # true position plus a handful of decoys
    decoys = [(19, 25, 5), (23, 6, 10), (17, 8, 6), (6, 25, 14)]
    candidates = [pos] + decoys
    ranked = identify_trajectory(
        cipher, candidates, rotors, refl, rings, model, restarts=20, seed=42)
    best_score, best_pos = ranked[0]
    assert best_pos == pos, f"true {pos} not ranked first: {ranked[:3]}"


def test_crack_ciphertext_only_end_to_end_scoped():
    """Component wiring on a pre-narrowed survivor set (keeps the test quick).

    The full 26^3 IC sweep is ~31s and lives in scripts/crack_barbarossa.py;
    here we validate that identify + beam on a small candidate set recover
    the message end to end.
    """
    msg, cipher, rotors, refl, rings, pos, known = _barb()
    model = LanguageModel.german_military()
    candidates = [pos, (19, 25, 5), (23, 6, 10)]
    ranked = identify_trajectory(
        cipher, candidates, rotors, refl, rings, model, restarts=20, seed=42)
    traj = fast_trajectory(rotors, refl, ranked[0][1], rings, len(cipher))
    _, _, dec = beam_swap_search(cipher, traj, model, rounds=10, beam_width=50)
    assert "".join(chr(d + 65) for d in dec) == known
