#!/usr/bin/env python3
"""Crack Enigma messages from the database.

Usage:
  python scripts/crack.py barbarossa-1     # crack one message
  python scripts/crack.py --all            # verify + crack all
  python scripts/crack.py --verify         # just verify decryptions

Method: beam_swap_search with n-gram symbol-transition scoring.
When rotors/reflector/rings/position are all known, recovers the
plugboard directly. When position is unknown, does a fast sweep.
"""

import argparse
import sys
import time

from enigma.attack import beam_swap_search
from enigma.language import LanguageModel
from enigma.messages import MESSAGES, EnigmaMessage, get_message
from enigma.simulator import Enigma, Plugboard, fast_trajectory


def verify(msg: EnigmaMessage) -> str | None:
    """Decrypt with known key, return plaintext or None."""
    if not msg.rotors or not msg.initial_positions or not msg.reflector:
        return None
    ct = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
    if len(ct) < 5:
        return None

    positions = [ord(c) - 65 for c in msg.initial_positions]
    rings = [ord(c) - 65 for c in msg.ring_settings]
    plug = Plugboard.from_pairs(msg.plugboard.split()) if msg.plugboard else Plugboard.identity()
    kw = dict(rotor_names=tuple(msg.rotors), reflector_name=msg.reflector,
              positions=positions, ring_settings=rings, plugboard=plug)
    if msg.fourth_rotor:
        kw["fourth_rotor_name"] = msg.fourth_rotor
        kw["fourth_position"] = ord(msg.fourth_position) - 65 if msg.fourth_position else 0
        kw["fourth_ring"] = 0

    return Enigma(**kw).encrypt(msg.ciphertext)


def crack(msg: EnigmaMessage, model: LanguageModel) -> dict | None:
    """Recover plugboard from ciphertext using beam swap.

    If position is known: run beam swap directly on that trajectory.
    If position is unknown but rotors/reflector/rings known: sweep
    positions with a fast 2-round beam swap, then refine the best.
    """
    ct = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
    if len(ct) < 20 or not msg.rotors or not msg.reflector:
        return None

    cipher = [ord(c) - 65 for c in ct]
    L = len(cipher)
    rotor_names = tuple(msg.rotors)
    reflector = msg.reflector
    rings = tuple(ord(c) - 65 for c in msg.ring_settings) if msg.ring_settings else (0, 0, 0)

    fourth_kw = {}
    if msg.fourth_rotor:
        fourth_kw["fourth_rotor_name"] = msg.fourth_rotor
        fourth_kw["fourth_position"] = ord(msg.fourth_position) - 65 if msg.fourth_position else 0
        fourth_kw["fourth_ring"] = 0

    t0 = time.time()

    if msg.initial_positions:
        # Position known: single trajectory, full beam swap.
        pos = tuple(ord(c) - 65 for c in msg.initial_positions)
        traj = fast_trajectory(rotor_names, reflector, pos, rings, L, **fourth_kw)
        score, plug, dec = beam_swap_search(cipher, traj, model, rounds=10)
        return _build_result(pos, plug, dec, score, time.time() - t0)

    # Position unknown: sweep all 17,576 with fast scoring.
    # Use a single-letter decrypt check as prefilter (instant).
    best_score = float("-inf")
    best = None

    for pl in range(26):
        for pm in range(26):
            for pr in range(26):
                traj = fast_trajectory(rotor_names, reflector,
                                       (pl, pm, pr), rings, L, **fourth_kw)
                # Quick 2-round beam swap as a coarse filter.
                score, plug, dec = beam_swap_search(
                    cipher, traj, model, rounds=2, beam_width=20,
                )
                if score > best_score:
                    best_score = score
                    best = ((pl, pm, pr), plug, dec, score)

                if time.time() - t0 > 60:
                    break
            if time.time() - t0 > 60:
                break
        if time.time() - t0 > 60:
            break

    if best is None:
        return None

    # Refine the best candidate with more rounds.
    pos, plug, dec, score = best
    traj = fast_trajectory(rotor_names, reflector, pos, rings, L, **fourth_kw)
    score, plug, dec = beam_swap_search(
        cipher, traj, model, start_plug=plug, rounds=5,
    )
    return _build_result(pos, plug, dec, score, time.time() - t0)


def _build_result(pos, plug, dec, score, elapsed):
    return {
        "positions": pos,
        "plug_map": plug,
        "plaintext": "".join(chr(d + 65) for d in dec),
        "score": score,
        "pairs": [(a, plug[a]) for a in range(26) if plug[a] > a],
        "elapsed": elapsed,
    }


def main():
    parser = argparse.ArgumentParser(description="Crack Enigma messages")
    parser.add_argument("message_id", nargs="?", help="Message ID to crack")
    parser.add_argument("--all", action="store_true", help="Process all messages")
    parser.add_argument("--verify", action="store_true", help="Only verify")
    args = parser.parse_args()

    model = LanguageModel.german_military()

    if args.message_id:
        msg = get_message(args.message_id)
        if msg is None:
            print(f"Unknown message: {args.message_id}")
            print(f"Available: {', '.join(m.id for m in MESSAGES)}")
            return 1
        messages = [msg]
    elif args.all:
        messages = MESSAGES
    else:
        parser.print_help()
        return 0

    for msg in messages:
        ct_len = len("".join(c for c in msg.ciphertext if "A" <= c <= "Z"))
        if ct_len < 5:
            continue

        print(f"\n{'='*60}")
        print(f"[{msg.id}] {ct_len} chars")
        print(f"{'='*60}")

        # Verify
        dec = verify(msg)
        if dec:
            if msg.known_plaintext:
                known = "".join(c for c in msg.known_plaintext if "A" <= c <= "Z")
                ok = dec == known[:len(dec)]
                print(f"  VERIFY: {'OK' if ok else 'MISMATCH'}")
            else:
                print(f"  DECRYPT: {dec[:60]}")
        elif not msg.rotors:
            print(f"  NO KEY")

        if args.verify:
            continue

        # Attack
        if not msg.rotors:
            print(f"  SKIP: no rotor info")
            continue

        print(f"  ATTACK...", end="", flush=True)
        result = crack(msg, model)
        if result:
            pos = result["positions"]
            pos_str = "".join(chr(p + 65) for p in pos)
            true_pos = msg.initial_positions or "???"
            pairs = result["pairs"]
            print(f" {result['elapsed']:.1f}s")
            print(f"  Position:  {pos_str} ({'OK' if pos_str == true_pos else 'true=' + true_pos})")
            print(f"  Plugboard: {' '.join(chr(a+65)+chr(b+65) for a,b in pairs)} ({len(pairs)} pairs)")
            print(f"  Plaintext: {result['plaintext'][:60]}")
        else:
            print(f" no result")

    return 0


if __name__ == "__main__":
    sys.exit(main())
