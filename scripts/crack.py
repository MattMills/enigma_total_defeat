#!/usr/bin/env python3
"""Crack an Enigma message from the database.

Usage:
  python scripts/crack.py barbarossa-1          # crack specific message
  python scripts/crack.py --all                 # verify + crack all messages
  python scripts/crack.py --verify              # just verify known decryptions

Method:
  1. Verify: decrypt with known key, confirm plaintext matches.
  2. Attack: for messages with known rotors/reflector/rings,
     recover position + plugboard using beam_swap_search with
     n-gram symbol-transition scoring.
"""

import argparse
import sys
import time

from enigma.attack import beam_swap_search
from enigma.language import LanguageModel, index_of_coincidence
from enigma.messages import MESSAGES, EnigmaMessage, get_message
from enigma.simulator import Enigma, Plugboard, fast_trajectory


def verify(msg: EnigmaMessage) -> bool | None:
    """Decrypt with known key, compare to known plaintext."""
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

    dec = Enigma(**kw).encrypt(msg.ciphertext)

    if msg.known_plaintext:
        known = "".join(c for c in msg.known_plaintext if "A" <= c <= "Z")
        return dec == known[:len(dec)]
    return None


def crack(msg: EnigmaMessage, model: LanguageModel, time_limit: float = 10.0) -> dict | None:
    """Recover position + plugboard from ciphertext.

    Requires known rotors, reflector, rings. Discovers position and plugboard.

    Phase 1: IC-filter all 17,576 positions → top 200 survivors.
    Phase 2: beam_swap_search on each survivor (n-gram symbol scoring).
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

    # Phase 1: IC filter
    ic_scores = []
    for pl in range(26):
        for pm in range(26):
            for pr in range(26):
                traj = fast_trajectory(rotor_names, reflector, (pl, pm, pr), rings, L, **fourth_kw)
                dec = [traj[t][cipher[t]] for t in range(L)]
                ic_scores.append((index_of_coincidence(dec), (pl, pm, pr)))
    ic_scores.sort(reverse=True)
    survivors = [pos for _, pos in ic_scores[:200]]
    phase1_time = time.time() - t0

    # Phase 2: beam swap on survivors
    best_score = float("-inf")
    best_result = None
    for pos in survivors:
        if time.time() - t0 > time_limit:
            break
        traj = fast_trajectory(rotor_names, reflector, pos, rings, L, **fourth_kw)
        score, plug, dec = beam_swap_search(cipher, traj, model, rounds=3)
        if score > best_score:
            best_score = score
            best_result = {
                "positions": pos,
                "plug_map": plug,
                "plaintext": "".join(chr(d + 65) for d in dec),
                "score": score,
                "pairs": [(a, plug[a]) for a in range(26) if plug[a] > a],
            }

    elapsed = time.time() - t0
    if best_result:
        best_result["elapsed"] = elapsed
        best_result["phase1_time"] = phase1_time
    return best_result


def main():
    parser = argparse.ArgumentParser(description="Crack Enigma messages")
    parser.add_argument("message_id", nargs="?", help="Message ID to crack")
    parser.add_argument("--all", action="store_true", help="Process all messages")
    parser.add_argument("--verify", action="store_true", help="Only verify, don't attack")
    args = parser.parse_args()

    model = LanguageModel.german_military()

    if args.message_id:
        messages = [get_message(args.message_id)]
        if messages[0] is None:
            print(f"Unknown message: {args.message_id}")
            print(f"Available: {', '.join(m.id for m in MESSAGES)}")
            return 1
    elif args.all:
        messages = MESSAGES
    else:
        parser.print_help()
        return 0

    for msg in messages:
        if msg is None:
            continue
        ct_len = len("".join(c for c in msg.ciphertext if "A" <= c <= "Z"))
        if ct_len < 5:
            continue

        print(f"\n{'='*60}")
        print(f"[{msg.id}] {ct_len} chars — {msg.source[:50]}")
        print(f"{'='*60}")

        # Verify
        ok = verify(msg)
        if ok is True:
            print(f"  VERIFY: OK")
        elif ok is False:
            print(f"  VERIFY: MISMATCH")
        elif msg.rotors:
            # Has key but no known plaintext — decrypt and show
            positions = [ord(c) - 65 for c in msg.initial_positions]
            rings = [ord(c) - 65 for c in msg.ring_settings]
            plug = Plugboard.from_pairs(msg.plugboard.split()) if msg.plugboard else Plugboard.identity()
            kw = dict(rotor_names=tuple(msg.rotors), reflector_name=msg.reflector,
                      positions=positions, ring_settings=rings, plugboard=plug)
            if msg.fourth_rotor:
                kw["fourth_rotor_name"] = msg.fourth_rotor
                kw["fourth_position"] = ord(msg.fourth_position) - 65 if msg.fourth_position else 0
                kw["fourth_ring"] = 0
            dec = Enigma(**kw).encrypt(msg.ciphertext)
            print(f"  DECRYPT: {dec[:60]}")
        else:
            print(f"  NO KEY (blind target)")

        if args.verify:
            continue

        # Attack
        if not msg.rotors:
            print(f"  SKIP: no rotor info for blind attack")
            continue

        print(f"  ATTACK...", end="", flush=True)
        result = crack(msg, model)
        if result:
            pos_str = "".join(chr(p + 65) for p in result["positions"])
            true_pos = msg.initial_positions or "???"
            pos_ok = pos_str == true_pos
            n_pairs = len(result["pairs"])
            print(f" {result['elapsed']:.1f}s")
            print(f"  Position: {pos_str} ({'OK' if pos_ok else 'true=' + true_pos})")
            print(f"  Plugboard: {' '.join(chr(a+65)+chr(b+65) for a,b in result['pairs'])} ({n_pairs} pairs)")
            print(f"  Score: {result['score']:.3f}")
            print(f"  Plaintext: {result['plaintext'][:60]}")

            if msg.known_plaintext:
                known = "".join(c for c in msg.known_plaintext if "A" <= c <= "Z")
                match = sum(a == b for a, b in zip(result["plaintext"], known))
                print(f"  Match: {match}/{min(len(result['plaintext']), len(known))}")
        else:
            print(f" no result")

    return 0


if __name__ == "__main__":
    sys.exit(main())
