#!/usr/bin/env python3
"""Crack Enigma messages from the database.

Usage:
  python scripts/crack.py barbarossa-1     # crack one message
  python scripts/crack.py --all            # verify + crack all
  python scripts/crack.py --verify         # just verify decryptions

Searches over unknown key components:
  - Position always searched (17,576 options per rotor combo)
  - Rotors searched if unknown (60 M3 combos or 336 naval)
  - Plugboard recovered via beam_swap_search with n-gram scoring
  - Reflector searched if unknown
"""

import argparse
import itertools
import sys
import time

from enigma.attack import beam_swap_search
from enigma.language import LanguageModel
from enigma.messages import MESSAGES, EnigmaMessage, MachineType, get_message
from enigma.simulator import (
    Enigma, Plugboard, fast_trajectory,
    M3_ROTORS, NAVAL_ROTORS, GREEK_ROTORS, M3_REFLECTORS, M4_REFLECTORS,
)


def verify(msg: EnigmaMessage) -> str | None:
    """Decrypt with known key, return plaintext or None."""
    if not msg.rotors or not msg.initial_positions or not msg.reflector:
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


def crack(msg: EnigmaMessage, model: LanguageModel, time_limit: float = 120.0) -> dict | None:
    """Crack a message, searching over all unknown key components."""
    ct = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
    if len(ct) < 20:
        return None

    cipher = [ord(c) - 65 for c in ct]
    L = len(cipher)
    t0 = time.time()

    # Determine what we know vs what we need to search.
    if msg.rotors:
        rotor_combos = [tuple(msg.rotors)]
    elif msg.machine_type == MachineType.M4:
        rotor_combos = list(itertools.permutations(NAVAL_ROTORS, 3))
    else:
        rotor_combos = list(itertools.permutations(M3_ROTORS, 3))

    if msg.reflector:
        reflectors = [msg.reflector]
    elif msg.machine_type == MachineType.M4:
        reflectors = list(M4_REFLECTORS)
    else:
        reflectors = list(M3_REFLECTORS)

    rings = tuple(ord(c) - 65 for c in msg.ring_settings) if msg.ring_settings else (0, 0, 0)

    if msg.fourth_rotor:
        fourth_configs = [(msg.fourth_rotor, ord(msg.fourth_position) - 65 if msg.fourth_position else 0)]
    elif msg.machine_type == MachineType.M4:
        fourth_configs = [(gr, fp) for gr in GREEK_ROTORS for fp in range(26)]
    else:
        fourth_configs = [(None, 0)]

    if msg.initial_positions:
        positions_to_try = [tuple(ord(c) - 65 for c in msg.initial_positions)]
    else:
        positions_to_try = None  # will sweep all 17,576

    # Search
    best_score = float("-inf")
    best_result = None
    configs_tried = 0

    for refl in reflectors:
        for rotors in rotor_combos:
            for fourth_name, fourth_pos in fourth_configs:
                fourth_kw = {}
                if fourth_name:
                    fourth_kw = dict(fourth_rotor_name=fourth_name,
                                    fourth_position=fourth_pos, fourth_ring=0)

                if positions_to_try:
                    pos_list = positions_to_try
                else:
                    pos_list = [(pl, pm, pr) for pl in range(26)
                                for pm in range(26) for pr in range(26)]

                for pos in pos_list:
                    traj = fast_trajectory(rotors, refl, pos, rings, L, **fourth_kw)

                    # Adaptive rounds: more rounds for fewer configs.
                    n_rounds = 10 if len(rotor_combos) == 1 else 3
                    beam = 50 if len(rotor_combos) == 1 else 20

                    score, plug, dec = beam_swap_search(
                        cipher, traj, model, rounds=n_rounds, beam_width=beam,
                    )
                    configs_tried += 1

                    if score > best_score:
                        best_score = score
                        best_result = _build_result(
                            rotors, refl, pos, rings, plug, dec, score,
                            fourth_name, fourth_pos,
                        )

                    if time.time() - t0 > time_limit:
                        break
                if time.time() - t0 > time_limit:
                    break
            if time.time() - t0 > time_limit:
                break
        if time.time() - t0 > time_limit:
            break

    if best_result:
        best_result["elapsed"] = time.time() - t0
        best_result["configs_tried"] = configs_tried
    return best_result


def _build_result(rotors, refl, pos, rings, plug, dec, score,
                  fourth_name=None, fourth_pos=0):
    return {
        "rotors": rotors,
        "reflector": refl,
        "positions": pos,
        "rings": rings,
        "plug_map": plug,
        "plaintext": "".join(chr(d + 65) for d in dec),
        "score": score,
        "pairs": [(a, plug[a]) for a in range(26) if plug[a] > a],
        "fourth_rotor": fourth_name,
        "fourth_position": fourth_pos,
    }


def main():
    parser = argparse.ArgumentParser(description="Crack Enigma messages")
    parser.add_argument("message_id", nargs="?", help="Message ID to crack")
    parser.add_argument("--all", action="store_true", help="Process all messages")
    parser.add_argument("--verify", action="store_true", help="Only verify")
    parser.add_argument("--time-limit", type=float, default=120.0, help="Max seconds per message")
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
        print(f"[{msg.id}] {ct_len} chars — {msg.machine_type.value}")
        print(f"{'='*60}")

        # What do we know?
        known = []
        unknown = []
        if msg.rotors:
            known.append(f"rotors={'-'.join(msg.rotors)}")
        else:
            unknown.append("rotors")
        if msg.reflector:
            known.append(f"refl={msg.reflector}")
        else:
            unknown.append("reflector")
        if msg.ring_settings:
            known.append(f"rings={msg.ring_settings}")
        else:
            unknown.append("rings")
        if msg.initial_positions:
            known.append(f"pos={msg.initial_positions}")
        else:
            unknown.append("position")
        unknown.append("plugboard")
        if msg.fourth_rotor:
            known.append(f"4th={msg.fourth_rotor}({msg.fourth_position})")
        elif msg.machine_type == MachineType.M4:
            unknown.append("4th rotor")

        print(f"  Known:   {', '.join(known) or 'nothing'}")
        print(f"  Unknown: {', '.join(unknown)}")

        # Verify if possible
        dec = verify(msg)
        if dec:
            if msg.known_plaintext:
                known_pt = "".join(c for c in msg.known_plaintext if "A" <= c <= "Z")
                ok = dec == known_pt[:len(dec)]
                print(f"  Verify:  {'OK' if ok else 'MISMATCH'}")
            else:
                print(f"  Decrypt: {dec[:60]}")

        if args.verify:
            continue

        # Attack
        print(f"  Cracking...", end="", flush=True)
        result = crack(msg, model, time_limit=args.time_limit)
        if result:
            pos = result["positions"]
            pos_str = "".join(chr(p + 65) for p in pos)
            pairs = result["pairs"]
            rotors_str = "-".join(result["rotors"])
            print(f" {result['elapsed']:.1f}s ({result.get('configs_tried', '?')} configs)")
            print(f"  Rotors:    {rotors_str} / {result['reflector']}")
            if result["fourth_rotor"]:
                print(f"  4th rotor: {result['fourth_rotor']}({chr(result['fourth_position']+65)})")
            print(f"  Position:  {pos_str}", end="")
            if msg.initial_positions:
                print(f" ({'OK' if pos_str == msg.initial_positions else 'true=' + msg.initial_positions})")
            else:
                print()
            print(f"  Plugboard: {' '.join(chr(a+65)+chr(b+65) for a,b in pairs)} ({len(pairs)} pairs)")
            print(f"  Plaintext: {result['plaintext'][:60]}")
        else:
            print(f" no result")

    return 0


if __name__ == "__main__":
    sys.exit(main())
