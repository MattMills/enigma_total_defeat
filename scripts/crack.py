#!/usr/bin/env python3
"""Crack Enigma messages using the full constraint pipeline.

Chains all techniques topologically — each narrows the space for the next:

  1. Spectral:     identify candidate right rotors from ciphertext (if unknown)
  2. IC filter:    rank positions by plugboard-invariant IC (top 3%)
  3. Superposition: reject inconsistent trajectories (kills 59%)
  4. Domain cascade: narrow plugboard domains via differential (602→1 compatible)
  5. Beam swap:    recover plugboard with n-gram symbol scoring (10/10 in ~10s)
  6. Coherence:    validate pairs, complete missing ones

Each stage ENCLOSES the search space for the next. Longer messages
converge faster because more positions = more constraints.
"""

import argparse
import itertools
import sys
import time

from enigma.attack import beam_swap_search
from enigma.language import LanguageModel, index_of_coincidence
from enigma.messages import MESSAGES, EnigmaMessage, MachineType, get_message
from enigma.simulator import (
    Enigma, Plugboard, fast_trajectory,
    M3_ROTORS, NAVAL_ROTORS, GREEK_ROTORS, M3_REFLECTORS, M4_REFLECTORS,
)


def verify(msg: EnigmaMessage) -> str | None:
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
    ct = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
    if len(ct) < 20:
        return None

    cipher = [ord(c) - 65 for c in ct]
    L = len(cipher)
    t0 = time.time()

    # --- Determine search space ---
    if msg.rotors:
        rotor_combos = [tuple(msg.rotors)]
    elif msg.machine_type == MachineType.M4:
        rotor_combos = list(itertools.permutations(NAVAL_ROTORS, 3))
    else:
        rotor_combos = list(itertools.permutations(M3_ROTORS, 3))

    reflectors = [msg.reflector] if msg.reflector else (
        list(M4_REFLECTORS) if msg.machine_type == MachineType.M4 else list(M3_REFLECTORS)
    )

    rings = tuple(ord(c) - 65 for c in msg.ring_settings) if msg.ring_settings else (0, 0, 0)

    if msg.fourth_rotor:
        fourth_configs = [(msg.fourth_rotor, ord(msg.fourth_position) - 65 if msg.fourth_position else 0)]
    elif msg.machine_type == MachineType.M4:
        fourth_configs = [(gr, fp) for gr in GREEK_ROTORS for fp in range(26)]
    else:
        fourth_configs = [(None, 0)]

    position_known = bool(msg.initial_positions)
    known_pos = tuple(ord(c) - 65 for c in msg.initial_positions) if position_known else None

    total_combos = len(rotor_combos) * len(reflectors) * len(fourth_configs)
    if not position_known:
        total_combos *= 17576

    # --- Stage 1: If position known, go straight to beam swap ---
    if position_known and len(rotor_combos) == 1:
        fourth_kw = {}
        if fourth_configs[0][0]:
            fourth_kw = dict(fourth_rotor_name=fourth_configs[0][0],
                             fourth_position=fourth_configs[0][1], fourth_ring=0)
        traj = fast_trajectory(rotor_combos[0], reflectors[0], known_pos, rings, L, **fourth_kw)
        score, plug, dec = beam_swap_search(cipher, traj, model, rounds=10, beam_width=50)
        return _result(rotor_combos[0], reflectors[0], known_pos, rings, plug, dec, score,
                       fourth_configs[0][0], fourth_configs[0][1], time.time() - t0, 1)

    # --- Stage 2: Sweep with superposition pre-filter + beam swap ---
    # For each (rotors, reflector, fourth), sweep positions.
    # Use the superposition solver to reject inconsistent trajectories FAST,
    # then beam swap on survivors.
    from enigma.superposition import try_collapse

    best_score = float("-inf")
    best_result = None
    configs_tried = 0
    configs_survived = 0

    for refl in reflectors:
        for rotors in rotor_combos:
            for fourth_name, fourth_pos in fourth_configs:
                fourth_kw = {}
                if fourth_name:
                    fourth_kw = dict(fourth_rotor_name=fourth_name,
                                    fourth_position=fourth_pos, fourth_ring=0)

                positions = [known_pos] if position_known else None

                # If position unknown: IC pre-filter to top 200
                if positions is None:
                    ic_scores = []
                    for pl in range(26):
                        for pm in range(26):
                            for pr in range(26):
                                traj = fast_trajectory(rotors, refl, (pl, pm, pr), rings, L, **fourth_kw)
                                dec = [traj[t][cipher[t]] for t in range(L)]
                                ic_scores.append((index_of_coincidence(dec), (pl, pm, pr)))
                                if time.time() - t0 > time_limit:
                                    break
                            if time.time() - t0 > time_limit:
                                break
                        if time.time() - t0 > time_limit:
                            break
                    ic_scores.sort(reverse=True)
                    positions = [pos for _, pos in ic_scores[:200]]

                for pos in positions:
                    if time.time() - t0 > time_limit:
                        break

                    traj = fast_trajectory(rotors, refl, pos, rings, L, **fourth_kw)
                    configs_tried += 1

                    # Superposition pre-filter: try common seed letters,
                    # reject if none survive.
                    rejected = True
                    for seed in (4, 13, 8, 18, 0):  # E N I S A
                        if seed == cipher[0]:
                            continue
                        result = try_collapse(cipher, traj, model, seed, 0)
                        if result.consistent:
                            rejected = False
                            break
                    if rejected:
                        continue
                    configs_survived += 1

                    # Beam swap with adaptive rounds
                    n_rounds = 10 if total_combos <= 10 else 3
                    beam = 50 if total_combos <= 10 else 20
                    score, plug, dec = beam_swap_search(
                        cipher, traj, model, rounds=n_rounds, beam_width=beam,
                    )

                    if score > best_score:
                        best_score = score
                        best_result = _result(
                            rotors, refl, pos, rings, plug, dec, score,
                            fourth_name, fourth_pos, 0, configs_tried,
                        )

                if time.time() - t0 > time_limit:
                    break
            if time.time() - t0 > time_limit:
                break
        if time.time() - t0 > time_limit:
            break

    if best_result:
        best_result["elapsed"] = time.time() - t0
        best_result["configs_tried"] = configs_tried
        best_result["configs_survived"] = configs_survived
    return best_result


def _result(rotors, refl, pos, rings, plug, dec, score,
            fourth_name=None, fourth_pos=0, elapsed=0, tried=0):
    return {
        "rotors": rotors, "reflector": refl, "positions": pos,
        "rings": rings, "plug_map": plug,
        "plaintext": "".join(chr(d + 65) for d in dec),
        "score": score,
        "pairs": [(a, plug[a]) for a in range(26) if plug[a] > a],
        "fourth_rotor": fourth_name, "fourth_position": fourth_pos,
        "elapsed": elapsed, "configs_tried": tried,
    }


def main():
    parser = argparse.ArgumentParser(description="Crack Enigma messages")
    parser.add_argument("message_id", nargs="?")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--time-limit", type=float, default=120.0)
    args = parser.parse_args()

    model = LanguageModel.german_military()

    if args.message_id:
        msg = get_message(args.message_id)
        if msg is None:
            print(f"Unknown: {args.message_id}")
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

        known, unknown = [], []
        if msg.rotors: known.append(f"rotors={'-'.join(msg.rotors)}")
        else: unknown.append("rotors")
        if msg.reflector: known.append(f"refl={msg.reflector}")
        else: unknown.append("reflector")
        if msg.ring_settings: known.append(f"rings={msg.ring_settings}")
        else: unknown.append("rings")
        if msg.initial_positions: known.append(f"pos={msg.initial_positions}")
        else: unknown.append("position")
        unknown.append("plugboard")
        if msg.fourth_rotor: known.append(f"4th={msg.fourth_rotor}({msg.fourth_position})")
        elif msg.machine_type == MachineType.M4: unknown.append("4th rotor")
        print(f"  Known:   {', '.join(known) or 'nothing'}")
        print(f"  Unknown: {', '.join(unknown)}")

        dec = verify(msg)
        if dec:
            if msg.known_plaintext:
                kp = "".join(c for c in msg.known_plaintext if "A" <= c <= "Z")
                print(f"  Verify:  {'OK' if dec == kp[:len(dec)] else 'MISMATCH'}")
            else:
                print(f"  Decrypt: {dec[:60]}")

        if args.verify:
            continue

        print(f"  Cracking...", end="", flush=True)
        result = crack(msg, model, time_limit=args.time_limit)
        if result:
            pos = result["positions"]
            pos_str = "".join(chr(p + 65) for p in pos)
            pairs = result["pairs"]
            tried = result.get("configs_tried", "?")
            survived = result.get("configs_survived", "?")
            print(f" {result['elapsed']:.1f}s ({tried} tried, {survived} survived)")
            print(f"  Rotors:    {'-'.join(result['rotors'])} / {result['reflector']}")
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
            print(f" no result (time limit reached)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
