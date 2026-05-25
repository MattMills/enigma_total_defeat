#!/usr/bin/env python3
"""Crack Enigma messages using the full integrated pipeline.

Chains all techniques topologically — each narrows the space for the next:

  0. Topology:     O(1) cache lookup for known configurations
  1. Spectral:     identify candidate right rotors from ciphertext (if unknown)
  2. IC filter:    rank positions by plugboard-invariant IC (top 3%)
  3. Superposition: reject inconsistent trajectories (kills 59%)
  4. Domain cascade: narrow plugboard domains via differential (602→1 compatible)
  5. Beam swap:    recover plugboard with n-gram symbol scoring (10/10 in ~10s)
  6. Validation:   binary discriminator (0 excluded bigrams = correct)

Each stage ENCLOSES the search space for the next. Longer messages
converge faster because more positions = more constraints.
"""

import argparse
import itertools
import sys
import time

from enigma.language import LanguageModel
from enigma.messages import MESSAGES, EnigmaMessage, MachineType, get_message
from enigma.pipeline import crack_full, crack_with_known_trajectory, crack_zero_knowledge, PipelineResult
from enigma.simulator import (
    Enigma, Plugboard,
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

    t0 = time.time()

    # --- Determine search space from message metadata ---
    known_rotors = tuple(msg.rotors) if msg.rotors else None
    reflectors = [msg.reflector] if msg.reflector else (
        list(M4_REFLECTORS) if msg.machine_type == MachineType.M4 else list(M3_REFLECTORS)
    )
    rings = tuple(ord(c) - 65 for c in msg.ring_settings) if msg.ring_settings else (0, 0, 0)
    known_pos = tuple(ord(c) - 65 for c in msg.initial_positions) if msg.initial_positions else None

    rotor_pool = NAVAL_ROTORS if msg.machine_type == MachineType.M4 else M3_ROTORS

    fourth_rotors = None
    fourth_positions = None
    if msg.fourth_rotor:
        fourth_rotors = (msg.fourth_rotor,)
        fourth_positions = [ord(msg.fourth_position) - 65] if msg.fourth_position else None
    elif msg.machine_type == MachineType.M4:
        fourth_rotors = GREEK_ROTORS
        fourth_positions = list(range(26))

    # --- Known trajectory: use crack_with_known_trajectory ---
    if known_pos and known_rotors:
        fourth_kw = {}
        if msg.fourth_rotor:
            fourth_kw["fourth_rotor_name"] = msg.fourth_rotor
            fourth_kw["fourth_position"] = ord(msg.fourth_position) - 65 if msg.fourth_position else 0
        result = crack_with_known_trajectory(
            ct, known_rotors, reflectors[0], known_pos, rings,
            model=model, beam_rounds=12, beam_width=80,
            use_domain_cascade=True, **fourth_kw,
        )
        return _from_pipeline_result(result)

    # --- Zero knowledge: use hierarchical phase-space solver ---
    if not known_rotors and not known_pos:
        # Collect same-day messages for cross-validation
        same_day = [ct]
        if msg.date:
            for other in MESSAGES:
                if other.id != msg.id and other.date == msg.date:
                    other_ct = "".join(c for c in other.ciphertext if "A" <= c <= "Z")
                    if len(other_ct) >= 20:
                        same_day.append(other_ct)

        results = crack_zero_knowledge(
            same_day,
            model=model,
            rotor_pool=rotor_pool,
            reflector_names=tuple(reflectors),
            beam_rounds=10,
            beam_width=50,
            search_rings=True,
            time_limit=time_limit,
            progress=True,
            fourth_rotors=fourth_rotors,
            fourth_positions=fourth_positions,
        )
        if not results:
            return None
        return _from_pipeline_result(results[0])

    # --- Partial knowledge: use full pipeline ---
    results = crack_full(
        ct,
        model=model,
        rotor_pool=rotor_pool,
        reflector_names=tuple(reflectors),
        ring_settings=rings,
        known_rotors=known_rotors,
        known_positions=known_pos,
        ic_survivors=200,
        superposition_filter=True,
        domain_cascade=False,
        beam_rounds=5,
        beam_width=30,
        time_limit=time_limit,
        fourth_rotors=fourth_rotors,
        fourth_positions=fourth_positions,
    )

    if not results:
        return None
    return _from_pipeline_result(results[0])


def _from_pipeline_result(r: PipelineResult) -> dict:
    return {
        "rotors": r.rotor_names, "reflector": r.reflector_name,
        "positions": r.positions, "rings": r.ring_settings,
        "plug_map": r.plugboard_map,
        "plaintext": r.plaintext,
        "score": r.score,
        "pairs": r.plugboard_pairs,
        "fourth_rotor": r.fourth_rotor_name,
        "fourth_position": r.fourth_position,
        "elapsed": r.elapsed,
        "configs_tried": 0,
        "configs_survived": 0,
        "stages_used": r.stages_used,
        "n_excluded_bigrams": r.n_excluded_bigrams,
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
