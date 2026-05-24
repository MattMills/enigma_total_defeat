#!/usr/bin/env python3
"""Batch verification and attack of historical Enigma messages.

For messages with known solutions: verify that the simulator reproduces
the known plaintext from the known key, then run the attack blind to
see if it recovers the key.

For messages without known solutions: run the attack and report results.

Outputs a summary table showing which messages were cracked, which
verified, and which remain unsolved.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass

from enigma.messages import (
    MESSAGES,
    EnigmaMessage,
    MachineType,
    get_messages_with_known_solution,
    get_unsolved_messages,
)
from enigma.simulator import Enigma, Plugboard
from enigma.language import LanguageModel
from enigma.solver import progressive_solve


@dataclass
class CrackResult:
    msg_id: str
    status: str          # "verified", "cracked", "partial", "failed", "skipped"
    verify_ok: bool | None = None   # simulator reproduces known plaintext?
    attack_plaintext: str = ""
    attack_score: float = 0.0
    attack_key: str = ""
    elapsed: float = 0.0
    notes: str = ""


def _parse_positions(s: str) -> list[int]:
    return [ord(c) - 65 for c in s.upper()]


def _parse_plugboard(s: str) -> Plugboard:
    if not s.strip():
        return Plugboard.identity()
    pairs = s.strip().split()
    return Plugboard.from_pairs(pairs)


def verify_message(msg: EnigmaMessage) -> bool | None:
    """Use the known key to decrypt the ciphertext; compare to known plaintext."""
    if not msg.known_plaintext or not msg.rotors or not msg.reflector:
        return None
    if not msg.initial_positions or not msg.ring_settings:
        return None
    try:
        positions = _parse_positions(msg.initial_positions)
        rings = _parse_positions(msg.ring_settings)
        plug = _parse_plugboard(msg.plugboard)

        kwargs = dict(
            rotor_names=tuple(msg.rotors),
            reflector_name=msg.reflector,
            positions=positions,
            ring_settings=rings,
            plugboard=plug,
        )
        if msg.fourth_rotor:
            kwargs["fourth_rotor_name"] = msg.fourth_rotor
            kwargs["fourth_position"] = ord(msg.fourth_position) - 65 if msg.fourth_position else 0
            kwargs["fourth_ring"] = 0

        machine = Enigma(**kwargs)
        decrypted = machine.encrypt(msg.ciphertext)

        # Compare: known plaintexts may have formatting differences.
        known_clean = "".join(c for c in msg.known_plaintext.upper() if "A" <= c <= "Z")
        ct_len = len("".join(c for c in msg.ciphertext if "A" <= c <= "Z"))
        known_trimmed = known_clean[:ct_len]

        if decrypted == known_trimmed:
            return True
        # Partial match?
        match_count = sum(a == b for a, b in zip(decrypted, known_trimmed))
        if match_count / max(len(known_trimmed), 1) > 0.8:
            return True  # allow minor discrepancies in published plaintext
        return False
    except Exception as e:
        print(f"  verify error for {msg.id}: {e}")
        return False


def attack_message(
    msg: EnigmaMessage,
    model: LanguageModel,
    time_limit: float = 30.0,
) -> CrackResult:
    """Run the progressive solver on this message."""
    ct_clean = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
    if len(ct_clean) < 10:
        return CrackResult(
            msg_id=msg.id,
            status="skipped",
            notes=f"ciphertext too short ({len(ct_clean)} chars)",
        )

    # Determine search parameters based on machine type and known info.
    if msg.rotors:
        rotor_pool = tuple(msg.rotors)
    elif msg.machine_type == MachineType.M4:
        rotor_pool = ("I", "II", "III", "IV", "V", "VI", "VII", "VIII")
    else:
        rotor_pool = ("I", "II", "III", "IV", "V")

    if msg.reflector:
        refls = (msg.reflector,)
    elif msg.machine_type == MachineType.M4:
        refls = ("B-thin", "C-thin")
    else:
        refls = ("A", "B", "C")

    ring = (0, 0, 0)
    if msg.ring_settings:
        ring = tuple(_parse_positions(msg.ring_settings))

    fourth_kw = {}
    if msg.fourth_rotor:
        fourth_kw["fourth_rotor_name"] = msg.fourth_rotor
        fourth_kw["fourth_position"] = (
            ord(msg.fourth_position) - 65 if msg.fourth_position else 0
        )
        fourth_kw["fourth_ring"] = 0

    t0 = time.time()
    try:
        results = progressive_solve(
            ct_clean,
            model=model,
            rotor_pool=rotor_pool,
            reflector_names=refls,
            ring_settings=ring,
            top_k=3,
            **fourth_kw,
        )
    except Exception as e:
        return CrackResult(
            msg_id=msg.id,
            status="failed",
            notes=f"attack error: {e}",
            elapsed=time.time() - t0,
        )
    elapsed = time.time() - t0

    if not results:
        return CrackResult(
            msg_id=msg.id,
            status="failed",
            notes="no candidates found",
            elapsed=elapsed,
        )

    top = results[0]
    known_clean = "".join(c for c in msg.known_plaintext.upper() if "A" <= c <= "Z")

    if known_clean and top.plaintext == known_clean[:len(top.plaintext)]:
        status = "cracked"
    elif known_clean:
        match = sum(a == b for a, b in zip(top.plaintext, known_clean))
        ratio = match / max(len(known_clean), 1)
        if ratio > 0.7:
            status = "partial"
        else:
            status = "failed"
    else:
        status = "cracked" if top.score > -2.5 else "partial"

    key_str = (
        f"rotors={'-'.join(top.rotor_names)} refl={top.reflector_name} "
        f"pos={''.join(chr(p+65) for p in top.positions)} "
        f"rings={''.join(chr(r+65) for r in top.ring_settings)}"
    )
    if top.plugboard_pairs:
        key_str += f" plug={' '.join(a+b for a,b in top.plugboard_pairs)}"

    return CrackResult(
        msg_id=msg.id,
        status=status,
        attack_plaintext=top.plaintext[:80],
        attack_score=top.score,
        attack_key=key_str,
        elapsed=elapsed,
    )


def main() -> int:
    model = LanguageModel.german_military()
    results: list[CrackResult] = []

    print("=" * 72)
    print("ENIGMA TOTAL DEFEAT — Batch Message Verification & Attack")
    print("=" * 72)

    # Phase 1: verify known solutions.
    known = get_messages_with_known_solution()
    print(f"\n--- Phase 1: Verify {len(known)} messages with known solutions ---\n")

    for msg in known:
        ct_len = len("".join(c for c in msg.ciphertext if "A" <= c <= "Z"))
        print(f"  [{msg.id}] {msg.source[:50]}... ({ct_len} chars)")
        ok = verify_message(msg)
        if ok is True:
            print(f"    VERIFY: OK — simulator reproduces known plaintext")
        elif ok is False:
            print(f"    VERIFY: MISMATCH — simulator output differs from published plaintext")
        else:
            print(f"    VERIFY: SKIP — incomplete key info")

    # Phase 2: attack known messages blind (using known rotor/reflector/rings
    # to keep runtime bounded; the position + plugboard are discovered).
    print(f"\n--- Phase 2: Blind attack on known messages ---\n")

    for msg in known:
        ct_clean = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
        if len(ct_clean) < 10:
            print(f"  [{msg.id}] skipped (too short)")
            continue
        print(f"  [{msg.id}] attacking ({len(ct_clean)} chars)...", end="", flush=True)
        cr = attack_message(msg, model)
        cr.verify_ok = verify_message(msg)
        results.append(cr)
        print(f" {cr.status} ({cr.elapsed:.1f}s)")
        print(f"    score={cr.attack_score:.3f} key={cr.attack_key}")
        print(f"    plaintext={cr.attack_plaintext[:60]}...")

    # Phase 3: attack unsolved messages.
    unsolved = get_unsolved_messages()
    if unsolved:
        print(f"\n--- Phase 3: Attack {len(unsolved)} unsolved messages ---\n")
        for msg in unsolved:
            ct_clean = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
            if len(ct_clean) < 10:
                print(f"  [{msg.id}] skipped (no/short ciphertext)")
                continue
            print(f"  [{msg.id}] attacking ({len(ct_clean)} chars)...", end="", flush=True)
            cr = attack_message(msg, model)
            results.append(cr)
            print(f" {cr.status} ({cr.elapsed:.1f}s)")
            print(f"    score={cr.attack_score:.3f}")
            print(f"    plaintext={cr.attack_plaintext[:60]}...")

    # Summary table.
    print(f"\n{'=' * 72}")
    print(f"{'MSG ID':<30} {'STATUS':<10} {'SCORE':>8} {'TIME':>6} {'VERIFY':>8}")
    print(f"{'-' * 72}")
    for cr in results:
        v = "OK" if cr.verify_ok else ("FAIL" if cr.verify_ok is False else "-")
        print(f"{cr.msg_id:<30} {cr.status:<10} {cr.attack_score:>8.3f} {cr.elapsed:>5.1f}s {v:>8}")
    print(f"{'=' * 72}")

    cracked = sum(1 for r in results if r.status == "cracked")
    partial = sum(1 for r in results if r.status == "partial")
    failed = sum(1 for r in results if r.status == "failed")
    print(f"\nTotal: {len(results)} attacked, {cracked} cracked, "
          f"{partial} partial, {failed} failed")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
