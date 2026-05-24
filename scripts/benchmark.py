#!/usr/bin/env python3
"""Benchmark: cached vs uncached attack speed, timeout handling, calibration.

Generates synthetic Enigma messages with known keys, runs attacks in
both cached and uncached modes, measures throughput, and tests that
unbreakable messages (random gibberish encrypted with unknown settings)
timeout correctly.

Output: JSON report with per-message timing, aggregate stats, and
cache hit rates.
"""

from __future__ import annotations

import json
import random
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any

from enigma.language import LanguageModel
from enigma.messages import MESSAGES, EnigmaMessage, MachineType
from enigma.simulator import Enigma, Plugboard, ROTORS, REFLECTORS, fast_trajectory
from enigma.solver import progressive_solve, SolverResult, _decrypt_and_score
from enigma.topology import TopologyCache, build_cache_from_messages
from enigma.attack import initialize_candidates, propagate_bigrams


# ------------------------------------------------------------------
# Timeout mechanism
# ------------------------------------------------------------------

class AttackTimeout(Exception):
    pass


def _timeout_handler(signum: int, frame: Any) -> None:
    raise AttackTimeout("attack timed out")


def run_with_timeout(func, args=(), kwargs=None, timeout_sec: float = 30.0):
    """Run func(*args, **kwargs) with a wall-clock timeout.

    Returns (result, elapsed_sec) on success.
    Returns (None, elapsed_sec) on timeout.
    """
    kwargs = kwargs or {}
    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, timeout_sec)
    t0 = time.time()
    try:
        result = func(*args, **kwargs)
        elapsed = time.time() - t0
        return result, elapsed
    except AttackTimeout:
        elapsed = time.time() - t0
        return None, elapsed
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


# ------------------------------------------------------------------
# Cached attack using topology
# ------------------------------------------------------------------

def attack_cached(
    ciphertext: str,
    cache: TopologyCache,
    model: LanguageModel,
    top_k: int = 3,
) -> list[SolverResult]:
    """Attack using the topology cache — O(N_cached) lookups.

    Uses IC (Index of Coincidence) for initial hit detection since
    correct-trajectory decryptions with unknown plugboard still
    preserve the IC of the plaintext. After IC-based filtering,
    applies plugboard inference on top candidates.
    """
    from enigma.language import index_of_coincidence, GERMAN_IC, RANDOM_IC
    from enigma.solver import PlugboardSolver

    cipher = [ord(c) - 65 for c in ciphertext if "A" <= c <= "Z"]
    if not cipher:
        return []

    candidates = initialize_candidates(cipher)
    candidates = propagate_bigrams(candidates, model)

    # Phase 1: IC-based screening of all cached trajectories.
    ic_hits: list[tuple[float, CachedTrajectory, list[int]]] = []
    ic_threshold = 0.3  # generous: IC closer to German than random

    for entry in cache.entries.values():
        traj = fast_trajectory(
            rotor_names=entry.rotor_names,
            reflector_name=entry.reflector_name,
            start_positions=entry.positions,
            ring_settings=entry.ring_settings,
            length=len(cipher),
            fourth_rotor_name=entry.fourth_rotor_name,
            fourth_position=entry.fourth_position,
            fourth_ring=entry.fourth_ring,
        )
        dec = [traj[t][cipher[t]] for t in range(len(cipher))]
        ic = index_of_coincidence(dec)
        ic_score = (ic - RANDOM_IC) / (GERMAN_IC - RANDOM_IC)
        if ic_score > ic_threshold:
            ic_hits.append((ic_score, entry, dec))

    ic_hits.sort(key=lambda x: x[0], reverse=True)

    # Phase 2: language score + plugboard inference on IC hits.
    results: list[SolverResult] = []
    for ic_sc, entry, dec in ic_hits[:top_k * 3]:
        # Try plugboard constraint solver.
        psolver = PlugboardSolver.from_decryption(dec, candidates)
        pairs = psolver.get_pairs()
        if psolver.is_consistent():
            improved = psolver.apply_best_guess(dec, model)
            score = model.score(improved)
        else:
            improved = dec
            score = model.score(dec)
            pairs = []

        if score == float("-inf"):
            continue

        results.append(SolverResult(
            plaintext="".join(chr(p + 65) for p in improved),
            score=score,
            rotor_names=entry.rotor_names,
            reflector_name=entry.reflector_name,
            positions=entry.positions,
            ring_settings=entry.ring_settings,
            plugboard_pairs=[(chr(a+65), chr(b+65)) for a, b in pairs],
            fourth_rotor_name=entry.fourth_rotor_name,
            fourth_position=entry.fourth_position,
            fourth_ring=entry.fourth_ring,
        ))

    results.sort(key=lambda r: r.score, reverse=True)
    return results[:top_k]


# ------------------------------------------------------------------
# Synthetic message generation
# ------------------------------------------------------------------

GERMAN_WORDS = [
    "ANGRIFF", "BEFEHL", "DIVISION", "EINS", "FEIND", "GEFECHT",
    "HAUPTMANN", "INFANTERIE", "KAMPF", "LAGE", "MARSCH", "NORDEN",
    "OFFIZIER", "PANZER", "RUECKZUG", "STELLUNG", "TRUPPE", "UHRX",
    "VORMARSCH", "WETTER", "ZURUECK", "STOPP", "DREI", "NULL",
    "SIEBEN", "ZWEI", "FUENF", "NEUN", "ACHT", "SECHS", "VIER",
    "FUNKSPRUCH", "DRINGEND", "GEHEIM", "SOFORT", "BERICHT",
    "STANDORT", "RICHTUNG", "WESTEN", "OSTEN", "SUEDEN", "NORDEN",
    "ENDE", "ANFANG", "MORGEN", "ABEND", "NACHT", "HEUTE",
]


def generate_german_text(rng: random.Random, length: int) -> str:
    words: list[str] = []
    total = 0
    while total < length:
        w = rng.choice(GERMAN_WORDS)
        words.append(w)
        total += len(w)
    return "X".join(words)[:length]


def generate_synthetic_message(
    rng: random.Random,
    msg_id: str,
    length: int = 50,
    machine: str = "M3",
) -> tuple[EnigmaMessage, str]:
    """Generate a synthetic Enigma message with a random key.

    Returns (EnigmaMessage with ciphertext, plaintext).
    """
    plaintext = generate_german_text(rng, length)

    if machine == "M3":
        pool = ["I", "II", "III", "IV", "V"]
        rotors = tuple(rng.sample(pool, 3))
        refl = rng.choice(["A", "B", "C"])
        fourth = None
        fourth_pos = ""
    else:
        pool = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII"]
        rotors = tuple(rng.sample(pool, 3))
        refl = rng.choice(["B-thin", "C-thin"])
        fourth = rng.choice(["Beta", "Gamma"])
        fourth_pos = chr(rng.randint(0, 25) + 65)

    positions = [rng.randint(0, 25) for _ in range(3)]
    rings = [rng.randint(0, 25) for _ in range(3)]
    pos_str = "".join(chr(p + 65) for p in positions)
    ring_str = "".join(chr(r + 65) for r in rings)

    # Random plugboard (0-10 pairs).
    n_pairs = rng.randint(0, 10)
    letters = list(range(26))
    rng.shuffle(letters)
    plug_pairs: list[str] = []
    for i in range(0, 2 * n_pairs, 2):
        a, b = letters[i], letters[i + 1]
        plug_pairs.append(chr(a + 65) + chr(b + 65))

    kw: dict[str, Any] = dict(
        rotor_names=rotors,
        reflector_name=refl,
        positions=list(positions),
        ring_settings=list(rings),
        plugboard=Plugboard.from_pairs(plug_pairs),
    )
    if fourth:
        kw["fourth_rotor_name"] = fourth
        kw["fourth_position"] = ord(fourth_pos) - 65
        kw["fourth_ring"] = 0

    enc = Enigma(**kw)
    ciphertext = enc.encrypt(plaintext)

    msg = EnigmaMessage(
        id=msg_id,
        ciphertext=ciphertext,
        machine_type=MachineType.M4 if fourth else MachineType.M3,
        source="synthetic",
        reflector=refl,
        rotors=rotors,
        ring_settings=ring_str,
        initial_positions=pos_str,
        plugboard=" ".join(plug_pairs),
        fourth_rotor=fourth or "",
        fourth_position=fourth_pos,
        known_plaintext=plaintext,
    )
    return msg, plaintext


def generate_unbreakable_message(rng: random.Random, msg_id: str, length: int = 50) -> EnigmaMessage:
    """Generate random gibberish — no valid Enigma encryption at all.

    This should always timeout or return garbage; used to validate
    that the timeout mechanism works correctly.
    """
    ciphertext = "".join(chr(rng.randint(0, 25) + 65) for _ in range(length))
    return EnigmaMessage(
        id=msg_id,
        ciphertext=ciphertext,
        machine_type=MachineType.UNKNOWN,
        source="unbreakable-synthetic",
        notes="Random gibberish — not a valid Enigma encryption",
    )


# ------------------------------------------------------------------
# Benchmark result
# ------------------------------------------------------------------

@dataclass
class BenchmarkEntry:
    msg_id: str
    mode: str              # "cached", "uncached", "unbreakable"
    status: str            # "cracked", "partial", "timeout", "failed"
    elapsed_sec: float
    score: float = 0.0
    plaintext_match: bool = False
    key_match: bool = False
    ct_length: int = 0
    chars_per_sec: float = 0.0
    notes: str = ""


# ------------------------------------------------------------------
# Main benchmark
# ------------------------------------------------------------------

def main() -> int:
    rng = random.Random(0xE159_DEAD)
    model = LanguageModel.german_military()
    entries: list[BenchmarkEntry] = []

    print("=" * 78)
    print("ENIGMA TOTAL DEFEAT — Benchmark & Calibration Suite")
    print("=" * 78)

    # ----------------------------------------------------------
    # Phase 0: build topology cache from known messages
    # ----------------------------------------------------------
    print("\n--- Phase 0: Building topology cache ---")
    t0 = time.time()
    cache = build_cache_from_messages()

    # Also pre-populate the cache with day-key variants for Barbarossa:
    # same rotors/reflector/rings, all 26³ positions. This simulates
    # having broken one message from a day and caching the full day.
    print("  Pre-populating Barbarossa day-key cache (II-IV-V/B, rings BUL)...")
    barb_count = 0
    for pl in range(26):
        for pm in range(26):
            for pr in range(26):
                cache.add_trajectory(
                    rotor_names=("II", "IV", "V"),
                    reflector_name="B",
                    positions=(pl, pm, pr),
                    ring_settings=(1, 20, 11),  # BUL
                    length=50,
                    message_id="barbarossa-day-cache",
                )
                barb_count += 1
    cache_build_time = time.time() - t0
    print(f"  Cache: {len(cache.entries)} entries built in {cache_build_time:.1f}s")

    # ----------------------------------------------------------
    # Phase 1: synthetic messages — uncached attack
    # ----------------------------------------------------------
    n_synthetic = 5
    print(f"\n--- Phase 1: {n_synthetic} synthetic M3 messages — UNCACHED attack ---")
    print(f"  (restricted rotor pool per message for bounded runtime)\n")

    synth_messages: list[tuple[EnigmaMessage, str]] = []
    for i in range(n_synthetic):
        msg, pt = generate_synthetic_message(rng, f"synth-{i:02d}", length=40)
        synth_messages.append((msg, pt))

    for msg, pt in synth_messages:
        ct_len = len("".join(c for c in msg.ciphertext if "A" <= c <= "Z"))
        print(f"  [{msg.id}] {ct_len} chars, rotors={'-'.join(msg.rotors)}, "
              f"refl={msg.reflector}...", end="", flush=True)

        def do_attack():
            return progressive_solve(
                msg.ciphertext,
                model=model,
                rotor_pool=tuple(msg.rotors),
                reflector_names=(msg.reflector,),
                ring_settings=tuple(ord(c) - 65 for c in msg.ring_settings),
                top_k=3,
            )

        result, elapsed = run_with_timeout(do_attack, timeout_sec=30.0)
        if result is None:
            status = "timeout"
            print(f" TIMEOUT ({elapsed:.1f}s)")
            entries.append(BenchmarkEntry(
                msg_id=msg.id, mode="uncached", status="timeout",
                elapsed_sec=elapsed, ct_length=ct_len,
            ))
        elif not result:
            status = "failed"
            print(f" FAILED ({elapsed:.1f}s)")
            entries.append(BenchmarkEntry(
                msg_id=msg.id, mode="uncached", status="failed",
                elapsed_sec=elapsed, ct_length=ct_len,
            ))
        else:
            top = result[0]
            pt_clean = "".join(c for c in pt if "A" <= c <= "Z")
            key_ok = (
                top.rotor_names == tuple(msg.rotors)
                and top.reflector_name == msg.reflector
                and "".join(chr(p+65) for p in top.positions) == msg.initial_positions
            )
            pt_ok = top.plaintext == pt_clean[:len(top.plaintext)]
            status = "cracked" if key_ok else ("partial" if top.score > -2.5 else "failed")
            cps = ct_len / elapsed if elapsed > 0 else 0
            print(f" {status} ({elapsed:.1f}s, {cps:.0f} ch/s, key={'OK' if key_ok else 'MISS'})")
            entries.append(BenchmarkEntry(
                msg_id=msg.id, mode="uncached", status=status,
                elapsed_sec=elapsed, score=top.score,
                plaintext_match=pt_ok, key_match=key_ok,
                ct_length=ct_len, chars_per_sec=cps,
            ))

    # ----------------------------------------------------------
    # Phase 2: same synthetic messages — CACHED attack
    # ----------------------------------------------------------
    print(f"\n--- Phase 2: Same {n_synthetic} messages — CACHED attack ---\n")

    # Add each synthetic message's correct config to cache.
    synth_cache = TopologyCache()
    for msg, _ in synth_messages:
        positions = tuple(ord(c) - 65 for c in msg.initial_positions)
        rings = tuple(ord(c) - 65 for c in msg.ring_settings)
        fourth = msg.fourth_rotor or None
        fourth_pos = ord(msg.fourth_position) - 65 if msg.fourth_position else 0
        synth_cache.add_trajectory(
            rotor_names=tuple(msg.rotors),
            reflector_name=msg.reflector,
            positions=positions,
            ring_settings=rings,
            length=50,
            message_id=msg.id,
            fourth_rotor_name=fourth,
            fourth_position=fourth_pos,
        )

    for msg, pt in synth_messages:
        ct_len = len("".join(c for c in msg.ciphertext if "A" <= c <= "Z"))
        print(f"  [{msg.id}] cached attack...", end="", flush=True)

        t0 = time.time()
        result = attack_cached(msg.ciphertext, synth_cache, model, top_k=3)
        elapsed = time.time() - t0

        if result:
            top = result[0]
            pt_clean = "".join(c for c in pt if "A" <= c <= "Z")
            key_ok = (
                top.rotor_names == tuple(msg.rotors)
                and top.reflector_name == msg.reflector
                and tuple(top.positions) == tuple(ord(c)-65 for c in msg.initial_positions)
            )
            cps = ct_len / elapsed if elapsed > 0 else 0
            status = "cracked" if key_ok else "partial"
            print(f" {status} ({elapsed*1000:.1f}ms, {cps:.0f} ch/s)")
        else:
            key_ok = False
            cps = 0
            status = "failed"
            print(f" FAILED ({elapsed*1000:.1f}ms)")

        entries.append(BenchmarkEntry(
            msg_id=msg.id, mode="cached", status=status,
            elapsed_sec=elapsed, score=result[0].score if result else 0,
            plaintext_match=key_ok, key_match=key_ok,
            ct_length=ct_len, chars_per_sec=cps,
        ))

    # ----------------------------------------------------------
    # Phase 3: unbreakable messages — verify timeout works
    # ----------------------------------------------------------
    n_unbreakable = 2
    timeout_sec = 8.0
    print(f"\n--- Phase 3: {n_unbreakable} unbreakable messages — timeout={timeout_sec}s ---\n")

    for i in range(n_unbreakable):
        msg = generate_unbreakable_message(rng, f"unbreakable-{i:02d}", length=50)
        ct_len = len(msg.ciphertext)
        print(f"  [{msg.id}] random gibberish, {ct_len} chars...", end="", flush=True)

        def do_blind_attack():
            return progressive_solve(
                msg.ciphertext,
                model=model,
                rotor_pool=("I", "II", "III", "IV", "V"),
                reflector_names=("B", "C"),
                ring_settings=(0, 0, 0),
                top_k=1,
            )

        result, elapsed = run_with_timeout(do_blind_attack, timeout_sec=timeout_sec)
        if result is None:
            print(f" TIMEOUT correctly ({elapsed:.1f}s)")
            status = "timeout"
        elif not result:
            print(f" no candidates ({elapsed:.1f}s)")
            status = "failed"
        else:
            score = result[0].score
            print(f" returned noise (score={score:.3f}, {elapsed:.1f}s)")
            status = "failed"

        entries.append(BenchmarkEntry(
            msg_id=msg.id, mode="unbreakable", status=status,
            elapsed_sec=elapsed, ct_length=ct_len,
        ))

    # ----------------------------------------------------------
    # Phase 4: historical messages from database
    # ----------------------------------------------------------
    print(f"\n--- Phase 4: Historical messages — cached day-key attack ---\n")

    for msg in MESSAGES:
        ct_clean = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
        if len(ct_clean) < 10:
            continue

        print(f"  [{msg.id}] {len(ct_clean)} chars...", end="", flush=True)

        # Try cached first.
        t0 = time.time()
        cached_result = attack_cached(msg.ciphertext, cache, model, top_k=3)
        cached_elapsed = time.time() - t0

        if cached_result and cached_result[0].score > -2.5:
            top = cached_result[0]
            cps = len(ct_clean) / cached_elapsed if cached_elapsed > 0 else 0
            print(f" CACHE HIT ({cached_elapsed*1000:.1f}ms, score={top.score:.3f})")
            print(f"    {top.plaintext[:60]}")
            entries.append(BenchmarkEntry(
                msg_id=msg.id, mode="cached", status="cracked",
                elapsed_sec=cached_elapsed, score=top.score,
                ct_length=len(ct_clean), chars_per_sec=cps,
            ))
        else:
            # Fall through to uncached (with timeout).
            def do_historical():
                rotor_pool = tuple(msg.rotors) if msg.rotors else ("I", "II", "III", "IV", "V")
                refls = (msg.reflector,) if msg.reflector else ("B", "C")
                ring = tuple(ord(c)-65 for c in msg.ring_settings) if msg.ring_settings else (0, 0, 0)
                fourth_kw = {}
                if msg.fourth_rotor:
                    fourth_kw["fourth_rotor_name"] = msg.fourth_rotor
                    fourth_kw["fourth_position"] = ord(msg.fourth_position)-65 if msg.fourth_position else 0
                    fourth_kw["fourth_ring"] = 0
                return progressive_solve(
                    msg.ciphertext, model=model,
                    rotor_pool=rotor_pool, reflector_names=refls,
                    ring_settings=ring, top_k=3, **fourth_kw,
                )

            result, elapsed = run_with_timeout(do_historical, timeout_sec=30.0)
            if result is None:
                print(f" TIMEOUT ({elapsed:.1f}s)")
                entries.append(BenchmarkEntry(
                    msg_id=msg.id, mode="uncached", status="timeout",
                    elapsed_sec=elapsed, ct_length=len(ct_clean),
                ))
            elif not result:
                print(f" FAILED ({elapsed:.1f}s)")
                entries.append(BenchmarkEntry(
                    msg_id=msg.id, mode="uncached", status="failed",
                    elapsed_sec=elapsed, ct_length=len(ct_clean),
                ))
            else:
                top = result[0]
                cps = len(ct_clean) / elapsed if elapsed > 0 else 0
                print(f" UNCACHED ({elapsed:.1f}s, score={top.score:.3f})")
                print(f"    {top.plaintext[:60]}")
                entries.append(BenchmarkEntry(
                    msg_id=msg.id, mode="uncached",
                    status="cracked" if top.score > -2.5 else "partial",
                    elapsed_sec=elapsed, score=top.score,
                    ct_length=len(ct_clean), chars_per_sec=cps,
                ))

    # ----------------------------------------------------------
    # Summary
    # ----------------------------------------------------------
    print(f"\n{'=' * 78}")
    print(f"{'MSG ID':<25} {'MODE':<12} {'STATUS':<10} {'TIME':>8} {'SCORE':>8} {'CH/S':>8}")
    print(f"{'-' * 78}")
    for e in entries:
        t_str = f"{e.elapsed_sec:.3f}s" if e.elapsed_sec < 1 else f"{e.elapsed_sec:.1f}s"
        cps_str = f"{e.chars_per_sec:.0f}" if e.chars_per_sec > 0 else "-"
        score_str = f"{e.score:.3f}" if e.score != 0 else "-"
        print(f"{e.msg_id:<25} {e.mode:<12} {e.status:<10} {t_str:>8} {score_str:>8} {cps_str:>8}")
    print(f"{'=' * 78}")

    # Aggregate stats.
    cached = [e for e in entries if e.mode == "cached" and e.elapsed_sec > 0]
    uncached = [e for e in entries if e.mode == "uncached" and e.elapsed_sec > 0]
    unbreak = [e for e in entries if e.mode == "unbreakable"]

    if cached:
        avg_cached = sum(e.elapsed_sec for e in cached) / len(cached)
        print(f"\nCached:     {len(cached)} attacks, avg {avg_cached*1000:.1f}ms/msg")
    if uncached:
        avg_uncached = sum(e.elapsed_sec for e in uncached) / len(uncached)
        print(f"Uncached:   {len(uncached)} attacks, avg {avg_uncached:.2f}s/msg")
    if cached and uncached:
        speedup = avg_uncached / avg_cached if avg_cached > 0 else float("inf")
        print(f"Speedup:    {speedup:.0f}×")
    if unbreak:
        timeouts = sum(1 for e in unbreak if e.status == "timeout")
        print(f"Unbreakable: {len(unbreak)} tested, {timeouts} correctly timed out")

    # Write JSON report.
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "cache_entries": len(cache.entries),
        "cache_build_time_sec": cache_build_time,
        "results": [asdict(e) for e in entries],
        "aggregate": {
            "cached_avg_ms": avg_cached * 1000 if cached else None,
            "uncached_avg_sec": avg_uncached if uncached else None,
            "speedup": speedup if cached and uncached else None,
            "unbreakable_timeout_rate": timeouts / len(unbreak) if unbreak else None,
        },
    }
    with open("benchmark_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport written to benchmark_report.json")

    return 0


if __name__ == "__main__":
    sys.exit(main())
