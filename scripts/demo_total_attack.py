#!/usr/bin/env python3
"""Demo the idealized zero-knowledge total attack.

Tests against increasingly difficult scenarios to show exactly where
each technique contributes and what the limits are.
"""

import sys
import time

sys.path.insert(0, ".")

from enigma.language import LanguageModel
from enigma.messages import get_message
from enigma.scenarios import (
    scenario_no_plugboard,
    scenario_light_plugboard,
    scenario_heavy_plugboard,
    make_scenario,
    GERMAN_PLAINTEXTS,
)
from enigma.total_attack import total_attack


def header(text):
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}")


def run_attack(name, ciphertext, expected_plaintext, **kwargs):
    print(f"\nScenario: {name}")
    ct_len = sum(1 for c in ciphertext if "A" <= c <= "Z")
    print(f"  Ciphertext length: {ct_len}")
    print(f"  Expected: {expected_plaintext[:60]}...")

    t0 = time.time()
    results = total_attack(ciphertext, progress=True, **kwargs)
    elapsed = time.time() - t0

    if results:
        top = results[0]
        print(f"\n  Result:")
        print(f"    Rotors:    {'-'.join(top.rotor_names)}/{top.reflector_name}")
        print(f"    Position:  {''.join(chr(p+65) for p in top.positions)}")
        print(f"    Rings:     {''.join(chr(r+65) for r in top.ring_settings)}")
        print(f"    Plugboard: {top.plug_str or '(none)'}")
        print(f"    Excluded:  {top.n_excluded_bigrams}")
        print(f"    Score:     {top.score:.3f}")
        print(f"    Stages:    {top.stages_used}")
        print(f"    Plaintext: {top.plaintext[:70]}...")

        expected_clean = "".join(c for c in expected_plaintext if "A" <= c <= "Z")
        match = top.plaintext == expected_clean[:len(top.plaintext)]
        print(f"    MATCH:     {'YES' if match else 'NO'}")
        print(f"    Time:      {elapsed:.1f}s")
        return match
    else:
        print(f"  No results found in {elapsed:.1f}s")
        return False


# ==================================================================
header("BENCHMARK RESULTS (from enigma.benchmark)")
# ==================================================================
print("Running compatibility benchmark first to show which techniques")
print("work under which conditions...")
from enigma.benchmark import run_benchmark
run_benchmark(verbose=True)


# ==================================================================
header("TEST 1: No plugboard, known rotor triple")
# ==================================================================
s = scenario_no_plugboard()
run_attack(
    "no_plugboard (II-IV-V/B, no plug, no rings, 58 chars)",
    s.ciphertext_str, s.plaintext,
    rotor_pool=("II", "IV", "V"),
    reflector_names=("B",),
    time_limit=60,
    beam_rounds=5,
    beam_width=30,
)

# ==================================================================
header("TEST 2: Light plugboard (3 pairs), known rotor triple")
# ==================================================================
s = scenario_light_plugboard()
run_attack(
    "light_plugboard (I-III-V/B, 3 pairs, 64 chars)",
    s.ciphertext_str, s.plaintext,
    rotor_pool=("I", "III", "V"),
    reflector_names=("B",),
    time_limit=60,
    beam_rounds=8,
    beam_width=50,
)

# ==================================================================
header("TEST 3: Historical Barbarossa-1 (174 chars, 10 pairs, known rotors)")
# ==================================================================
msg = get_message("barbarossa-1")
ct = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
expected = "".join(c for c in msg.known_plaintext if "A" <= c <= "Z")
run_attack(
    f"Barbarossa-1 ({len(ct)} chars, 10-pair plugboard, rings BUL)",
    ct, expected,
    rotor_pool=("II", "IV", "V"),
    reflector_names=("B",),
    time_limit=180,
    beam_rounds=12,
    beam_width=80,
    ic_survivors_per_combo=30,
)


# ==================================================================
header("ANALYSIS")
# ==================================================================
print("""
The total_attack chains techniques based on benchmark compatibility:

  Phase 0: Spectral narrows right rotor (ciphertext-only, plug-invariant)
  Phase 1: Inline IC sweep ranks positions (plug-invariant, 0.5s/combo)
  Phase 2: Superposition filter rejects wrong trajectories
  Phase 3: Brute-force ring (26 trials, IC-scored)
  Phase 4: Domain cascade seeds beam_swap when it converges
  Phase 5: Beam swap recovers plugboard
  Phase 6: Validation: 0 excluded bigrams AND >30% quadgram density

Wasteful combinations avoided (from benchmark):
  - CRT ring decomposition: fails on short messages (0% success)
  - Greedy swap: fails on >3 plugboard pairs (40% overall)
  - Hyperchart: converges to wrong involution (0% success)
  - Circular projection: fails on no-plug and heavy-plug (20% success)
  - Bidirectional score: fails on heavy plugboard (80%, but 0% at 10 pairs)

Key insight: beam_swap is powerful enough to make ANY trajectory look
like valid German on short messages. The quadgram density discriminator
catches these false positives — correct German has 70-80% valid quadgrams
while beam_swap-invented text has <30%.
""")
