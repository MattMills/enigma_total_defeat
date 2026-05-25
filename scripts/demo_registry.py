#!/usr/bin/env python3
"""Demo: exercise every registered technique via synthetic scenarios.

Shows the registry infrastructure in action — creates test scenarios
with known ground truth, runs each technique, and reports results.
"""

from __future__ import annotations

import sys
import time

sys.path.insert(0, ".")

from enigma.language import LanguageModel
from enigma.registry import REGISTRY, Domain
from enigma.scenarios import (
    scenario_no_plugboard,
    scenario_light_plugboard,
    scenario_medium_plugboard,
    scenario_heavy_plugboard,
    scenario_with_rings,
    scenario_m4,
    scenario_short_message,
    scenario_multi_message,
    wrong_trajectory,
)

model = LanguageModel.german_military()


def header(text):
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}")


def subheader(text):
    print(f"\n--- {text} ---")


def timed(fn, *args, **kwargs):
    t0 = time.time()
    result = fn(*args, **kwargs)
    elapsed = time.time() - t0
    return result, elapsed


# ==================================================================
header("REGISTRY OVERVIEW")
# ==================================================================

print(f"\nTotal techniques registered: {len(REGISTRY)}")
print()
for domain in Domain:
    techniques = REGISTRY.list_by_domain(domain)
    names = [t.name for t in techniques]
    print(f"  {domain.value:20s} ({len(techniques):2d}): {', '.join(names)}")


# ==================================================================
header("SCENARIO GENERATION")
# ==================================================================

s = scenario_no_plugboard()
print(f"\nScenario: {s.name}")
print(f"  Plaintext:  {s.plaintext[:60]}...")
print(f"  Ciphertext: {s.ciphertext_str[:60]}...")
print(f"  Rotors:     {'-'.join(s.rotor_names)} / {s.reflector_name}")
print(f"  Position:   {''.join(chr(p+65) for p in s.positions)}")
print(f"  Rings:      {''.join(chr(r+65) for r in s.ring_settings)}")
print(f"  Plugboard:  {' '.join(s.plugboard_pairs) or '(none)'}")
print(f"  Length:     {len(s.cipher)} chars")

# Verify roundtrip
dec = []
for t in range(len(s.cipher)):
    c = s.cipher[t]
    p_c = s.plugboard_map[c]
    d = s.trajectory[t][p_c]
    p = s.plugboard_map[d]
    dec.append(p)
recovered = "".join(chr(d + 65) for d in dec)
print(f"  Roundtrip:  {'PASS' if recovered == s.plaintext else 'FAIL'}")


# ==================================================================
header("DOMAIN: ROTOR IDENTIFICATION")
# ==================================================================

subheader("spectral_rotor_id")
t_spectral = REGISTRY.get("spectral_rotor_id")
print(f"  Description: {t_spectral.description}")
results, elapsed = timed(t_spectral, s.cipher, s.reflector_name)
print(f"  Ranking (correlation with ciphertext differential profile):")
for name, corr in results:
    marker = " <-- correct" if name == s.rotor_names[2] else ""
    print(f"    {name:5s}  corr={corr:+.4f}{marker}")
print(f"  Time: {elapsed:.3f}s")

subheader("spectral_signature")
t_sig = REGISTRY.get("spectral_signature")
sig = t_sig("V", "B")
print(f"  Rotor V signature:")
print(f"    Cycle structure: {sig.cycle_lengths}")
print(f"    Fixed points:    {sig.fixed_points}")
print(f"    Order:           {sig.order}")
print(f"    Diff profile:    [{', '.join(f'{d:.1f}' for d in sig.differential_profile[:8])}...]")

subheader("circular_rotor_id")
t_circ = REGISTRY.get("circular_rotor_id")
results, elapsed = timed(t_circ, s.ciphertext_str)
print(f"  Circular projection attack (R^676 orbit space):")
for r in results:
    marker = " <-- correct" if r.right_rotor == s.rotor_names[2] else ""
    print(f"    {r.right_rotor:5s}  best_pos={chr(r.best_position+65)}  corr={r.correlation:.2f}{marker}")
print(f"  Time: {elapsed:.3f}s")


# ==================================================================
header("DOMAIN: POSITION SEARCH")
# ==================================================================

subheader("inline_ic_sweep")
t_ic = REGISTRY.get("inline_ic_sweep")
results, elapsed = timed(t_ic, s.cipher, s.rotor_names, s.reflector_name, s.ring_settings, top_k=10)
print(f"  Top 10 positions by IC (plugboard-invariant):")
for ic, pos in results[:10]:
    pos_str = "".join(chr(p + 65) for p in pos)
    marker = " <-- correct" if pos == s.positions else ""
    print(f"    {pos_str}  IC={ic:.4f}{marker}")
correct_rank = next((i for i, (_, p) in enumerate(results) if p == s.positions), -1)
print(f"  Correct position rank: {correct_rank + 1} of {len(results)}")
print(f"  Time: {elapsed:.3f}s")


# ==================================================================
header("DOMAIN: TRAJECTORY SCORING")
# ==================================================================

correct_traj = s.trajectory
wrong_traj = wrong_trajectory(s)

subheader("superposition_filter")
t_super = REGISTRY.get("superposition_filter")
res_correct, _ = timed(t_super, s.cipher, correct_traj, model)
res_wrong, _ = timed(t_super, s.cipher, wrong_traj, model)
print(f"  Correct trajectory survives: {res_correct}")
print(f"  Wrong trajectory survives:   {res_wrong}")

subheader("superposition_collapse (seed=E at position 0)")
t_collapse = REGISTRY.get("superposition_collapse")
result, elapsed = timed(t_collapse, s.cipher, correct_traj, model, seed_letter=4, seed_position=0)
print(f"  Consistent: {result.consistent}")
print(f"  Plug entries determined: {result.n_plug_determined}")
print(f"  Plaintext positions determined: {result.n_pt_determined}/{len(s.cipher)}")
if result.n_pt_determined > 0:
    print(f"  Partial plaintext: {result.plaintext_str()[:60]}")
print(f"  Time: {elapsed:.3f}s")

subheader("validation_discriminator")
t_val = REGISTRY.get("validation_discriminator")
correct_dec = [ord(c) - 65 for c in s.plaintext]
wrong_dec_id = [correct_traj[t][s.cipher[t]] for t in range(len(s.cipher))]
n_correct = t_val(correct_dec, model)
n_wrong = t_val(wrong_dec_id, model)
print(f"  Correct decryption: {n_correct} excluded bigrams (0 = correct)")
print(f"  Identity decrypt:   {n_wrong} excluded bigrams")

subheader("ngram_counter")
t_ngram = REGISTRY.get("ngram_counter")
counts_correct = t_ngram(correct_dec)
counts_wrong = t_ngram(wrong_dec_id)
print(f"  Correct: bigrams={counts_correct['bigrams']}, trigrams={counts_correct['trigrams']}, quadgrams={counts_correct['quadgrams']}")
print(f"  Wrong:   bigrams={counts_wrong['bigrams']}, trigrams={counts_wrong['trigrams']}, quadgrams={counts_wrong['quadgrams']}")


# ==================================================================
header("DOMAIN: PLUGBOARD RECOVERY")
# ==================================================================

s_plug = scenario_light_plugboard()
print(f"\nUsing scenario: {s_plug.name}")
print(f"  Plugboard: {' '.join(s_plug.plugboard_pairs)}")
print(f"  Plaintext: {s_plug.plaintext[:50]}...")

subheader("beam_swap (primary method)")
t_beam = REGISTRY.get("beam_swap")
(score, plug, dec), elapsed = timed(
    t_beam, s_plug.cipher, s_plug.trajectory, model, rounds=8, beam_width=50
)
plaintext = "".join(chr(d + 65) for d in dec)
pairs = [(a, plug[a]) for a in range(26) if plug[a] > a]
print(f"  Recovered plugboard: {' '.join(chr(a+65)+chr(b+65) for a,b in pairs)}")
print(f"  Plaintext match: {plaintext == s_plug.plaintext}")
print(f"  Score: {score:.3f}")
print(f"  Decrypted: {plaintext[:50]}...")
print(f"  Time: {elapsed:.3f}s")

subheader("greedy_swap")
t_greedy = REGISTRY.get("greedy_swap")
(score, plug), elapsed = timed(t_greedy, s_plug.cipher, s_plug.trajectory, model)
pairs = [(a, plug[a]) for a in range(26) if plug[a] > a]
dec = [plug[s_plug.trajectory[t][plug[s_plug.cipher[t]]]] for t in range(len(s_plug.cipher))]
plaintext = "".join(chr(d + 65) for d in dec)
print(f"  Recovered pairs: {' '.join(chr(a+65)+chr(b+65) for a,b in pairs)}")
print(f"  Plaintext match: {plaintext == s_plug.plaintext}")
print(f"  Time: {elapsed:.3f}s")

subheader("domain_cascade")
t_dc = REGISTRY.get("domain_cascade")
results, elapsed = timed(t_dc, s_plug.cipher, s_plug.trajectory, model)
print(f"  Survivors: {len(results)}")
if results:
    dp, pt = results[0]
    avg_domain = sum(len(d) for d in dp.domains) / 26
    n_det = dp.n_determined()
    print(f"  Best survivor: {n_det}/26 letters determined, avg domain size={avg_domain:.1f}")
    print(f"  Determined pairs: {dp.pairs()}")
print(f"  Time: {elapsed:.3f}s")

subheader("hyperchart (Birkhoff polytope, 30 iterations)")
t_hyper = REGISTRY.get("hyperchart")
result, elapsed = timed(t_hyper, s_plug.cipher, s_plug.trajectory, model, iterations=30)
print(f"  Convergence: {result.convergence[0]:.3f} -> {result.convergence[-1]:.3f}")
print(f"  Pairs found: {' '.join(chr(a+65)+chr(b+65) for a,b in result.plugboard_pairs)}")
print(f"  Score: {result.score:.3f}")
print(f"  Time: {elapsed:.3f}s")

subheader("unwind_bidirectional (5 positions from each end)")
t_unwind = REGISTRY.get("unwind_bidirectional")
paths, elapsed = timed(t_unwind, s_plug.cipher, s_plug.trajectory, model, beam_width=200, n_positions=5)
print(f"  Paths found: {len(paths)}")
if paths:
    best = paths[0]
    print(f"  Best: {len(best.plug)} plug entries, score={best.score:.3f}")
print(f"  Time: {elapsed:.3f}s")

subheader("signed_propagation")
t_prop = REGISTRY.get("signed_propagation")
(prop, consistent), elapsed = timed(t_prop, s_plug.cipher, s_plug.trajectory, model)
print(f"  Consistent: {consistent}")
print(f"  {prop.summary()}")
print(f"  Determined plug pairs: {prop.plug_pairs()}")
print(f"  Time: {elapsed:.3f}s")

subheader("arc_consistency (from correct decryption)")
from enigma.attack import initialize_candidates, propagate_bigrams
candidates = initialize_candidates(s_plug.cipher)
candidates = propagate_bigrams(candidates, model)
correct_dec = [ord(c) - 65 for c in s_plug.plaintext]
t_arc = REGISTRY.get("arc_consistency")
solver, elapsed = timed(t_arc, correct_dec, candidates)
print(f"  Consistent: {solver.is_consistent()}")
print(f"  Determined: {solver.is_determined()}")
print(f"  Ambiguity: {solver.ambiguity()}")
print(f"  Pairs: {solver.get_pairs()}")
print(f"  Time: {elapsed:.3f}s")


# ==================================================================
header("DOMAIN: RING RECOVERY")
# ==================================================================

s_ring = scenario_with_rings()
print(f"\nUsing scenario: {s_ring.name}")
print(f"  True ring: {''.join(chr(r+65) for r in s_ring.ring_settings)} (right ring = {s_ring.ring_settings[2]})")

subheader("turnover_ring_refine (brute force 26 right-ring values)")
t_ring = REGISTRY.get("turnover_ring_refine")
(rings, score), elapsed = timed(
    t_ring, s_ring.cipher, s_ring.rotor_names, s_ring.reflector_name,
    s_ring.positions, model,
)
print(f"  Found ring: {''.join(chr(r+65) for r in rings)} (right ring = {rings[2]})")
print(f"  Correct: {rings[2] == s_ring.ring_settings[2]}")
print(f"  Score: {score:.3f}")
print(f"  Time: {elapsed:.3f}s")

subheader("crt_ring_refine (CRT decomposition: 26 = 2 x 13)")
t_crt = REGISTRY.get("crt_ring_refine")
(rings, score), elapsed = timed(
    t_crt, s_ring.cipher, s_ring.rotor_names, s_ring.reflector_name,
    s_ring.positions, model,
)
print(f"  Found ring: {''.join(chr(r+65) for r in rings)} (right ring = {rings[2]})")
print(f"  Correct: {rings[2] == s_ring.ring_settings[2]}")
print(f"  Time: {elapsed:.3f}s")


# ==================================================================
header("DOMAIN: CACHING")
# ==================================================================

subheader("topology_fingerprint")
t_fp = REGISTRY.get("topology_fingerprint")
fp = t_fp(s.trajectory)
print(f"  Fingerprint: {fp}")
fp2 = t_fp(wrong_trajectory(s))
print(f"  Wrong traj:  {fp2}")
print(f"  Different:   {fp != fp2}")

subheader("topology_cache_build + topology_cache_match")
t_build = REGISTRY.get("topology_cache_build")
cache, elapsed = timed(t_build)
print(f"  Cache entries: {len(cache.entries)}")
print(f"  Rotor triples: {len(cache.differential_cache)}")
print(f"  Build time: {elapsed:.3f}s")

t_match = REGISTRY.get("topology_cache_match")
results, elapsed = timed(t_match, cache, s.cipher, model, top_k=3)
if results:
    score, entry, dec = results[0]
    print(f"  Best match: {'-'.join(entry.rotor_names)}/{entry.reflector_name} "
          f"pos={''.join(chr(p+65) for p in entry.positions)} score={score:.3f}")
print(f"  Match time: {elapsed:.3f}s")


# ==================================================================
header("DOMAIN: MULTI-MESSAGE")
# ==================================================================

msgs = scenario_multi_message()
print(f"\n{len(msgs)} messages with shared day key:")
for m in msgs:
    print(f"  {m.name}: pos={''.join(chr(p+65) for p in m.positions)} len={len(m.cipher)}")

subheader("coupled_hyperchart (30 iterations)")
t_coupled = REGISTRY.get("coupled_hyperchart")
result, elapsed = timed(
    t_coupled,
    [m.cipher for m in msgs],
    msgs[0].rotor_names,
    msgs[0].reflector_name,
    [m.positions for m in msgs],
    msgs[0].ring_settings,
    model,
    iterations=30,
)
print(f"  Coupling score: {result.coupling_score:.2f}")
print(f"  Pairs found: {' '.join(chr(a+65)+chr(b+65) for a,b in result.plugboard_pairs)}")
print(f"  True pairs:  {' '.join(msgs[0].plugboard_pairs)}")
for i, pm in enumerate(result.per_message):
    print(f"  Message {i+1}: excl_bg={pm['n_excluded_bigrams']} score={pm['score']:.3f} "
          f"text={pm['plaintext'][:30]}...")
print(f"  Time: {elapsed:.3f}s")


# ==================================================================
header("DOMAIN: FULL SOLVE (known trajectory)")
# ==================================================================

s_heavy = scenario_heavy_plugboard()
print(f"\nUsing scenario: {s_heavy.name}")
print(f"  10-pair plugboard, {len(s_heavy.cipher)} chars")

subheader("pipeline_known_trajectory")
t_pipe = REGISTRY.get("pipeline_known_trajectory")
result, elapsed = timed(
    t_pipe,
    s_heavy.ciphertext_str, s_heavy.rotor_names, s_heavy.reflector_name,
    s_heavy.positions, s_heavy.ring_settings,
    beam_rounds=10, beam_width=50,
)
print(f"  Stages used: {result.stages_used}")
print(f"  Score: {result.score:.3f}")
print(f"  Excluded bigrams: {result.n_excluded_bigrams}")
print(f"  Plug pairs: {result.plug_str}")
print(f"  Plaintext match: {result.plaintext == s_heavy.plaintext}")
print(f"  Decrypted: {result.plaintext[:60]}...")
print(f"  Time: {elapsed:.3f}s")


# ==================================================================
header("M4 FOUR-ROTOR SUPPORT")
# ==================================================================

s_m4 = scenario_m4()
print(f"\nUsing scenario: {s_m4.name}")
print(f"  Rotors: Beta-{'-'.join(s_m4.rotor_names)} / {s_m4.reflector_name}")
print(f"  4th rotor: {s_m4.fourth_rotor_name} at position {chr(s_m4.fourth_position+65)}")

t_pipe = REGISTRY.get("pipeline_known_trajectory")
result, elapsed = timed(
    t_pipe,
    s_m4.ciphertext_str, s_m4.rotor_names, s_m4.reflector_name,
    s_m4.positions, s_m4.ring_settings,
    fourth_rotor_name=s_m4.fourth_rotor_name,
    fourth_position=s_m4.fourth_position,
    fourth_ring=s_m4.fourth_ring,
    beam_rounds=8, beam_width=50,
)
print(f"  Stages: {result.stages_used}")
print(f"  Match: {result.plaintext == s_m4.plaintext}")
print(f"  Decrypted: {result.plaintext[:50]}...")
print(f"  Time: {elapsed:.3f}s")


# ==================================================================
header("SUMMARY")
# ==================================================================

print(f"\nAll {len(REGISTRY)} techniques demonstrated across {len(Domain)} domains.")
print(f"Every technique is individually testable via: pytest tests/test_registry.py")
print(f"No dead code remains — all modules are exercised through the registry.")
