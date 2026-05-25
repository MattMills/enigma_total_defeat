# Audit: Uncommitted/Unused Techniques in Enigma Total Defeat

## Techniques Demonstrated Working but NOT Integrated into crack.py

### 1. IC Filter (Trajectory Pre-Screening)
- **What:** Index of Coincidence scoring to rank 17,576 positions
- **Result:** Correct trajectory ranks in top 3% (rank ~529 of 17,576)
- **Module:** `enigma/attack.py` — `_sorted_chi_squared()` and `attack_with_plugboard()` exist but are NEVER CALLED
- **Issue:** Takes 31s for 174-char message, exceeds time budget

### 2. Superposition Solver (Trajectory Rejection)
- **What:** Seeds from position 0, cascades via cipher equation, rejects inconsistent trajectories
- **Result:** Rejects 59% of wrong trajectories, correct trajectory always survives
- **Module:** `enigma/superposition.py` — `try_collapse()`, `CollapseResult` exist but NEVER IMPORTED by any script
- **Issue:** The `try_collapse` greedy branching is too permissive — needs the binary discriminator (0 excluded bigrams = correct)

### 3. Domain Cascade with Differential
- **What:** Per-letter plugboard domains (sets of possible values), narrowed by differential analysis across all positions sharing a ciphertext letter, plus involution enforcement
- **Result:** Narrows 602 seeds to 1 correct-compatible. Domains go from 26 to ~20-23. Only 1 of 602 seeds is compatible with the true plugboard.
- **Module:** `enigma/crack.py` — `DomainPlug`, `crack_trajectory()`, `_cascade()` exist but NEVER CALLED from any script
- **Key insight verified:** With correct plaintext known, plugboard fully determined by position 17. Only 5 "free" positions need branching; rest have x forced by previously-touched letters.

### 4. Per-Pair Coherence Scoring
- **What:** Score each plugboard pair by bigram quality at positions where that pair interacts with the cipher equation
- **Result:** Wrong pairs (DX, LZ) score -4.3 and 0.0; correct pairs score -1.7 to -3.5. Cleanly separates wrong from correct.
- **Module:** NOT in any module — only demonstrated in console
- **Console command was:** compute interaction_score per pair, sort, remove worst pairs

### 5. Combinatorial Completion Search
- **What:** Given N correct pairs, search for remaining pairs from freed letters using proper perfect-matching enumeration
- **Result:** With 7 correct pairs, finds DL HZ RX as #1 of 3,328 candidates
- **Module:** NOT in any module — the `_perfect_matchings()` and `all_pairings()` functions were in `crack_barbarossa.py` which was DELETED
- **Critical bug found and fixed:** Original `gen_pairings()` was broken (forced sequential selection, couldn't skip unpaired letters). Fixed version uses `combinations()` + `_perfect_matchings()`.

### 6. Beam Swap with N-gram Symbol Scoring
- **What:** Beam search on swap+unpair operator space, scored by n-gram validity (bigram-of-bigrams, trigram-of-trigrams)
- **Result:** 10/10 plugboard from IDENTITY in 9.8s on Barbarossa-1
- **Module:** `enigma/attack.py` — `beam_swap_search()` — THIS IS THE ONLY TECHNIQUE ACTIVELY USED
- **Used by:** `scripts/crack.py`, `scripts/run_attack.py`

### 7. Spectral Rotor Signatures
- **What:** Each rotor has unique algebraic signature (cycle structure, order, differential profile)
- **Result:** Rotor I order=60, II order=168, VII order=26 (unique signatures). Identification weak on <200 char texts.
- **Module:** `enigma/spectral.py` — `RotorSignature`, `identify_right_rotor()` exist but NEVER IMPORTED

### 8. Topology Cache
- **What:** Pre-computed trajectory fingerprints for known day-keys. Cache hit = O(1) lookup vs O(26³) search.
- **Result:** 8,777× speedup on cached lookups (1ms vs 8.8s)
- **Module:** `enigma/topology.py` — `TopologyCache`, `build_cache_from_messages()` exist but NEVER IMPORTED by any script

### 9. Circular/Bidirectional Constraint Propagation
- **What:** Forward + backward bigram constraints propagate simultaneously along the trajectory
- **Result:** Bidirectional correctly identifies wrong trajectories via excluded bigrams at both ends
- **Module:** `enigma/circular.py` — `bidirectional_score()`, `bidirectional_attack()` exist but NEVER IMPORTED

### 10. Hyperchart Solver (Birkhoff Polytope)
- **What:** Plugboard as doubly-stochastic matrix, temperature-annealed multi-peak ascent
- **Result:** Discriminates correct trajectory (finite score) from wrong (−∞). Plugboard convergence needs work.
- **Module:** `enigma/hyperchart.py` — `solve_hyperchart()`, `hyperchart_attack()` exist but NEVER IMPORTED

### 11. Unwind Module
- **What:** Sequential forward/backward constraint unwinding with beam search
- **Result:** Framework correct but beam scoring (unigram) prunes correct path
- **Module:** `enigma/unwind.py` — `unwind_forward()`, `unwind_backward()`, `unwind_bidirectional()` exist but NEVER IMPORTED

### 12. Binary Discriminator (0 Excluded Bigrams = Correct)
- **What:** Correct plugboard produces 0 excluded bigrams in decrypted text. Every wrong plugboard produces 1-5.
- **Result:** Perfect binary discrimination confirmed on Barbarossa-1
- **Module:** NOT in any module — only demonstrated in console. The n-gram tables (`ngram_data.py`) capture this but no function implements the binary check.

### 13. CRT Ring Setting Search
- **What:** Decompose 26 = 2 × 13 for ring settings. Test mod-2 and mod-13 independently, CRT combine.
- **Result:** 15 trials instead of 26 for right ring setting
- **Module:** `enigma/solver.py` — `crt()`, `crt_multi()`, `refine_ring_from_turnover()` exist but NEVER CALLED from any script

### 14. Plugboard Constraint Solver (Arc Consistency)
- **What:** Given no-plugboard decryption and per-position candidate sets, enforce P(d[t]) ∈ C[t] with involution propagation
- **Result:** Framework correct but candidate sets too loose (20-25 per position) for effective narrowing
- **Module:** `enigma/solver.py` — `PlugboardSolver` class exists but NEVER CALLED from crack.py

---

## The Correct Pipeline (Topologically Enclosing)

Each stage narrows the space for the next. NOT multiplicative — each constraint ENCLOSES:

```
Ciphertext (L chars)
    ↓
[Spectral] Identify candidate right rotors → 5→2 rotors
    ↓
[IC Filter] Rank positions → 17,576 → ~500 survivors (top 3%)
    ↓
[Superposition] Reject inconsistent trajectories → 500 → ~200 (59% killed)
    ↓
[Domain Cascade] Narrow plugboard domains → 200 → ~1 compatible seed
    ↓
[Beam Swap] Recover plugboard with n-gram scoring → 10/10 pairs
    ↓
[Coherence + Completion] Validate pairs, fix remaining → verified plaintext
```

Currently only the beam swap step is active. All others exist as code but are not wired into the pipeline.

## Key Numbers to Remember

- 602 seeds from position 0, exactly 1 correct-compatible
- Plugboard fully determined by position 17 (with known plaintext)
- Only 5 "free" positions need branching; rest have x forced
- Average 3.6 successors per bigram symbol (branching factor)
- 93% of trigrams exclusory, 99% of quadgrams exclusory
- Binary discriminator: 0 excluded bigrams = correct, 1-5 = wrong
- Beam swap from identity: 10/10 in 9.8s (Barbarossa-1)
- Beam swap from 7/10: 10/10 in 2.3s
- IC filter: correct trajectory at rank 529 of 17,576

## Files That Exist but Are Dead Code

| Module | Functions | Status |
|--------|-----------|--------|
| `superposition.py` | `try_collapse`, `collapse_attack` | Never imported |
| `crack.py` | `DomainPlug`, `crack_trajectory`, `_cascade` | Never called |
| `circular.py` | `bidirectional_score`, `bidirectional_attack`, `RotorOrbit` | Never imported |
| `spectral.py` | `RotorSignature`, `identify_right_rotor` | Never imported |
| `hyperchart.py` | `solve_hyperchart`, `hyperchart_attack` | Never imported |
| `unwind.py` | `unwind_forward`, `unwind_backward`, `unwind_bidirectional` | Never imported |
| `topology.py` | `TopologyCache`, `build_cache_from_messages` | Never imported |
| `solver.py` | `PlugboardSolver`, `progressive_solve`, `crt` | Never called from scripts |
| `attack.py` | `attack_with_plugboard`, `infer_plugboard` | Never called from scripts |
| `propagate.py` | `SignedPropagator`, `branch_and_prune` | Never called |
