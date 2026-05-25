# Adelic CRT-Diagonal Hyperchart: Development Notes

## Architecture

33 manifolds, each its own CRT basis, interfering diagonally via Gold codes.

### Manifold Structure
- 7 structural: combo(60), refl(3), pos_L(26), pos_M(26), pos_R(26), ring_M(26), ring_R(26)
- 26 plugboard: P(A)(26), P(B)(26), ..., P(Z)(26)
- Each stores state as belief vector decomposed across prime bases
- Size 26 → {mod-2, mod-13} lanes; Size 60 → {mod-4, mod-3, mod-5} lanes

### Gold Code Interference (Layer 1: Manifold Identity)
- n=5 Gold codes: length 31, family size 33 (exactly our manifold count)
- Auto-correlation: 31 (full self-extraction)
- Cross-correlation: bounded [-7, +9] (controlled diagonal leak)
- Each manifold spreads its state into shared interference space using its unique code
- Cross-correlation IS the diagonal information flow between manifolds

### Gold Code Layer 2: Value Codes (Parallel Evaluation)
- Second Gold code family spreads ALL possible values simultaneously
- 26 values × 26 codes → one shared signal
- Extract winner via correlation (no sequential sweep needed)
- Verified: 4x signal-to-noise ratio (208 correct vs 48.8 noise)
- Enables: 60 combos × 26 positions = 1560 parallel evaluations

### Per-Position Signal Encoding
Every position t in the message produces signals:
- c_t: ciphertext letter (fixed data)
- E_t(c_t): no-plug decryption (structural manifolds determine this)
- P(c_t): plugboard on ciphertext (plug manifold for c_t)
- E_t(P(c_t)): trajectory applied to plugged ciphertext
- P(E_t(P(c_t))): full decryption (two plug manifolds involved)
- bigram_valid: is (dec[t-1], dec[t]) in BIGRAMS_OBSERVED?
- trigram_valid: is bigram-of-bigram transition valid?

All signals Gold-coded into interference space independently.
L=174 positions × 7 transforms = ~1200 simultaneous signals.

### Coherence Metric
- Total coherence = Σ (1 × bigram_valid + 3 × trigram_valid) over all positions
- VERIFIED WORKING:
  - Correct trajectory: coherence = 208 (55/57 bigrams, 51/55 trigrams)
  - Best wrong trajectory at any position: coherence ≤ 81
  - Only 2/17,576 positions exceed coherence 100 for correct combo
  - 4x gap between correct and best wrong → perfect discrimination

### Involution Constraint (Plugboard)
- P(a) = b ⟹ P(b) = a
- Enforced via Sinkhorn projection on joint 26×26 matrix → doubly-stochastic
- Decomposes back to per-letter manifold beliefs after projection

## Key Findings

### The Enigma During a Message is S¹ + Kicks
- Right rotor: active oscillator, cycles every 26 steps (the "circle")
- Middle rotor: 4-12 discrete kicks per message (perturbations)
- Left rotor: 0-1 steps, effectively STATIC (configuration, not dynamics)
- Plugboard: STATIC throughout message (boundary condition)
- Period-26 structure is the dominant signal

### Coherence Perfectly Discriminates (No-Plugboard Case)
- Full sweep of correct combo: best coherence at exact correct position
- Wrong combos: max coherence ~79 (across ALL positions sampled)
- Correct combo at correct position: coherence 208
- GAP: 208 vs 79 = definitive separation

### IC Cannot Discriminate With Heavy Plugboard
- With 10-pair plugboard: IC at correct position ≈ 0.042 (barely above random 0.038)
- No-plug bigram analysis makes wrong trajectories look BETTER than correct
- The plugboard scrambles all frequency-based signals
- Only per-position n-gram validity (the anti-set structure) discriminates

### Exploration is the Bottleneck (Not Scoring)
- Full sweep: 11.2s per combo × 60 combos = ~11 minutes
- Sampled sweep (stride-6): misses correct position (9 between 6 and 12)
- Need: efficient exploration that hits the sharp peak
- Solution: dual Gold code layer for parallel evaluation

## Implementation Status

### Working
- [x] Gold code generation (n=5, family 33, verified cross-correlation [-7,+9])
- [x] Per-position signal computation (all intermediate values)
- [x] Coherence metric (perfectly discriminates correct from wrong)
- [x] Dual Gold code layer (parallel value evaluation, 4x SNR verified)
- [x] Sinkhorn plugboard projection
- [x] Prime-base vector decomposition

### Needs Implementation
- [ ] Wire dual Gold code into main loop (parallel combo×position evaluation)
- [ ] Adaptive exploration: start coarse, refine where coherence is high
- [ ] Multi-message coupling: shared plug/ring/combo manifolds across messages
- [ ] FEC between layers: detect/correct when cross-correlation introduces error
- [ ] Pre-computed rotor differential fingerprints as prior on combo manifold

## Theoretical Basis

Based on:
- **SAMR** (Sierpiński-Adelic Mixed-Radix): mixed-radix odometer with tail-first causality
- **HOCF** (Hybrid Orthogonality Constraint Formalism): orthogonality-driven constraints with CRT-scalable enforcement
- **P-adic Circle Formalism**: exact integer representation via adelic encoding
- **Dynamical State Entropy**: anti-set exclusory structure (bigram exclusions = the anti-manifold that collapses key space)
- **Gold codes**: CDMA-like separation with controlled cross-talk for diagonal interference

## Performance Targets
- No-plugboard message (58 chars): should solve in <30s
- 10-pair plugboard (174 chars, Barbarossa): should solve in <5min
- Multiple same-day messages: coupling should accelerate by ~Nx for N messages
