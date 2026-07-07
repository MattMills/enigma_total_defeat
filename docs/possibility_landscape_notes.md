# Possibility Landscape — resolving rotors from operative geometry

Step one (`enigma/schematic.py`) exposes the operative geometry `E`: the
plugboard-independent rotor+reflector permutation at each step. Step two
(`enigma/landscape.py`) inverts it — given evidence about `E`, which rotor
configuration produced it?

All numbers below are produced by, and re-checked against, the simulator in
this repo. Reproduce with `scripts/landscape.py`.

## 1. The core algebraic structure

The operative geometry factors exactly as

```
    E = W⁻¹ · U · W
```

where `U` is the reflector and `W` is the **forward rotor stack** (the
signal's path in through right → middle → left, before the reflector).
Each rotor at offset `o` contributes `ρ⁻ᵒ · wiring · ρᵒ` (a rotation
conjugate of its wiring), so

```
    W(o_L,o_M,o_R) = (ρ⁻ᵒᴸ L ρᵒᴸ) ∘ (ρ⁻ᵒᴹ M ρᵒᴹ) ∘ (ρ⁻ᵒᴿ R ρᵒᴿ)
```

Consequences:

- `E` is a **fixed-point-free involution** for free: conjugating the
  reflector (already a fixed-point-free involution) can never change that.
  This is *why* Enigma can't encipher a letter to itself.
- The right rotor sits on the outside of the conjugation, so advancing it by
  one (every keypress) re-conjugates the whole cascade: **one step changes
  ~all 26 entries of `E`.** There is no locally-stable topology; the geometry
  is globally reshuffled per letter. (`geometry_differential` measures this —
  it reads ~26 every step.)

### Storage factorisation

Because the right rotor is the outermost conjugation, at fixed `(o_L,o_M)`
all 26 geometries share one inner block:

```
    E(o_R) = A(o_R)⁻¹ · Q(o_L,o_M) · A(o_R),   A(o_R) = ρ⁻ᵒᴿ R ρᵒᴿ
```

Verified: the 26 right-rotor geometries reconstruct exactly from a single
stored `Q`. So the landscape needs **26² inner blocks per (triple,
reflector)**, not 26³ — a 26× reduction, with the right-rotor variants
derived on the fly.

## 2. Injectivity — one full geometry resolves the rotors

Enumerating **all 1,054,560** M3 configs (60 rotor orders × 26³ offsets,
reflector B):

| configs | distinct `E` | collisions |
|--------:|-------------:|-----------:|
| 1,054,560 | 1,054,560 | 0 |

`config → E` is **injective**. A single fully-observed operative geometry
pins the rotor order *and* the three offsets exactly — an O(1) dictionary
lookup (`RotorLandscape.resolve_geometry`).

## 3. But you never observe a full `E`

Each keypress advances the right rotor, so consecutive letters are enciphered
by *different* geometries `E₀, E₁, …`. Live operation yields exactly **one
cell per step**, `Eₜ(pₜ) = cₜ` — and with a plugboard even that cell is
masked to `P(Eₜ(P(pₜ)))`.

So resolution from traffic is a *trajectory match*, not a lookup. With known
plaintext and no plugboard, each crib letter is a ~1/26 filter on the config
space:

| crib length k | surviving configs |
|--------------:|------------------:|
| 1 | 42,172 |
| 2 | 1,617 |
| 3 | 69 |
| 4 | 2 |
| 5 | **1** |

**~5 known-plaintext letters uniquely resolve the rotor configuration**
(order + offsets). See `resolve_crib` / `resolution_curve`.

## 4. Honest scope

- **Ring vs. position.** The instantaneous `E` depends only on
  `offset = position − ring`, so it resolves *offsets*, not absolute rings.
  The ring is invisible until a **turnover** happens inside the observed
  window (the notch fires on absolute position). A crib spanning a middle-
  rotor turnover separates them; one that doesn't leaves a ring degeneracy.
- **Plugboard.** The landscape collapses the *rotor* search. It does not read
  plugboard-enciphered traffic on its own — each crib cell is masked, and the
  ~10-pair Steckerbrett must be solved jointly (the job of the existing
  beam-search / hyperchart code). The value is decomposition: an intractable
  joint (rotor × plugboard) search becomes rotor lookup, then a much smaller
  plugboard solve.

## 5. M4 is a *small* addition, not a bigger table

The Kriegsmarine M4 adds a Greek 4th wheel (Beta/Gamma) and a thin reflector
(B-thin/C-thin) inboard of the stack. **Neither steps during a message**, so
they fold into a single effective reflector `U' = G⁻¹ · U_thin · G` that is
*constant* for the whole message. From the three stepping rotors' point of
view, an M4 is just an M3 with one of **104** fixed reflectors (2 greek × 2
thin × 26 greek offsets). Historically this is exactly why **Beta @ A +
B-thin reproduces UKW-B** and Gamma @ A + C-thin reproduces UKW-C — M4 was
backward compatible with M3 (both verified in `enigma/landscape_m4.py`).

Consequently there is **no large M4 dataset**. The geometry law
`E = W⁻¹ · U' · W` is generative:

| what | size |
|------|------|
| new wirings over M3 (VI, VII, VIII, Beta, Gamma, B-thin, C-thin) | ~182 bytes |
| 104 effective reflectors (derived in ~1 ms; cached) | ~2.7 KB |
| flat `(triple, offset, reflector) → E` table | ~9.8 GB — **not built** |

Resolution uses the conjugation `W · E · W⁻¹ = U'`: scan `(triple, offsets)`,
test whether the conjugate is one of the 104 reflectors, and read off the
entire 4-rotor config (rotors, offsets, Greek wheel, thin reflector, Greek
offset) — no stored table. The flat table would only cache an already-cheap
function, so it is deliberately avoided; slice serialization exists purely as
an optional interchange format.
