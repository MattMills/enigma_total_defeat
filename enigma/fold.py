"""Fold/unfold the Enigma signal path through the reflector.

The Enigma's physical topology is FOLDED: the signal enters the rotor
stack, hits the reflector, and returns through the SAME rotors in
reverse. The reflector is the fold point — it turns the signal around.

FOLDED VIEW (physical reality):
  P → R → M → L → [4] → Ref → [4⁻¹] → L⁻¹ → M⁻¹ → R⁻¹ → P
  The signal traverses 7 layers (9 for M4), bouncing at the reflector.
  The same physical rotor appears twice (forward and inverse).

UNFOLDED VIEW (mathematical reality):
  The fold is opened out into a straight chain of 7 (or 9) DISTINCT
  permutations. The forward and inverse passes through each rotor are
  laid side by side. The reflector becomes a COUPLER connecting the
  two halves.

  Unfolded: P → R → M → L → [4] → Ref=coupler → [4⁻¹] → L⁻¹ → M⁻¹ → R⁻¹ → P

  But the crucial insight: in the unfolded view, each rotor-pair
  (R_fwd, R_inv) is NOT independent. They are the SAME permutation
  traversed in opposite directions. The reflector COUPLES them:
  it takes the output of the forward stack and feeds it as input
  to the inverse stack, with a fixed-point-free involution twist.

THE REFLECTOR'S TOPOLOGICAL EFFECT:

  Without the reflector, the forward stack R→M→L would be an arbitrary
  permutation σ ∈ S₂₆ (26! possibilities). The inverse stack L⁻¹→M⁻¹→R⁻¹
  would be σ⁻¹. Their composition σ⁻¹ ∘ σ = identity — useless.

  The reflector Rf inserts between them: σ⁻¹ ∘ Rf ∘ σ. This is a
  CONJUGATION of the reflector by the forward stack. Since Rf is a
  fixed-point-free involution, so is σ⁻¹ ∘ Rf ∘ σ. The reflector's
  involution property is PRESERVED through conjugation — this is why
  the complete machine is an involution at every position.

  The reflector's CYCLE STRUCTURE is also preserved: 13 disjoint
  2-cycles map to 13 disjoint 2-cycles, but the PAIRINGS change
  depending on σ (the forward stack at this position). Different
  positions have different σ (because the rotors stepped), so the
  13 pairings change at every position — but there are ALWAYS exactly
  13 pairings.

WHAT UNFOLDING EXPOSES:

  1. SYMMETRY CONSTRAINT: layers i and (n-1-i) in the unfolded path
     use the SAME rotor wiring. The forward pass determines the inverse.
     An attacker who deduces one half automatically knows the other.

  2. PAIRING PROPAGATION: the reflector's 13 pairs propagate through
     the rotor stack. At the reflector, letter a is paired with b.
     After passing through L⁻¹, the pair becomes (L⁻¹(a), L⁻¹(b)).
     After M⁻¹, it becomes (M⁻¹(L⁻¹(a)), M⁻¹(L⁻¹(b))). The 13
     pairs at the output are the reflector's pairs conjugated by σ⁻¹.

  3. OFFSET ALIGNMENT: in the unfolded view, layers i and (n-1-i) share
     the SAME offset (because it's the same rotor at the same position).
     This means the two halves are not independent permutations — they
     are mirror images with shared state.

  4. DEAD ZONE: the reflector occupies a single layer but determines the
     ENTIRE involution structure. Removing the reflector and replacing
     it with an arbitrary permutation would break the involution property
     and make the machine asymmetric (encrypt ≠ decrypt). The reflector
     is the topological constraint that makes Enigma Enigma.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from enigma.simulator import ROTORS, REFLECTORS, Plugboard


@dataclass
class UnfoldedLayer:
    """One layer in the unfolded signal path."""
    index: int
    name: str
    component: str
    direction: str  # "forward", "reflect", "inverse"
    offset: int
    wiring: tuple[int, ...]
    mirror_index: int  # index of the paired layer (-1 for reflector)
    signal_in: int
    signal_out: int
    # The signal value in the "inner" coordinate (before/after offset removal)
    inner_in: int
    inner_out: int


@dataclass
class FoldedPosition:
    """Signal path at one position, showing both folded and unfolded views."""
    t: int
    plaintext: int
    ciphertext: int
    offsets: tuple[int, int, int]  # oL, oM, oR
    fourth_offset: int

    # Folded: the physical signal path (layers indexed 0..N-1)
    folded_layers: list[UnfoldedLayer]

    # Unfolded: same layers but annotated with mirror structure
    # The reflector is at the center; layers i and (n-1-i) are mirrors
    fold_point: int  # index of the reflector layer

    # The reflector's 13 pairs at this position (in the outer coordinate)
    reflector_pairs_outer: list[tuple[int, int]]

    # The complete machine's 13 pairs (the operative geometry's 2-cycles)
    machine_pairs: list[tuple[int, int]]

    # How the reflector's pairs propagate through the inverse stack
    # pair_propagation[i] = the reflector pair after passing through layers fold+1..i
    pair_propagation: list[list[tuple[int, int]]]


@dataclass
class FoldTopology:
    """Complete fold/unfold analysis across all positions."""
    rotor_names: tuple[str, str, str]
    reflector_name: str
    ring_settings: tuple[int, int, int]
    start_positions: tuple[int, int, int]
    plugboard_pairs: list[str]
    fourth_rotor_name: str | None
    positions: list[FoldedPosition]

    def n_layers(self) -> int:
        if self.positions:
            return len(self.positions[0].folded_layers)
        return 0


def trace_fold(
    plaintext: str,
    rotor_names: tuple[str, str, str] = ("II", "IV", "V"),
    reflector_name: str = "B",
    positions: tuple[int, int, int] = (0, 0, 0),
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    plugboard_pairs: list[str] | None = None,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> FoldTopology:
    """Trace the signal path with explicit fold/unfold structure."""
    pairs_list = plugboard_pairs or []
    plug = Plugboard.from_pairs(pairs_list) if pairs_list else Plugboard()
    P = plug.mapping

    left = ROTORS[rotor_names[0]]
    middle = ROTORS[rotor_names[1]]
    right = ROTORS[rotor_names[2]]
    refl = REFLECTORS[reflector_name]

    has_fourth = fourth_rotor_name is not None
    if has_fourth:
        fourth = ROTORS[fourth_rotor_name]
        o4 = (fourth_position - fourth_ring) % 26
    else:
        fourth = None
        o4 = 0

    pL, pM, pR = positions
    rL, rM, rR = ring_settings

    plain_ints = [ord(c) - 65 for c in plaintext if "A" <= c <= "Z"]
    fold_positions: list[FoldedPosition] = []

    for t, p_letter in enumerate(plain_ints):
        # Stepping
        if pM in middle.notches:
            pL = (pL + 1) % 26
            pM = (pM + 1) % 26
        elif pR in right.notches:
            pM = (pM + 1) % 26
        pR = (pR + 1) % 26

        oL = (pL - rL) % 26
        oM = (pM - rM) % 26
        oR = (pR - rR) % 26

        layers: list[UnfoldedLayer] = []
        s = p_letter
        idx = 0

        # --- FORWARD HALF ---

        # Plugboard in
        s_out = P[s]
        layers.append(UnfoldedLayer(
            idx, "plug_in", "plugboard", "forward", 0,
            tuple(P), -1, s, s_out, s, s_out,
        ))
        s = s_out
        idx += 1

        # Right forward
        s_off = (s + oR) % 26
        raw = right.wiring[s_off]
        s_out = (raw - oR) % 26
        layers.append(UnfoldedLayer(
            idx, "right_fwd", right.name, "forward", oR,
            right.wiring, -1, s, s_out, s_off, raw,
        ))
        s = s_out
        idx += 1

        # Middle forward
        s_off = (s + oM) % 26
        raw = middle.wiring[s_off]
        s_out = (raw - oM) % 26
        layers.append(UnfoldedLayer(
            idx, "mid_fwd", middle.name, "forward", oM,
            middle.wiring, -1, s, s_out, s_off, raw,
        ))
        s = s_out
        idx += 1

        # Left forward
        s_off = (s + oL) % 26
        raw = left.wiring[s_off]
        s_out = (raw - oL) % 26
        layers.append(UnfoldedLayer(
            idx, "left_fwd", left.name, "forward", oL,
            left.wiring, -1, s, s_out, s_off, raw,
        ))
        s = s_out
        idx += 1

        # Fourth forward
        if has_fourth:
            s_off = (s + o4) % 26
            raw = fourth.wiring[s_off]
            s_out = (raw - o4) % 26
            layers.append(UnfoldedLayer(
                idx, "4th_fwd", fourth.name, "forward", o4,
                fourth.wiring, -1, s, s_out, s_off, raw,
            ))
            s = s_out
            idx += 1

        # --- FOLD POINT: REFLECTOR ---
        fold_idx = idx
        s_out = refl.wiring[s]
        layers.append(UnfoldedLayer(
            idx, "reflector", refl.name, "reflect", 0,
            refl.wiring, -1, s, s_out, s, s_out,
        ))
        s = s_out
        idx += 1

        # --- INVERSE HALF ---

        if has_fourth:
            s_off = (s + o4) % 26
            raw = fourth.inverse[s_off]
            s_out = (raw - o4) % 26
            layers.append(UnfoldedLayer(
                idx, "4th_inv", fourth.name, "inverse", o4,
                fourth.inverse, -1, s, s_out, s_off, raw,
            ))
            s = s_out
            idx += 1

        # Left inverse
        s_off = (s + oL) % 26
        raw = left.inverse[s_off]
        s_out = (raw - oL) % 26
        layers.append(UnfoldedLayer(
            idx, "left_inv", left.name, "inverse", oL,
            left.inverse, -1, s, s_out, s_off, raw,
        ))
        s = s_out
        idx += 1

        # Middle inverse
        s_off = (s + oM) % 26
        raw = middle.inverse[s_off]
        s_out = (raw - oM) % 26
        layers.append(UnfoldedLayer(
            idx, "mid_inv", middle.name, "inverse", oM,
            middle.inverse, -1, s, s_out, s_off, raw,
        ))
        s = s_out
        idx += 1

        # Right inverse
        s_off = (s + oR) % 26
        raw = right.inverse[s_off]
        s_out = (raw - oR) % 26
        layers.append(UnfoldedLayer(
            idx, "right_inv", right.name, "inverse", oR,
            right.inverse, -1, s, s_out, s_off, raw,
        ))
        s = s_out
        idx += 1

        # Plugboard out
        s_out = P[s]
        layers.append(UnfoldedLayer(
            idx, "plug_out", "plugboard", "inverse", 0,
            tuple(P), -1, s, s_out, s, s_out,
        ))
        c_letter = s_out
        idx += 1

        # Set mirror indices: layer i mirrors layer (n-1-i)
        n = len(layers)
        for i in range(n):
            layers[i].mirror_index = n - 1 - i

        # Reflector pairs in OUTER coordinates (after passing through forward stack)
        # At the reflector, signal a maps to b. Both a and b are in the "inner"
        # coordinate space (after forward rotors). The OUTER pairs are what the
        # complete machine sees.
        refl_pairs_outer = []
        seen = set()
        for a in range(26):
            if a in seen:
                continue
            b = refl.wiring[a]
            refl_pairs_outer.append((min(a, b), max(a, b)))
            seen.add(a)
            seen.add(b)

        # Machine pairs (the operative geometry's 2-cycles)
        # Compute full operative geometry without plugboard
        E = [0] * 26
        for x in range(26):
            sx = (right.wiring[(x + oR) % 26] - oR) % 26
            sx = (middle.wiring[(sx + oM) % 26] - oM) % 26
            sx = (left.wiring[(sx + oL) % 26] - oL) % 26
            if has_fourth:
                sx = (fourth.wiring[(sx + o4) % 26] - o4) % 26
            sx = refl.wiring[sx]
            if has_fourth:
                sx = (fourth.inverse[(sx + o4) % 26] - o4) % 26
            sx = (left.inverse[(sx + oL) % 26] - oL) % 26
            sx = (middle.inverse[(sx + oM) % 26] - oM) % 26
            sx = (right.inverse[(sx + oR) % 26] - oR) % 26
            E[x] = sx

        machine_pairs = []
        seen = set()
        for a in range(26):
            if a in seen:
                continue
            b = E[a]
            machine_pairs.append((min(a, b), max(a, b)))
            seen.add(a)
            seen.add(b)

        # Pair propagation: trace how reflector pairs transform through
        # each inverse layer. Start with reflector pairs, apply each
        # inverse layer in sequence.
        pair_prop: list[list[tuple[int, int]]] = [refl_pairs_outer]

        current_pairs = list(refl_pairs_outer)
        inv_layers = [l for l in layers if l.direction == "inverse" and l.component != "plugboard"]
        for layer in inv_layers:
            new_pairs = []
            seen = set()
            for a, b in current_pairs:
                # Apply this layer's transformation
                a_off = (a + layer.offset) % 26
                b_off = (b + layer.offset) % 26
                a_out = (layer.wiring[a_off] - layer.offset) % 26
                b_out = (layer.wiring[b_off] - layer.offset) % 26
                pair = (min(a_out, b_out), max(a_out, b_out))
                if pair[0] not in seen:
                    new_pairs.append(pair)
                    seen.add(pair[0])
                    seen.add(pair[1])
            current_pairs = new_pairs
            pair_prop.append(sorted(new_pairs))

        fold_positions.append(FoldedPosition(
            t=t,
            plaintext=p_letter,
            ciphertext=c_letter,
            offsets=(oL, oM, oR),
            fourth_offset=o4 if has_fourth else 0,
            folded_layers=layers,
            fold_point=fold_idx,
            reflector_pairs_outer=sorted(refl_pairs_outer),
            machine_pairs=sorted(machine_pairs),
            pair_propagation=pair_prop,
        ))

    return FoldTopology(
        rotor_names=rotor_names,
        reflector_name=reflector_name,
        ring_settings=ring_settings,
        start_positions=positions,
        plugboard_pairs=pairs_list,
        fourth_rotor_name=fourth_rotor_name,
        positions=fold_positions,
    )


def render_fold(ft: FoldTopology, max_positions: int | None = None) -> str:
    """Render the fold/unfold analysis."""
    lines: list[str] = []
    n = max_positions or len(ft.positions)
    n_layers = ft.n_layers()

    lines.append("=" * 90)
    lines.append("FOLD / UNFOLD TOPOLOGY")
    lines.append("=" * 90)

    lines.append(f"\nMachine: {'-'.join(ft.rotor_names)} / {ft.reflector_name}"
                 f"{f' / {ft.fourth_rotor_name}' if ft.fourth_rotor_name else ''}")
    lines.append(f"Plugboard: {' '.join(ft.plugboard_pairs) or '(none)'}")

    # Show fold structure
    if ft.positions:
        p0 = ft.positions[0]
        fwd_names = [l.name for l in p0.folded_layers if l.direction == "forward"]
        ref_name = [l.name for l in p0.folded_layers if l.direction == "reflect"]
        inv_names = [l.name for l in p0.folded_layers if l.direction == "inverse"]

        lines.append(f"\nFOLDED (physical signal path — {n_layers} layers):")
        lines.append(f"  {'  →  '.join(fwd_names)}  →  {ref_name[0]}  →  {'  →  '.join(inv_names)}")
        lines.append(f"  {'─' * 40}↗ FOLD POINT ↘{'─' * 40}")

        lines.append(f"\nUNFOLDED (laid flat — mirror pairs visible):")
        for i, layer in enumerate(p0.folded_layers):
            mirror = layer.mirror_index
            if i < p0.fold_point:
                partner = p0.folded_layers[mirror]
                lines.append(f"  [{i:2d}] {layer.name:12s} ({layer.component:4s} {layer.direction:7s} +{layer.offset:2d})"
                             f"  ←──mirrors──→  "
                             f"[{mirror:2d}] {partner.name:12s} ({partner.component:4s} {partner.direction:7s} +{partner.offset:2d})"
                             f"  SAME rotor, SAME offset")
            elif i == p0.fold_point:
                lines.append(f"  [{i:2d}] {layer.name:12s} ({layer.component})  *** FOLD POINT ***"
                             f"  Fixed-point-free involution: 13 pairs")
            # skip inverse half (shown as mirror)

    # Per-position detail
    for pos in ft.positions[:n]:
        pt = chr(pos.plaintext + 65)
        ct = chr(pos.ciphertext + 65)
        off_str = f"L={pos.offsets[0]:2d} M={pos.offsets[1]:2d} R={pos.offsets[2]:2d}"
        if ft.fourth_rotor_name:
            off_str += f" 4th={pos.fourth_offset:2d}"

        lines.append(f"\n{'─'*90}")
        lines.append(f"t={pos.t:3d}  {pt}→{ct}  offsets: {off_str}")

        # Folded view: signal path with fold point marked
        lines.append(f"\n  FOLDED signal path:")
        for layer in pos.folded_layers:
            in_ch = chr(layer.signal_in + 65)
            out_ch = chr(layer.signal_out + 65)
            inner_in = chr(layer.inner_in + 65)
            inner_out = chr(layer.inner_out + 65)

            if layer.direction == "reflect":
                lines.append(f"    ┌─ FOLD ─┐")
                lines.append(f"    │ [{layer.index:2d}] {layer.name:12s}  "
                             f"{in_ch}→{out_ch}  "
                             f"(reflector pair: {in_ch}↔{out_ch})")
                lines.append(f"    └─ FOLD ─┘")
            elif layer.direction == "forward":
                lines.append(f"    ↓  [{layer.index:2d}] {layer.name:12s}  "
                             f"{in_ch}→{out_ch}  "
                             f"inner: {inner_in}→{inner_out}  "
                             f"[{layer.component} +{layer.offset:2d}]")
            else:
                lines.append(f"    ↑  [{layer.index:2d}] {layer.name:12s}  "
                             f"{in_ch}→{out_ch}  "
                             f"inner: {inner_in}→{inner_out}  "
                             f"[{layer.component} +{layer.offset:2d}]")

        # Pair propagation
        lines.append(f"\n  PAIR PROPAGATION (reflector pairs through inverse stack):")
        inv_layer_names = ["reflector"] + [
            l.name for l in pos.folded_layers
            if l.direction == "inverse" and l.component != "plugboard"
        ]
        for i, (name, pairs) in enumerate(zip(inv_layer_names, pos.pair_propagation)):
            pair_str = " ".join(f"{chr(a+65)}{chr(b+65)}" for a, b in pairs)
            if i == 0:
                lines.append(f"    at reflector:   {pair_str}")
            else:
                lines.append(f"    after {name:12s}: {pair_str}")

        # Machine pairs (what the world sees)
        pair_str = " ".join(f"{chr(a+65)}{chr(b+65)}" for a, b in pos.machine_pairs)
        lines.append(f"    MACHINE OUTPUT:   {pair_str}")

    # Cross-position analysis
    lines.append(f"\n{'='*90}")
    lines.append("REFLECTOR EFFECT ACROSS POSITIONS")
    lines.append(f"{'='*90}")

    lines.append(f"\nThe reflector's 13 pairs are FIXED:")
    if ft.positions:
        refl_str = " ".join(f"{chr(a+65)}{chr(b+65)}" for a, b in ft.positions[0].reflector_pairs_outer)
        lines.append(f"  {ft.reflector_name}: {refl_str}")

    lines.append(f"\nBut the MACHINE's 13 pairs change at every position")
    lines.append(f"(because the rotor offsets change the conjugation σ⁻¹·Ref·σ):\n")
    lines.append(f"  {'t':>3}  machine pairs (σ⁻¹·Ref·σ)")
    lines.append(f"  {'---':>3}  {'─'*60}")
    for pos in ft.positions[:n]:
        pair_str = " ".join(f"{chr(a+65)}{chr(b+65)}" for a, b in pos.machine_pairs)
        lines.append(f"  {pos.t:3d}  {pair_str}")

    # Show which pairs are STABLE across positions
    if len(ft.positions) >= 2:
        lines.append(f"\n  Pair stability (how many positions share each pair):")
        from collections import Counter
        all_pairs = Counter()
        for pos in ft.positions[:n]:
            for pair in pos.machine_pairs:
                all_pairs[pair] += 1
        stable = [(pair, count) for pair, count in all_pairs.most_common() if count > 1]
        if stable:
            for pair, count in stable[:10]:
                lines.append(f"    {chr(pair[0]+65)}{chr(pair[1]+65)}: appears at {count}/{min(n, len(ft.positions))} positions")
        else:
            lines.append(f"    No pair appears at more than 1 position (complete rotation)")

    return "\n".join(lines)
