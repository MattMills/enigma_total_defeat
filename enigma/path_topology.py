"""Path-topological simulator: complete causal structure of the Enigma.

Traces every signal through the machine at every position, recording
the full topology of operations — WHAT acts, WHERE it acts, WHEN it
acts, and HOW it transforms the topology for subsequent positions.

The Enigma is viewed as a sequence of causal events in a 2D universe:
  - Horizontal axis: message position t = 0, 1, ..., L-1
  - Vertical axis: signal path through the machine layers

At each position t, the signal traverses a fixed sequence of layers:

  Layer 0: PLUGBOARD_IN      P(plaintext)
  Layer 1: RIGHT_FWD         R(signal + oR) - oR
  Layer 2: MIDDLE_FWD        M(signal + oM) - oM
  Layer 3: LEFT_FWD          L(signal + oL) - oL
  Layer 4: FOURTH_FWD        4th(signal + o4) - o4  (M4 only)
  Layer 5: REFLECTOR         Rf(signal)
  Layer 6: FOURTH_INV        4th_inv(signal + o4) - o4  (M4 only)
  Layer 7: LEFT_INV          L_inv(signal + oL) - oL
  Layer 8: MIDDLE_INV        M_inv(signal + oM) - oM
  Layer 9: RIGHT_INV         R_inv(signal + oR) - oR
  Layer 10: PLUGBOARD_OUT    P(signal)

Before each position, the STEPPING event occurs:
  - Right rotor ALWAYS steps
  - Middle rotor steps if right is at notch OR middle is at notch (double-step)
  - Left rotor steps if middle is at notch

The stepping changes the offsets (oL, oM, oR) which changes the
permutation at every layer for the next position. This is the
topological self-modification: the act of encrypting changes the
structure of the encryption.

The complete topology is a 2D grid:
  topology[t][layer] = CausalEvent(input, output, permutation, offset)

This grid can be "read" in both directions:
  Forward:  plaintext → ciphertext (encryption)
  Backward: ciphertext → plaintext (decryption, same path reversed)

The Enigma's involution property means the forward and backward paths
are IDENTICAL — the topology is symmetric.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

from enigma.simulator import (
    ROTORS,
    REFLECTORS,
    Plugboard,
    M3_ROTORS,
    M3_REFLECTORS,
)


class Layer(Enum):
    STEP = "step"
    PLUGBOARD_IN = "plugboard_in"
    RIGHT_FWD = "right_fwd"
    MIDDLE_FWD = "middle_fwd"
    LEFT_FWD = "left_fwd"
    FOURTH_FWD = "fourth_fwd"
    REFLECTOR = "reflector"
    FOURTH_INV = "fourth_inv"
    LEFT_INV = "left_inv"
    MIDDLE_INV = "middle_inv"
    RIGHT_INV = "right_inv"
    PLUGBOARD_OUT = "plugboard_out"


@dataclass
class StepEvent:
    """Rotor stepping event that occurs before each position."""
    right_stepped: bool
    middle_stepped: bool
    left_stepped: bool
    trigger: str
    positions_before: tuple[int, int, int]
    positions_after: tuple[int, int, int]


@dataclass
class CausalEvent:
    """One signal transformation at one layer and position."""
    layer: Layer
    position: int
    signal_in: int
    signal_out: int
    component_name: str
    offset: int
    signal_plus_offset: int
    raw_lookup: int
    is_identity: bool


@dataclass
class PositionTopology:
    """Complete signal path at one message position."""
    t: int
    plaintext: int
    ciphertext: int
    step: StepEvent
    events: list[CausalEvent]
    rotor_positions: tuple[int, int, int]
    rotor_offsets: tuple[int, int, int]
    operative_geometry: list[int]


@dataclass
class PathTopology:
    """Complete topological description of an Enigma encryption."""
    rotor_names: tuple[str, str, str]
    reflector_name: str
    ring_settings: tuple[int, int, int]
    start_positions: tuple[int, int, int]
    plugboard_pairs: list[str]
    fourth_rotor_name: str | None
    fourth_position: int
    plaintext: str
    ciphertext: str
    positions: list[PositionTopology]

    @property
    def length(self) -> int:
        return len(self.positions)

    def layer_names(self) -> list[str]:
        if self.positions:
            return [e.layer.value for e in self.positions[0].events]
        return []

    def signal_matrix(self) -> list[list[int]]:
        """t × layer matrix of signal values through the machine."""
        return [[e.signal_out for e in pos.events] for pos in self.positions]

    def operative_geometries(self) -> list[list[int]]:
        """The sequence of 26-element permutations (plugboard excluded)."""
        return [pos.operative_geometry for pos in self.positions]

    def stepping_timeline(self) -> list[dict]:
        """When and why each rotor stepped."""
        return [
            {
                "t": pos.t,
                "trigger": pos.step.trigger,
                "R": pos.step.right_stepped,
                "M": pos.step.middle_stepped,
                "L": pos.step.left_stepped,
                "pos_before": "".join(chr(p + 65) for p in pos.step.positions_before),
                "pos_after": "".join(chr(p + 65) for p in pos.step.positions_after),
            }
            for pos in self.positions
        ]

    def plugboard_topology(self) -> dict:
        """Which letters are swapped and how often each appears."""
        counts_in = [0] * 26
        counts_out = [0] * 26
        for pos in self.positions:
            ev_in = pos.events[0]
            ev_out = pos.events[-1]
            if not ev_in.is_identity:
                counts_in[pos.plaintext] += 1
            if not ev_out.is_identity:
                counts_out[pos.ciphertext] += 1
        return {
            "pairs": self.plugboard_pairs,
            "in_activations": counts_in,
            "out_activations": counts_out,
        }

    def cycle_structure_at(self, t: int) -> list[list[int]]:
        """Cycle decomposition of the operative geometry at position t."""
        E = self.positions[t].operative_geometry
        seen = [False] * 26
        cycles = []
        for i in range(26):
            if seen[i]:
                continue
            cycle = []
            j = i
            while not seen[j]:
                seen[j] = True
                cycle.append(j)
                j = E[j]
            cycles.append(cycle)
        return sorted(cycles, key=lambda c: (-len(c), c[0]))

    def fixed_point_check(self) -> list[bool]:
        """Verify no position has a fixed point (Enigma invariant)."""
        return [
            all(E[i] != i for i in range(26))
            for E in self.operative_geometries()
        ]

    def involution_check(self) -> list[bool]:
        """Verify every operative geometry is an involution."""
        result = []
        for E in self.operative_geometries():
            result.append(all(E[E[i]] == i for i in range(26)))
        return result


def trace(
    plaintext: str,
    rotor_names: tuple[str, str, str] = ("II", "IV", "V"),
    reflector_name: str = "B",
    positions: tuple[int, int, int] = (0, 0, 0),
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    plugboard_pairs: list[str] | None = None,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> PathTopology:
    """Trace the complete path topology of an Enigma encryption.

    Returns a PathTopology containing every causal event at every
    position — the full topological description of the encryption
    from plaintext to ciphertext.
    """
    pairs = plugboard_pairs or []
    plug = Plugboard.from_pairs(pairs) if pairs else Plugboard()
    P = plug.mapping

    left = ROTORS[rotor_names[0]]
    middle = ROTORS[rotor_names[1]]
    right = ROTORS[rotor_names[2]]
    refl = REFLECTORS[reflector_name]

    Lw, Le = left.wiring, left.inverse
    Mw, Me = middle.wiring, middle.inverse
    Rw, Re = right.wiring, right.inverse
    Rf = list(refl.wiring)

    has_fourth = fourth_rotor_name is not None
    if has_fourth:
        fourth = ROTORS[fourth_rotor_name]
        Fw, Fe = fourth.wiring, fourth.inverse
        o4 = (fourth_position - fourth_ring) % 26
    else:
        fourth = None
        Fw = Fe = ()
        o4 = 0

    pL, pM, pR = positions
    rL, rM, rR = ring_settings

    plain_ints = [ord(c) - 65 for c in plaintext if "A" <= c <= "Z"]
    pos_topos: list[PositionTopology] = []
    cipher_ints: list[int] = []

    for t, p_letter in enumerate(plain_ints):
        # --- STEPPING ---
        pos_before = (pL, pM, pR)
        middle_at_notch = pM in middle.notches
        right_at_notch = pR in right.notches

        stepped_L = False
        stepped_M = False
        stepped_R = True  # right always steps

        if middle_at_notch:
            pL = (pL + 1) % 26
            pM = (pM + 1) % 26
            stepped_L = True
            stepped_M = True
            trigger = "double_step" if right_at_notch else "middle_at_notch"
        elif right_at_notch:
            pM = (pM + 1) % 26
            stepped_M = True
            trigger = "right_at_notch"
        else:
            trigger = "normal"
        pR = (pR + 1) % 26

        pos_after = (pL, pM, pR)
        step = StepEvent(
            right_stepped=stepped_R,
            middle_stepped=stepped_M,
            left_stepped=stepped_L,
            trigger=trigger,
            positions_before=pos_before,
            positions_after=pos_after,
        )

        oL = (pL - rL) % 26
        oM = (pM - rM) % 26
        oR = (pR - rR) % 26

        events: list[CausalEvent] = []
        s = p_letter

        # Layer 0: Plugboard in
        s_out = P[s]
        events.append(CausalEvent(
            Layer.PLUGBOARD_IN, t, s, s_out,
            "plugboard", 0, s, s_out, s == s_out,
        ))
        s = s_out

        # Layer 1: Right forward
        s_off = (s + oR) % 26
        raw = Rw[s_off]
        s_out = (raw - oR) % 26
        events.append(CausalEvent(
            Layer.RIGHT_FWD, t, s, s_out,
            right.name, oR, s_off, raw, False,
        ))
        s = s_out

        # Layer 2: Middle forward
        s_off = (s + oM) % 26
        raw = Mw[s_off]
        s_out = (raw - oM) % 26
        events.append(CausalEvent(
            Layer.MIDDLE_FWD, t, s, s_out,
            middle.name, oM, s_off, raw, False,
        ))
        s = s_out

        # Layer 3: Left forward
        s_off = (s + oL) % 26
        raw = Lw[s_off]
        s_out = (raw - oL) % 26
        events.append(CausalEvent(
            Layer.LEFT_FWD, t, s, s_out,
            left.name, oL, s_off, raw, False,
        ))
        s = s_out

        # Layer 4: Fourth forward (M4 only)
        if has_fourth:
            s_off = (s + o4) % 26
            raw = Fw[s_off]
            s_out = (raw - o4) % 26
            events.append(CausalEvent(
                Layer.FOURTH_FWD, t, s, s_out,
                fourth.name, o4, s_off, raw, False,
            ))
            s = s_out

        # Layer 5: Reflector
        s_out = Rf[s]
        events.append(CausalEvent(
            Layer.REFLECTOR, t, s, s_out,
            refl.name, 0, s, s_out, False,
        ))
        s = s_out

        # Layer 6: Fourth inverse (M4 only)
        if has_fourth:
            s_off = (s + o4) % 26
            raw = Fe[s_off]
            s_out = (raw - o4) % 26
            events.append(CausalEvent(
                Layer.FOURTH_INV, t, s, s_out,
                fourth.name + "_inv", o4, s_off, raw, False,
            ))
            s = s_out

        # Layer 7: Left inverse
        s_off = (s + oL) % 26
        raw = Le[s_off]
        s_out = (raw - oL) % 26
        events.append(CausalEvent(
            Layer.LEFT_INV, t, s, s_out,
            left.name + "_inv", oL, s_off, raw, False,
        ))
        s = s_out

        # Layer 8: Middle inverse
        s_off = (s + oM) % 26
        raw = Me[s_off]
        s_out = (raw - oM) % 26
        events.append(CausalEvent(
            Layer.MIDDLE_INV, t, s, s_out,
            middle.name + "_inv", oM, s_off, raw, False,
        ))
        s = s_out

        # Layer 9: Right inverse
        s_off = (s + oR) % 26
        raw = Re[s_off]
        s_out = (raw - oR) % 26
        events.append(CausalEvent(
            Layer.RIGHT_INV, t, s, s_out,
            right.name + "_inv", oR, s_off, raw, False,
        ))
        s = s_out

        # Layer 10: Plugboard out
        s_out = P[s]
        events.append(CausalEvent(
            Layer.PLUGBOARD_OUT, t, s, s_out,
            "plugboard", 0, s, s_out, s == s_out,
        ))
        c_letter = s_out
        cipher_ints.append(c_letter)

        # Operative geometry (plugboard-excluded full permutation)
        E = [0] * 26
        for x in range(26):
            sx = (Rw[(x + oR) % 26] - oR) % 26
            sx = (Mw[(sx + oM) % 26] - oM) % 26
            sx = (Lw[(sx + oL) % 26] - oL) % 26
            if has_fourth:
                sx = (Fw[(sx + o4) % 26] - o4) % 26
            sx = Rf[sx]
            if has_fourth:
                sx = (Fe[(sx + o4) % 26] - o4) % 26
            sx = (Le[(sx + oL) % 26] - oL) % 26
            sx = (Me[(sx + oM) % 26] - oM) % 26
            sx = (Re[(sx + oR) % 26] - oR) % 26
            E[x] = sx

        pos_topos.append(PositionTopology(
            t=t,
            plaintext=p_letter,
            ciphertext=c_letter,
            step=step,
            events=events,
            rotor_positions=pos_after,
            rotor_offsets=(oL, oM, oR),
            operative_geometry=E,
        ))

    return PathTopology(
        rotor_names=rotor_names,
        reflector_name=reflector_name,
        ring_settings=ring_settings,
        start_positions=positions,
        plugboard_pairs=pairs,
        fourth_rotor_name=fourth_rotor_name,
        fourth_position=fourth_position,
        plaintext=plaintext,
        ciphertext="".join(chr(c + 65) for c in cipher_ints),
        positions=pos_topos,
    )


def render(topo: PathTopology, max_positions: int | None = None) -> str:
    """Render the full path topology as a human-readable string."""
    lines: list[str] = []
    n = max_positions or topo.length

    lines.append("=" * 90)
    lines.append("PATH TOPOLOGY: Complete causal structure of Enigma encryption")
    lines.append("=" * 90)

    lines.append(f"\nMachine:   {'-'.join(topo.rotor_names)} / {topo.reflector_name}")
    if topo.fourth_rotor_name:
        lines.append(f"4th rotor: {topo.fourth_rotor_name} at {chr(topo.fourth_position + 65)}")
    lines.append(f"Positions: {''.join(chr(p+65) for p in topo.start_positions)}")
    lines.append(f"Rings:     {''.join(chr(r+65) for r in topo.ring_settings)}")
    lines.append(f"Plugboard: {' '.join(topo.plugboard_pairs) or '(none)'}")
    lines.append(f"Plaintext: {topo.plaintext[:70]}")
    lines.append(f"Ciphertext:{topo.ciphertext[:70]}")
    lines.append(f"Length:    {topo.length}")

    # Invariant checks
    fp_ok = topo.fixed_point_check()
    inv_ok = topo.involution_check()
    lines.append(f"\nInvariants:")
    lines.append(f"  Fixed-point-free: {'ALL PASS' if all(fp_ok) else 'FAIL at ' + str([i for i,v in enumerate(fp_ok) if not v])}")
    lines.append(f"  Involution:       {'ALL PASS' if all(inv_ok) else 'FAIL at ' + str([i for i,v in enumerate(inv_ok) if not v])}")

    # Stepping timeline
    lines.append(f"\n{'='*90}")
    lines.append("STEPPING TIMELINE")
    lines.append(f"{'='*90}")
    lines.append(f"  {'t':>3}  {'before':>6} → {'after':>6}  {'R':>1} {'M':>1} {'L':>1}  trigger")
    lines.append(f"  {'---':>3}  {'------':>6}   {'------':>6}  {'-':>1} {'-':>1} {'-':>1}  -------")
    for s in topo.stepping_timeline()[:n]:
        lines.append(
            f"  {s['t']:3d}  {s['pos_before']:>6} → {s['pos_after']:>6}  "
            f"{'Y' if s['R'] else '.':>1} {'Y' if s['M'] else '.':>1} {'Y' if s['L'] else '.':>1}  "
            f"{s['trigger']}"
        )

    # Signal path per position
    lines.append(f"\n{'='*90}")
    lines.append("SIGNAL PATH (per position)")
    lines.append(f"{'='*90}")

    for pos in topo.positions[:n]:
        p_ch = chr(pos.plaintext + 65)
        c_ch = chr(pos.ciphertext + 65)
        pos_str = "".join(chr(p + 65) for p in pos.rotor_positions)
        off_str = ",".join(str(o) for o in pos.rotor_offsets)

        lines.append(f"\n  t={pos.t:3d}  {p_ch}→{c_ch}  "
                      f"pos={pos_str}  offsets=({off_str})  "
                      f"step={pos.step.trigger}")

        for ev in pos.events:
            in_ch = chr(ev.signal_in + 65)
            out_ch = chr(ev.signal_out + 65)
            marker = "·" if ev.is_identity else "→"
            off_str = f"+{ev.offset:2d}" if ev.offset else "   "
            lines.append(
                f"    {ev.layer.value:16s}  {in_ch} {marker} {out_ch}  "
                f"[{ev.component_name:10s} {off_str}  "
                f"({ev.signal_in:2d}{off_str}={ev.signal_plus_offset:2d})"
                f"→wiring[{ev.signal_plus_offset:2d}]={ev.raw_lookup:2d}"
                f"→({ev.raw_lookup:2d}{'-'+str(ev.offset) if ev.offset else ''})%26={ev.signal_out:2d}]"
            )

    # Cycle structure
    lines.append(f"\n{'='*90}")
    lines.append("OPERATIVE GEOMETRY CYCLE STRUCTURE")
    lines.append(f"{'='*90}")
    for pos in topo.positions[:n]:
        cycles = topo.cycle_structure_at(pos.t)
        cycle_strs = []
        for c in cycles:
            letters = "".join(chr(x + 65) for x in c)
            cycle_strs.append(f"({letters})")
        cycle_type = sorted([len(c) for c in cycles], reverse=True)
        lines.append(f"  t={pos.t:3d}  type={cycle_type}  {''.join(cycle_strs)}")

    # Signal flow matrix
    lines.append(f"\n{'='*90}")
    lines.append("SIGNAL FLOW MATRIX (letter at each layer)")
    lines.append(f"{'='*90}")

    layer_names = topo.layer_names()
    header = "  t  PT  " + "  ".join(f"{ln[:7]:>7}" for ln in layer_names) + "  CT"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))

    for pos in topo.positions[:n]:
        pt = chr(pos.plaintext + 65)
        ct = chr(pos.ciphertext + 65)
        signals = "  ".join(f"{chr(ev.signal_out+65):>7}" for ev in pos.events)
        lines.append(f"  {pos.t:2d}  {pt}   {signals}  {ct}")

    return "\n".join(lines)
