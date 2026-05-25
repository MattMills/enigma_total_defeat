"""Component topology: minimal and maximal structural descriptions.

Each Enigma component is described by its INTRINSIC topology (what it is
independently) and its INTERACTION topology (how it couples with neighbors).

Components interact ONLY at state-change boundaries:
  - Rotor stepping: right rotor always, middle at right-notch, left at middle-notch
  - Signal handoff: each layer passes a single integer 0-25 to the next
  - Plugboard: wraps the entire rotor stack at entry and exit

The minimal description of each component is the information needed to
compute its contribution. The maximal description includes all derived
properties (cycle structure, order, period, differential signature).

Coupling points — where and when state changes occur:
  1. STEP event: right position increments (ALWAYS)
  2. NOTCH event: right position equals notch → middle steps
  3. DOUBLE-STEP event: middle position equals notch → middle AND left step
  4. SIGNAL entry: integer arrives from previous layer
  5. SIGNAL exit: integer departs to next layer

What CAUSES each state change:
  - Stepping: the mechanical odometer advances before each encryption
  - Notch: a physical pawl engages when a ring letter aligns with a cam
  - Signal: electrical current flows through the rotor wiring
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from enigma.simulator import ROTORS, REFLECTORS, Rotor, Reflector


# ------------------------------------------------------------------
# Intrinsic component topology
# ------------------------------------------------------------------

@dataclass
class PermutationTopology:
    """Intrinsic topology of a single permutation (rotor wiring or reflector)."""
    name: str
    wiring: tuple[int, ...]
    inverse: tuple[int, ...]
    cycle_structure: list[list[int]]
    cycle_type: list[int]
    fixed_points: list[int]
    order: int
    is_involution: bool
    is_fixed_point_free: bool
    derangement: bool

    @classmethod
    def from_permutation(cls, name: str, perm: tuple[int, ...]) -> "PermutationTopology":
        n = len(perm)
        inv = [0] * n
        for i, p in enumerate(perm):
            inv[p] = i

        seen = [False] * n
        cycles: list[list[int]] = []
        for i in range(n):
            if seen[i]:
                continue
            cycle = []
            j = i
            while not seen[j]:
                seen[j] = True
                cycle.append(j)
                j = perm[j]
            cycles.append(cycle)

        cycle_type = sorted([len(c) for c in cycles], reverse=True)
        fixed = [i for i in range(n) if perm[i] == i]
        is_inv = all(perm[perm[i]] == i for i in range(n))
        is_fpf = len(fixed) == 0

        from math import gcd
        order = 1
        for c in cycle_type:
            order = order * c // gcd(order, c)

        return cls(
            name=name,
            wiring=perm,
            inverse=tuple(inv),
            cycle_structure=sorted(cycles, key=lambda c: (-len(c), c[0])),
            cycle_type=cycle_type,
            fixed_points=fixed,
            order=order,
            is_involution=is_inv,
            is_fixed_point_free=is_fpf,
            derangement=is_fpf,
        )


@dataclass
class RotorTopology:
    """Complete intrinsic topology of a rotor."""
    name: str
    forward: PermutationTopology
    inverse: PermutationTopology
    notches: tuple[int, ...]
    notch_letters: str
    has_notch: bool
    is_greek: bool  # Beta/Gamma: no notch, doesn't step

    # Derived: how the rotor transforms the signal as offset changes
    offset_cycle_length: int = 26  # always 26 for standard rotors
    turnover_positions: list[int] = field(default_factory=list)

    @classmethod
    def from_rotor(cls, rotor: Rotor) -> "RotorTopology":
        fwd = PermutationTopology.from_permutation(rotor.name + "_fwd", rotor.wiring)
        inv = PermutationTopology.from_permutation(rotor.name + "_inv", rotor.inverse)

        return cls(
            name=rotor.name,
            forward=fwd,
            inverse=inv,
            notches=rotor.notches,
            notch_letters="".join(chr(n + 65) for n in rotor.notches),
            has_notch=len(rotor.notches) > 0,
            is_greek=len(rotor.notches) == 0 and rotor.name in ("Beta", "Gamma"),
            turnover_positions=list(rotor.notches),
        )


@dataclass
class ReflectorTopology:
    """Complete intrinsic topology of a reflector."""
    name: str
    permutation: PermutationTopology
    pairs: list[tuple[int, int]]

    @classmethod
    def from_reflector(cls, refl: Reflector) -> "ReflectorTopology":
        perm = PermutationTopology.from_permutation(refl.name, refl.wiring)
        pairs = []
        seen: set[int] = set()
        for i in range(26):
            if i not in seen:
                j = refl.wiring[i]
                pairs.append((i, j))
                seen.add(i)
                seen.add(j)
        return cls(name=refl.name, permutation=perm, pairs=sorted(pairs))


@dataclass
class PlugboardTopology:
    """Intrinsic topology of a plugboard configuration."""
    pairs: list[tuple[int, int]]
    mapping: list[int]
    n_pairs: int
    n_free: int  # letters not in any pair
    free_letters: list[int]
    permutation: PermutationTopology

    @classmethod
    def from_pairs(cls, pair_strs: list[str]) -> "PlugboardTopology":
        mapping = list(range(26))
        pairs = []
        used: set[int] = set()
        for p in pair_strs:
            a, b = ord(p[0]) - 65, ord(p[1]) - 65
            mapping[a], mapping[b] = b, a
            pairs.append((min(a, b), max(a, b)))
            used.add(a)
            used.add(b)
        free = [i for i in range(26) if i not in used]
        perm = PermutationTopology.from_permutation("plugboard", tuple(mapping))
        return cls(
            pairs=sorted(pairs),
            mapping=mapping,
            n_pairs=len(pairs),
            n_free=len(free),
            free_letters=free,
            permutation=perm,
        )


# ------------------------------------------------------------------
# Interaction topology: coupling between components
# ------------------------------------------------------------------

@dataclass
class CouplingPoint:
    """A point where two components interact."""
    source: str
    target: str
    coupling_type: str  # "signal", "step", "notch"
    when: str  # "every_position", "at_notch", "at_double_step", "never"
    what_changes: str
    direction: str  # "forward", "backward", "both"


@dataclass
class SteppingTopology:
    """The odometer-like stepping structure of the rotor assembly."""
    right_rotor: str
    middle_rotor: str
    left_rotor: str
    right_notches: tuple[int, ...]
    middle_notches: tuple[int, ...]
    right_period: int  # always 26
    middle_period: int  # 26 * (26 / n_right_notches) for single-notch
    left_period: int  # middle_period * (26 / n_middle_notches)
    double_step_interval: int  # approximate positions between double steps
    total_period: int  # LCM of all periods before full cycle

    @classmethod
    def compute(cls, right: Rotor, middle: Rotor, left: Rotor) -> "SteppingTopology":
        r_notches = len(right.notches) or 1
        m_notches = len(middle.notches) or 1

        r_period = 26
        m_period = 26 * (26 // r_notches)
        l_period = m_period * (26 // m_notches)

        from math import gcd
        total = r_period
        for p in [m_period, l_period]:
            total = total * p // gcd(total, p)

        double_interval = m_period  # approximate

        return cls(
            right_rotor=right.name,
            middle_rotor=middle.name,
            left_rotor=left.name,
            right_notches=right.notches,
            middle_notches=middle.notches,
            right_period=r_period,
            middle_period=m_period,
            left_period=l_period,
            double_step_interval=double_interval,
            total_period=total,
        )


# ------------------------------------------------------------------
# Full machine topology
# ------------------------------------------------------------------

@dataclass
class MachineTopology:
    """Complete topological description of an Enigma machine configuration."""
    # Components
    right_rotor: RotorTopology
    middle_rotor: RotorTopology
    left_rotor: RotorTopology
    reflector: ReflectorTopology
    plugboard: PlugboardTopology
    fourth_rotor: RotorTopology | None

    # Interaction structure
    stepping: SteppingTopology
    coupling_points: list[CouplingPoint]

    # Derived global properties
    signal_path_length: int  # number of layers signal traverses
    n_static_components: int  # components that never change
    n_dynamic_components: int  # components that step
    key_space_size: int  # total number of possible configurations
    effective_key_bits: float  # log2(key_space_size)

    @classmethod
    def build(
        cls,
        rotor_names: tuple[str, str, str],
        reflector_name: str,
        plugboard_pairs: list[str] | None = None,
        fourth_rotor_name: str | None = None,
    ) -> "MachineTopology":
        right = RotorTopology.from_rotor(ROTORS[rotor_names[2]])
        middle = RotorTopology.from_rotor(ROTORS[rotor_names[1]])
        left = RotorTopology.from_rotor(ROTORS[rotor_names[0]])
        refl = ReflectorTopology.from_reflector(REFLECTORS[reflector_name])
        plug = PlugboardTopology.from_pairs(plugboard_pairs or [])
        fourth = RotorTopology.from_rotor(ROTORS[fourth_rotor_name]) if fourth_rotor_name else None

        stepping = SteppingTopology.compute(
            ROTORS[rotor_names[2]],
            ROTORS[rotor_names[1]],
            ROTORS[rotor_names[0]],
        )

        # Build coupling points
        couplings = [
            CouplingPoint("keyboard", "plugboard", "signal", "every_position",
                          "plaintext letter enters plugboard", "forward"),
            CouplingPoint("plugboard", "right_rotor", "signal", "every_position",
                          "plugboard output enters right rotor", "forward"),
            CouplingPoint("right_rotor", "middle_rotor", "signal", "every_position",
                          "right rotor output enters middle rotor", "forward"),
            CouplingPoint("middle_rotor", "left_rotor", "signal", "every_position",
                          "middle rotor output enters left rotor", "forward"),
        ]
        if fourth:
            couplings.append(CouplingPoint(
                "left_rotor", "fourth_rotor", "signal", "every_position",
                "left rotor output enters fourth rotor", "forward"))
            couplings.append(CouplingPoint(
                "fourth_rotor", "reflector", "signal", "every_position",
                "fourth rotor output enters reflector", "forward"))
        else:
            couplings.append(CouplingPoint(
                "left_rotor", "reflector", "signal", "every_position",
                "left rotor output enters reflector", "forward"))

        # Return path
        couplings.extend([
            CouplingPoint("reflector", "left_rotor" if not fourth else "fourth_rotor",
                          "signal", "every_position",
                          "reflector output returns through rotors", "backward"),
            CouplingPoint("right_rotor", "plugboard", "signal", "every_position",
                          "right rotor inverse output enters plugboard", "backward"),
            CouplingPoint("plugboard", "lampboard", "signal", "every_position",
                          "plugboard output lights ciphertext lamp", "backward"),
        ])

        # Stepping couplings
        couplings.extend([
            CouplingPoint("mechanism", "right_rotor", "step", "every_position",
                          "right rotor advances by 1", "forward"),
            CouplingPoint("right_rotor", "middle_rotor", "notch", "at_notch",
                          "right rotor notch triggers middle step", "forward"),
            CouplingPoint("middle_rotor", "left_rotor", "notch", "at_double_step",
                          "middle rotor notch triggers left step AND middle re-step", "forward"),
        ])

        path_len = 9 if not fourth else 11
        n_static = 2 + (1 if fourth else 0)  # reflector + plugboard + fourth
        n_dynamic = 3  # right, middle, left

        import math
        key_space = 60 * 3 * (26**3) * (26**3)  # rotors × reflectors × positions × rings
        # plugboard: C(26,2) × C(24,2) × ... for 10 pairs
        plug_space = 1
        for i in range(plug.n_pairs):
            n = 26 - 2 * i
            plug_space *= n * (n - 1) // 2
        plug_space //= math.factorial(plug.n_pairs)  # unordered pairs
        key_space *= plug_space if plug.n_pairs > 0 else 1

        return cls(
            right_rotor=right,
            middle_rotor=middle,
            left_rotor=left,
            reflector=refl,
            plugboard=plug,
            fourth_rotor=fourth,
            stepping=stepping,
            coupling_points=couplings,
            signal_path_length=path_len,
            n_static_components=n_static,
            n_dynamic_components=n_dynamic,
            key_space_size=key_space,
            effective_key_bits=math.log2(key_space) if key_space > 0 else 0,
        )


def render_component_topology(mt: MachineTopology) -> str:
    """Render the full component topology as human-readable text."""
    lines: list[str] = []

    lines.append("=" * 80)
    lines.append("COMPONENT TOPOLOGY: Minimal and Maximal Structural Descriptions")
    lines.append("=" * 80)

    # Machine overview
    lines.append(f"\nMachine: {mt.left_rotor.name}-{mt.middle_rotor.name}-{mt.right_rotor.name}"
                 f" / {mt.reflector.name}"
                 f"{f' / {mt.fourth_rotor.name}' if mt.fourth_rotor else ''}")
    lines.append(f"Signal path: {mt.signal_path_length} layers")
    lines.append(f"Static components: {mt.n_static_components}  Dynamic: {mt.n_dynamic_components}")
    lines.append(f"Key space: {mt.key_space_size:.2e} ({mt.effective_key_bits:.1f} bits)")

    # Each rotor
    for label, rt in [("RIGHT", mt.right_rotor), ("MIDDLE", mt.middle_rotor), ("LEFT", mt.left_rotor)]:
        lines.append(f"\n--- {label} ROTOR: {rt.name} ---")
        lines.append(f"  MINIMAL: wiring = {rt.forward.wiring}")
        lines.append(f"  Notch: {''.join(chr(n+65) for n in rt.notches) or '(none)'}")
        lines.append(f"  MAXIMAL:")
        lines.append(f"    Cycle type: {rt.forward.cycle_type}")
        for c in rt.forward.cycle_structure:
            letters = "".join(chr(x+65) for x in c)
            lines.append(f"      ({letters})")
        lines.append(f"    Order: {rt.forward.order}")
        lines.append(f"    Fixed points: {[chr(f+65) for f in rt.forward.fixed_points] or 'none'}")
        lines.append(f"    Involution: {rt.forward.is_involution}")
        lines.append(f"    Derangement: {rt.forward.derangement}")
        lines.append(f"  STATE CHANGE: offset increments by 1 at {'every position' if label == 'RIGHT' else 'right notch' if label == 'MIDDLE' else 'middle notch'}")
        lines.append(f"  CAUSE: {'mechanical pawl engages every keypress' if label == 'RIGHT' else 'right rotor ring aligns with notch cam' if label == 'MIDDLE' else 'middle rotor ring aligns with notch cam'}")

    if mt.fourth_rotor:
        lines.append(f"\n--- FOURTH ROTOR: {mt.fourth_rotor.name} ---")
        lines.append(f"  MINIMAL: wiring = {mt.fourth_rotor.forward.wiring}")
        lines.append(f"  STATE CHANGE: never (static)")
        lines.append(f"  CAUSE: Greek rotors have no pawl mechanism")

    # Reflector
    lines.append(f"\n--- REFLECTOR: {mt.reflector.name} ---")
    lines.append(f"  MINIMAL: pairs = {' '.join(chr(a+65)+chr(b+65) for a,b in mt.reflector.pairs)}")
    lines.append(f"  MAXIMAL:")
    lines.append(f"    Involution: {mt.reflector.permutation.is_involution} (REQUIRED)")
    lines.append(f"    Fixed-point-free: {mt.reflector.permutation.is_fixed_point_free} (REQUIRED)")
    lines.append(f"    Cycle type: {mt.reflector.permutation.cycle_type} (always [2]*13)")
    lines.append(f"  STATE CHANGE: never (hardwired)")
    lines.append(f"  CAUSE: physical wiring is fixed")

    # Plugboard
    lines.append(f"\n--- PLUGBOARD ---")
    lines.append(f"  MINIMAL: pairs = {' '.join(chr(a+65)+chr(b+65) for a,b in mt.plugboard.pairs) or '(none)'}")
    lines.append(f"  MAXIMAL:")
    lines.append(f"    Pairs: {mt.plugboard.n_pairs}  Free: {mt.plugboard.n_free}")
    lines.append(f"    Free letters: {''.join(chr(f+65) for f in mt.plugboard.free_letters)}")
    lines.append(f"    Involution: {mt.plugboard.permutation.is_involution} (REQUIRED)")
    lines.append(f"  STATE CHANGE: never (set once per day)")
    lines.append(f"  CAUSE: physical cable connections")

    # Stepping topology
    lines.append(f"\n--- STEPPING TOPOLOGY ---")
    lines.append(f"  Right period:  {mt.stepping.right_period} positions")
    lines.append(f"  Middle period: {mt.stepping.middle_period} positions")
    lines.append(f"  Left period:   {mt.stepping.left_period} positions")
    lines.append(f"  Full cycle:    {mt.stepping.total_period} positions")
    lines.append(f"  Double-step interval: ~{mt.stepping.double_step_interval} positions")

    # Coupling points
    lines.append(f"\n--- COUPLING POINTS (where state changes between objects) ---")
    for cp in mt.coupling_points:
        lines.append(f"  {cp.source:15s} → {cp.target:15s}  "
                     f"type={cp.coupling_type:6s}  when={cp.when:18s}  "
                     f"{cp.what_changes}")

    return "\n".join(lines)
