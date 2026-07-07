"""Schematic breakdown of signal action over the rotors.

This module makes the *operative geometry* legible. For a given machine
configuration it exposes, letter by letter, the full path a signal takes
through the cascade:

    plugboard -> R rotor -> M rotor -> L rotor -> [4th] -> reflector
              -> [4th] -> L rotor -> M rotor -> R rotor -> plugboard

The composite rotor+reflector permutation at a step (the plugboard is a
separate involution applied on the outside) is exactly what the rest of
the attack code calls E_t / the operative geometry. It is the object the
topology cache fingerprints, because it is fully determined by the rotor
mechanics and is INDEPENDENT of the plugboard and the plaintext.

Everything here is a reference/visualization path: it re-derives what
``Enigma.encrypt_letter`` and ``fast_trajectory`` compute, but keeps every
intermediate letter so the transition can be inspected and rendered.

Provenance / scope note (see docs/rotor_topology_notes.md): the operative
geometry is genuinely pre-computable and plugboard-independent, but the
configuration space is large and the plugboard still has to be solved on
top of any matched geometry. This module gives you the exact object to
reason about that with; it does not by itself "solve all crypttext".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from enigma.simulator import (
    ROTORS,
    REFLECTORS,
    Plugboard,
    Rotor,
)


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# The fixed left-to-right order in which a signal visits the stages on a
# single encryption. R is the fast (rightmost) rotor; the reflector is the
# turning point.
STAGE_LABELS = (
    "in",       # letter presented to the entry wheel (post-plugboard)
    "R>",       # forward through right rotor
    "M>",       # forward through middle rotor
    "L>",       # forward through left rotor
    "4>",       # forward through 4th (Greek) rotor, M4 only
    "REF",      # reflector
    "4<",       # back through 4th (Greek) rotor, M4 only
    "L<",       # back through left rotor
    "M<",       # back through middle rotor
    "R<",       # back through right rotor
    "out",      # letter leaving the entry wheel (pre-plugboard)
)


def _through_rotor(signal: int, rotor: Rotor, offset: int, forward: bool) -> int:
    """One rotor traversal, matching ``Enigma._through_rotor`` exactly."""
    table = rotor.wiring if forward else rotor.inverse
    return (table[(signal + offset) % 26] - offset) % 26


@dataclass(frozen=True)
class Config:
    """A concrete machine configuration for schematic inspection."""

    rotor_names: tuple[str, str, str]        # (left, middle, right)
    reflector_name: str = "B"
    ring_settings: tuple[int, int, int] = (0, 0, 0)
    start_positions: tuple[int, int, int] = (0, 0, 0)
    fourth_rotor_name: str | None = None
    fourth_position: int = 0
    fourth_ring: int = 0

    @classmethod
    def from_letters(
        cls,
        rotor_names: tuple[str, str, str],
        reflector_name: str = "B",
        rings: str = "AAA",
        positions: str = "AAA",
        fourth_rotor_name: str | None = None,
        fourth_position: str = "A",
        fourth_ring: str = "A",
    ) -> "Config":
        return cls(
            rotor_names=rotor_names,
            reflector_name=reflector_name,
            ring_settings=tuple(ord(c) - 65 for c in rings),          # type: ignore[arg-type]
            start_positions=tuple(ord(c) - 65 for c in positions),    # type: ignore[arg-type]
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=ord(fourth_position) - 65,
            fourth_ring=ord(fourth_ring) - 65,
        )


def stepped_positions(cfg: Config, length: int) -> list[tuple[int, int, int]]:
    """Core-rotor positions at each encryption step 0..length-1.

    Stepping is applied BEFORE the step's permutation is computed, matching
    ``Enigma.encrypt_letter`` / ``fast_trajectory``. The 4th rotor never
    steps.
    """
    left = ROTORS[cfg.rotor_names[0]]
    middle = ROTORS[cfg.rotor_names[1]]
    right = ROTORS[cfg.rotor_names[2]]
    pL, pM, pR = cfg.start_positions
    out: list[tuple[int, int, int]] = []
    for _ in range(length):
        if pM in middle.notches:
            pL = (pL + 1) % 26
            pM = (pM + 1) % 26
        elif pR in right.notches:
            pM = (pM + 1) % 26
        pR = (pR + 1) % 26
        out.append((pL, pM, pR))
    _ = left  # left is only referenced for symmetry / future notch models
    return out


def letter_path(cfg: Config, positions: tuple[int, int, int], letter: int) -> list[int]:
    """Full stage-by-stage trace of one letter at fixed core positions.

    ``positions`` are the ALREADY-STEPPED core positions (use
    ``stepped_positions`` to obtain them for a given step). Returns a list
    aligned with :data:`STAGE_LABELS`; the 4th-rotor stages are included as
    repeated values (pass-through) when the machine has no 4th rotor, so the
    list length is stable.
    """
    rotors = [ROTORS[n] for n in cfg.rotor_names]  # L, M, R
    refl = REFLECTORS[cfg.reflector_name]
    oL = (positions[0] - cfg.ring_settings[0]) % 26
    oM = (positions[1] - cfg.ring_settings[1]) % 26
    oR = (positions[2] - cfg.ring_settings[2]) % 26

    fourth = ROTORS[cfg.fourth_rotor_name] if cfg.fourth_rotor_name else None
    o4 = (cfg.fourth_position - cfg.fourth_ring) % 26

    s = letter
    trace = [s]                                              # in
    s = _through_rotor(s, rotors[2], oR, True); trace.append(s)   # R>
    s = _through_rotor(s, rotors[1], oM, True); trace.append(s)   # M>
    s = _through_rotor(s, rotors[0], oL, True); trace.append(s)   # L>
    if fourth is not None:
        s = _through_rotor(s, fourth, o4, True)
    trace.append(s)                                          # 4>
    s = refl.wiring[s]; trace.append(s)                      # REF
    if fourth is not None:
        s = _through_rotor(s, fourth, o4, False)
    trace.append(s)                                          # 4<
    s = _through_rotor(s, rotors[0], oL, False); trace.append(s)  # L<
    s = _through_rotor(s, rotors[1], oM, False); trace.append(s)  # M<
    s = _through_rotor(s, rotors[2], oR, False); trace.append(s)  # R<
    trace.append(s)                                          # out
    return trace


def operative_geometry(cfg: Config, positions: tuple[int, int, int]) -> list[int]:
    """The composite rotor+reflector permutation E at fixed core positions.

    This is the plugboard-independent object the topology cache
    fingerprints. ``operative_geometry(cfg, p)[x]`` == final stage of
    ``letter_path(cfg, p, x)``.
    """
    return [letter_path(cfg, positions, x)[-1] for x in range(26)]


def stage_table(cfg: Config, positions: tuple[int, int, int]) -> list[list[int]]:
    """26 x len(STAGE_LABELS) table: one full path per input letter."""
    return [letter_path(cfg, positions, x) for x in range(26)]


def geometry_trajectory(cfg: Config, length: int) -> list[list[int]]:
    """Operative geometry E_t for each step t in 0..length-1."""
    return [operative_geometry(cfg, p) for p in stepped_positions(cfg, length)]


# ------------------------------------------------------------------
# Rendering
# ------------------------------------------------------------------


def _s(x: int) -> str:
    return chr(x + 65)


def render_stage_table(cfg: Config, step: int = 0) -> str:
    """Human-readable ASCII schematic of every letter's path at one step.

    ``step`` selects which encryption position to show (0 = the first
    letter, after the machine has stepped once).
    """
    positions = stepped_positions(cfg, step + 1)[step]
    has4 = cfg.fourth_rotor_name is not None
    # Choose which stage columns to display.
    cols = [i for i, lbl in enumerate(STAGE_LABELS)
            if has4 or lbl not in ("4>", "4<")]
    labels = [STAGE_LABELS[i] for i in cols]

    header_bits = [
        f"rotors={'-'.join(cfg.rotor_names)}",
        f"reflector={cfg.reflector_name}",
        f"rings={''.join(_s(r) for r in cfg.ring_settings)}",
        f"start={''.join(_s(p) for p in cfg.start_positions)}",
        f"step={step}",
        f"positions={''.join(_s(p) for p in positions)}",
    ]
    if has4:
        header_bits.insert(2, f"greek={cfg.fourth_rotor_name}"
                              f"@{_s(cfg.fourth_position)}")

    lines = [
        "Operative geometry — schematic breakdown over the rotors",
        "  " + "  ".join(header_bits),
        "",
    ]
    head = "  ".join(f"{lbl:>3}" for lbl in labels)
    lines.append("     " + head)
    lines.append("     " + "-" * len(head))
    table = stage_table(cfg, positions)
    for x in range(26):
        row = table[x]
        cells = "  ".join(f"{_s(row[i]):>3}" for i in cols)
        lines.append(f"  {_s(x)}  {cells}")
    lines.append("")
    og = operative_geometry(cfg, positions)
    lines.append("  E (composite, plugboard-independent):")
    lines.append("    in : " + " ".join(ALPHABET))
    lines.append("    out: " + " ".join(_s(v) for v in og))
    lines.append(f"    involution={all(og[og[i]] == i for i in range(26))}  "
                 f"fixed-point-free={all(og[i] != i for i in range(26))}")
    return "\n".join(lines)


def to_dict(cfg: Config, length: int = 1) -> dict:
    """JSON-friendly dump of the schematic for ``length`` steps."""
    steps = []
    for t, positions in enumerate(stepped_positions(cfg, length)):
        table = stage_table(cfg, positions)
        og = operative_geometry(cfg, positions)
        steps.append({
            "step": t,
            "positions": "".join(_s(p) for p in positions),
            "operative_geometry": "".join(_s(v) for v in og),
            "paths": {
                _s(x): "".join(_s(v) for v in table[x]) for x in range(26)
            },
        })
    return {
        "config": {
            "rotors": list(cfg.rotor_names),
            "reflector": cfg.reflector_name,
            "rings": "".join(_s(r) for r in cfg.ring_settings),
            "start_positions": "".join(_s(p) for p in cfg.start_positions),
            "fourth_rotor": cfg.fourth_rotor_name,
            "fourth_position": _s(cfg.fourth_position) if cfg.fourth_rotor_name else None,
        },
        "stage_labels": list(STAGE_LABELS),
        "steps": steps,
    }
