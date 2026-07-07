"""Possibility landscape: inverting the operative geometry to resolve rotors.

Step one (``enigma/schematic.py``) makes the operative geometry E legible:
the plugboard-independent rotor+reflector permutation at each step. This
module is step two — the *inverse* problem. Given evidence about the
geometry, which rotor configuration produced it?

Empirical facts, all verified against the simulator (see
``docs/possibility_landscape_notes.md``):

  * ``config -> E`` is **injective**. Over all 1,054,560 M3 configs
    (60 rotor orders x 26^3 offset-triples, reflector B) every operative
    geometry E is distinct — zero collisions. A single fully-observed
    geometry pins the rotor order AND the three offsets exactly.

  * Every keypress advances the right rotor, which sits *outside* the whole
    cascade and therefore CONJUGATES it. One step changes all 26 entries of
    E: there is no locally-stable topology, the geometry is globally
    reshuffled per letter. This is what "advancement imputes topology on the
    output at every stage" means concretely.

  * Operationally you never observe a full E. Each keypress yields exactly
    one cell ``E_t(p_t) = c_t`` of a *moving* permutation (and with a
    plugboard that cell is masked to ``P(E_t(P(p_t)))``). With known
    plaintext and no plugboard, ~5 crib letters uniquely resolve the
    configuration — each letter is a ~1/26 filter (empirically
    42172 -> 1617 -> 69 -> 2 -> 1 survivors).

Two resolvers follow from this:

  * :meth:`RotorLandscape.resolve_geometry` — O(1) lookup from a full E to
    its config. Use when a full geometry has been recovered by other means.

  * :func:`resolve_crib` — prune the config space by matching a known
    plaintext/ciphertext crib, the operational path. Returns the surviving
    configurations; narrows to one in a handful of letters.

Scope / honesty note. The instantaneous index resolves ``(rotor order,
offsets)`` under a fixed reflector; offsets alone do not separate absolute
position from ring setting — only a *turnover* observed within the window
does (the ring is invisible until the middle rotor steps). And the crib
resolver assumes a known (or absent) plugboard; with an unknown plugboard
each crib cell is masked and the plugboard must be solved jointly, which is
what the beam-search / hyperchart code already does. The landscape does not
by itself read plugboard-enciphered traffic — it collapses the rotor search
so that only the plugboard remains.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from enigma.schematic import (
    Config,
    letter_path,
    operative_geometry,
    stepped_positions,
)
from enigma.simulator import M3_ROTORS


def m3_triples(rotors: tuple[str, ...] = M3_ROTORS) -> list[tuple[str, str, str]]:
    """All ordered rotor triples (left, middle, right) from ``rotors``."""
    return [t for t in itertools.permutations(rotors, 3)]


def _offset_config(triple: tuple[str, str, str], reflector: str,
                   offsets: tuple[int, int, int]) -> Config:
    """A Config whose stepped geometry at the given offsets is E.

    The instantaneous geometry depends only on offset = position - ring, so
    we canonicalise with ring = AAA and position = offset.
    """
    return Config(rotor_names=triple, reflector_name=reflector,
                  ring_settings=(0, 0, 0), start_positions=offsets)


def geometry_at_offsets(triple: tuple[str, str, str], reflector: str,
                        offsets: tuple[int, int, int]) -> list[int]:
    """Operative geometry E for a rotor triple at a fixed offset-triple."""
    return operative_geometry(_offset_config(triple, reflector, offsets), offsets)


# ------------------------------------------------------------------
# Instantaneous-geometry index (the precomputed possibility landscape)
# ------------------------------------------------------------------


@dataclass
class RotorLandscape:
    """Injective map: full operative geometry E -> (rotor triple, offsets).

    Building the full M3 landscape for one reflector is ~10^6 entries and
    takes tens of seconds. Pass a subset of ``triples`` for a partial index.
    """

    reflector: str = "B"
    index: dict[bytes, tuple[tuple[str, str, str], tuple[int, int, int]]] = field(
        default_factory=dict)
    collisions: int = 0
    cross_triple_collisions: int = 0

    def build(self, triples: list[tuple[str, str, str]] | None = None) -> "RotorLandscape":
        triples = triples if triples is not None else m3_triples()
        idx = self.index
        for triple in triples:
            for oL in range(26):
                for oM in range(26):
                    for oR in range(26):
                        E = bytes(geometry_at_offsets(triple, self.reflector,
                                                      (oL, oM, oR)))
                        prev = idx.get(E)
                        if prev is not None:
                            self.collisions += 1
                            if prev[0] != triple:
                                self.cross_triple_collisions += 1
                        else:
                            idx[E] = (triple, (oL, oM, oR))
        return self

    def resolve_geometry(
        self, geometry: list[int] | bytes
    ) -> tuple[tuple[str, str, str], tuple[int, int, int]] | None:
        """Return the (triple, offsets) that produced this full E, or None."""
        key = geometry if isinstance(geometry, bytes) else bytes(geometry)
        return self.index.get(key)

    def __len__(self) -> int:
        return len(self.index)


# ------------------------------------------------------------------
# Crib resolver (the operational path)
# ------------------------------------------------------------------


def _clean(text: str) -> list[int]:
    return [ord(c) - 65 for c in text.upper() if "A" <= c <= "Z"]


def resolve_crib(
    plaintext: str,
    ciphertext: str,
    *,
    reflector: str = "B",
    triples: list[tuple[str, str, str]] | None = None,
    rings: tuple[int, int, int] = (0, 0, 0),
    limit: int | None = None,
) -> list[tuple[tuple[str, str, str], tuple[int, int, int]]]:
    """Configs whose trajectory turns ``plaintext`` into ``ciphertext``.

    Assumes no plugboard (or a plugboard already stripped from both texts).
    Enumerates rotor triples x 26^3 start positions at the given ``rings``
    and keeps those matching every crib letter (early-abort). Returns the
    list of surviving ``(triple, start_positions)``.

    ``rings`` defaults to AAA; because only offset = position - ring enters
    the instantaneous geometry, that resolves the *offset* trajectory. To
    fix absolute rings you need a turnover inside the crib window.
    """
    P = _clean(plaintext)
    C = _clean(ciphertext)
    n = min(len(P), len(C))
    if limit is not None:
        n = min(n, limit)
    if n == 0:
        raise ValueError("need at least one aligned plaintext/ciphertext letter")
    P, C = P[:n], C[:n]

    triples = triples if triples is not None else m3_triples()
    survivors: list[tuple[tuple[str, str, str], tuple[int, int, int]]] = []
    for triple in triples:
        for s0 in range(26):
            for s1 in range(26):
                for s2 in range(26):
                    cfg = Config(rotor_names=triple, reflector_name=reflector,
                                 ring_settings=rings, start_positions=(s0, s1, s2))
                    posns = stepped_positions(cfg, n)
                    ok = True
                    for t in range(n):
                        if letter_path(cfg, posns[t], P[t])[-1] != C[t]:
                            ok = False
                            break
                    if ok:
                        survivors.append((triple, (s0, s1, s2)))
    return survivors


def resolution_curve(
    plaintext: str,
    ciphertext: str,
    *,
    reflector: str = "B",
    triples: list[tuple[str, str, str]] | None = None,
    rings: tuple[int, int, int] = (0, 0, 0),
    lengths: list[int] | None = None,
) -> list[tuple[int, int]]:
    """Survivor count as a function of crib length.

    Returns ``[(k, n_survivors), ...]`` — the empirical 1/26-per-letter
    collapse of the possibility landscape.
    """
    P = _clean(plaintext)
    C = _clean(ciphertext)
    n = min(len(P), len(C))
    lengths = lengths if lengths is not None else list(range(1, min(n, 8) + 1))
    curve: list[tuple[int, int]] = []
    for k in lengths:
        if k > n:
            break
        survivors = resolve_crib(plaintext, ciphertext, reflector=reflector,
                                 triples=triples, rings=rings, limit=k)
        curve.append((k, len(survivors)))
        if len(survivors) <= 1:
            break
    return curve


# ------------------------------------------------------------------
# Characterising how advancement imputes topology
# ------------------------------------------------------------------


def stepping_events(cfg: Config, length: int) -> list[dict]:
    """Per-step record of which rotors moved and any turnover.

    ``moved`` is the set of rotors ('L','M','R') that advanced going into
    step t. The right rotor always moves; the middle moves on a right-rotor
    notch (or a double-step); the left moves with the middle.
    """
    posns = stepped_positions(cfg, length)
    events: list[dict] = []
    prev = tuple(cfg.start_positions)
    for t, pos in enumerate(posns):
        moved = set()
        for i, tag in enumerate("LMR"):
            if pos[i] != prev[i]:
                moved.add(tag)
        events.append({
            "step": t,
            "positions": "".join(chr(p + 65) for p in pos),
            "moved": moved,
            "middle_stepped": "M" in moved,
            "double_step": moved == {"L", "M", "R"},
        })
        prev = pos
    return events


def geometry_differential(cfg: Config, length: int) -> list[int]:
    """How many of the 26 entries of E change at each step.

    Because the right rotor conjugates the whole cascade, this is ~26 every
    step: the operative geometry is globally reshuffled per keypress. The
    function exists to make that fact measurable rather than asserted.
    """
    Es = [operative_geometry(cfg, p) for p in stepped_positions(cfg, length)]
    out = [0]
    for t in range(1, len(Es)):
        out.append(sum(1 for i in range(26) if Es[t][i] != Es[t - 1][i]))
    return out
