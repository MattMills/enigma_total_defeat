"""M4 possibility landscape: 4-rotor operative-geometry inversion.

Extends ``enigma/landscape.py`` to the Kriegsmarine M4. Two things change
relative to M3:

  * The rotor triple is three of *eight* (I-V plus naval VI-VIII), ordered —
    336 triples instead of 60.
  * A Greek 4th wheel (Beta/Gamma) and a thin reflector (B-thin/C-thin) sit
    inboard of the stack. Neither steps in normal use, so they COLLAPSE into
    a single "effective reflector" ``U'``.

Verified against the simulator:

  * The 4th wheel + thin reflector produce exactly **104** distinct
    fixed-point-free involutions ``U'`` (2 greek x 2 thin x 26 greek offsets).
  * The M4 operative geometry obeys the *same* conjugation law as M3,

        E = W⁻¹ · U' · W          (W = forward naval rotor stack)

    so M4 needs no new table format — only a larger reflector alphabet.

Because of that law the landscape is **generative, not stored**. Every
geometry is recomputed from the wirings in microseconds, so there is no
large M4 dataset: over M3, the only new data is the wirings for the naval
rotors + Greek wheels (~182 bytes) plus the 104 effective reflectors
(~2.7 KB, and themselves derived from those wirings in ~1 ms). The
336 x 104 x 26³ ≈ 6.1x10⁸-entry *flat* table (~9.8 GB) is deliberately NOT
built — materialising it would only cache a function that is already cheap.

The Greek wheel and thin reflector do not step, so ``U'`` is CONSTANT for a
whole message: an M4 is, from the three stepping rotors' point of view, just
an M3 with one of 104 fixed reflectors. (Historically this is why Beta at
position A + B-thin reproduces UKW-B exactly — M4 was backward compatible
with M3.)

Resolution uses only the conjugation. From a full geometry,

        W · E · W⁻¹ = U'

so scanning ``(triple, offsets)`` and testing whether ``W E W⁻¹`` is one of
the 104 effective reflectors recovers the ENTIRE 4-rotor configuration —
rotor order, offsets, Greek wheel, thin reflector and Greek offset — in a
few seconds, with no stored table. :meth:`M4Landscape.serialize_slice` is an
OPTIONAL interchange format for a single config slice (never the whole
space); it is not how the resolver works.
"""

from __future__ import annotations

import itertools
import json
import struct
from dataclasses import dataclass

from enigma.simulator import ROTORS, REFLECTORS, NAVAL_ROTORS, GREEK_ROTORS, M4_REFLECTORS


THIN_REFLECTORS = M4_REFLECTORS  # ("B-thin", "C-thin")


def _through(sig: int, rotor, off: int, forward: bool) -> int:
    table = rotor.wiring if forward else rotor.inverse
    return (table[(sig + off) % 26] - off) % 26


def naval_triples(rotors: tuple[str, ...] = NAVAL_ROTORS) -> list[tuple[str, str, str]]:
    """All ordered (left, middle, right) triples from the eight M4 rotors."""
    return [t for t in itertools.permutations(rotors, 3)]


# ------------------------------------------------------------------
# Effective reflectors: the collapsed Greek wheel + thin reflector
# ------------------------------------------------------------------


@dataclass(frozen=True)
class GreekSetting:
    greek: str          # "Beta" | "Gamma"
    thin: str           # "B-thin" | "C-thin"
    greek_offset: int   # 0..25  (greek_position - greek_ring)


def effective_reflector(setting: GreekSetting) -> tuple[int, ...]:
    """Collapse a Greek wheel + thin reflector into one involution U'."""
    G = ROTORS[setting.greek]
    U = REFLECTORS[setting.thin].wiring
    o = setting.greek_offset % 26
    out = [0] * 26
    for x in range(26):
        s = _through(x, G, o, True)
        s = U[s]
        s = _through(s, G, o, False)
        out[x] = s
    return tuple(out)


def build_effective_reflectors() -> dict[tuple[int, ...], GreekSetting]:
    """The 104 distinct effective reflectors, keyed by the involution itself."""
    table: dict[tuple[int, ...], GreekSetting] = {}
    for greek in GREEK_ROTORS:
        for thin in THIN_REFLECTORS:
            for goff in range(26):
                setting = GreekSetting(greek, thin, goff)
                U = effective_reflector(setting)
                # Each is a fixed-point-free involution; keep the first
                # provenance if two settings ever coincide (they do not).
                table.setdefault(U, setting)
    return table


# ------------------------------------------------------------------
# Forward rotor stack W and the geometry law E = W^-1 U' W
# ------------------------------------------------------------------


def forward_stack(triple: tuple[str, str, str], offsets: tuple[int, int, int]) -> list[int]:
    """W: forward through right -> middle -> left (no reflector)."""
    L, M, R = (ROTORS[n] for n in triple)
    oL, oM, oR = offsets
    W = [0] * 26
    for x in range(26):
        s = _through(x, R, oR, True)
        s = _through(s, M, oM, True)
        s = _through(s, L, oL, True)
        W[x] = s
    return W


def geometry(triple: tuple[str, str, str], offsets: tuple[int, int, int],
             u_prime: tuple[int, ...]) -> list[int]:
    """E = W⁻¹ · U' · W for an M4 configuration."""
    W = forward_stack(triple, offsets)
    Winv = [0] * 26
    for x, w in enumerate(W):
        Winv[w] = x
    return [Winv[u_prime[W[x]]] for x in range(26)]


@dataclass(frozen=True)
class M4Solution:
    rotors: tuple[str, str, str]
    offsets: tuple[int, int, int]
    greek: str
    thin: str
    greek_offset: int

    def describe(self) -> str:
        off = "".join(chr(o + 65) for o in self.offsets)
        return (f"{'-'.join(self.rotors)} offs={off}  "
                f"{self.greek}@{chr(self.greek_offset + 65)} / {self.thin}")


# ------------------------------------------------------------------
# Landscape / resolver
# ------------------------------------------------------------------


class M4Landscape:
    """Conjugation-based inversion of the 4-rotor operative geometry."""

    def __init__(self) -> None:
        self.effective: dict[tuple[int, ...], GreekSetting] = build_effective_reflectors()

    def resolve_geometry(
        self,
        geom: list[int],
        triples: list[tuple[str, str, str]] | None = None,
        find_all: bool = False,
    ) -> list[M4Solution]:
        """Recover the M4 config(s) that produce a full operative geometry E.

        Uses ``W E W⁻¹ = U'``: for each candidate ``(triple, offsets)`` the
        conjugate of E must be one of the 104 effective reflectors. Returns
        the matching solution(s); by injectivity there is exactly one over
        the full triple set (set ``find_all`` to confirm uniqueness on a
        subset).
        """
        E = list(geom)
        triples = triples if triples is not None else naval_triples()
        out: list[M4Solution] = []
        for triple in triples:
            for oL in range(26):
                for oM in range(26):
                    for oR in range(26):
                        W = forward_stack(triple, (oL, oM, oR))
                        Winv = [0] * 26
                        for x, w in enumerate(W):
                            Winv[w] = x
                        V = tuple(W[E[Winv[x]]] for x in range(26))  # W E W^-1
                        setting = self.effective.get(V)
                        if setting is not None:
                            out.append(M4Solution(
                                rotors=triple, offsets=(oL, oM, oR),
                                greek=setting.greek, thin=setting.thin,
                                greek_offset=setting.greek_offset))
                            if not find_all:
                                return out
        return out

    # -- rainbow-table serialization of a config slice ---------------------

    # Row layout: 8-byte E-hash + 8-byte config
    #   triple_id:H(2)  greek_id:B(1)  thin_id:B(1)  greek_offset:B(1)
    #   oL:B  oM:B  oR:B (3)  -> 8 config bytes -> 16-byte rows.
    _ROW_FMT = ">8sHBBBBBB"
    _ROW_BYTES = struct.calcsize(_ROW_FMT)  # 16

    def serialize_slice(
        self,
        path: str,
        triples: list[tuple[str, str, str]],
        settings: list[GreekSetting] | None = None,
    ) -> dict:
        """Write a compact ``hash(E) -> config`` table for a config slice.

        Format: a JSON header line, then fixed-width binary rows of
        ``8-byte E-hash + 8-byte packed config`` (16 bytes/row). The full
        config is recoverable from every row via :func:`load_slice`. Returns
        build stats. The full M4 table is ~6.1x10⁸ rows, so callers
        serialize only the slice they need.
        """
        import hashlib

        if settings is None:
            settings = [GreekSetting(g, t, o)
                        for g in GREEK_ROTORS for t in THIN_REFLECTORS
                        for o in range(26)]
        triple_ids = {t: i for i, t in enumerate(triples)}
        greek_ids = {g: i for i, g in enumerate(GREEK_ROTORS)}
        thin_ids = {t: i for i, t in enumerate(THIN_REFLECTORS)}

        rows = 0
        header = {
            "kind": "enigma-m4-rainbow-slice",
            "row_bytes": self._ROW_BYTES,
            "triples": ["-".join(t) for t in triples],
            "greek": list(GREEK_ROTORS),
            "thin": list(THIN_REFLECTORS),
            "hash": "sha256-8",
        }
        with open(path, "wb") as fh:
            fh.write((json.dumps(header) + "\n").encode())
            for setting in settings:
                U = effective_reflector(setting)
                for triple in triples:
                    for oL in range(26):
                        for oM in range(26):
                            for oR in range(26):
                                E = geometry(triple, (oL, oM, oR), U)
                                h = hashlib.sha256(bytes(E)).digest()[:8]
                                fh.write(struct.pack(
                                    self._ROW_FMT, h,
                                    triple_ids[triple],
                                    greek_ids[setting.greek],
                                    thin_ids[setting.thin],
                                    setting.greek_offset,
                                    oL, oM, oR))
                                rows += 1
        return {"rows": rows, "row_bytes": self._ROW_BYTES, "path": path}

    @staticmethod
    def load_slice(path: str) -> dict[bytes, M4Solution]:
        """Load a serialized slice into ``{E-hash: M4Solution}``."""
        with open(path, "rb") as fh:
            header = json.loads(fh.readline().decode())
            triples = [tuple(s.split("-")) for s in header["triples"]]
            greek = header["greek"]
            thin = header["thin"]
            table: dict[bytes, M4Solution] = {}
            row_bytes = header["row_bytes"]
            while True:
                row = fh.read(row_bytes)
                if len(row) < row_bytes:
                    break
                h, tid, gid, thid, goff, oL, oM, oR = struct.unpack(
                    M4Landscape._ROW_FMT, row)
                table[h] = M4Solution(
                    rotors=triples[tid], offsets=(oL, oM, oR),
                    greek=greek[gid], thin=thin[thid], greek_offset=goff)
        return table

    @staticmethod
    def lookup_hash(table: dict[bytes, M4Solution], geom: list[int]) -> M4Solution | None:
        """O(1) rainbow-table lookup of a full geometry E in a loaded slice."""
        import hashlib
        return table.get(hashlib.sha256(bytes(geom)).digest()[:8])
