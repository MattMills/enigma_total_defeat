"""Faithful Enigma simulator (M3 and M4).

Implements:
  - Wehrmacht rotors I-V (single notch each).
  - Naval rotors VI-VIII (double notch each, Z and M).
  - Greek rotors Beta and Gamma (no notch, do not step) for M4.
  - Reflectors UKW-A/B/C (M3) and B-thin/C-thin (M4).
  - Plugboard (Steckerbrett).
  - Ring settings (Ringstellung).
  - Wehrmacht stepping with double-step anomaly.

Exposes both letter-level encryption (`Enigma.encrypt`) and operative
geometry sequences (`fast_trajectory`) as required by Part II of the
geometric cryptanalysis design doc.

The fast trajectory builder avoids per-letter machine cloning and is the
hot path used by the GCP attack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _to_int(s: str) -> list[int]:
    return [ord(c) - 65 for c in s]


def _to_str(xs: Iterable[int]) -> str:
    return "".join(chr(x + 65) for x in xs)


@dataclass(frozen=True)
class Rotor:
    name: str
    wiring: tuple[int, ...]        # forward permutation
    inverse: tuple[int, ...]       # inverse permutation
    notches: tuple[int, ...]       # turnover positions (possibly empty)

    @classmethod
    def from_string(
        cls,
        name: str,
        wiring_str: str,
        notch_letters: str = "",
    ) -> "Rotor":
        wiring = tuple(_to_int(wiring_str))
        if len(wiring) != 26 or set(wiring) != set(range(26)):
            raise ValueError(f"rotor {name}: wiring is not a permutation of 0..25")
        inverse = [0] * 26
        for i, w in enumerate(wiring):
            inverse[w] = i
        notches = tuple(ord(c) - 65 for c in notch_letters)
        return cls(
            name=name,
            wiring=wiring,
            inverse=tuple(inverse),
            notches=notches,
        )

    @property
    def notch(self) -> int:
        """Deprecated single-notch accessor; returns first notch or -1."""
        return self.notches[0] if self.notches else -1


@dataclass(frozen=True)
class Reflector:
    name: str
    wiring: tuple[int, ...]

    @classmethod
    def from_string(cls, name: str, wiring_str: str) -> "Reflector":
        return cls(name=name, wiring=tuple(_to_int(wiring_str)))

    def validate(self) -> None:
        for i, w in enumerate(self.wiring):
            if w == i:
                raise ValueError(f"reflector {self.name} has fixed point at {i}")
            if self.wiring[w] != i:
                raise ValueError(f"reflector {self.name} not involution at {i}")


# Historical Wehrmacht rotors (Enigma I / M3 — single notch).
# Historical Kriegsmarine rotors VI-VIII have a double notch at Z and M.
ROTORS: dict[str, Rotor] = {
    "I":     Rotor.from_string("I",     "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II":    Rotor.from_string("II",    "AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III":   Rotor.from_string("III",   "BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV":    Rotor.from_string("IV",    "ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V":     Rotor.from_string("V",     "VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
    "VI":    Rotor.from_string("VI",    "JPGVOUMFYQBENHZRDKASXLICTW", "ZM"),
    "VII":   Rotor.from_string("VII",   "NZJHGRCXMYSWBOUFAIVLPEKQDT", "ZM"),
    "VIII":  Rotor.from_string("VIII",  "FKQHTLXOCBJSPDZRAMEWNIUYGV", "ZM"),
    # Greek rotors for M4 (do not step in normal use).
    "Beta":  Rotor.from_string("Beta",  "LEYJVCNIXWPBQMDRTAKZGFUHOS"),
    "Gamma": Rotor.from_string("Gamma", "FSOKANUERHMBTIYCWLQPZXVGJD"),
}

# M3 reflectors and M4 thin reflectors.
REFLECTORS: dict[str, Reflector] = {
    "A":      Reflector.from_string("A",      "EJMZALYXVBWFCRQUONTSPIKHGD"),
    "B":      Reflector.from_string("B",      "YRUHQSLDPXNGOKMIEBFZCWVJAT"),
    "C":      Reflector.from_string("C",      "FVPJIAOYEDRZXWGCTKUQSBNMHL"),
    "B-thin": Reflector.from_string("B-thin", "ENKQAUYWJICOPBLMDXZVFTHRGS"),
    "C-thin": Reflector.from_string("C-thin", "RDOBJNTKVEHMLFCWZAXGYIPSUQ"),
}

# Convenient subsets used by the attack.
M3_ROTORS = ("I", "II", "III", "IV", "V")
NAVAL_ROTORS = ("I", "II", "III", "IV", "V", "VI", "VII", "VIII")
GREEK_ROTORS = ("Beta", "Gamma")
M3_REFLECTORS = ("A", "B", "C")
M4_REFLECTORS = ("B-thin", "C-thin")

for _r in REFLECTORS.values():
    _r.validate()


@dataclass
class Plugboard:
    """Involution on 26 letters, <=13 disjoint pairs."""
    mapping: list[int] = field(default_factory=lambda: list(range(26)))

    @classmethod
    def from_pairs(cls, pairs: Sequence[tuple[int, int] | str]) -> "Plugboard":
        m = list(range(26))
        seen: set[int] = set()
        for pair in pairs:
            if isinstance(pair, str):
                if len(pair) != 2:
                    raise ValueError(f"plugboard pair must be 2 chars: {pair!r}")
                a, b = ord(pair[0]) - 65, ord(pair[1]) - 65
            else:
                a, b = pair
            if a == b:
                raise ValueError(f"plugboard pair must connect distinct letters: {a},{b}")
            if a in seen or b in seen:
                raise ValueError(f"plugboard letter used twice: {a},{b}")
            seen.add(a)
            seen.add(b)
            m[a], m[b] = b, a
        if len(seen) > 26:
            raise ValueError("too many plugboard pairs")
        return cls(mapping=m)

    @classmethod
    def identity(cls) -> "Plugboard":
        return cls(mapping=list(range(26)))

    def apply(self, x: int) -> int:
        return self.mapping[x]


# ---------------------------------------------------------------------------
# Stateful machine (M3 + M4)
# ---------------------------------------------------------------------------


@dataclass
class Enigma:
    """Stateful Enigma machine.

    Three core rotors (left, middle, right) always.
    Optional fourth (Greek) rotor + thin reflector for M4 mode.
    """

    rotor_names: tuple[str, str, str]              # (left, middle, right)
    reflector_name: str
    positions: list[int]                            # [L, M, R], 0..25
    ring_settings: list[int]                        # [L, M, R], 0..25
    plugboard: Plugboard = field(default_factory=Plugboard.identity)

    # M4 extension:
    fourth_rotor_name: str | None = None            # "Beta" or "Gamma" or None
    fourth_position: int = 0                        # 0..25
    fourth_ring: int = 0                            # 0..25

    def __post_init__(self) -> None:
        self._rotors = tuple(ROTORS[n] for n in self.rotor_names)
        self._reflector = REFLECTORS[self.reflector_name]
        if len(self.positions) != 3 or len(self.ring_settings) != 3:
            raise ValueError("positions and ring_settings must have length 3")
        self.positions = [p % 26 for p in self.positions]
        self.ring_settings = [r % 26 for r in self.ring_settings]
        if self.fourth_rotor_name is not None:
            self._fourth = ROTORS[self.fourth_rotor_name]
            if self._fourth.notches:
                raise ValueError(
                    f"fourth rotor {self.fourth_rotor_name} has notches; "
                    "only Beta/Gamma (no-notch) are valid 4th rotors"
                )
            if not self.reflector_name.endswith("-thin"):
                raise ValueError(
                    "M4 mode requires a thin reflector (B-thin or C-thin)"
                )
            self.fourth_position %= 26
            self.fourth_ring %= 26
        else:
            self._fourth = None
            if self.reflector_name.endswith("-thin"):
                raise ValueError(
                    "thin reflector requires a fourth (Beta/Gamma) rotor"
                )

    # ------------------------------------------------------------------
    # Stepping

    def _step(self) -> None:
        """Advance core rotors per Wehrmacht stepping; 4th rotor never steps."""
        left, middle, right = self._rotors
        right_at_notch = self.positions[2] in right.notches
        middle_at_notch = self.positions[1] in middle.notches

        if middle_at_notch:
            self.positions[0] = (self.positions[0] + 1) % 26
            self.positions[1] = (self.positions[1] + 1) % 26
        elif right_at_notch:
            self.positions[1] = (self.positions[1] + 1) % 26
        self.positions[2] = (self.positions[2] + 1) % 26

    # ------------------------------------------------------------------
    # Letter pipeline

    def _through_rotor(self, signal: int, idx: int, forward: bool) -> int:
        rotor = self._rotors[idx]
        offset = (self.positions[idx] - self.ring_settings[idx]) % 26
        table = rotor.wiring if forward else rotor.inverse
        return (table[(signal + offset) % 26] - offset) % 26

    def _through_fourth(self, signal: int, forward: bool) -> int:
        assert self._fourth is not None
        offset = (self.fourth_position - self.fourth_ring) % 26
        table = self._fourth.wiring if forward else self._fourth.inverse
        return (table[(signal + offset) % 26] - offset) % 26

    def encrypt_letter(self, letter: int) -> int:
        self._step()
        s = self.plugboard.apply(letter)
        for i in (2, 1, 0):
            s = self._through_rotor(s, i, forward=True)
        if self._fourth is not None:
            s = self._through_fourth(s, forward=True)
        s = self._reflector.wiring[s]
        if self._fourth is not None:
            s = self._through_fourth(s, forward=False)
        for i in (0, 1, 2):
            s = self._through_rotor(s, i, forward=False)
        s = self.plugboard.apply(s)
        return s

    def encrypt(self, text: str) -> str:
        out = []
        for c in text:
            if not ("A" <= c <= "Z"):
                continue
            out.append(chr(self.encrypt_letter(ord(c) - 65) + 65))
        return "".join(out)

    def clone(self) -> "Enigma":
        return Enigma(
            rotor_names=self.rotor_names,
            reflector_name=self.reflector_name,
            positions=list(self.positions),
            ring_settings=list(self.ring_settings),
            plugboard=Plugboard(mapping=list(self.plugboard.mapping)),
            fourth_rotor_name=self.fourth_rotor_name,
            fourth_position=self.fourth_position,
            fourth_ring=self.fourth_ring,
        )

    # ------------------------------------------------------------------
    # Operative geometry (slow reference path; the attack uses
    # fast_trajectory() below).

    def operative_geometry(self) -> tuple[int, ...]:
        result = [0] * 26
        for letter in range(26):
            tmp = self.clone()
            result[letter] = tmp.encrypt_letter(letter)
        return tuple(result)

    def trajectory(self, length: int) -> list[tuple[int, ...]]:
        return [tuple(g) for g in fast_trajectory(
            rotor_names=self.rotor_names,
            reflector_name=self.reflector_name,
            start_positions=tuple(self.positions),
            ring_settings=tuple(self.ring_settings),
            length=length,
            fourth_rotor_name=self.fourth_rotor_name,
            fourth_position=self.fourth_position,
            fourth_ring=self.fourth_ring,
        )]


# ---------------------------------------------------------------------------
# Fast trajectory builder (hot path used by the GCP attack)
# ---------------------------------------------------------------------------


def fast_trajectory(
    rotor_names: tuple[str, str, str],
    reflector_name: str,
    start_positions: tuple[int, int, int],
    ring_settings: tuple[int, int, int],
    length: int,
    *,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> list[list[int]]:
    """Return [E'_t for t in 0..length-1], the rotor+reflector permutation
    at each step (without plugboard).

    Stepping is applied BEFORE the t-th permutation is computed, matching
    Enigma.encrypt_letter semantics. The 4th (Greek) rotor does not step,
    so we collapse it together with the thin reflector into a single
    effective reflector before the main loop.
    """
    left = ROTORS[rotor_names[0]]
    middle = ROTORS[rotor_names[1]]
    right = ROTORS[rotor_names[2]]
    refl = REFLECTORS[reflector_name]

    Lw, Le = left.wiring, left.inverse
    Mw, Me = middle.wiring, middle.inverse
    Rw, Re = right.wiring, right.inverse
    Rf = refl.wiring
    right_notches = right.notches
    middle_notches = middle.notches

    # Collapse 4th rotor + thin reflector into a single 26-entry table.
    if fourth_rotor_name is not None:
        fourth = ROTORS[fourth_rotor_name]
        o4 = (fourth_position - fourth_ring) % 26
        combined = [0] * 26
        for x in range(26):
            s = (fourth.wiring[(x + o4) % 26] - o4) % 26
            s = Rf[s]
            s = (fourth.inverse[(s + o4) % 26] - o4) % 26
            combined[x] = s
        Rf = tuple(combined)

    pL, pM, pR = start_positions
    rL, rM, rR = ring_settings
    geom: list[list[int]] = []

    for _ in range(length):
        # Step rotors (right always; middle on double-step or right-notch).
        if pM in middle_notches:
            pL = (pL + 1) % 26
            pM = (pM + 1) % 26
        elif pR in right_notches:
            pM = (pM + 1) % 26
        pR = (pR + 1) % 26

        oL = (pL - rL) % 26
        oM = (pM - rM) % 26
        oR = (pR - rR) % 26

        E = [0] * 26
        for x in range(26):
            s = (Rw[(x + oR) % 26] - oR) % 26
            s = (Mw[(s + oM) % 26] - oM) % 26
            s = (Lw[(s + oL) % 26] - oL) % 26
            s = Rf[s]
            s = (Le[(s + oL) % 26] - oL) % 26
            s = (Me[(s + oM) % 26] - oM) % 26
            s = (Re[(s + oR) % 26] - oR) % 26
            E[x] = s
        geom.append(E)
    return geom
