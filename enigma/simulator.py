"""Faithful Enigma I (Wehrmacht) simulator.

Implements rotors I-V, reflectors UKW-A/B/C, plugboard, and ring settings.
Exposes both letter-level encryption and the operative geometry E_t at each
position, as required by the geometric cryptanalysis attack.
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
    wiring: tuple[int, ...]      # forward permutation
    inverse: tuple[int, ...]     # inverse permutation
    notch: int                   # turnover position (rotor letter at window)

    @classmethod
    def from_string(cls, name: str, wiring_str: str, notch_letter: str) -> "Rotor":
        wiring = tuple(_to_int(wiring_str))
        inverse = [0] * 26
        for i, w in enumerate(wiring):
            inverse[w] = i
        return cls(
            name=name,
            wiring=wiring,
            inverse=tuple(inverse),
            notch=ord(notch_letter) - 65,
        )


@dataclass(frozen=True)
class Reflector:
    name: str
    wiring: tuple[int, ...]

    @classmethod
    def from_string(cls, name: str, wiring_str: str) -> "Reflector":
        return cls(name=name, wiring=tuple(_to_int(wiring_str)))

    def validate(self) -> None:
        # Fixed-point-free involution
        for i, w in enumerate(self.wiring):
            if w == i:
                raise ValueError(f"reflector {self.name} has fixed point at {i}")
            if self.wiring[w] != i:
                raise ValueError(f"reflector {self.name} not involution at {i}")


# Historical Wehrmacht rotors (Enigma I / M3).
ROTORS: dict[str, Rotor] = {
    "I":   Rotor.from_string("I",   "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II":  Rotor.from_string("II",  "AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III": Rotor.from_string("III", "BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV":  Rotor.from_string("IV",  "ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V":   Rotor.from_string("V",   "VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
}

REFLECTORS: dict[str, Reflector] = {
    "A": Reflector.from_string("A", "EJMZALYXVBWFCRQUONTSPIKHGD"),
    "B": Reflector.from_string("B", "YRUHQSLDPXNGOKMIEBFZCWVJAT"),
    "C": Reflector.from_string("C", "FVPJIAOYEDRZXWGCTKUQSBNMHL"),
}

for _r in REFLECTORS.values():
    _r.validate()


@dataclass
class Plugboard:
    """Involution on 26 letters, ≤13 disjoint pairs."""
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


@dataclass
class Enigma:
    """Stateful Enigma machine. Three rotors (left, middle, right)."""

    rotor_names: tuple[str, str, str]              # (left, middle, right)
    reflector_name: str
    positions: list[int]                            # [left, middle, right], 0..25
    ring_settings: list[int]                        # [left, middle, right], 0..25
    plugboard: Plugboard = field(default_factory=Plugboard.identity)

    def __post_init__(self) -> None:
        self._rotors = tuple(ROTORS[n] for n in self.rotor_names)
        self._reflector = REFLECTORS[self.reflector_name]
        if len(self.positions) != 3 or len(self.ring_settings) != 3:
            raise ValueError("positions and ring_settings must have length 3")
        self.positions = [p % 26 for p in self.positions]
        self.ring_settings = [r % 26 for r in self.ring_settings]

    # ------------------------------------------------------------------
    # Stepping

    def _step(self) -> None:
        """Advance rotors according to Wehrmacht stepping (with double-step)."""
        left, middle, right = self._rotors
        # Right always steps. Middle steps if right is at notch (before stepping).
        # Double-step: middle also steps if it itself is at its own notch (this
        # also causes the left rotor to step). The right rotor's notch test is
        # against its position before stepping.
        right_at_notch = self.positions[2] == right.notch
        middle_at_notch = self.positions[1] == middle.notch

        if middle_at_notch:
            # Double-step: middle and left both advance, right also advances.
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

    def encrypt_letter(self, letter: int) -> int:
        self._step()
        s = self.plugboard.apply(letter)
        # Right -> middle -> left
        for i in (2, 1, 0):
            s = self._through_rotor(s, i, forward=True)
        s = self._reflector.wiring[s]
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
        )

    # ------------------------------------------------------------------
    # Operative geometry

    def operative_geometry(self) -> tuple[int, ...]:
        """Return E_t at the current state without advancing the machine.

        E_t is the permutation such that E_t(p_t) = c_t when the machine is
        used at this point in the trajectory. By construction it is a
        fixed-point-free involution with cycle type (2^13).
        """
        # We must step before encrypting, so emulate the step on a clone for
        # every letter without consuming the real machine state.
        result = [0] * 26
        for letter in range(26):
            tmp = self.clone()
            result[letter] = tmp.encrypt_letter(letter)
        return tuple(result)

    def trajectory(self, length: int) -> list[tuple[int, ...]]:
        """Return [E_0, E_1, ..., E_{length-1}] from the current state.

        Stepping is applied in lockstep with encryption: E_t is the geometry
        observed at the t-th encryption (after t+1 steps from start).
        """
        traj: list[tuple[int, ...]] = []
        machine = self.clone()
        for _ in range(length):
            # Compute E_t by trying each letter on a peek-ahead clone.
            peek = machine.clone()
            row = [0] * 26
            for letter in range(26):
                p = peek.clone()
                row[letter] = p.encrypt_letter(letter)
            traj.append(tuple(row))
            # advance the real machine one position
            machine.encrypt_letter(0)
        return traj
