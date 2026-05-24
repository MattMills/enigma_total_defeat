"""Tests for the Enigma simulator.

Verifies the structural invariants required by Part II of the design doc
(involution, fixed-point-free, cycle type 2^13) plus historical test
vectors and round-trip correctness.
"""

from __future__ import annotations

import pytest

from enigma.simulator import (
    Enigma,
    Plugboard,
    REFLECTORS,
    ROTORS,
)


def _cycle_type(perm: tuple[int, ...]) -> tuple[int, ...]:
    seen = [False] * len(perm)
    cycles: list[int] = []
    for i in range(len(perm)):
        if seen[i]:
            continue
        j = i
        n = 0
        while not seen[j]:
            seen[j] = True
            j = perm[j]
            n += 1
        cycles.append(n)
    return tuple(sorted(cycles))


# ---------------------------------------------------------------- rotors


def test_rotor_inverses_are_inverses():
    for name, rotor in ROTORS.items():
        for i in range(26):
            assert rotor.inverse[rotor.wiring[i]] == i, name


def test_reflectors_are_fixed_point_free_involutions():
    for name, refl in REFLECTORS.items():
        for i in range(26):
            assert refl.wiring[i] != i, f"{name} has fixed point"
            assert refl.wiring[refl.wiring[i]] == i, f"{name} not involution"


# ---------------------------------------------------------------- operative geometry


def test_operative_geometry_is_involution_and_fixed_point_free():
    machine = Enigma(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=[0, 0, 0],
        ring_settings=[0, 0, 0],
    )
    for _ in range(50):
        geom = machine.operative_geometry()
        for i in range(26):
            assert geom[i] != i, "fixed point in operative geometry"
            assert geom[geom[i]] == i, "operative geometry not involution"
        assert _cycle_type(geom) == tuple([2] * 13)
        # Advance the machine
        machine.encrypt_letter(0)


def test_operative_geometry_matches_encrypt_letter():
    machine = Enigma(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=[0, 0, 0],
        ring_settings=[0, 0, 0],
    )
    for _ in range(30):
        geom = machine.operative_geometry()
        letter = 7
        encrypted = machine.encrypt_letter(letter)
        assert geom[letter] == encrypted


# ---------------------------------------------------------------- round trip


def test_round_trip_no_plugboard():
    plaintext = "DASISTEINTESTDERENIGMAIMPLEMENTIERUNGXENDE"
    cfg = dict(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=[5, 12, 20],
        ring_settings=[0, 0, 0],
    )
    enc = Enigma(**cfg)
    ciphertext = enc.encrypt(plaintext)
    dec = Enigma(**cfg)
    recovered = dec.encrypt(ciphertext)
    assert recovered == plaintext
    # And no letter encrypts to itself.
    for p, c in zip(plaintext, ciphertext):
        assert p != c


def test_round_trip_with_plugboard():
    plaintext = "WETTERBERICHTHEUTEKLARSICHTNULLNULLDREINULL"
    plug = Plugboard.from_pairs(["AB", "CD", "EF", "GH", "IJ"])
    cfg = dict(
        rotor_names=("II", "IV", "V"),
        reflector_name="C",
        positions=[3, 9, 14],
        ring_settings=[1, 2, 3],
    )
    enc = Enigma(plugboard=Plugboard(mapping=list(plug.mapping)), **cfg)
    ciphertext = enc.encrypt(plaintext)
    dec = Enigma(plugboard=Plugboard(mapping=list(plug.mapping)), **cfg)
    assert dec.encrypt(ciphertext) == plaintext


# --------------------------------------------------------------- double-step


def test_double_stepping_happens():
    # Configure middle rotor to be at its notch so the next step triggers
    # the Wehrmacht double-step anomaly.
    rotor_ii_notch = ROTORS["II"].notch  # E -> 4
    machine = Enigma(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        # right rotor any, middle rotor at its notch, left rotor 0
        positions=[0, rotor_ii_notch, 0],
        ring_settings=[0, 0, 0],
    )
    before = list(machine.positions)
    machine.encrypt_letter(0)
    after = list(machine.positions)
    # Right always advances. Because middle was at its notch, middle and
    # left both advance too.
    assert after[2] == (before[2] + 1) % 26
    assert after[1] == (before[1] + 1) % 26
    assert after[0] == (before[0] + 1) % 26


# ----------------------------------------------------------- known test vector


def test_known_enigma_test_vector():
    """Historical test: I-II-III, UKW-B, positions AAA, rings AAA, no plugboard.

    The phrase "AAAAA" should encipher to "BDZGO" with these settings, a
    widely cited Enigma I demonstration vector.
    """
    machine = Enigma(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=[0, 0, 0],
        ring_settings=[0, 0, 0],
    )
    assert machine.encrypt("AAAAA") == "BDZGO"
