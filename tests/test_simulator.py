"""Tests for the Enigma simulator (M3 and M4).

Verifies structural invariants required by Part II of the design doc
(involution, fixed-point-free, cycle type 2^13). Tests M4 round-trip,
fast_trajectory correctness, and naval double-notch stepping.
"""

from __future__ import annotations

import pytest

from enigma.simulator import (
    Enigma,
    Plugboard,
    REFLECTORS,
    ROTORS,
    fast_trajectory,
)


def _cycle_type(perm: tuple[int, ...] | list[int]) -> tuple[int, ...]:
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


def test_naval_rotors_have_double_notch():
    for name in ("VI", "VII", "VIII"):
        assert len(ROTORS[name].notches) == 2, f"{name} should have 2 notches"
    assert ord("Z") - 65 in ROTORS["VI"].notches
    assert ord("M") - 65 in ROTORS["VI"].notches


def test_greek_rotors_have_no_notch():
    for name in ("Beta", "Gamma"):
        assert len(ROTORS[name].notches) == 0


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


# ---------------------------------------------------------------- fast trajectory


def test_fast_trajectory_matches_operative_geometry():
    """fast_trajectory must produce the same permutations as the stateful machine."""
    cfg = dict(
        rotor_names=("II", "IV", "V"),
        reflector_name="B",
        positions=[3, 9, 14],
        ring_settings=[1, 2, 3],
    )
    machine = Enigma(**cfg)
    traj = fast_trajectory(
        rotor_names=("II", "IV", "V"),
        reflector_name="B",
        start_positions=(3, 9, 14),
        ring_settings=(1, 2, 3),
        length=40,
    )
    for t in range(40):
        geom = machine.operative_geometry()
        assert tuple(traj[t]) == geom, f"mismatch at t={t}"
        machine.encrypt_letter(0)


def test_fast_trajectory_m4():
    """M4 fast_trajectory should match M4 Enigma encrypt."""
    cfg = dict(
        rotor_names=("I", "II", "III"),
        reflector_name="B-thin",
        positions=[0, 0, 0],
        ring_settings=[0, 0, 0],
        fourth_rotor_name="Beta",
        fourth_position=0,
        fourth_ring=0,
    )
    machine = Enigma(**cfg)
    traj = fast_trajectory(
        rotor_names=("I", "II", "III"),
        reflector_name="B-thin",
        start_positions=(0, 0, 0),
        ring_settings=(0, 0, 0),
        length=30,
        fourth_rotor_name="Beta",
        fourth_position=0,
        fourth_ring=0,
    )
    for t in range(30):
        geom = machine.operative_geometry()
        for letter in range(26):
            assert traj[t][letter] == geom[letter], f"M4 mismatch at t={t} letter={letter}"
        machine.encrypt_letter(0)


def test_fast_trajectory_all_involutions():
    """Every E_t from fast_trajectory must be a FP-free involution."""
    traj = fast_trajectory(
        rotor_names=("III", "VII", "V"),
        reflector_name="C",
        start_positions=(5, 12, 20),
        ring_settings=(3, 7, 11),
        length=100,
    )
    for t, E in enumerate(traj):
        for i in range(26):
            assert E[i] != i, f"fixed point at t={t}, letter={i}"
            assert E[E[i]] == i, f"not involution at t={t}, letter={i}"
        assert _cycle_type(E) == tuple([2] * 13), f"wrong cycle type at t={t}"


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


def test_round_trip_m4():
    plaintext = "DASWETTERISTHEUTESEHRGUTUNDDIEMASCHINEFUNKTIONIERTBESTENS"
    plug = Plugboard.from_pairs(["AB", "XY"])
    cfg = dict(
        rotor_names=("II", "IV", "V"),
        reflector_name="B-thin",
        positions=[3, 9, 14],
        ring_settings=[0, 0, 0],
        fourth_rotor_name="Beta",
        fourth_position=5,
        fourth_ring=0,
    )
    enc = Enigma(plugboard=Plugboard(mapping=list(plug.mapping)), **cfg)
    ciphertext = enc.encrypt(plaintext)
    dec = Enigma(plugboard=Plugboard(mapping=list(plug.mapping)), **cfg)
    assert dec.encrypt(ciphertext) == plaintext


def test_round_trip_m4_gamma():
    plaintext = "ENIGMAVIERMITGAMMAROTORUNDDUENNEMREFLEKTOR"
    cfg = dict(
        rotor_names=("VII", "VIII", "III"),
        reflector_name="C-thin",
        positions=[10, 15, 20],
        ring_settings=[5, 3, 8],
        fourth_rotor_name="Gamma",
        fourth_position=12,
        fourth_ring=4,
    )
    enc = Enigma(**cfg)
    ciphertext = enc.encrypt(plaintext)
    dec = Enigma(**cfg)
    assert dec.encrypt(ciphertext) == plaintext


# --------------------------------------------------------------- double-step


def test_double_stepping_happens():
    rotor_ii_notch = ROTORS["II"].notches[0]  # E -> 4
    machine = Enigma(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=[0, rotor_ii_notch, 0],
        ring_settings=[0, 0, 0],
    )
    before = list(machine.positions)
    machine.encrypt_letter(0)
    after = list(machine.positions)
    assert after[2] == (before[2] + 1) % 26
    assert after[1] == (before[1] + 1) % 26
    assert after[0] == (before[0] + 1) % 26


def test_double_notch_naval_rotor():
    """Rotor VI at either of its notches (Z=25, M=12) should step middle."""
    for notch_pos in ROTORS["VI"].notches:
        machine = Enigma(
            rotor_names=("I", "II", "VI"),
            reflector_name="B",
            positions=[0, 0, notch_pos],
            ring_settings=[0, 0, 0],
        )
        before = list(machine.positions)
        machine.encrypt_letter(0)
        after = list(machine.positions)
        assert after[1] == (before[1] + 1) % 26, (
            f"naval rotor notch at {notch_pos} failed to step middle"
        )


# ----------------------------------------------------------- known test vector


def test_known_enigma_test_vector():
    """Historical test: I-II-III, UKW-B, positions AAA, rings AAA, no plugboard.
    AAAAA -> BDZGO.
    """
    machine = Enigma(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=[0, 0, 0],
        ring_settings=[0, 0, 0],
    )
    assert machine.encrypt("AAAAA") == "BDZGO"


def test_known_m4_equivalent_when_beta_a():
    """M4 with Beta at A and B-thin should match M3 with UKW-B.

    This is a known equivalence: the combination of Beta at position A
    with B-thin produces the same wiring as UKW-B in the M3.
    """
    plaintext = "HELLOENIGMAFOUR"
    m3 = Enigma(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=[0, 0, 0],
        ring_settings=[0, 0, 0],
    )
    m4 = Enigma(
        rotor_names=("I", "II", "III"),
        reflector_name="B-thin",
        positions=[0, 0, 0],
        ring_settings=[0, 0, 0],
        fourth_rotor_name="Beta",
        fourth_position=0,
        fourth_ring=0,
    )
    assert m3.encrypt(plaintext) == m4.encrypt(plaintext)
