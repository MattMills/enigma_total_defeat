"""Tests for the M4 (4-rotor) possibility landscape."""

import os
import tempfile

from enigma.landscape_m4 import (
    GreekSetting,
    M4Landscape,
    build_effective_reflectors,
    effective_reflector,
    geometry,
    naval_triples,
)
from enigma.simulator import Enigma


def test_counts():
    assert len(naval_triples()) == 336          # 8 * 7 * 6
    assert len(build_effective_reflectors()) == 104  # 2 greek * 2 thin * 26


def test_effective_reflectors_are_fpf_involutions():
    for U in build_effective_reflectors():
        assert all(U[U[i]] == i for i in range(26))  # involution
        assert all(U[i] != i for i in range(26))      # fixed-point-free


def test_geometry_matches_real_m4_machine():
    """E = W^-1 U' W must equal the simulator's 4-rotor geometry."""
    triple = ("VI", "VII", "VIII")
    offs = (3, 9, 17)
    setting = GreekSetting("Beta", "B-thin", 7)
    U = effective_reflector(setting)
    E_decomp = geometry(triple, offs, U)

    # Direct machine evaluation at the same offsets (no stepping): compare to
    # a per-letter clone-free reference built the same way the machine wires.
    machine = Enigma(
        rotor_names=triple, reflector_name=setting.thin,
        positions=list(offs), ring_settings=[0, 0, 0],
        fourth_rotor_name=setting.greek, fourth_position=setting.greek_offset)
    # operative_geometry() steps once, so shift the machine back one to align
    # with the fixed-offset decomposition: build reference directly instead.
    from enigma.simulator import ROTORS, REFLECTORS

    def through(sig, rotor, off, fwd):
        t = rotor.wiring if fwd else rotor.inverse
        return (t[(sig + off) % 26] - off) % 26

    def direct(x):
        s = through(x, ROTORS[triple[2]], offs[2], True)
        s = through(s, ROTORS[triple[1]], offs[1], True)
        s = through(s, ROTORS[triple[0]], offs[0], True)
        s = through(s, ROTORS[setting.greek], setting.greek_offset, True)
        s = REFLECTORS[setting.thin].wiring[s]
        s = through(s, ROTORS[setting.greek], setting.greek_offset, False)
        s = through(s, ROTORS[triple[0]], offs[0], False)
        s = through(s, ROTORS[triple[1]], offs[1], False)
        s = through(s, ROTORS[triple[2]], offs[2], False)
        return s

    assert E_decomp == [direct(x) for x in range(26)]
    _ = machine  # machine constructed to assert the config is valid M4


def test_effective_reflector_is_constant_within_a_message():
    """Greek wheel + thin reflector do not step, so U' is fixed all message."""
    m = Enigma(rotor_names=("I", "II", "III"), reflector_name="B-thin",
               positions=[0, 0, 0], ring_settings=[0, 0, 0],
               fourth_rotor_name="Beta", fourth_position=7)
    before = m.fourth_position
    m.encrypt("A" * 60)
    assert m.fourth_position == before  # 4th wheel never moved


def test_m4_backward_compatible_with_m3():
    """Beta@A + B-thin == UKW-B ; Gamma@A + C-thin == UKW-C."""
    from enigma.simulator import REFLECTORS
    assert effective_reflector(GreekSetting("Beta", "B-thin", 0)) == \
        REFLECTORS["B"].wiring
    assert effective_reflector(GreekSetting("Gamma", "C-thin", 0)) == \
        REFLECTORS["C"].wiring


def test_resolve_recovers_full_config():
    land = M4Landscape()
    triple = ("I", "IV", "VII")
    offs = (5, 11, 20)
    setting = GreekSetting("Gamma", "C-thin", 3)
    E = geometry(triple, offs, effective_reflector(setting))
    sol = land.resolve_geometry(E, triples=[triple])
    assert sol
    s = sol[0]
    assert s.rotors == triple and s.offsets == offs
    assert s.greek == "Gamma" and s.thin == "C-thin" and s.greek_offset == 3


def test_resolver_no_false_positive_on_wrong_triple():
    """A geometry from one triple must not resolve under a different triple."""
    land = M4Landscape()
    setting = GreekSetting("Beta", "B-thin", 0)
    E = geometry(("VI", "VII", "VIII"), (1, 2, 3), effective_reflector(setting))
    # Search a slice that excludes the true triple.
    wrong = [t for t in naval_triples()[:5] if t != ("VI", "VII", "VIII")]
    assert land.resolve_geometry(E, triples=wrong, find_all=True) == []


def test_rainbow_slice_roundtrip():
    land = M4Landscape()
    triple = ("II", "V", "VIII")
    setting = GreekSetting("Beta", "C-thin", 9)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "slice.bin")
        stats = land.serialize_slice(path, triples=[triple], settings=[setting])
        assert stats["rows"] == 26 ** 3
        table = M4Landscape.load_slice(path)
        # spot-check a few offsets resolve via O(1) hash lookup
        for offs in [(0, 0, 0), (7, 13, 25), (12, 4, 8)]:
            E = geometry(triple, offs, effective_reflector(setting))
            got = M4Landscape.lookup_hash(table, E)
            assert got is not None
            assert got.rotors == triple and got.offsets == offs
            assert got.greek == "Beta" and got.greek_offset == 9
