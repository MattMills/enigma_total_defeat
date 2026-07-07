"""Tests for the possibility-landscape resolver."""

from enigma.landscape import (
    RotorLandscape,
    geometry_at_offsets,
    geometry_differential,
    m3_triples,
    resolution_curve,
    resolve_crib,
    stepping_events,
)
from enigma.schematic import Config
from enigma.simulator import Enigma


def test_m3_triples_count():
    assert len(m3_triples()) == 60  # 5 * 4 * 3 ordered


def test_index_injective_on_subset():
    """No two (triple, offsets) collide on the same geometry."""
    triples = m3_triples()[:3]  # keep the test fast
    land = RotorLandscape(reflector="B").build(triples)
    assert land.collisions == 0
    assert land.cross_triple_collisions == 0
    assert len(land) == len(triples) * 26**3


def test_resolve_geometry_roundtrip():
    triples = m3_triples()[:2]
    land = RotorLandscape(reflector="B").build(triples)
    triple = triples[1]
    offsets = (5, 11, 20)
    E = geometry_at_offsets(triple, "B", offsets)
    assert land.resolve_geometry(E) == (triple, offsets)


def test_resolve_geometry_miss_returns_none():
    land = RotorLandscape(reflector="B").build(m3_triples()[:1])
    # A trivially impossible "geometry" (identity is never fixed-point-free E).
    assert land.resolve_geometry(bytes(range(26))) is None


def test_crib_resolves_true_config():
    """A short known-plaintext crib recovers the hidden rotor config."""
    triple = ("III", "I", "IV")
    start = (7, 2, 19)
    m = Enigma(rotor_names=triple, reflector_name="B",
               positions=list(start), ring_settings=[0, 0, 0])
    plain = "DIEWEHRMACHTGREIFTAN"
    cipher = m.encrypt(plain)

    survivors = resolve_crib(plain, cipher, reflector="B")
    assert (triple, start) in survivors
    assert len(survivors) == 1


def test_resolution_curve_is_monotone_and_collapses():
    triple = ("II", "V", "III")
    start = (1, 4, 9)
    m = Enigma(rotor_names=triple, reflector_name="B",
               positions=list(start), ring_settings=[0, 0, 0])
    plain = "OBERKOMMANDODERWEHRMACHT"
    cipher = m.encrypt(plain)

    curve = resolution_curve(plain, cipher, reflector="B",
                             lengths=[1, 2, 3, 4, 5, 6, 7, 8])
    counts = [n for _, n in curve]
    # survivors only ever shrink as the crib grows
    assert all(counts[i] >= counts[i + 1] for i in range(len(counts) - 1))
    # and it collapses to a unique config
    assert counts[-1] == 1


def test_geometry_differential_is_global_per_step():
    """Every keypress reshuffles most of E (right rotor conjugation)."""
    cfg = Config(rotor_names=("I", "II", "III"), reflector_name="B")
    diff = geometry_differential(cfg, 12)
    # diff[0] is the seed (0); every subsequent step changes many entries.
    assert diff[0] == 0
    assert all(d >= 20 for d in diff[1:])


def test_stepping_events_detect_middle_turnover():
    """Right rotor at its notch drives the middle rotor on the next step."""
    # Rotor III notch is at V; place right rotor one before so it turns over.
    cfg = Config(rotor_names=("I", "II", "III"), reflector_name="B",
                 start_positions=(0, 0, ord("V") - 65))
    events = stepping_events(cfg, 3)
    # First step: right advances off the notch and carries the middle.
    assert events[0]["middle_stepped"] is True
    assert "R" in events[0]["moved"]
