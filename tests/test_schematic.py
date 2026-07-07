"""Tests for the rotor-action schematic breakdown."""

from enigma.schematic import (
    Config,
    STAGE_LABELS,
    geometry_trajectory,
    letter_path,
    operative_geometry,
    stage_table,
    stepped_positions,
    to_dict,
)
from enigma.simulator import Enigma, fast_trajectory


def _cfg():
    return Config(rotor_names=("I", "II", "III"), reflector_name="B")


def test_letter_path_composes_to_machine_output():
    """The final stage of every letter's path == plugboard-free encryption."""
    cfg = _cfg()
    machine = Enigma(
        rotor_names=cfg.rotor_names,
        reflector_name=cfg.reflector_name,
        positions=list(cfg.start_positions),
        ring_settings=list(cfg.ring_settings),
    )
    og_reference = machine.operative_geometry()  # includes the first step
    positions = stepped_positions(cfg, 1)[0]
    composed = [letter_path(cfg, positions, x)[-1] for x in range(26)]
    assert composed == list(og_reference)


def test_operative_geometry_matches_fast_trajectory():
    """Schematic E_t must equal the attack hot-path trajectory."""
    cfg = Config(rotor_names=("II", "IV", "V"), reflector_name="B",
                 start_positions=(3, 7, 11), ring_settings=(1, 2, 3))
    length = 30
    ours = geometry_trajectory(cfg, length)
    theirs = fast_trajectory(
        rotor_names=cfg.rotor_names,
        reflector_name=cfg.reflector_name,
        start_positions=cfg.start_positions,
        ring_settings=cfg.ring_settings,
        length=length,
    )
    assert ours == theirs


def test_operative_geometry_is_reciprocal_involution():
    cfg = _cfg()
    for positions in stepped_positions(cfg, 5):
        og = operative_geometry(cfg, positions)
        assert sorted(og) == list(range(26))          # permutation
        assert all(og[og[i]] == i for i in range(26))  # involution
        assert all(og[i] != i for i in range(26))      # fixed-point-free


def test_stage_table_shape():
    cfg = _cfg()
    positions = stepped_positions(cfg, 1)[0]
    table = stage_table(cfg, positions)
    assert len(table) == 26
    assert all(len(row) == len(STAGE_LABELS) for row in table)


def test_to_dict_roundtrip_shape():
    cfg = _cfg()
    data = to_dict(cfg, length=4)
    assert len(data["steps"]) == 4
    for step in data["steps"]:
        assert len(step["operative_geometry"]) == 26
        assert len(step["paths"]) == 26
        assert all(len(v) == len(STAGE_LABELS) for v in step["paths"].values())


def test_m4_fourth_rotor_matches_machine():
    """With a Greek rotor + thin reflector the schematic still composes."""
    cfg = Config(
        rotor_names=("I", "II", "III"),
        reflector_name="B-thin",
        fourth_rotor_name="Beta",
        fourth_position=4,
    )
    machine = Enigma(
        rotor_names=cfg.rotor_names,
        reflector_name=cfg.reflector_name,
        positions=list(cfg.start_positions),
        ring_settings=list(cfg.ring_settings),
        fourth_rotor_name=cfg.fourth_rotor_name,
        fourth_position=cfg.fourth_position,
    )
    og_reference = machine.operative_geometry()
    positions = stepped_positions(cfg, 1)[0]
    composed = [letter_path(cfg, positions, x)[-1] for x in range(26)]
    assert composed == list(og_reference)
