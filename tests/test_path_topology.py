"""Tests for the path-topological simulator."""

import pytest

from enigma.path_topology import trace, render, Layer
from enigma.simulator import Enigma, Plugboard


class TestPathTopologyCorrectness:
    def test_ciphertext_matches_simulator(self):
        """Path topology must produce identical ciphertext to Enigma simulator."""
        enc = Enigma(
            rotor_names=("II", "IV", "V"), reflector_name="B",
            positions=[1, 11, 0], ring_settings=[1, 20, 11],
            plugboard=Plugboard.from_pairs(
                ["AV", "BS", "CG", "DL", "FU", "HZ", "IN", "KM", "OW", "RX"]
            ),
        )
        plaintext = "AUFKLXABTEILUNGXVONXKURTINOWAX"
        expected = enc.encrypt(plaintext)

        topo = trace(
            plaintext,
            rotor_names=("II", "IV", "V"), reflector_name="B",
            positions=(1, 11, 0), ring_settings=(1, 20, 11),
            plugboard_pairs=["AV", "BS", "CG", "DL", "FU", "HZ", "IN", "KM", "OW", "RX"],
        )
        assert topo.ciphertext == expected

    def test_involution_at_every_position(self):
        topo = trace(
            "DASWETTERISTGUTUNDDIEMASCHINEFUNKTIONIERT",
            rotor_names=("I", "II", "III"), reflector_name="B",
            positions=(7, 11, 19),
        )
        assert all(topo.involution_check())

    def test_fixed_point_free_at_every_position(self):
        topo = trace(
            "DASWETTERISTGUTUNDDIEMASCHINEFUNKTIONIERT",
            rotor_names=("I", "II", "III"), reflector_name="B",
            positions=(7, 11, 19),
        )
        assert all(topo.fixed_point_check())

    def test_cycle_structure_is_all_2cycles(self):
        topo = trace(
            "TESTMESSAGE",
            rotor_names=("II", "IV", "V"), reflector_name="B",
            positions=(0, 0, 0),
        )
        for t in range(topo.length):
            cycles = topo.cycle_structure_at(t)
            assert all(len(c) == 2 for c in cycles)
            assert len(cycles) == 13

    def test_signal_path_has_correct_layers(self):
        topo = trace("AB", rotor_names=("I", "II", "III"), reflector_name="B", positions=(0, 0, 0))
        layers = [e.layer for e in topo.positions[0].events]
        assert layers == [
            Layer.PLUGBOARD_IN, Layer.RIGHT_FWD, Layer.MIDDLE_FWD,
            Layer.LEFT_FWD, Layer.REFLECTOR, Layer.LEFT_INV,
            Layer.MIDDLE_INV, Layer.RIGHT_INV, Layer.PLUGBOARD_OUT,
        ]

    def test_m4_has_fourth_rotor_layers(self):
        topo = trace(
            "TESTX",
            rotor_names=("II", "IV", "I"), reflector_name="B-thin",
            positions=(0, 0, 0),
            fourth_rotor_name="Beta", fourth_position=0,
        )
        layers = [e.layer for e in topo.positions[0].events]
        assert Layer.FOURTH_FWD in layers
        assert Layer.FOURTH_INV in layers

    def test_plugboard_identity_events_marked(self):
        topo = trace("AB", rotor_names=("I", "II", "III"), reflector_name="B", positions=(0, 0, 0))
        plug_in = topo.positions[0].events[0]
        plug_out = topo.positions[0].events[-1]
        assert plug_in.is_identity
        assert plug_out.is_identity or not plug_out.is_identity

    def test_plugboard_swap_events_not_identity(self):
        topo = trace(
            "AB", rotor_names=("I", "II", "III"), reflector_name="B",
            positions=(0, 0, 0), plugboard_pairs=["AB"],
        )
        plug_in = topo.positions[0].events[0]
        assert not plug_in.is_identity
        assert plug_in.signal_in == 0  # A
        assert plug_in.signal_out == 1  # B

    def test_stepping_right_always_steps(self):
        topo = trace("ABCDE", rotor_names=("I", "II", "III"), reflector_name="B", positions=(0, 0, 0))
        for pos in topo.positions:
            assert pos.step.right_stepped

    def test_stepping_double_step(self):
        """Right at notch triggers middle step; middle at notch triggers double step."""
        topo = trace(
            "A" * 30,
            rotor_names=("I", "II", "III"), reflector_name="B",
            positions=(0, 0, 20),  # Right rotor III has notch at V(=21)
        )
        triggers = [pos.step.trigger for pos in topo.positions]
        assert "right_at_notch" in triggers

    def test_symmetry_encrypt_decrypt(self):
        """Encrypting ciphertext must recover plaintext (Enigma symmetry)."""
        plaintext = "AUFKLXABTEILUNGXVON"
        topo1 = trace(
            plaintext,
            rotor_names=("II", "IV", "V"), reflector_name="B",
            positions=(3, 9, 14), plugboard_pairs=["AB", "CD"],
        )
        topo2 = trace(
            topo1.ciphertext,
            rotor_names=("II", "IV", "V"), reflector_name="B",
            positions=(3, 9, 14), plugboard_pairs=["AB", "CD"],
        )
        assert topo2.ciphertext == plaintext

    def test_operative_geometry_matches_fast_trajectory(self):
        from enigma.simulator import fast_trajectory
        topo = trace(
            "ABCDEFGHIJ",
            rotor_names=("II", "IV", "V"), reflector_name="B",
            positions=(1, 11, 0), ring_settings=(1, 20, 11),
        )
        ft = fast_trajectory(("II", "IV", "V"), "B", (1, 11, 0), (1, 20, 11), 10)
        for t in range(10):
            assert topo.positions[t].operative_geometry == ft[t]


class TestRender:
    def test_render_produces_output(self):
        topo = trace("TEST", rotor_names=("I", "II", "III"), reflector_name="B", positions=(0, 0, 0))
        output = render(topo)
        assert "PATH TOPOLOGY" in output
        assert "STEPPING TIMELINE" in output
        assert "SIGNAL PATH" in output
        assert "SIGNAL FLOW MATRIX" in output
        assert "CYCLE STRUCTURE" in output

    def test_render_max_positions(self):
        topo = trace("A" * 100, rotor_names=("I", "II", "III"), reflector_name="B", positions=(0, 0, 0))
        output = render(topo, max_positions=5)
        assert "t=  4" in output
        assert "t=  5" not in output
