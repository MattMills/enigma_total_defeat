"""Tests for the fold/unfold topology."""

import pytest
from enigma.fold import trace_fold, render_fold


class TestFoldStructure:
    def test_m3_has_9_layers(self):
        ft = trace_fold("AB", rotor_names=("I", "II", "III"), reflector_name="B",
                        positions=(0, 0, 0))
        assert ft.n_layers() == 9

    def test_m4_has_11_layers(self):
        ft = trace_fold("AB", rotor_names=("II", "IV", "I"), reflector_name="B-thin",
                        positions=(0, 0, 0), fourth_rotor_name="Beta")
        assert ft.n_layers() == 11

    def test_fold_point_is_reflector(self):
        ft = trace_fold("A", rotor_names=("I", "II", "III"), reflector_name="B",
                        positions=(0, 0, 0))
        pos = ft.positions[0]
        fold_layer = pos.folded_layers[pos.fold_point]
        assert fold_layer.direction == "reflect"
        assert fold_layer.component == "B"

    def test_mirror_indices_symmetric(self):
        ft = trace_fold("A", rotor_names=("I", "II", "III"), reflector_name="B",
                        positions=(0, 0, 0))
        layers = ft.positions[0].folded_layers
        n = len(layers)
        for i, layer in enumerate(layers):
            assert layer.mirror_index == n - 1 - i

    def test_mirror_pairs_share_offset(self):
        ft = trace_fold("ABCDE", rotor_names=("II", "IV", "V"), reflector_name="B",
                        positions=(1, 11, 0), ring_settings=(1, 20, 11))
        for pos in ft.positions:
            layers = pos.folded_layers
            for i, layer in enumerate(layers):
                mirror = layers[layer.mirror_index]
                if layer.direction == "forward" and mirror.direction == "inverse":
                    assert layer.offset == mirror.offset, (
                        f"t={pos.t} layer {layer.name} offset={layer.offset} "
                        f"mirror {mirror.name} offset={mirror.offset}")
                    assert layer.component == mirror.component

    def test_mirror_pairs_share_component(self):
        ft = trace_fold("ABC", rotor_names=("I", "II", "III"), reflector_name="B",
                        positions=(0, 0, 0))
        for pos in ft.positions:
            layers = pos.folded_layers
            for layer in layers:
                if layer.direction == "forward":
                    mirror = layers[layer.mirror_index]
                    assert layer.component == mirror.component


class TestReflectorProperties:
    def test_reflector_pairs_are_involution(self):
        ft = trace_fold("ABCDE", rotor_names=("II", "IV", "V"), reflector_name="B",
                        positions=(0, 0, 0))
        for pos in ft.positions:
            refl_layer = pos.folded_layers[pos.fold_point]
            a, b = refl_layer.signal_in, refl_layer.signal_out
            assert a != b, "Reflector has fixed point"

    def test_reflector_pairs_fixed_across_positions(self):
        ft = trace_fold("A" * 26, rotor_names=("I", "II", "III"), reflector_name="B",
                        positions=(0, 0, 0))
        first_pairs = ft.positions[0].reflector_pairs_outer
        for pos in ft.positions:
            assert pos.reflector_pairs_outer == first_pairs

    def test_machine_pairs_change_per_position(self):
        ft = trace_fold("ABCDE", rotor_names=("II", "IV", "V"), reflector_name="B",
                        positions=(0, 0, 0))
        pairs_at_0 = ft.positions[0].machine_pairs
        pairs_at_1 = ft.positions[1].machine_pairs
        assert pairs_at_0 != pairs_at_1

    def test_machine_pairs_always_13(self):
        ft = trace_fold("A" * 10, rotor_names=("II", "IV", "V"), reflector_name="B",
                        positions=(1, 11, 0), ring_settings=(1, 20, 11))
        for pos in ft.positions:
            assert len(pos.machine_pairs) == 13

    def test_machine_pairs_are_involution(self):
        ft = trace_fold("A" * 10, rotor_names=("II", "IV", "V"), reflector_name="B",
                        positions=(1, 11, 0), ring_settings=(1, 20, 11))
        for pos in ft.positions:
            mapping = [0] * 26
            for a, b in pos.machine_pairs:
                mapping[a] = b
                mapping[b] = a
            for i in range(26):
                assert mapping[mapping[i]] == i


class TestPairPropagation:
    def test_propagation_starts_at_reflector(self):
        ft = trace_fold("A", rotor_names=("I", "II", "III"), reflector_name="B",
                        positions=(0, 0, 0))
        pos = ft.positions[0]
        assert pos.pair_propagation[0] == pos.reflector_pairs_outer

    def test_propagation_ends_at_machine_pairs(self):
        ft = trace_fold("A", rotor_names=("I", "II", "III"), reflector_name="B",
                        positions=(0, 0, 0))
        pos = ft.positions[0]
        assert pos.pair_propagation[-1] == pos.machine_pairs

    def test_each_propagation_step_has_13_pairs(self):
        ft = trace_fold("ABC", rotor_names=("II", "IV", "V"), reflector_name="B",
                        positions=(1, 11, 0), ring_settings=(1, 20, 11))
        for pos in ft.positions:
            for step_pairs in pos.pair_propagation:
                assert len(step_pairs) == 13

    def test_m4_propagation_has_extra_step(self):
        ft_m3 = trace_fold("A", rotor_names=("I", "II", "III"), reflector_name="B",
                           positions=(0, 0, 0))
        ft_m4 = trace_fold("A", rotor_names=("II", "IV", "I"), reflector_name="B-thin",
                           positions=(0, 0, 0), fourth_rotor_name="Beta")
        n_m3 = len(ft_m3.positions[0].pair_propagation)
        n_m4 = len(ft_m4.positions[0].pair_propagation)
        assert n_m4 == n_m3 + 1


class TestRender:
    def test_render_contains_fold_markers(self):
        ft = trace_fold("ABC", rotor_names=("I", "II", "III"), reflector_name="B",
                        positions=(0, 0, 0))
        output = render_fold(ft, max_positions=2)
        assert "FOLD POINT" in output
        assert "FOLD / UNFOLD" in output
        assert "mirrors" in output
        assert "PAIR PROPAGATION" in output
        assert "MACHINE OUTPUT" in output
