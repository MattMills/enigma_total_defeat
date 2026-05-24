"""Tests for the CRT-based progressive solver and plugboard constraint engine."""

from __future__ import annotations

import pytest

from enigma.language import LanguageModel
from enigma.simulator import Enigma, Plugboard
from enigma.solver import (
    PlugboardSolver,
    SolverResult,
    crt,
    extended_gcd,
    progressive_solve,
)
from enigma.attack import initialize_candidates, propagate_bigrams


# ---------------------------------------------------------------- CRT


def test_crt_basic():
    assert crt(0, 2, 0, 13) == 0
    assert crt(1, 2, 0, 13) == 13   # odd, ≡ 0 mod 13
    assert crt(0, 2, 1, 13) == 14   # even, ≡ 1 mod 13
    assert crt(1, 2, 5, 13) == 5    # 5 is odd, 5 mod 13 = 5
    # Verify all 26 values can be reconstructed.
    for n in range(26):
        assert crt(n % 2, 2, n % 13, 13) == n


def test_extended_gcd():
    g, x, y = extended_gcd(2, 13)
    assert g == 1
    assert 2 * x + 13 * y == 1


# ---------------------------------------------------------------- plugboard solver


def test_plugboard_solver_identity():
    """Correct decryption with no plugboard → solver returns identity."""
    model = LanguageModel.german_military()
    text = "DASWETTERISTHEUTESEHRGUTSTOPENDE"
    text_ints = [ord(c) - 65 for c in text]
    cipher_ints = list(range(26))  # dummy — candidates just need to include text_ints
    # Build candidates that include the actual letters.
    candidates = [set(range(26)) for _ in text_ints]
    solver = PlugboardSolver.from_decryption(text_ints, candidates)
    assert solver.is_consistent()
    # With no constraints excluding anything, identity should be allowed.
    pairs = solver.get_pairs()
    # All letters map to themselves (no forced swaps).
    assert len(pairs) == 0


def test_plugboard_solver_detects_swap():
    """Decryption with A↔B swap should be detected by constraint propagation."""
    model = LanguageModel.german_military()
    base = "DASWETTERISTHEUTESEHRGUTSTOPENDE"
    base_ints = [ord(c) - 65 for c in base]
    # Apply A↔B swap.
    swapped = [1 if x == 0 else 0 if x == 1 else x for x in base_ints]
    # Build candidates from base (correct) text: each position's candidate
    # set includes the TRUE plaintext letter.
    candidates = [{b} for b in base_ints]  # singletons = perfect knowledge
    solver = PlugboardSolver.from_decryption(swapped, candidates)
    assert solver.is_consistent()
    pairs = solver.get_pairs()
    # Should detect A↔B swap.
    pair_set = {tuple(sorted(p)) for p in pairs}
    assert (0, 1) in pair_set


def test_plugboard_solver_propagates_involution():
    """If P(A)=X is forced, then P(X)=A must also be forced."""
    allowed = [set(range(26)) for _ in range(26)]
    # Force P(0) = 23 (A→X).
    allowed[0] = {23}
    solver = PlugboardSolver(allowed=allowed)
    solver.propagate()
    assert solver.allowed[23] == {0}
    assert solver.is_consistent()


# ---------------------------------------------------------------- progressive solver


@pytest.mark.slow
def test_progressive_solve_recovers_key():
    """Progressive solver recovers correct key from ciphertext."""
    plaintext = "DASWETTERISTHEUTESEHRGUTSTOPENDE"
    cfg = dict(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=[7, 11, 19],
        ring_settings=[0, 0, 0],
    )
    enc = Enigma(**cfg)
    ciphertext = enc.encrypt(plaintext)

    results = progressive_solve(
        ciphertext,
        rotor_pool=("I", "II", "III"),
        reflector_names=("B",),
        ring_settings=(0, 0, 0),
        top_k=10,
    )
    assert results, "progressive solver returned no candidates"
    matched = [
        r for r in results
        if r.rotor_names == ("I", "II", "III")
        and r.reflector_name == "B"
        and tuple(r.positions) == (7, 11, 19)
    ]
    assert matched, (
        f"correct key not found. Top result: {results[0]}"
    )
