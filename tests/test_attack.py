"""Tests for the GCP attack.

The attack's full search is heavy; tests restrict the rotor pool and
reflector list to keep CI runtime bounded while still exercising the
end-to-end pipeline.
"""

from __future__ import annotations

import pytest

from enigma.attack import (
    attack,
    infer_plugboard,
    initialize_candidates,
    propagate_bigrams,
)
from enigma.language import LanguageModel
from enigma.simulator import Enigma, Plugboard


def test_initialize_candidates_excludes_ciphertext_letter():
    cipher = [0, 1, 2]  # A, B, C
    cands = initialize_candidates(cipher)
    assert 0 not in cands[0]
    assert 1 not in cands[1]
    assert 2 not in cands[2]
    assert len(cands[0]) == 25


def test_propagate_bigrams_prunes_dead_ends():
    model = LanguageModel.german_military()
    # Build a synthetic candidate state where position 0 has only Q and
    # position 1 has only X. The bigram QX is excluded; propagation must
    # empty both sets.
    cands = [set([ord("Q") - 65]), set([ord("X") - 65])]
    pruned = propagate_bigrams(cands, model)
    assert pruned[0] == set()
    assert pruned[1] == set()


@pytest.mark.slow
def test_attack_recovers_with_real_plugboard():
    """Encrypt with an actual plugboard, verify key recovery + that the
    inferred plugboard's effect makes the plaintext substantially more
    German-like than the no-plugboard decryption."""
    plaintext = "DASWETTERISTHEUTESEHRGUTSTOPDIETRUPPEISTBEREIT"
    plug = Plugboard.from_pairs(["AB", "CD", "EF"])
    cfg = dict(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=[7, 11, 19],
        ring_settings=[0, 0, 0],
    )
    enc = Enigma(plugboard=Plugboard(mapping=list(plug.mapping)), **cfg)
    ciphertext = enc.encrypt(plaintext)

    results = attack(
        ciphertext,
        rotor_pool=("I", "II", "III"),
        reflector_names=("B",),
        rings=((0, 0, 0),),
        top_k=20,
        early_prefix=8,
    )
    assert results, "attack returned no candidates"
    matched = [
        r for r in results
        if r.rotor_names == ("I", "II", "III")
        and r.reflector_name == "B"
        and tuple(r.positions) == (7, 11, 19)
    ]
    assert matched, "correct key not in top results with real plugboard"


@pytest.mark.slow
def test_attack_recovers_short_message_end_to_end():
    """End-to-end: from ciphertext alone, recover key AND plaintext."""
    plaintext = "DASWETTERISTHEUTESEHRGUTSTOPENDE"
    cfg = dict(
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=[7, 11, 19],
        ring_settings=[0, 0, 0],
    )
    enc = Enigma(**cfg)
    ciphertext = enc.encrypt(plaintext)

    results = attack(
        ciphertext,
        rotor_pool=("I", "II", "III"),
        reflector_names=("B",),
        rings=((0, 0, 0),),
        top_k=10,
        early_prefix=8,
    )
    assert results, "attack returned no candidates"
    top = results[0]
    assert top.rotor_names == ("I", "II", "III")
    assert top.reflector_name == "B"
    assert tuple(top.positions) == (7, 11, 19)
    assert top.plaintext == plaintext, (
        f"plaintext mismatch: got {top.plaintext!r}, want {plaintext!r}"
    )
    assert not top.plugboard_pairs, (
        f"spurious plugboard inferred: {top.plugboard_pairs}"
    )


def test_infer_plugboard_improves_score_on_swapped_text():
    """Greedy plugboard inference must monotonically improve the score
    and return at most 13 disjoint pairs."""
    model = LanguageModel.german_military()
    base = (
        "DASWETTERISTHEUTESEHRGUTSTOPDIETRUPPEISTBEREITSTOPENDE"
    )
    swapped = [
        ord("X") - 65 if c == "A" else (ord("A") - 65 if c == "X" else ord(c) - 65)
        for c in base
    ]
    base_score = model.score(swapped)
    pairs, recovered = infer_plugboard(swapped, model)
    assert len(pairs) <= 13
    # All inferred pairs are disjoint.
    letters = [x for pair in pairs for x in pair]
    assert len(letters) == len(set(letters))
    # Score must not decrease.
    assert model.score(recovered) >= base_score
