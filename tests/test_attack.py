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
def test_attack_evaluates_correct_key_in_top_candidates():
    """End-to-end: encrypt known German text, verify the correct key
    survives to the top candidate pool.

    Note: the bundled approximate bigram model is not sufficient to
    *uniquely* rank the true plaintext above all gibberish on short
    messages; the doc itself anticipates this and requires either a
    stronger (trigram / word-based) model or longer text for unique
    ranking. We assert the weaker property that the correct rotor
    settings are among the top-K results.
    """
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
        top_k=50,
        early_prefix=8,
    )
    assert results, "attack returned no candidates"
    matched = [
        r for r in results
        if r.rotor_names == ("I", "II", "III")
        and r.reflector_name == "B"
        and tuple(r.positions) == (7, 11, 19)
    ]
    assert matched, (
        "correct key not in top results; "
        f"best key={results[0].rotor_names}/{results[0].reflector_name}/"
        f"{results[0].positions}"
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
