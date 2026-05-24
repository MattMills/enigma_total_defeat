"""Tests for the German language model."""

from __future__ import annotations

import math

from enigma.language import (
    GERMAN_IC,
    RANDOM_IC,
    LanguageModel,
    index_of_coincidence,
)


def test_unigram_sum_close_to_one():
    m = LanguageModel.german_military()
    assert abs(sum(m.unigram) - 1.0) < 0.02


def test_bigram_rows_sum_to_one():
    m = LanguageModel.german_military()
    for row in m.bigram:
        assert abs(sum(row) - 1.0) < 1e-6


def test_excluded_bigrams_are_zero():
    m = LanguageModel.german_military()
    for pair in ["QX", "QY", "JQ", "XJ", "ZQ"]:
        a, b = ord(pair[0]) - 65, ord(pair[1]) - 65
        assert m.excluded[a][b]
        assert m.bigram[a][b] == 0.0


def test_score_rejects_impossible_bigram():
    m = LanguageModel.german_military()
    assert m.score_str("QXQX") == float("-inf")


def test_score_prefers_german_over_noise():
    m = LanguageModel.german_military()
    g = m.score_str("DASISTEIN")
    n = m.score_str("QXJQZVYJX")
    assert g > n
    assert n == float("-inf") or g - n > 1.0


def test_trigram_boost_rewards_common_german_trigrams():
    m = LanguageModel.german_military()
    # Plaintext rich in common trigrams must score above one with the same
    # bigram skeleton but trigram-shuffled junk.
    rich = "DASISTEINSCHENESEINGEDICHTUNDDAS"
    poor = "DURISTUUNTCHGNGSGINGGDISITUUNDDU"
    assert m.score_str(rich) > m.score_str(poor)


def test_index_of_coincidence_german_vs_random():
    import random

    german_text = (
        "DASWETTERISTHEUTESEHRGUTUNDDIETRUPPEISTBEREITZUMVORMARSCH"
        "DIELAGEISTUNVERAENDERTUNDDERFEINDISTBEKANNTSTOPENDE"
    )
    rng = random.Random(0xE159)
    random_text = [rng.randrange(26) for _ in range(len(german_text))]
    g_ic = index_of_coincidence([ord(c) - 65 for c in german_text])
    r_ic = index_of_coincidence(random_text)
    # German IC ~ 0.076, random ~ 0.038.
    assert g_ic > 0.055
    assert r_ic < 0.055
    assert g_ic > r_ic


def test_ic_score_maps_to_unit_scale():
    m = LanguageModel.german_military()
    # IC = GERMAN_IC -> 1.0; IC = RANDOM_IC -> 0.0
    # Construct a synthetic text with German-like IC by repeating letters
    # to bias coincidence.
    text = "AAAAAAAEEEEEEENNNNNNNIIIIIIIRRRRRRRSSSSSSS"  # many repeats
    sc = m.ic_score([ord(c) - 65 for c in text])
    assert sc > 1.0  # repeats push IC well above German
