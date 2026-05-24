"""Tests for the German language model."""

from __future__ import annotations

import math

from enigma.language import LanguageModel


def test_unigram_sum_close_to_one():
    m = LanguageModel.german_military()
    assert abs(sum(m.unigram) - 1.0) < 0.02


def test_bigram_rows_sum_to_one():
    m = LanguageModel.german_military()
    for row in m.bigram:
        assert abs(sum(row) - 1.0) < 1e-6


def test_excluded_bigrams_are_zero():
    m = LanguageModel.german_military()
    for pair in ["QX", "QY", "JQ", "XJ", "YQ", "ZX"]:
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
