"""German language model used for constraint propagation.

Provides unigram frequencies, bigram frequencies, exclusory bigrams, and
scoring utilities used by the GCP attack.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable


# Wehrmacht-traffic-style unigram frequencies (from the design doc).
UNIGRAM_FREQ: dict[str, float] = {
    "E": 0.147, "N": 0.099, "I": 0.080, "S": 0.072, "R": 0.072,
    "A": 0.065, "T": 0.061, "H": 0.051, "D": 0.047, "U": 0.042,
    "L": 0.035, "C": 0.030, "G": 0.028, "M": 0.026, "O": 0.024,
    "B": 0.022, "W": 0.019, "F": 0.017, "K": 0.016, "Z": 0.013,
    "P": 0.010, "V": 0.008, "X": 0.008, "J": 0.003, "Y": 0.002,
    "Q": 0.001,
}

# Bigrams treated as exclusory (membership mu = -1).
EXCLUSORY_BIGRAMS: frozenset[str] = frozenset({
    "QX", "QY", "QJ", "QK", "QV", "QW", "QZ",
    "JQ", "JX", "JZ",
    "XJ", "XQ",
    "YQ", "YX", "YJ",
    "ZX", "ZQ",
})


def _letter_idx(c: str) -> int:
    return ord(c) - 65


@dataclass
class LanguageModel:
    """Unigram + bigram model with exclusory bigrams."""

    unigram: list[float] = field(default_factory=list)         # size 26
    bigram: list[list[float]] = field(default_factory=list)    # 26x26
    excluded: list[list[bool]] = field(default_factory=list)   # 26x26

    @classmethod
    def german_military(cls) -> "LanguageModel":
        uni = [UNIGRAM_FREQ[chr(i + 65)] for i in range(26)]
        # Start from unigram product as a smooth background distribution.
        bg = [[uni[a] * uni[b] for b in range(26)] for a in range(26)]

        # Real German bigram frequencies (percent of all bigrams), drawn
        # from standard corpus studies. We translate each "real" frequency
        # into a multiplicative boost over the smooth background, so common
        # German bigrams are sharply preferred without zero-ing out the
        # rare-but-not-impossible ones.
        real_bigram_pct = {
            "EN": 3.88, "ER": 3.75, "CH": 2.75, "DE": 2.27, "EI": 1.99,
            "TE": 1.85, "IN": 1.67, "IE": 1.48, "GE": 1.45, "ND": 1.44,
            "ST": 1.42, "BE": 1.16, "NE": 1.16, "SE": 1.10, "UN": 0.96,
            "ES": 0.95, "RE": 0.94, "IC": 0.93, "HE": 0.89, "AN": 0.88,
            "DI": 0.81, "AU": 0.78, "LE": 0.79, "HT": 0.77, "NS": 0.74,
            "VE": 0.73, "RI": 0.72, "TI": 0.69, "IT": 0.68, "EL": 0.65,
            "RA": 0.62, "RT": 0.61, "AT": 0.61, "SI": 0.61, "AL": 0.61,
            "ME": 0.60, "TA": 0.59, "DA": 0.58, "RU": 0.56, "AR": 0.55,
            "WE": 0.55, "LI": 0.54, "ED": 0.54, "EH": 0.53, "SC": 0.53,
            "OR": 0.52, "RO": 0.50, "DU": 0.50, "EM": 0.49, "DR": 0.48,
            "GE": 0.48, "MI": 0.47, "NG": 0.47, "FE": 0.46, "UR": 0.45,
            "HA": 0.45, "HI": 0.44, "EU": 0.44, "HR": 0.44, "EG": 0.43,
            "ZU": 0.42, "FR": 0.42, "NT": 0.41, "IS": 0.40, "TR": 0.39,
            "AC": 0.39, "OM": 0.38, "PE": 0.38, "FT": 0.38, "WI": 0.37,
            "MA": 0.37, "AS": 0.36, "NA": 0.36, "UE": 0.36, "GR": 0.36,
            "EB": 0.35, "MM": 0.35, "BI": 0.34, "OC": 0.33, "OE": 0.33,
            "EW": 0.33, "PR": 0.32, "SO": 0.32, "LL": 0.32, "EF": 0.31,
            "LA": 0.31, "OL": 0.31, "AB": 0.30, "BA": 0.30, "NK": 0.30,
            "SP": 0.30, "EK": 0.30, "OT": 0.29, "EP": 0.29, "BR": 0.28,
            "OS": 0.28, "RD": 0.28, "GA": 0.28, "EA": 0.28, "VO": 0.27,
            "PA": 0.27, "AG": 0.27, "RS": 0.27, "AM": 0.27, "FA": 0.27,
            "SS": 0.26, "TT": 0.26, "OB": 0.26, "MO": 0.26, "ON": 0.26,
            "FI": 0.25, "TZ": 0.25, "SA": 0.25, "EV": 0.25, "PI": 0.24,
            "NN": 0.24, "OD": 0.24, "WA": 0.24, "OW": 0.24, "BL": 0.24,
            "KO": 0.23, "TH": 0.23, "MP": 0.23, "PO": 0.23, "GL": 0.22,
            "EE": 0.22, "OF": 0.22, "GU": 0.22, "LU": 0.22, "RL": 0.21,
            "LO": 0.21, "TO": 0.21, "WU": 0.21, "FU": 0.21, "PP": 0.20,
            "RM": 0.20, "NO": 0.20, "RG": 0.19, "WO": 0.19, "GI": 0.19,
            "LS": 0.18, "OG": 0.18, "RH": 0.18, "RW": 0.18, "NU": 0.18,
            "MU": 0.17, "AD": 0.17, "EZ": 0.17, "TZ": 0.17, "EI": 0.17,
            "BU": 0.17, "TU": 0.17, "NF": 0.17, "RB": 0.17, "OK": 0.16,
            "JA": 0.16, "GT": 0.15, "MB": 0.15, "ML": 0.15, "UF": 0.15,
            "RK": 0.15, "MS": 0.14, "BO": 0.14, "LT": 0.13, "PL": 0.13,
            "OP": 0.13, "BS": 0.12, "ZE": 0.12, "ZI": 0.12, "ZW": 0.11,
            "KE": 0.11, "KA": 0.11, "KI": 0.10, "KL": 0.10, "KR": 0.10,
            "KU": 0.10, "DT": 0.10, "FF": 0.09, "JE": 0.08, "VI": 0.08,
            "QU": 0.08, "PH": 0.07, "YS": 0.05, "YM": 0.05, "YN": 0.04,
            "YL": 0.04, "XE": 0.04, "XI": 0.03, "XA": 0.02, "XU": 0.02,
            "JU": 0.05, "JI": 0.04, "JO": 0.04, "VA": 0.05, "VR": 0.04,
            "VL": 0.04, "XX": 0.03, "JJ": 0.01,
        }
        # Normalize to fractions.
        total = sum(real_bigram_pct.values())
        boost_floor = 0.3   # how much we keep of the smooth background
        for pair, pct in real_bigram_pct.items():
            a, b = _letter_idx(pair[0]), _letter_idx(pair[1])
            # Replace cell with a strongly-weighted real frequency.
            bg[a][b] = (pct / total) + boost_floor * uni[a] * uni[b]

        excl = [[False] * 26 for _ in range(26)]
        for pair in EXCLUSORY_BIGRAMS:
            a, b = _letter_idx(pair[0]), _letter_idx(pair[1])
            excl[a][b] = True
            bg[a][b] = 0.0

        # Renormalize each row to sum to ~1 (conditional p(b|a)).
        for a in range(26):
            row_sum = sum(bg[a]) or 1.0
            bg[a] = [v / row_sum for v in bg[a]]

        return cls(unigram=uni, bigram=bg, excluded=excl)

    # ------------------------------------------------------------------

    def is_excluded(self, a: int, b: int) -> bool:
        return self.excluded[a][b]

    def score(self, plaintext: Iterable[int]) -> float:
        """Return per-character log-probability."""
        text = list(plaintext)
        if not text:
            return 0.0
        s = 0.0
        s += math.log(max(self.unigram[text[0]], 1e-9))
        for a, b in zip(text, text[1:]):
            p = self.bigram[a][b]
            if p <= 0.0:
                return float("-inf")
            s += math.log(p)
        return s / len(text)

    def score_str(self, plaintext: str) -> float:
        return self.score([ord(c) - 65 for c in plaintext if "A" <= c <= "Z"])

    def has_excluded_bigram(self, plaintext: Iterable[int]) -> bool:
        text = list(plaintext)
        for a, b in zip(text, text[1:]):
            if self.excluded[a][b]:
                return True
        return False
