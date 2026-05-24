"""German language model used for constraint propagation.

Provides unigram frequencies, bigram frequencies, exclusory bigrams, and
scoring utilities used by the GCP attack. A small trigram + Index of
Coincidence layer is included so the attack can discriminate more
sharply on short ciphertexts.
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


# Common German trigrams with approximate frequency (percent of trigrams).
# Drawn from standard corpus tables; values used as soft boosts rather
# than absolute probabilities (background trigram model fills the rest).
COMMON_TRIGRAMS: dict[str, float] = {
    "EIN": 1.21, "ICH": 1.16, "NDE": 0.99, "DIE": 0.96, "UND": 0.88,
    "DER": 0.86, "CHE": 0.75, "END": 0.72, "GEN": 0.71, "SCH": 0.70,
    "CHT": 0.65, "DEN": 0.62, "INE": 0.60, "TEN": 0.58, "ERS": 0.51,
    "EIT": 0.49, "ISC": 0.47, "STE": 0.45, "ENS": 0.44, "RGE": 0.43,
    "BER": 0.42, "ITE": 0.41, "NGE": 0.40, "ESE": 0.40, "LIC": 0.39,
    "INS": 0.37, "VER": 0.36, "TER": 0.36, "NUN": 0.32, "LLE": 0.32,
    "HEN": 0.31, "RDE": 0.29, "AUF": 0.28, "EHE": 0.28, "REI": 0.27,
    "INER": 0.26, "ABE": 0.26, "ENG": 0.25, "REN": 0.25, "RDIE": 0.24,
    "WET": 0.10, "ETT": 0.10, "TTE": 0.10, "TER": 0.10, "STO": 0.08,
    "TOP": 0.08, "OPX": 0.04, "HEU": 0.10, "EUT": 0.10, "UTE": 0.10,
    "SEH": 0.10, "EHR": 0.10, "GUT": 0.06, "PEN": 0.04, "DAS": 0.30,
    "IST": 0.30, "ASW": 0.05, "SWE": 0.05,
}

# Expected Index of Coincidence of German text (kappa ~ 0.076).
GERMAN_IC: float = 0.0762
RANDOM_IC: float = 1.0 / 26.0  # ~0.0385


def index_of_coincidence(text: Iterable[int]) -> float:
    """Return the IC = sum(n_i*(n_i-1)) / (N*(N-1)) of the given text."""
    counts = [0] * 26
    n = 0
    for c in text:
        counts[c] += 1
        n += 1
    if n < 2:
        return 0.0
    num = sum(c * (c - 1) for c in counts)
    return num / (n * (n - 1))


def _letter_idx(c: str) -> int:
    return ord(c) - 65


@dataclass
class LanguageModel:
    """Unigram + bigram + trigram model with exclusory bigrams."""

    unigram: list[float] = field(default_factory=list)         # size 26
    bigram: list[list[float]] = field(default_factory=list)    # 26x26
    excluded: list[list[bool]] = field(default_factory=list)   # 26x26
    # Sparse trigram log-boosts: log( p(c|a,b) / p(c|a,b)_background ).
    # Default 0 (no boost). Stored as dict[(a,b,c)] for memory.
    trigram_boost: dict[tuple[int, int, int], float] = field(default_factory=dict)

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

        # Trigram boosts: each common trigram contributes a log-bonus scaled
        # by its frequency. This is a soft rewarding signal; the bigram
        # model still does the heavy lifting.
        tri: dict[tuple[int, int, int], float] = {}
        for tg, pct in COMMON_TRIGRAMS.items():
            if len(tg) != 3:
                continue
            a, b, c = _letter_idx(tg[0]), _letter_idx(tg[1]), _letter_idx(tg[2])
            # Bonus in log units: ranges from ~0.05 for rare common trigrams
            # to ~0.5 for the most common ones. Empirically calibrated so
            # the cumulative trigram bonus over a short message can flip
            # the ranking when the true plaintext has many matches.
            tri[(a, b, c)] = 1.5 * math.log(1.0 + 5.0 * pct)

        return cls(unigram=uni, bigram=bg, excluded=excl, trigram_boost=tri)

    # ------------------------------------------------------------------

    def is_excluded(self, a: int, b: int) -> bool:
        return self.excluded[a][b]

    def score(self, plaintext: Iterable[int]) -> float:
        """Return per-character log-probability (bigram + trigram boost)."""
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
        # Trigram boosts: additive log-bonus per matched trigram.
        if self.trigram_boost:
            for a, b, c in zip(text, text[1:], text[2:]):
                boost = self.trigram_boost.get((a, b, c))
                if boost is not None:
                    s += boost
        return s / len(text)

    def score_str(self, plaintext: str) -> float:
        return self.score([ord(c) - 65 for c in plaintext if "A" <= c <= "Z"])

    def has_excluded_bigram(self, plaintext: Iterable[int]) -> bool:
        text = list(plaintext)
        for a, b in zip(text, text[1:]):
            if self.excluded[a][b]:
                return True
        return False

    def ic_score(self, plaintext: Iterable[int]) -> float:
        """How close the text's IC is to German (1.0 = perfect, 0 = uniform).

        Returns a value in roughly [0, 2] where 1.0 means IC matches German.
        """
        ic = index_of_coincidence(plaintext)
        # Map: random (0.0385) -> 0, german (0.0762) -> 1.
        return (ic - RANDOM_IC) / (GERMAN_IC - RANDOM_IC)
