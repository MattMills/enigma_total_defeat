"""Synthetic test scenario generator using the Enigma simulator.

Creates scenarios with known ground truth for every attack domain:
  - rotor_id:         known right rotor, ciphertext to identify it
  - position_search:  known position, ciphertext to find it
  - trajectory_score: correct + wrong trajectories to distinguish
  - plugboard:        known trajectory + plugboard to recover
  - ring:             known key with non-trivial ring to find
  - full_solve:       complete key to recover from ciphertext only
  - multi_message:    multiple messages with shared day key

Each scenario includes the ciphertext, all ground truth components,
and pre-computed trajectories so techniques can be tested without
re-deriving the key.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from enigma.language import LanguageModel
from enigma.simulator import Enigma, Plugboard, fast_trajectory


GERMAN_PLAINTEXTS = [
    "DASWETTERISTHEUTESEHRGUTSTOPDIEMASCHINEFUNKTIONIERTBESTENS",
    "AUFKLXABTEILUNGXVONXKURTINOWAXNORDWESTLXSEBEZXUAFFLIEGERSTRASZEX",
    "DREIGEHTLANGSAMABERSIQERVORWAERTSXEINSSIEBENNULLSEQSXUHRX",
    "FEINDLIQEINFANTERIEKOLONNEBEOBAQTETXANFANGXSUEDAUSGANGXBAERWALDE",
    "VONXHAABORXANXKOMMANDANTXUBOOTXFUENFXSIEBENXZWEIXSEQSXDREI",
    "BEIANGRIFFUNTERWASSERGEDRUECKTWABOSXLETZTERXGEGNERSTANDX",
    "KEINEBESONDERENVORKOMMNISSEXALLESRUHIGXENDEXXSTOPXENDE",
    "NORDWESTLIQERXWINDXSTAERKEXDREIXBISXVIERSTOPXSIQTXGUT",
]

SIMPLE_PLAINTEXTS = [
    "DASWETTERISTGUTUNDDIEMASCHINEFUNKTIONIERT",
    "DERXFEINDXGREIFTXANXAUSXNORDWESTLIQER",
    "ALLESSTILLXKEINEXBESONDERENXVORKOMMNISSE",
]

DEFAULT_MODEL = None

def _model():
    global DEFAULT_MODEL
    if DEFAULT_MODEL is None:
        DEFAULT_MODEL = LanguageModel.german_military()
    return DEFAULT_MODEL


@dataclass
class Scenario:
    """A synthetic test scenario with full ground truth."""
    name: str
    ciphertext_str: str
    cipher: list[int]
    plaintext: str
    rotor_names: tuple[str, str, str]
    reflector_name: str
    positions: tuple[int, int, int]
    ring_settings: tuple[int, int, int]
    plugboard_pairs: list[str]
    plugboard_map: list[int]
    trajectory: list[list[int]]
    fourth_rotor_name: str | None = None
    fourth_position: int = 0
    fourth_ring: int = 0
    model: LanguageModel = field(default_factory=_model)


def make_scenario(
    name: str,
    plaintext: str,
    rotor_names: tuple[str, str, str] = ("II", "IV", "V"),
    reflector_name: str = "B",
    positions: tuple[int, int, int] = (1, 11, 0),
    ring_settings: tuple[int, int, int] = (0, 0, 0),
    plugboard_pairs: list[str] | None = None,
    fourth_rotor_name: str | None = None,
    fourth_position: int = 0,
    fourth_ring: int = 0,
) -> Scenario:
    """Create a scenario by encrypting plaintext with known settings."""
    pairs = plugboard_pairs or []
    plug = Plugboard.from_pairs(pairs) if pairs else Plugboard()
    plug_map = list(plug.mapping)

    enc = Enigma(
        rotor_names=rotor_names,
        reflector_name=reflector_name,
        positions=list(positions),
        ring_settings=list(ring_settings),
        plugboard=plug,
        fourth_rotor_name=fourth_rotor_name,
        fourth_position=fourth_position,
        fourth_ring=fourth_ring,
    )

    ciphertext_str = enc.encrypt(plaintext)
    cipher = [ord(c) - 65 for c in ciphertext_str]

    fourth_kw = {}
    if fourth_rotor_name:
        fourth_kw = dict(
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=fourth_position,
            fourth_ring=fourth_ring,
        )

    trajectory = fast_trajectory(
        rotor_names, reflector_name, positions, ring_settings,
        len(cipher), **fourth_kw,
    )

    return Scenario(
        name=name,
        ciphertext_str=ciphertext_str,
        cipher=cipher,
        plaintext=plaintext,
        rotor_names=rotor_names,
        reflector_name=reflector_name,
        positions=positions,
        ring_settings=ring_settings,
        plugboard_pairs=pairs,
        plugboard_map=plug_map,
        trajectory=trajectory,
        fourth_rotor_name=fourth_rotor_name,
        fourth_position=fourth_position,
        fourth_ring=fourth_ring,
    )


# ------------------------------------------------------------------
# Pre-built scenario sets for each domain
# ------------------------------------------------------------------

def scenario_no_plugboard() -> Scenario:
    """Simple scenario: no plugboard, long plaintext, standard rotors."""
    return make_scenario(
        name="no_plugboard",
        plaintext=GERMAN_PLAINTEXTS[0],
        rotor_names=("II", "IV", "V"),
        reflector_name="B",
        positions=(3, 9, 14),
    )


def scenario_light_plugboard() -> Scenario:
    """3-pair plugboard."""
    return make_scenario(
        name="light_plugboard",
        plaintext=GERMAN_PLAINTEXTS[1],
        rotor_names=("I", "III", "V"),
        reflector_name="B",
        positions=(7, 11, 19),
        plugboard_pairs=["AB", "CD", "EF"],
    )


def scenario_medium_plugboard() -> Scenario:
    """6-pair plugboard."""
    return make_scenario(
        name="medium_plugboard",
        plaintext=GERMAN_PLAINTEXTS[2],
        rotor_names=("III", "I", "IV"),
        reflector_name="B",
        positions=(15, 2, 22),
        plugboard_pairs=["AB", "CD", "EF", "GH", "IJ", "KL"],
    )


def scenario_heavy_plugboard() -> Scenario:
    """10-pair plugboard (historical weight), long message for beam swap convergence."""
    long_text = (
        "AUFKLXABTEILUNGXVONXKURTINOWAXKURTINOWAXNORDWESTLX"
        "SEBEZXSEBEZXUAFFLIEGERSTRASZERIQTUNGXDUBROWKIXDUBROWKIX"
        "OPOTSCHKAXOPOTSCHKAXUMXEINSAQTDREINULLXUHRANGETRETENX"
        "ANGRIFFXINFXRGTX"
    )
    return make_scenario(
        name="heavy_plugboard",
        plaintext=long_text,
        rotor_names=("II", "IV", "V"),
        reflector_name="B",
        positions=(1, 11, 0),
        ring_settings=(1, 20, 11),
        plugboard_pairs=["AV", "BS", "CG", "DL", "FU", "HZ", "IN", "KM", "OW", "RX"],
    )


def scenario_with_rings() -> Scenario:
    """Non-trivial ring settings, no plugboard so scoring is clean."""
    return make_scenario(
        name="with_rings",
        plaintext=GERMAN_PLAINTEXTS[3],
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=(5, 17, 8),
        ring_settings=(0, 0, 15),
    )


def scenario_reflector_a() -> Scenario:
    """Uses reflector A (less common)."""
    return make_scenario(
        name="reflector_a",
        plaintext=GERMAN_PLAINTEXTS[5],
        rotor_names=("II", "I", "III"),
        reflector_name="A",
        positions=(0, 1, 2),
    )


def scenario_m4() -> Scenario:
    """M4 four-rotor machine."""
    return make_scenario(
        name="m4",
        plaintext=GERMAN_PLAINTEXTS[6],
        rotor_names=("II", "IV", "I"),
        reflector_name="B-thin",
        positions=(9, 13, 0),
        ring_settings=(0, 0, 21),
        plugboard_pairs=["AT", "BL", "DF", "GJ", "HM"],
        fourth_rotor_name="Beta",
        fourth_position=21,
    )


def scenario_short_message() -> Scenario:
    """Short message (31 chars) — harder for statistical techniques."""
    return make_scenario(
        name="short_message",
        plaintext=SIMPLE_PLAINTEXTS[0],
        rotor_names=("I", "II", "III"),
        reflector_name="B",
        positions=(7, 11, 19),
    )


def scenario_multi_message() -> list[Scenario]:
    """Multiple messages with the same day key (different positions)."""
    shared = dict(
        rotor_names=("II", "IV", "V"),
        reflector_name="B",
        ring_settings=(0, 0, 0),
        plugboard_pairs=["AV", "BS", "CG", "DL", "FU"],
    )
    return [
        make_scenario(
            name="multi_msg_1",
            plaintext=SIMPLE_PLAINTEXTS[0],
            positions=(3, 9, 14),
            **shared,
        ),
        make_scenario(
            name="multi_msg_2",
            plaintext=SIMPLE_PLAINTEXTS[1],
            positions=(18, 4, 22),
            **shared,
        ),
        make_scenario(
            name="multi_msg_3",
            plaintext=SIMPLE_PLAINTEXTS[2],
            positions=(0, 21, 7),
            **shared,
        ),
    ]


def all_single_scenarios() -> list[Scenario]:
    """Return all single-message scenarios."""
    return [
        scenario_no_plugboard(),
        scenario_light_plugboard(),
        scenario_medium_plugboard(),
        scenario_heavy_plugboard(),
        scenario_with_rings(),
        scenario_reflector_a(),
        scenario_m4(),
        scenario_short_message(),
    ]


def wrong_trajectory(scenario: Scenario) -> list[list[int]]:
    """Generate a wrong trajectory for contrast tests."""
    wrong_pos = ((scenario.positions[0] + 13) % 26,
                 (scenario.positions[1] + 13) % 26,
                 (scenario.positions[2] + 13) % 26)
    fourth_kw = {}
    if scenario.fourth_rotor_name:
        fourth_kw = dict(
            fourth_rotor_name=scenario.fourth_rotor_name,
            fourth_position=scenario.fourth_position,
            fourth_ring=scenario.fourth_ring,
        )
    return fast_trajectory(
        scenario.rotor_names, scenario.reflector_name,
        wrong_pos, scenario.ring_settings,
        len(scenario.cipher), **fourth_kw,
    )
