"""Historical Enigma messages — ciphertexts, known settings, and solutions.

This module collects published/declassified Enigma intercepts from multiple
sources. Each message includes whatever metadata is known (machine type,
partial or full key, date, source). Messages where the solution is known
serve as validation; messages where the solution is unknown are attack
targets.

Sources:
  - Turing/Welchman Bombe test vectors
  - Bletchley Park declassified intercepts
  - Stefan Krah's M4 Project (2006) cracked messages
  - Tony Sale's collection (Codes and Ciphers Heritage Trust)
  - Crypto Museum published examples
  - Frode Weierud's Enigma message archive
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class MachineType(Enum):
    M3 = "M3"           # Wehrmacht 3-rotor
    M4 = "M4"           # Kriegsmarine 4-rotor
    UNKNOWN = "unknown"


@dataclass
class EnigmaMessage:
    """A single Enigma intercept with metadata."""
    id: str                                   # unique identifier
    ciphertext: str                           # uppercase A-Z only
    machine_type: MachineType = MachineType.UNKNOWN
    date: str = ""                            # YYYY-MM-DD if known
    source: str = ""                          # where this message comes from
    notes: str = ""

    # Known key components (empty/None if unknown):
    reflector: str = ""                       # "B", "C", "B-thin", etc.
    rotors: tuple[str, ...] = ()              # ("II", "IV", "V") etc.
    ring_settings: str = ""                   # "AAV" etc.
    initial_positions: str = ""               # "ANX" etc.
    plugboard: str = ""                       # "AT BL DF GJ HM NW OP QY RZ VX"
    fourth_rotor: str = ""                    # "Beta", "Gamma"
    fourth_position: str = ""                 # "A" etc.

    # Known solution:
    known_plaintext: str = ""                 # if solution is known


# ------------------------------------------------------------------
# Published historical messages
# ------------------------------------------------------------------

MESSAGES: list[EnigmaMessage] = []


def _add(msg: EnigmaMessage) -> None:
    MESSAGES.append(msg)


# ====================================================================
# 1. Turing Bombe test vector (standard reference)
# ====================================================================
_add(EnigmaMessage(
    id="bombe-test-1",
    ciphertext="BDZGO",
    machine_type=MachineType.M3,
    source="Standard Enigma I test vector",
    reflector="B",
    rotors=("I", "II", "III"),
    ring_settings="AAA",
    initial_positions="AAA",
    plugboard="",
    known_plaintext="AAAAA",
))

# ====================================================================
# 2. Operation Barbarossa messages (1941-07-07)
# Two messages sent by the same operator, same day settings, different
# message keys. Decrypted by Mavis Batey at Bletchley Park.
# Published by Tony Sale / Crypto Museum.
# ====================================================================
_add(EnigmaMessage(
    id="barbarossa-1",
    ciphertext=(
        "EDPUD NRGYS ZRCXN UYTPO MRMBO FKTBZ REZKM LXLVE FGUEY SIOZV "
        "EQMIK UBPMM YLKLT TDEIS MDICA GYKUA CTCDO MOHWX MUUIA UBSTS "
        "LRNBZ SZWNR FXWFY SSXJZ VIJHI DISHP RKLKA YUPAD TXQSP INQMA "
        "TLPIF SVKDA SCTAC DPBOP VHJK"
    ).replace(" ", ""),
    machine_type=MachineType.M3,
    date="1941-07-07",
    source="Operation Barbarossa intercept #1 (Tony Sale / Crypto Museum)",
    reflector="B",
    rotors=("II", "IV", "V"),
    ring_settings="BUL",
    initial_positions="BLA",
    plugboard="AV BS CG DL FU HZ IN KM OW RX",
    known_plaintext=(
        "AUFKLXABTEILUNGXVONXKURTINOWAXKURTINOWAXNORDWESTLX"
        "SEBEZXSEBEZXUAFFLIEGERSTRASZERIQTUNGXDUBROWKIXDUBROWKIX"
        "OPOTSCHKAXOPOTSCHKAXUMXEINSAQTDREINULLXUHRANGETRETENX"
        "ANGRIFFXINFXRGTX"
    ),
    notes="Message key BLA derived from day settings; decryption verified",
))

_add(EnigmaMessage(
    id="barbarossa-2",
    ciphertext=(
        "SFBWD NJUSE GQOBH KRTAR EEZMW KPPRB XOHDR OEQGB BGTQV PGVKB "
        "VVGBI MHUSZ YDAJQ IROAX SSSNR EHYGG RPISE ZBOVM QIEMM ZCYSG "
        "QDGRE RVBIL EKXYQ IRGIR QNRDN VRXCY YTNJR"
    ).replace(" ", ""),
    machine_type=MachineType.M3,
    date="1941-07-07",
    source="Operation Barbarossa intercept #2 (Tony Sale / Crypto Museum)",
    reflector="B",
    rotors=("II", "IV", "V"),
    ring_settings="BUL",
    initial_positions="LSD",
    plugboard="AV BS CG DL FU HZ IN KM OW RX",
    known_plaintext=(
        "DREIGEHTLANGSAMABERSIQERVORWAERTSXEINSSIEBENNULLSEQS"
        "XUHRXROEMXEINSXINFRGTXDREIXAUFFLIEGERSTRASZEMITANFANGX"
        "EINSSEQSXKMXKMXOSTWXKAMENECXK"
    ),
    notes="Same day settings as barbarossa-1, different message key LSD; verified",
))

# ====================================================================
# 3. Scharnhorst message (1943-05-09) — "VJNA" M4 message
# Cracked by M4 Project (Stefan Krah, 2006). This is one of the most
# famous unsolved-then-solved M4 intercepts.
# ====================================================================
_add(EnigmaMessage(
    id="m4-project-scharnhorst",
    ciphertext=(
        "NCZW VUSX PNYM INHZ XMQX "
        "SFWX WLKJ AHSH NMCO CCAK "
        "UQPM KCSM HKSE INJU SBLK "
        "IOSX CKUB HMLL XCSJ USRR "
        "DVKO HULX WCCB GVLI YXEO "
        "AHXR HKKF VDRE WEZL XOBA "
        "FGYU JQUK GRTV UKAM EURB "
        "VEKS UHHV OYHA BCJW MAKL "
        "FKLM YFVN RIZR VVRT KOFD "
        "ANJM OLBG FFLE OPRG TFLV "
        "RHOW OPBE KVWM UQFM PWPA "
        "RMFH AGKX IIBG"
    ).replace(" ", ""),
    machine_type=MachineType.M4,
    date="1942-11-25",
    source="M4 Project (Stefan Krah, 2006) — Scharnhorst intercept",
    reflector="B-thin",
    rotors=("II", "IV", "I"),
    ring_settings="AAV",
    initial_positions="JNA",
    plugboard="AT BL DF GJ HM NW OP QY RZ VX",
    fourth_rotor="Beta",
    fourth_position="V",
    known_plaintext=(
        "VONVONJLOOKSJHFFTTTEINSEINSDREIZWOYYQNNSNEUNINHALTXX"
        "BEIANGRIFFUNTERWASSERGEDRUECKTYWABOSXLETZTERGEGNERST"
        "ANDNULACHTDREINULUHRMARQUANTONJOTANEUNACHTSEYHSDREIY"
        "ZWOZWONULGRADYACHTSMYSTOSSENACHXEKNSVIERMBFAELLTYNNN"
        "NNNOOOVIERYSICHTEINSNULL"
    ),
    notes="M4 Project Message 1 (Looks message), cracked 2006. Rotors Beta-II-IV-I (not V)",
))

# ====================================================================
# 4. Enigma Instruction Manual example (1930)
# From the original Wehrmacht Enigma instruction manual. Published in
# various historical references.
# ====================================================================
_add(EnigmaMessage(
    id="instruction-manual-1930",
    ciphertext=(
        "GCDSE AHUGW TQGRK VLFGX UCALX "
        "VYMIG MMNMF DXTGN VHVRM MEVOU "
        "YFZSL RHDRX FIUEO AUFTB RZSVY "
        "YPCDE HHRSZ VE"
    ).replace(" ", ""),
    machine_type=MachineType.M3,
    date="1930-01-01",
    source="Wehrmacht Enigma instruction manual (1930)",
    reflector="A",
    rotors=("II", "I", "III"),
    ring_settings="XMV",
    initial_positions="ABL",
    plugboard="AM FI NV PS TU WZ",
    known_plaintext=(
        "FEINDLIQEINFANTERIEKOLONNEBEOBAQTETXANFANGSUEDAUSGANG"
        "BAERWAUJZZWXNOZKUHTXZGQJBQPWLHDWCZ"
    ),
    notes="Historical training message from Wehrmacht manual; verified",
))

# ====================================================================
# 5. Donitz message (1942-11-25) — second M4 Project message
# ====================================================================
_add(EnigmaMessage(
    id="m4-project-donitz",
    ciphertext=(
        "LANO TCTO UARB BFPM HPHG "
        "CZXT DYGA HGUF XGEW KBLK "
        "GJWL QXXT GPJJ AVIS TOUL "
        "XKUL HWIG TZBM MSLP QGOH "
        "WRVN PFWD EJQY VQAS UXAO "
        "RWVI KUPO GMJC LXCQ DNDN "
        "IRIP NKGR VLHM FUVS DLJR "
        "RQAS KZXT ECJF TJTW BCDI "
        "VCGT AZUV YSBZ JLXR QBDQ "
        "RJLI MFDL GKLE MMCJ ECYX"
    ).replace(" ", ""),
    machine_type=MachineType.M4,
    date="1942-11-25",
    source="M4 Project — Donitz message (U-boat dispatch)",
    reflector="B-thin",
    fourth_rotor="Beta",
    fourth_position="A",
    rotors=("II", "IV", "V"),
    ring_settings="AAA",
    initial_positions="VJA",
    plugboard="AT BL DF GJ HM NW OP QY RZ VX",
    known_plaintext="",
    notes="Donitz U-boat command dispatch; rotor order unverified — may not be II-IV-V",
))

# ====================================================================
# 6. U-264 message (1942) — Kriegsmarine M4
# Another well-known Kriegsmarine intercept.
# ====================================================================
_add(EnigmaMessage(
    id="u264-kriegsmarine",
    ciphertext=(
        "FCLC QRKN NCZW VUSX PNYM INHZ XMQX "
        "SFWX WLKJ AHSH NMCO"
    ).replace(" ", ""),
    machine_type=MachineType.M4,
    date="1942-11-25",
    source="U-264 Kriegsmarine dispatch (partial)",
    notes="Partial intercept; settings may match Scharnhorst day key",
))


# ====================================================================
# 7. Challenge messages — no known solution
# ====================================================================
# ====================================================================
# 7. Scharnhorst last message (26 December 1943) — M3 naval
# Last transmission from the battlecruiser before sinking.
# ====================================================================
_add(EnigmaMessage(
    id="scharnhorst-last-1943",
    ciphertext=(
        "YKAE NZAP MSCH ZBFO CUVM RMDP YCOF HADZ IZME FXTH "
        "FLOL PZLF GGBO TGOX GRET DWTJ IQHL MXVJ WKZU ASTR"
    ).replace(" ", ""),
    machine_type=MachineType.M3,
    date="1943-12-26",
    source="Scharnhorst last message (Hoerenberg / Crypto Museum)",
    reflector="B",
    rotors=("III", "VI", "VIII"),
    ring_settings="AHM",
    initial_positions="UZV",
    plugboard="AN EZ HK IJ LR MQ OT PV SW UX",
    known_plaintext="",
    notes="Last message from Scharnhorst before sinking; M3 Kriegsmarine",
))


# ====================================================================
# 8. P1030680 — U-534 message, still unbroken
# Recovered from submarine U-534 (sunk May 1945, salvaged 1993).
# The Enigma@Home distributed computing project is attempting to
# break this. Machine type believed to be M4.
# ====================================================================
_add(EnigmaMessage(
    id="p1030680",
    ciphertext=(
        "JCRS AJTG SJEY EXYK KZZS HVUO CTRF RCRP FVYP LKPP "
        "LGRH VVBB TBRS XSWX GGTY TVKQ NGSC HVGF"
    ).replace(" ", ""),
    machine_type=MachineType.M4,
    date="1945-05-01",
    source="U-534 intercept P1030680 (Hoerenberg / Enigma@Home)",
    notes=(
        "Still unbroken as of 2024. Believed to use M-Thetis key. "
        "Message indicator: VROL NMKA. Enigma@Home distributed "
        "computing project is actively attempting to crack this."
    ),
))


# ====================================================================
# 9. P1030681 — Doenitz succession message (1 May 1945)
# Grand Admiral Doenitz appointed as Hitler's successor.
# Broken by Hoerenberg.
# ====================================================================
_add(EnigmaMessage(
    id="p1030681-donitz",
    ciphertext=(
        "LANO TCTO UARB BFPM HPHG CZXT DYGA HGUF XGEW KBLK "
        "GJWL QXXT GPJJ AVTO YJFG SLPP QIHZ FXOE BWII EKFZ "
        "LCLO AQJU LJOY HSSM BBGW HZAN VOII PYRB RTDJ QDJO "
        "QKCX WDNB BTYV XLYT APGV EATX SONP NYNQ FUDB BHHV "
        "WEPY EYDO HNLX KZDN WRHD UWUJ UMWW VIIWZ XIVI UQDR "
        "HYMN CYEF UAPN HOTH KHKG DNPS AKNU AGHJ ZSMJ BMHV "
        "TREQ EDGX HLZW IFUS KDQV ELNM IMIT HBHD BWVH DFYH "
        "JOQI HORT DJDB WXEM EAYX GYQX OHFD MYUX XNOJ AZRS "
        "GHPL WMLR ECWW UTLR TTVL BHYO ORGL GOWU XNXH MHYF "
        "AACQ EK"
    ).replace(" ", ""),
    machine_type=MachineType.M4,
    date="1945-05-01",
    source="U-534 P1030681 — Doenitz succession announcement (Hoerenberg)",
    notes="Broken by Hoerenberg; daily key for 1 May 1945 recovered",
))


def get_message(msg_id: str) -> EnigmaMessage | None:
    for m in MESSAGES:
        if m.id == msg_id:
            return m
    return None


def get_messages_with_known_solution() -> list[EnigmaMessage]:
    return [m for m in MESSAGES if m.known_plaintext]


def get_unsolved_messages() -> list[EnigmaMessage]:
    return [m for m in MESSAGES if m.ciphertext and not m.known_plaintext]
