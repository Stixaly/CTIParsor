"""Precision filters for the threat actors CyNER (Stage 2d) and the places
spaCy (Stage 2) propose (ADR-0088, measured in
docs/eval/ner-precision-2026-10.md).

`NER_PRECISION_FILTERS=false` restores the behaviour before ADR-0088.

A. CyNER's `Threat_group` label fires on any span that talks about actors,
   and ADR-0050 removed only the spans made of its own category vocabulary.
   In a text written with capitals, a span with no capital letter and no
   digit ("cybercriminals", "underground forums") is not written as a proper
   name, and a span made only of category words, platform names,
   nationalities or countries ("Chinese threat actors", "Iran", "United
   States") names nothing either.

D. spaCy's GPE label, mapped to location, fires on products and vendors
   ("C&C", "XSS", "GitHub").  A value is kept only when it can be a place
   name, and a leading "the" is dropped ("the United States").

Three other leads were measured with these and not adopted, each under the
document's +5-point gate on its own: the same rule A for CyNER's malware,
reducing "Ryuk ransomware" to "Ryuk", and dropping spaCy's PRODUCT label.
Registered as one lead and measured once on AnnoCTR test (ADR-0089), they
doubled malware precision but cost locations through the LLM's answers, and
were not adopted either (docs/eval/ner-malware-2026-10.md; the code is at
commit ccb9edf).
"""
from __future__ import annotations

import functools

from models.schemas import EntityType
from pipeline.env_flags import env_bool
from pipeline.regex_safety import compile_pattern


def enabled() -> bool:
    return env_bool("NER_PRECISION_FILTERS", default=True)


# ── Vocabulary ───────────────────────────────────────────────────────────────

# Category nouns and modifiers that describe a kind of actor (or of malware,
# which actor spans mention) without naming one, beyond ADR-0050's list
# (stage2d_cyner._GENERIC_TOKENS).  From CyNER's false positives on the
# AnnoCTR train split.  Words that form real names are left out on purpose:
# "agent" (X-Agent), "crew" (Shell Crew), "circles" (Circles).
_MORE_GENERIC: frozenset[str] = frozenset("""
cybercriminal cybercriminals criminal criminals cybercrime crime crimeware ecrime
underground forum forums marketplace marketplaces market markets shop shops hub hubs
community ecosystem economy landscape scene ring cabal syndicate syndicates
gang gangs crews adversary adversaries perpetrator perpetrators scammer scammers
fraudster fraudsters extortionist extortionists hacktivist hacktivists activist activists
affiliate affiliates author authors developer developers member members purveyor purveyors
organization organizations organisation organisations enterprise enterprises
nation nations regime agents intelligence spy spies kiddies script insider insiders
botnet botnets bot bots rats banking keylogger keyloggers toolkit toolkits
kit kits packer packers crypter crypters cryptominer cryptominers cryptomining
grabber grabbers logger loggers injector injectors skimmer skimmers worm worms adware
spyware implant implants toolset sample samples strain strains families executable
executables remote access maas raas spam malspam phishing email emails spear credential
credentials stealing theft infection infections distribution extortion disinformation
deception influence social engineering hacking
bad same multiple separate distinct unknown unidentified skilled sophisticated advanced
elite level petty politically motivated speaking aligned organized organised coordinated
mass small domestic internal covert hostile persistent notorious prolific final secondary
second decoy encrypted packed mobile undisclosed multipurpose multistage financially
financial
""".split())

# A nationality or a country is not a threat actor ("Chinese", "Iran").
_DEMONYMS: frozenset[str] = frozenset("""
chinese russian iranian korean north south american israeli vietnamese pakistani indian
turkish arab arabic syrian ukrainian belarusian european western eastern asian
""".split())

# Words that form real names with another word (X-Agent, Shell Crew) and so
# stay out of the vocabulary, but name nothing alone.
_NOT_A_NAME_ALONE: frozenset[str] = frozenset({"agent", "crew", "miner"})


@functools.lru_cache(maxsize=1)
def _countries() -> frozenset[str]:
    # Stage 4's country table, the one a Location needs to ship.
    from pipeline.stage4_stix_mapping import _COUNTRY_ISO
    return frozenset(_COUNTRY_ISO) | {"korea", "prc", "dprk", "us", "usa", "hong kong"}


@functools.lru_cache(maxsize=1)
def _platforms() -> frozenset[str]:
    # Stage 2's list of the software names spaCy calls PRODUCT ("linux",
    # "windows", "android", "json"), and a few it lacks: not actors, not places.
    from pipeline.stage2_extraction import _NER_PRODUCT_BLOCKLIST
    return _NER_PRODUCT_BLOCKLIST | {"powershell", "mac", "vbs", "vba", "excel", "office"}


def _tokens(value: str) -> list[str]:
    # str.split, not a compile_pattern("[\s\-]+"): under RE2 `\s` is ASCII
    # only, and "Chinese\xa0threat actors" from a PDF would stay one token.
    return value.lower().replace("-", " ").split()


def _all_generic(value: str, extra: frozenset[str] = frozenset()) -> bool:
    """True when no token of 3+ characters names anything (ADR-0050's rule,
    with the wider vocabulary)."""
    from pipeline.stage2d_cyner import _GENERIC_TOKENS
    return not [t for t in _tokens(value) if len(t) >= 3 and t not in _GENERIC_TOKENS
                and t not in _MORE_GENERIC and t not in extra]


# ── A. CyNER threat actors: ordinary language ────────────────────────────────

# Below this share of capital letters a text is written in lower case (a chat
# log, a lowercased OCR): case says nothing there, and the capital-letter test
# is skipped.  Every AnnoCTR train and dev report is above 1.6%.
_CASED_TEXT_SHARE = 0.005


def text_is_cased(text: str) -> bool:
    """Counted on words made only of letters, so that an appendix of lowercase
    hashes, base64 or URLs does not make a report look lowercase."""
    letters = upper = 0
    for word in text.split():
        word = word.strip(".,;:!?()[]{}\"'’“”")
        if word.isalpha():
            letters += len(word)
            upper += sum(c.isupper() for c in word)
    return letters == 0 or upper >= _CASED_TEXT_SHARE * letters


_CVE_RE = compile_pattern(r"^cve-\d{4}-\d+$")


def actor_is_ordinary(value: str, cased: bool = True) -> bool:
    """True when a CyNER threat-actor fragment is not a name: ordinary
    language, a country or a nationality, a number, a CVE id."""
    low = value.lower()
    if not any(c.isalpha() for c in value) or _CVE_RE.match(low) or low in _NOT_A_NAME_ALONE:
        return True
    if cased and not any(c.isupper() or c.isdigit() for c in value):
        return True
    if (low[4:] if low.startswith("the ") else low) in _countries():
        return True
    return _all_generic(value, _platforms() | _DEMONYMS | _countries())


def refine_cyner(value: str, etype: EntityType, cased: bool = True) -> str:
    """The CyNER fragment to keep, or "" to drop it.  `cased`: whether the
    report is written with capitals (text_is_cased).  Malware is untouched."""
    if etype == EntityType.THREAT_ACTOR and actor_is_ordinary(value, cased):
        return ""
    return value


# ── D. spaCy places ──────────────────────────────────────────────────────────

# Abbreviations that are places; any other all-capital value of five letters
# or fewer is an acronym (XSS, SCADA, IRGC, JSON).
_PLACE_ABBREVIATIONS: frozenset[str] = frozenset({
    "US", "U.S.", "USA", "U.S.A.", "UK", "U.K.", "UAE", "PRC", "USSR", "DPRK", "ROK", "EU",
    "KSA", "DC", "D.C.", "NYC", "HK",
})
# Besides letters (São Paulo, Zürich): spaces, periods, hyphens, apostrophes.
# No digit, "&", "+", "_", bracket, slash or "=" (C&C, C++, regsvr32, a URL,
# a file name).
_PLACE_PUNCTUATION = frozenset(" .'’-")


def _is_country(value: str) -> bool:
    return value.lower() in _countries() or value in _PLACE_ABBREVIATIONS


def _camel_case(value: str) -> bool:
    """A capital right after a small letter inside a word (GitHub, DocuSign),
    except after "Mc" / "Mac" at the start of a word (McLean, MacKenzie)."""
    for i in range(1, len(value)):
        if value[i].isupper() and value[i - 1].islower():
            word_start = max(value.rfind(" ", 0, i), value.rfind("-", 0, i)) + 1
            if value[word_start:i] not in ("Mc", "Mac"):
                return True
    return False


def place_name(value: str) -> str:
    """`value` on one line and without a leading "the" or a trailing
    apostrophe, or "" when it cannot be a place name."""
    value = " ".join(value.split())        # "Saudi\nArabia" from a wrapped line
    if value.lower().startswith("the "):
        value = value[4:]
    value = value.rstrip("'’")         # "the United States'" (a plural possessive)
    if not value:
        return ""
    if _is_country(value):
        return value
    if not all(c.isalpha() or c in _PLACE_PUNCTUATION for c in value):
        return ""
    if not value[0].isupper():          # "beirut" in a URL, "netflix"
        return ""
    letters = [c for c in value if c.isalpha()]
    if len(letters) <= 5 and all(c.isupper() for c in letters):
        return ""
    if _camel_case(value):              # GitHub, FilePath, DocuSign
        return ""
    if _all_generic(value, _platforms()):   # Payload, Exploit, Linux
        return ""
    return value


def refine_spacy(value: str, etype: EntityType) -> str:
    """The spaCy entity value to keep (possibly shortened), or "" to drop it.
    Only locations are filtered."""
    if etype == EntityType.LOCATION:
        return place_name(value)
    return value
