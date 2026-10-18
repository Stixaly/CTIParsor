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

The malware lead (ADR-0089, docs/eval/ner-malware-2026-10.md), measured as
one lead on top of A and D, `NER_PRECISION_MALWARE`:

A for malware. Rule A judges CyNER's `Malware` fragments too ("banking
   trojan", "same malware"); the nationalities and countries added for
   actors are not added for malware ("China Chopper").
B. A name with its category around it is reduced to the name ("Ryuk
   ransomware", "hacking group TA505"), CyNER's spans are split on brackets
   too ("Winnti Group (APT41"), and a shortened name that meets the same name
   keeps the higher confidence.  Malware and threat actors.
C. spaCy's PRODUCT label no longer proposes malware.
"""
from __future__ import annotations

import functools

from models.schemas import EntityType
from pipeline.env_flags import env_bool
from pipeline.regex_safety import compile_pattern


def enabled() -> bool:
    return env_bool("NER_PRECISION_FILTERS", default=True)


def malware_enabled() -> bool:
    """ADR-0089's malware lead.  Off whenever the filters are off."""
    return enabled() and env_bool("NER_PRECISION_MALWARE", default=True)


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


def _is_generic_word(token: str, extra: frozenset[str]) -> bool:
    from pipeline.stage2d_cyner import _GENERIC_TOKENS
    return token in _GENERIC_TOKENS or token in _MORE_GENERIC or token in extra


def _all_generic(value: str, extra: frozenset[str] = frozenset()) -> bool:
    """True when no token of 3+ characters names anything (ADR-0050's rule,
    with the wider vocabulary)."""
    return not [t for t in _tokens(value) if len(t) >= 3 and not _is_generic_word(t, extra)]


@functools.lru_cache(maxsize=None)
def _not_a_name_for(etype: EntityType) -> frozenset[str]:
    """Words that name nothing for this type besides the category words: a
    platform, and for a threat actor a nationality or a country."""
    if etype == EntityType.THREAT_ACTOR:
        return _platforms() | _DEMONYMS | _countries()
    return _platforms()


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


def _not_written_as_a_name(value: str, cased: bool) -> bool:
    """No letter, a CVE id, a word that names nothing alone, or (in a report
    written with capitals) neither a capital letter nor a digit."""
    low = value.lower()
    if not any(c.isalpha() for c in value) or _CVE_RE.match(low) or low in _NOT_A_NAME_ALONE:
        return True
    return cased and not any(c.isupper() or c.isdigit() for c in value)


def actor_is_ordinary(value: str, cased: bool = True) -> bool:
    """True when a CyNER threat-actor fragment is not a name: ordinary
    language, a country or a nationality, a number, a CVE id."""
    if _not_written_as_a_name(value, cased):
        return True
    low = value.lower()
    if (low[4:] if low.startswith("the ") else low) in _countries():
        return True
    return _all_generic(value, _not_a_name_for(EntityType.THREAT_ACTOR))


def malware_is_ordinary(value: str, cased: bool = True) -> bool:
    """Rule A for a CyNER malware fragment (ADR-0089): ordinary language, a
    platform, a number, a CVE id.  The nationalities and countries that
    count as category words for an actor do not here ("China Chopper");
    ADR-0050's own list has one ("russian")."""
    return _not_written_as_a_name(value, cased) or _all_generic(value, _not_a_name_for(EntityType.MALWARE))


def refine_cyner(value: str, etype: EntityType, cased: bool = True, malware: bool = False) -> str:
    """The CyNER fragment to keep (possibly shortened), or "" to drop it.
    `cased`: whether the report is written with capitals (text_is_cased).
    `malware`: ADR-0089's lead (malware_enabled); without it, malware is
    untouched and nothing is shortened."""
    if malware:
        value = cyner_normalise(value, etype)
        if etype == EntityType.MALWARE and malware_is_ordinary(value, cased):
            return ""
    if etype == EntityType.THREAT_ACTOR and actor_is_ordinary(value, cased):
        return ""
    return value


# ── B. CyNER: a name with its category around it (ADR-0089) ────────────────

# A trailing category word that never ends a name: "Ryuk ransomware", "TA575
# campaign", "TrickBot banking trojan".  "RAT", "loader", "stealer",
# "dropper" and "kit" are not here: Hallaj Pro RAT, Smoke Loader, Miner
# Dropper and RIG Exploit Kit are names.
_TRAILING_HEADS: dict[EntityType, tuple[str, ...]] = {
    EntityType.MALWARE: (
        "ransomware", "malware", "malwares", "payload", "payloads", "botnet", "botnets",
        "bots", "banking trojan", "trojan", "variant", "variants", "sample", "samples",
        "binary", "binaries", "executable", "executables", "family", "families", "strain",
        "strains", "infection", "infections", "campaign", "campaigns", "backdoor",
        "backdoors", "version", "service", "module", "plugin", "spam", "phishing"),
    EntityType.THREAT_ACTOR: (
        "campaign", "campaigns", "operation", "operations", "operators", "activity",
        "members", "affiliates", "threat actor", "threat actors", "threat group",
        "threat groups", "groups", "actors", "phishing", "spam", "attack", "attacks"),
}

# The category noun that ends a leading run of category words: "hacking group
# TA505", "multipurpose trojan QBot".  Per type: an actor keeps "Backdoor" in
# "Backdoor Diplomacy".
_LEADING_HEADS: dict[EntityType, frozenset[str]] = {
    EntityType.MALWARE: frozenset(
        "malware ransomware trojan rat backdoor botnet family variant tool framework".split()),
    EntityType.THREAT_ACTOR: frozenset("group groups actor actors hacker hackers gang".split()),
}

_FRAGMENT_SPLIT_RE = compile_pattern(r"[,/()\[\]]")


def split_cyner(raw_value: str) -> list[str]:
    """Stage 2d's split on commas and slashes, and on brackets: "Winnti Group
    (APT41" gives "Winnti Group" and "APT41"."""
    parts = [p.strip() for p in _FRAGMENT_SPLIT_RE.split(raw_value)]
    return [p for p in parts if p] or [raw_value]


def _names_something(value: str, etype: EntityType) -> bool:
    return any(c.isalpha() for c in value) and not _all_generic(value, _not_a_name_for(etype))


def _strip_trailing_heads(value: str, etype: EntityType) -> str:
    heads = sorted(_TRAILING_HEADS.get(etype, ()), key=len, reverse=True)
    stripped = True
    while stripped:
        stripped = False
        low = value.lower()
        for head in heads:
            if low.endswith(" " + head):
                rest = value[: len(value) - len(head) - 1].rstrip()
                if _names_something(rest, etype):
                    value, stripped = rest, True
                break
    return value


def _strip_leading_heads(value: str, etype: EntityType) -> str:
    heads = _LEADING_HEADS.get(etype, frozenset())
    words = value.split()
    extra = _not_a_name_for(etype)
    last_head = -1
    for i, word in enumerate(words):
        low = word.lower()
        if not (len(low) < 3 or all(_is_generic_word(t, extra) for t in _tokens(low))):
            break
        if low in heads:
            last_head = i
    else:
        return value        # nothing but category words: rule A judges it whole
    if last_head >= 0:
        rest = " ".join(words[last_head + 1:])
        if _names_something(rest, etype):
            return rest
    return value


def cyner_normalise(value: str, etype: EntityType) -> str:
    """`value` without its leading and trailing category words, as long as
    what remains names something ("Group 123" and "Linux backdoor" stay
    whole, and rule A then judges them)."""
    return _strip_trailing_heads(_strip_leading_heads(value, etype), etype)


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


def refine_spacy(value: str, etype: EntityType, malware: bool = False) -> str:
    """The spaCy entity value to keep (possibly shortened), or "" to drop it.
    Locations are filtered; with `malware` (ADR-0089, lead C), spaCy's
    PRODUCT label no longer proposes malware."""
    if etype == EntityType.LOCATION:
        return place_name(value)
    if malware and etype == EntityType.MALWARE:
        return ""
    return value
