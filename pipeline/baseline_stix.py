"""
Reading a STIX 2.1 bundle the analyst already has, and matching it to what
CTIParsor extracts (ADR-0090).

Pure: no store, no network, no file of its own (the first JSON-schema
validation may install the schemas into stix2-validator's package directory,
as Stage 5 does).  Review (Stage 3r) and Stage 4 both match
through this module, so the badges the analyst sees and the bundle that ships
cannot diverge (I6).  A baseline object, a job-store row and an object CTIParsor
built are all reduced to *keys* in one space (architecture 5.2), by one
normalisation (`normalize_value`); two things designate the same entity when
they share a strong key, or a name key within one family.

Sections: constants and types, families, entity types, normalisation, keys,
resolution, references, index types, intake (checks, scope, markings, index).
"""
from __future__ import annotations

import copy
import enum
import hashlib
import ipaddress
import json
import re
from collections import Counter, deque
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

import stix2
from stix2 import registry as stix2_registry
from stix2patterns.exceptions import ParseException
from stix2patterns.v21.pattern import Pattern

from pipeline import stage5_validation
from pipeline.aliases import alias_surface_forms, canonical_name, mitre_id_for, technique_id_for
from pipeline.detection import pattern_check, yara_check
from pipeline.stage2_extraction import refang
from pipeline.stage4_stix_mapping import (
    _COUNTRY_ISO,
    OPENCTI_EXTENSION_ID,
    TLP_LEVELS,
    _authoring_identity,
    _expand_registry_hive,
    _pap_marking,
    _tlp_marking,
    normalise_tlp,
)
from pipeline.stix_access import field

# ── Constants and types ─────────────────────────────────────────────────────

INDEX_VERSION = 1
MAX_BASELINE_BYTES = 20 * 1024 * 1024
MAX_BASELINE_OBJECTS = 10_000

# enrichment_status values (architecture 5.3)
NEW = "new"
MATCHED = "matched"
BASELINE_IN_TEXT = "baseline_in_text"
BASELINE_ONLY = "baseline_only"
IMPORTED = frozenset({BASELINE_IN_TEXT, BASELINE_ONLY})

# entities.source of a row imported from the baseline
SOURCE = "baseline_stix"


class BaselineError(ValueError):
    """The bundle cannot be used at all.  The message is shown to the analyst (HTTP 400)."""


Key = tuple[str, ...]          # ("obs", "ipv4-addr", "1.2.3.4"), ("mitre", "T1059.001"), …

T = TypeVar("T")

# Kinds whose match is certain.  "named" is the one other kind that can merge,
# and only inside a family.  "file_name" is weak: it designates a file only when
# exactly one baseline file carries the name (`BaselineIndex.lookup_weak`).
_STRONG_KINDS = frozenset({"id", "obs", "hash", "mitre", "cve", "loc"})

# ── Families ────────────────────────────────────────────────────────────────

# Two names match only within a family.  Without it an OpenCTI intrusion-set
# APT29 and CTIParsor's threat-actor APT29 never meet (ADR-0090).
_FAMILY = {"threat-actor": "actor", "intrusion-set": "actor", "malware": "software", "tool": "software"}


def family(stix_type: str) -> str:
    return _FAMILY.get(stix_type, stix_type)


# ── Entity types ────────────────────────────────────────────────────────────

# EntityType value -> STIX type, for every type CTIParsor emits.  Stage 4 has no
# such table (it builds each type in its own branch); tests/test_baseline_stix.py
# builds each type through Stage 4 and compares, so the two cannot drift.
_OBSERVABLE_TO_STIX = {
    "ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name", "url": "url",
    "email": "email-addr", "mac_addr": "mac-addr", "asn": "autonomous-system",
    "md5": "file", "sha1": "file", "sha256": "file", "file": "file",
    "registry_key": "windows-registry-key", "mutex": "mutex",
    "network_traffic": "network-traffic", "user_account": "user-account",
}
ENTITY_TO_STIX: dict[str, str] = {
    **_OBSERVABLE_TO_STIX,
    "cve": "vulnerability",
    # technique, tactic and procedure are legacy rows; Stage 4 still maps them
    "ttp": "attack-pattern", "technique": "attack-pattern",
    "tactic": "attack-pattern", "procedure": "attack-pattern",
    "malware": "malware", "threat_actor": "threat-actor", "intrusion_set": "intrusion-set",
    "tool": "tool", "campaign": "campaign", "infrastructure": "infrastructure",
    "identity": "identity", "location": "location", "incident": "incident",
}
OBSERVABLE_ENTITY_TYPES = frozenset(_OBSERVABLE_TO_STIX)

# SCO type -> the EntityType value whose normalisation applies to its value.
_ENTITY_OF_SCO = {
    "ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "domain-name": "domain", "url": "url",
    "email-addr": "email", "mac-addr": "mac_addr", "autonomous-system": "asn",
    "windows-registry-key": "registry_key", "mutex": "mutex", "user-account": "user_account",
}
# SCO type -> the property that holds its value, in an object and in a pattern.
_SCO_VALUE_FIELD = {
    "ipv4-addr": "value", "ipv6-addr": "value", "domain-name": "value", "url": "value",
    "email-addr": "value", "mac-addr": "value", "autonomous-system": "number",
    "windows-registry-key": "key", "mutex": "name", "user-account": "user_id",
}
# The SDO types that get name keys (everything else keeps its id key only).
_NAMED_STIX_TYPES = frozenset(set(ENTITY_TO_STIX.values()) - set(_OBSERVABLE_TO_STIX.values()))
_HASH_ENTITY_ALGO = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}


def _entity_type_value(entity_type: object) -> str:
    """The string of an EntityType, or of a plain string."""
    return str(getattr(entity_type, "value", entity_type))


# ── Normalisation ───────────────────────────────────────────────────────────

# One function for both sides, so a baseline value and a CTIParsor value meet.
# CTIParsor lowercases the value it dedups on (`_map_iocs_to_scos`), hence the
# lowercase of every observable but IP addresses, which get their canonical form.
_ASN = re.compile(r"(?:as)?\s*(\d+)", re.IGNORECASE)


def _canonical_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if "/" in value:                       # STIX allows a CIDR in ipv4-addr / ipv6-addr
        try:
            return str(ipaddress.ip_interface(value))
        except ValueError:
            pass
    return value.lower()


def _norm_name(name: str) -> str:
    return " ".join(name.casefold().split())


def normalize_value(entity_type: str, value: str) -> str:
    """The form of `value` that keys are made of.  `entity_type` is an EntityType value."""
    et = _entity_type_value(entity_type)
    v = value.strip()
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate ("\ud800", which JSON can carry): no value matches it,
        # and re2, which refang runs on where it is installed (CI), cannot read it.
        return ""
    if et in OBSERVABLE_ENTITY_TYPES:
        v = refang(v).strip()              # a defanged SCO value, or a defanged report one
    if et in ("ipv4", "ipv6"):
        return _canonical_ip(v)
    if et == "asn":
        m = _ASN.fullmatch(v)
        return (m.group(1).lstrip("0") or "0") if m else v.lower()
    if et == "registry_key":
        return _expand_registry_hive(v).lower()
    if et == "cve":
        return v.upper()
    if et in OBSERVABLE_ENTITY_TYPES:
        return v.lower()
    return _norm_name(v)


# ── Keys ────────────────────────────────────────────────────────────────────

# Both kinds of key are returned as (strong + named keys, weak keys); a weak key
# (a file name) counts only when one baseline file alone carries it (lot 7).

_HASH_ALGOS = {"MD5": "MD5", "SHA1": "SHA-1", "SHA256": "SHA-256"}
# Stage 4 writes source_name="capec" for a CAPEC id, which a row carries as mitre_id.
_MITRE_SOURCES = frozenset({"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack", "capec"})
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_ESCAPE = re.compile(r"\\(.)")


def _hash_algo(name: object) -> str | None:
    """A hash name as producers write it ("SHA256", "sha-256") in the STIX vocabulary."""
    return _HASH_ALGOS.get(re.sub(r"[-_\s]", "", str(name)).upper())


def _strings(value: object) -> list[str]:
    return [s.strip() for s in value if isinstance(s, str) and s.strip()] if isinstance(value, list) else []


def _obs_key(sco_type: str, raw: object) -> Key | None:
    norm = normalize_value(_ENTITY_OF_SCO[sco_type], str(raw))
    return ("obs", sco_type, norm) if norm else None


def _hash_key(algo: str, raw: object) -> Key | None:
    norm = normalize_value("sha256", str(raw))      # every hash type normalises alike
    return ("hash", algo, norm) if norm else None


def _named_keys(stix_type: str, name: str, aliases: Iterable[str] = ()) -> set[Key]:
    """("named", family, form) for the name, its aliases and, for an actor or a
    piece of software, its MITRE canonical name and surface forms.  The STIX type
    goes to `aliases` every time (ADR-0021)."""
    fam = family(stix_type)
    forms = {name, *aliases}
    if fam in ("actor", "software"):
        forms.add(canonical_name(name, stix_type))
        forms |= alias_surface_forms(name, stix_type)
    return {("named", fam, f) for f in map(_norm_name, forms) if f}


# A Location with one of these is finer than a country: it must not resolve to one.
_SUBNATIONAL = ("city", "administrative_area", "street_address", "postal_code", "latitude", "longitude")


def _iso_of(value: str) -> str | None:
    """An ISO 3166-1 alpha-2 code, from a code or from a country name as Stage 4 resolves it."""
    text = value.strip()
    return text.upper() if len(text) == 2 and text.isalpha() else _COUNTRY_ISO.get(text.lower())


def _name_key(name: str) -> set[Key]:
    """("loc", ISO-2) from a name Stage 4 resolves to a country."""
    iso = _COUNTRY_ISO.get(name.strip().lower())
    return {("loc", iso)} if iso else set()


def _location_key(obj: object, name: str) -> set[Key]:
    """("loc", ISO-2) of a Location, only when it is a country.

    OpenCTI writes `country` as the country NAME ("France"), only for a Country,
    and the kind of place in its extension (`location_type`) or, in older exports,
    in `x_opencti_location_type`.  A place with a city, an area, an address, a
    postal code or coordinates, or of another type, is not its country; a `name`
    that is not the country's own (a "Paris" in "FR") says the same.
    """
    if any(field(obj, p) not in (None, "") for p in _SUBNATIONAL):
        return set()
    types = [field(obj, "x_opencti_location_type")]
    extensions = field(obj, "extensions")
    extension = extensions.get(OPENCTI_EXTENSION_ID) if isinstance(extensions, Mapping) else None
    types.append(extension.get("location_type") if isinstance(extension, Mapping) else None)
    if any(t.strip().casefold() != "country" for t in types if isinstance(t, str) and t.strip()):
        return set()
    country = field(obj, "country")
    if not (isinstance(country, str) and country.strip()):
        return _name_key(name)                          # no country stated: the name decides
    iso = _iso_of(country)
    if iso is None:
        return set()
    if name and _COUNTRY_ISO.get(name.lower()) != iso and name.casefold() != country.strip().casefold():
        return set()
    return {("loc", iso)}


def keys_for_row(entity_type: str, value: str, mitre_id: str | None = None) -> tuple[set[Key], set[Key]]:
    """(strong + named keys, weak keys) of a job-store row or a RawEntity."""
    et = _entity_type_value(entity_type)
    stix_type = ENTITY_TO_STIX.get(et)
    if stix_type is None:
        return set(), set()
    norm = normalize_value(et, value)
    if not norm:
        return set(), set()
    if et in _HASH_ENTITY_ALGO:
        return {("hash", _HASH_ENTITY_ALGO[et], norm)}, set()
    if et == "file":
        return set(), {("file_name", norm)}
    if et in OBSERVABLE_ENTITY_TYPES:
        return {("obs", stix_type, norm)}, set()
    if et == "cve":
        return {("cve", norm)}, set()
    keys = _named_keys(stix_type, value.strip())
    mitre = mitre_id.strip().upper() if mitre_id and mitre_id.strip() else None
    if mitre is None and family(stix_type) in ("actor", "software"):
        mitre = mitre_id_for(value, stix_type)
    elif mitre is None and stix_type == "attack-pattern":
        mitre = technique_id_for(value)
    if mitre:
        keys.add(("mitre", mitre.upper()))
    if stix_type == "location":
        keys |= _name_key(value)
    return keys, set()


def keys_for_object(obj: object) -> tuple[set[Key], set[Key]]:
    """The same, for a STIX object (a dict, or a stix2 instance CTIParsor built)."""
    strong: set[Key] = set()
    weak: set[Key] = set()
    stix_type = field(obj, "type") or ""
    stix_id = field(obj, "id")
    if isinstance(stix_id, str) and stix_id:
        strong.add(("id", stix_id))

    if stix_type == "file":
        hashes = field(obj, "hashes")
        if isinstance(hashes, Mapping):
            for algo, digest in hashes.items():
                std = _hash_algo(algo)
                key = _hash_key(std, digest) if std else None
                if key:
                    strong.add(key)
        name = normalize_value("file", str(field(obj, "name") or ""))
        if name:
            weak.add(("file_name", name))
    elif stix_type in _SCO_VALUE_FIELD:
        raw = field(obj, _SCO_VALUE_FIELD[stix_type])
        key = _obs_key(stix_type, raw) if raw is not None else None
        if key:
            strong.add(key)
    elif stix_type == "indicator":
        if field(obj, "pattern_type") == "stix":
            from_pattern = pattern_keys(str(field(obj, "pattern") or ""))
            strong |= from_pattern[0]
            weak |= from_pattern[1]
    elif stix_type in _NAMED_STIX_TYPES:
        strong |= _named_object_keys(obj, stix_type)
    return strong, weak


def _named_object_keys(obj: object, stix_type: str) -> set[Key]:
    keys: set[Key] = set()
    name = field(obj, "name")
    name = name.strip() if isinstance(name, str) else ""
    aliases = _strings(field(obj, "aliases")) + _strings(field(obj, "x_mitre_aliases"))
    keys |= _named_keys(stix_type, name, aliases)

    mitre = {
        str(field(ref, "external_id")).strip().upper()
        for ref in field(obj, "external_references") or ()
        if field(ref, "source_name") in _MITRE_SOURCES and field(ref, "external_id")
    }
    if not mitre and name:
        guess = None
        if family(stix_type) in ("actor", "software"):
            guess = mitre_id_for(name, stix_type)
        elif stix_type == "attack-pattern":
            guess = technique_id_for(name)
        mitre = {guess.upper()} if guess else set()
    keys |= {("mitre", m) for m in mitre}

    if stix_type == "vulnerability":
        cves = {str(field(ref, "external_id")).strip() for ref in field(obj, "external_references") or ()
                if field(ref, "source_name") == "cve" and field(ref, "external_id")}
        cves |= {name} if _CVE.fullmatch(name) else set()
        keys |= {("cve", normalize_value("cve", c)) for c in cves}
    elif stix_type == "location":
        keys |= _location_key(obj, name)
    return keys


def _literal(raw: str) -> str:
    """stix2patterns returns string literals WITH their quotes ("'1.2.3.4'"), and
    numbers bare.  STIX escapes `\\'` and `\\\\` inside a string."""
    if len(raw) >= 2 and raw[0] == raw[-1] == "'":
        return _ESCAPE.sub(r"\1", raw[1:-1])
    return raw


# stix2patterns' parser is recursive: a pattern of a thousand terms or of a few
# hundred nested brackets exhausts it.  Measured: 1 200 OR terms raise
# RecursionError on 3.14, and on CI (3.12, the full suite under coverage) a
# 4 000-term OR killed the test process without a word.  A pattern beyond these
# bounds never reaches a parser, the stix2 library's included; real indicators
# (MISP, OpenCTI, CTIParsor's own) stay far below them.
_MAX_PATTERN_CHARS = 65_536
_MAX_PATTERN_JOINERS = 256          # AND, OR, FOLLOWEDBY outside literals
_MAX_PATTERN_DEPTH = 64             # brackets and parentheses outside literals
_PATTERN_JOINERS = frozenset({"AND", "OR", "FOLLOWEDBY"})


def pattern_too_complex(pattern: str) -> bool:
    """True when `pattern` is too long, too deeply nested or joins too many terms
    to be handed to a parser.  One linear pass; what is quoted is skipped."""
    if len(pattern) > _MAX_PATTERN_CHARS:
        return True
    depth = joiners = 0
    word: list[str] = []
    in_literal = escaped = False
    for ch in pattern + " ":
        if in_literal:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "'":
                in_literal = False
            continue
        if ch.isalpha():
            word.append(ch)
            continue
        if word:
            if "".join(word).upper() in _PATTERN_JOINERS:
                joiners += 1
                if joiners > _MAX_PATTERN_JOINERS:
                    return True
            word.clear()
        if ch == "'":
            in_literal = True
        elif ch in "([":
            depth += 1
            if depth > _MAX_PATTERN_DEPTH:
                return True
        elif ch in ")]":
            depth -= 1
    return False


def pattern_keys(pattern: str) -> tuple[set[Key], set[Key]]:
    """The keys a STIX 2.1 pattern states with `=`.  A pattern that does not parse,
    is too complex to be parsed (`pattern_too_complex`), or states nothing but
    MATCHES, LIKE, IN, NOT = and the like, has none: it is copied without
    matching.  Never raises."""
    strong: set[Key] = set()
    weak: set[Key] = set()
    if not isinstance(pattern, str) or pattern_too_complex(pattern):
        return strong, weak
    try:
        # RecursionError: kept as a last resort below the bounds above.
        comparisons = Pattern(pattern).inspect().comparisons
    except (ParseException, RecursionError):
        return strong, weak
    for obj_type, items in comparisons.items():
        for path, op, raw in items:
            if op != "=":
                continue
            props = tuple(path)
            value = _literal(raw)
            if obj_type == "file" and len(props) == 2 and props[0] == "hashes":
                algo = _hash_algo(props[1])       # SSDEEP, TLSH, …: no CTIParsor entity type
                key = _hash_key(algo, value) if algo else None
                if key:
                    strong.add(key)
            elif obj_type == "file" and props == ("name",):
                name = normalize_value("file", value)
                if name:
                    weak.add(("file_name", name))
            elif props == (_SCO_VALUE_FIELD.get(obj_type),):
                key = _obs_key(obj_type, value)
                if key:
                    strong.add(key)
    return strong, weak


# ── Resolution ──────────────────────────────────────────────────────────────

class _Ambiguous(enum.Enum):
    AMBIGUOUS = "ambiguous"

    def __bool__(self) -> bool:
        return False                   # "no entry" and "several" both read as falsy; test `is AMBIGUOUS`


# What `resolve` returns when several baseline entries fit and none has the
# exact type: nothing merges, and the caller notes `baseline_ambiguous`.
AMBIGUOUS = _Ambiguous.AMBIGUOUS


def resolve(keys: set[Key], stix_type: str | None, by_key: Mapping[Key, Sequence[T]],
            type_of: Callable[[T], str]) -> T | None | _Ambiguous:
    """The baseline candidate `keys` designate, None when there is none, AMBIGUOUS
    when there are several and none has the exact `stix_type`.

    Candidates are those that share a strong key, or a name key of `stix_type`'s
    family (any family when `stix_type` is None); weak keys are never looked at.
    One candidate is the answer; several are narrowed to the exact type.
    """
    fam = family(stix_type) if stix_type else None
    found: dict[int, T] = {}
    for key in keys:
        if key[0] == "named":
            if fam is not None and key[1] != fam:
                continue
        elif key[0] not in _STRONG_KINDS:
            continue
        for candidate in by_key.get(key, ()):
            found.setdefault(id(candidate), candidate)
    if not found:
        return None
    candidates = list(found.values())
    if len(candidates) == 1:
        return candidates[0]
    exact = [c for c in candidates if stix_type is not None and type_of(c) == stix_type]
    return exact[0] if len(exact) == 1 else AMBIGUOUS


# ── References ──────────────────────────────────────────────────────────────

# Any `<type>--<something>`: an id that fails the strict format is still a
# reference, and what points at an excluded invalid object must follow it out.
_REF_TYPE = re.compile(r"[a-z][a-z0-9-]*")


def _is_ref_id(item: str) -> bool:
    """`<type>--<something without whitespace>`, checked without a pattern that
    backtracks (a regex of the whole form is quadratic on "a" + "-" * n + " ")."""
    kind, separator, rest = item.partition("--")
    return bool(separator and rest and _REF_TYPE.fullmatch(kind) and rest.split() == [rest])


def iter_refs(obj: object) -> Iterator[str]:
    """Every id `obj` references: any key ending in _ref / _refs, at any depth
    (extensions, granular_markings[].marking_ref, network-traffic src_ref, …).
    Only values that are STIX ids; one per occurrence, in no set order."""
    stack: list[object] = [obj]
    while stack:                     # a loop, not recursion: the depth is the bundle's
        node = stack.pop()
        if isinstance(node, Mapping):
            for key, value in node.items():
                if isinstance(key, str) and key.endswith(("_ref", "_refs")):
                    items = value if isinstance(value, (list, tuple)) else (value,)
                    for item in items:
                        if isinstance(item, str) and _is_ref_id(item):
                            yield item
                stack.append(value)
        elif isinstance(node, (list, tuple)):
            stack.extend(node)


def ref_closure(objects: Mapping[str, dict], candidates: set[str], excluded: set[str],
                protected: AbstractSet[str] = frozenset()) -> tuple[set[str], dict[str, str]]:
    """(kept ids, {dropped id: reason}).

    Starts from `candidates - excluded` and drops, until nothing moves, every
    object that references an excluded or an already dropped id.  An object goes
    whole, never pruned (I2).  A reference to an id absent from `objects` drops
    nothing: it dangled in the source bundle already.  `protected` objects (the
    chosen Report) are never dropped.  Excluded ids are not in the dict: the
    caller holds their reasons.
    """
    kept = set(candidates) - excluded
    referrers: dict[str, list[str]] = {}
    for oid in sorted(kept):
        if oid in objects:
            for ref in set(iter_refs(objects[oid])):
                referrers.setdefault(ref, []).append(oid)
    dropped: dict[str, str] = {}
    queue = deque(sorted(excluded))
    while queue:
        bad = queue.popleft()
        for oid in referrers.get(bad, ()):
            if oid not in dropped and oid not in protected:
                dropped[oid] = f"baseline_refs_closure:{bad}"
                queue.append(oid)
    return kept.difference(dropped), dropped


# ── Index types ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Entry:
    """One thing the review shows as an entity.  An IoC held as an SCO, its
    Indicator(s) and the based-on between them is ONE entry."""
    entry_id: str                      # the SDO id; for an IoC, the SCO id, or the Indicator id if alone
    stix_type: str                     # for an IoC, the observable's type, whichever object holds it
    entity_type: str                   # EntityType value
    value: str                         # what the card shows
    mitre_id: str | None
    keys: frozenset[Key]               # strong keys + ("named", family, name)
    weak_keys: frozenset[Key]          # ("file_name", …): see BaselineIndex.lookup_weak
    sco_id: str | None = None
    indicator_ids: tuple[str, ...] = ()
    object_ids: tuple[str, ...] = ()   # every object of the entry, based-on SROs included
    surface_forms: tuple[str, ...] = ()  # searched in the report text (Stage 3r pass 2)


@dataclass(frozen=True)
class Relation:
    stix_id: str
    relationship_type: str
    source_ref: str
    target_ref: str
    source_entry: str | None           # entry_id, after routing an Indicator to its IoC
    target_entry: str | None


@dataclass
class Intake:
    """What /inspect shows and what job_baselines.intake_json stores."""
    sha256: str
    bundle_id: str
    counts: dict[str, int]                                       # imported, by STIX type; + out_of_scope, dangling_refs
    excluded: list[dict] = dataclass_field(default_factory=list)  # {id, type, reason, detail}, all str
    warnings: list[str] = dataclass_field(default_factory=list)
    reports: list[dict] = dataclass_field(default_factory=list)   # {id, name, published, refs}: every report
    scope_report_id: str | None = None                           # the report chosen (D4); None when the bundle has none
    needs_report_choice: bool = False                            # several reports and none chosen yet
    min_tlp: str | None = None                                   # in `normalise_tlp`'s vocabulary
    min_pap: str | None = None                                   # in `_pap_marking`'s: WHITE, GREEN, AMBER, RED


@dataclass
class BaselineIndex:
    """The normalised form of a baseline: ids and keys, not the objects."""
    version: int
    sha256: str
    bundle_id: str
    entries: list[Entry]
    relations: list[Relation]
    imported_ids: frozenset[str]        # in scope and not excluded: every object of the bundle that ships
    passthrough_ids: frozenset[str]     # imported, in no entry and no relation (reports and authors too)
    report_ids: tuple[str, ...]         # the reports among the imported objects
    scope_report_id: str | None = None
    # key -> entries, built by the first `lookup`; neither serialised nor compared
    _by_key: dict[Key, list[Entry]] | None = dataclass_field(default=None, init=False, repr=False, compare=False)
    _by_weak: dict[Key, list[Entry]] | None = dataclass_field(default=None, init=False, repr=False, compare=False)

    def lookup(self, keys: set[Key], stix_type: str | None = None) -> Entry | None | _Ambiguous:
        """The entry `keys` designate (`resolve`'s rule): None, one entry, or AMBIGUOUS."""
        if self._by_key is None:
            by_key: dict[Key, list[Entry]] = {}
            for entry in self.entries:
                for key in entry.keys:
                    if _key_fits(key, entry.stix_type):
                        by_key.setdefault(key, []).append(entry)
            self._by_key = by_key
        return resolve(keys, stix_type, self._by_key, lambda entry: entry.stix_type)

    def lookup_weak(self, weak: set[Key]) -> Entry | None:
        """The one baseline file a file name designates: None when no entry or more
        than one carries the name, or when the one that does holds no file object
        (a name-only Indicator alone: Stage 4 has no file to merge into, so Stage 3r
        must not show the row as that entry either, I6)."""
        if self._by_weak is None:
            by_weak: dict[Key, list[Entry]] = {}
            for entry in self.entries:
                for key in entry.weak_keys:
                    by_weak.setdefault(key, []).append(entry)
            self._by_weak = by_weak
        found = {e.entry_id: e for key in weak for e in self._by_weak.get(key, ())}
        if len(found) != 1:
            return None
        (carrier,) = found.values()
        return carrier if carrier.sco_id is not None else None

    def to_json(self) -> str:
        return json.dumps({
            "version": self.version, "sha256": self.sha256, "bundle_id": self.bundle_id,
            "entries": [_entry_to_dict(e) for e in self.entries],
            "relations": [vars(r) for r in self.relations],
            "imported_ids": sorted(self.imported_ids), "passthrough_ids": sorted(self.passthrough_ids),
            "report_ids": list(self.report_ids), "scope_report_id": self.scope_report_id,
        }, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> BaselineIndex:
        """Refuses another INDEX_VERSION, and what is not an index."""
        try:
            data = json.loads(raw)
            version = data["version"]
        except (KeyError, TypeError, ValueError) as exc:
            raise BaselineError(f"not a baseline index: {_failure(exc)}") from exc
        if version != INDEX_VERSION:
            raise BaselineError(f"baseline index version {version!r} is not the current {INDEX_VERSION}")
        try:
            return cls(
                version=version, sha256=data["sha256"], bundle_id=data["bundle_id"],
                entries=[_entry_from_dict(e) for e in data["entries"]],
                relations=[Relation(**r) for r in data["relations"]],
                imported_ids=frozenset(data["imported_ids"]), passthrough_ids=frozenset(data["passthrough_ids"]),
                report_ids=tuple(data["report_ids"]), scope_report_id=data["scope_report_id"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise BaselineError(f"not a baseline index: {_failure(exc)}") from exc


def _entry_to_dict(entry: Entry) -> dict[str, Any]:
    out = dict(vars(entry))
    for name in ("keys", "weak_keys"):
        out[name] = sorted(list(k) for k in out[name])
    for name in ("indicator_ids", "object_ids", "surface_forms"):
        out[name] = list(out[name])
    return out


def _entry_from_dict(data: dict[str, Any]) -> Entry:
    return Entry(
        **{**data,
           "keys": frozenset(tuple(k) for k in data["keys"]),
           "weak_keys": frozenset(tuple(k) for k in data["weak_keys"]),
           "indicator_ids": tuple(data["indicator_ids"]), "object_ids": tuple(data["object_ids"]),
           "surface_forms": tuple(data["surface_forms"])})


# ── Markings ────────────────────────────────────────────────────────────────

# PAP, least to most restrictive, in the vocabulary of `_pap_marking`.
_PAP_ORDER = ("WHITE", "GREEN", "AMBER", "RED")
# Matched on a text with its whitespace removed and upper-cased, so "TLP: amber
# strict" and "TLP:AMBER+STRICT" are one; no pattern here can backtrack.
_TLP_NAME = re.compile(r"TLP:(CLEAR|WHITE|GREEN|AMBER(?:\+?STRICT)?|RED)")
_PAP_NAME = re.compile(r"PAP:(CLEAR|WHITE|GREEN|AMBER|RED)")
_LEVEL_HINT = re.compile(r"\b(?:TLP|PAP)\b", re.IGNORECASE)
_MARKINGS_LISTED = 10                  # markings that resolve to nothing, named one by one in the warnings
_LEVEL_TEXT_MAX = 100                  # a longer text states no level, and is not squeezed
_TLP_2_0 = "tlp_2_0"                   # the property of the TLP 2.0 extension (levels such as "amber+strict")

# The markings CTIParsor emits, by id: ("tlp", level) or ("pap", level).  The
# TLP 1.0 ids of the STIX 2.1 specification are among them (stix2's constants),
# and so is AMBER+STRICT, the one TLP 2.0 level.
_KNOWN_MARKINGS: dict[str, tuple[str, str]] = {
    **{_tlp_marking(level).id: ("tlp", level) for level in TLP_LEVELS},
    **{_pap_marking(level).id: ("pap", level) for level in _PAP_ORDER},
}


def _level_in(text: object) -> tuple[str, str] | None:
    """The ("tlp" | "pap", level) a short text states, in CTIParsor's vocabulary."""
    if not isinstance(text, str) or len(text) > _LEVEL_TEXT_MAX:
        return None
    compact = "".join(text.split()).upper()
    if m := _TLP_NAME.fullmatch(compact):
        return "tlp", normalise_tlp(m.group(1).replace("AMBERSTRICT", "AMBER+STRICT"))
    if m := _PAP_NAME.fullmatch(compact):
        return "pap", "WHITE" if m.group(1) == "CLEAR" else m.group(1)
    return None


def _prefixed(prefix: str, value: object) -> str | None:
    """"amber" -> "TLP:amber"; "pap:amber" stays (OpenCTI writes both)."""
    if not isinstance(value, str):
        return None
    return value if value.strip().upper().startswith(prefix) else f"{prefix}:{value}"


def _marking_texts(marking: object) -> list[object]:
    """Every text of a marking-definition that can state a level: its name,
    `definition.tlp` / `.pap` / `.statement` and the `tlp_2_0` of an extension."""
    texts: list[object] = [field(marking, "name")]
    definition = field(marking, "definition")
    if isinstance(definition, Mapping):
        texts += [_prefixed("TLP", definition.get("tlp")), _prefixed("PAP", definition.get("pap")),
                  definition.get("statement")]
    extensions = field(marking, "extensions")
    if isinstance(extensions, Mapping):
        texts += [_prefixed("TLP", ext.get(_TLP_2_0)) for ext in extensions.values() if isinstance(ext, Mapping)]
    return texts


def _marking_states(marking: object) -> set[tuple[str, str]]:
    """The most restrictive TLP and the most restrictive PAP a marking-definition
    states, whichever of its texts says them.  Empty when it states none."""
    read = [r for r in map(_level_in, _marking_texts(marking)) if r]
    states = set()
    for kind, order in (("tlp", TLP_LEVELS), ("pap", _PAP_ORDER)):
        levels = [level for k, level in read if k == kind]
        if levels:
            states.add((kind, max(levels, key=order.index)))
    return states


def _looks_like_level(marking: object) -> bool:
    """Does a marking-definition present itself as a TLP or a PAP (so that an
    unreadable one is worth a warning)?"""
    definition_type = _str(marking, "definition_type").casefold()
    statement = field(marking, "definition")
    statement = _text(statement.get("statement")) if isinstance(statement, Mapping) else ""
    extensions = field(marking, "extensions")
    return (definition_type in ("tlp", "pap") or _str(marking, "name").strip().upper().startswith(("TLP", "PAP"))
            or (definition_type == "statement" and bool(_LEVEL_HINT.search(statement[:300])))
            or (isinstance(extensions, Mapping)
                and any(isinstance(e, Mapping) and _TLP_2_0 in e for e in extensions.values())))


def _marking_refs(obj: object) -> list[str]:
    """The markings an object carries: `object_marking_refs` and every
    `granular_markings[].marking_ref`."""
    refs = field(obj, "object_marking_refs")
    found = [r for r in refs if isinstance(r, str)] if isinstance(refs, (list, tuple)) else []
    granular = field(obj, "granular_markings")
    if isinstance(granular, (list, tuple)):
        found += [r for g in granular if isinstance(r := field(g, "marking_ref"), str)]
    return found


def _most_restrictive(objects: Iterable[object], markings: Mapping[str, object],
                      warnings: list[str]) -> tuple[str | None, str | None]:
    """(TLP, PAP) of the most restrictive marking the `objects` carry.  A marking
    is known by its id or, failing that, by its content among `markings`; one
    that presents itself as a TLP or a PAP and states no level is warned about."""
    tlp: list[str] = []
    pap: list[str] = []
    unreadable: set[str] = set()
    missing: dict[str, None] = {}
    for obj in objects:
        for ref in _marking_refs(obj):
            states: set[tuple[str, str]] = set()
            if ref in _KNOWN_MARKINGS:
                states = {_KNOWN_MARKINGS[ref]}
            elif ref in markings:
                states = _marking_states(markings[ref])
                if not states and ref not in unreadable and _looks_like_level(markings[ref]):
                    unreadable.add(ref)
                    warnings.append(f"the marking {_clip(ref)} looks like a TLP or a PAP but states no level that "
                                    "can be read: it is ignored in the minimum")
            else:
                missing[ref] = None
            for kind, level in states:
                (tlp if kind == "tlp" else pap).append(level)
    for ref in list(missing)[:_MARKINGS_LISTED]:
        warnings.append(f"marking {_clip(ref)} cannot be read: not counted in the TLP/PAP minimum")
    if len(missing) > _MARKINGS_LISTED:
        warnings.append(f"{len(missing) - _MARKINGS_LISTED} more marking(s) cannot be read: not counted in the "
                        "TLP/PAP minimum")
    return (max(tlp, key=TLP_LEVELS.index) if tlp else None,
            max(pap, key=_PAP_ORDER.index) if pap else None)


# ── Intake ──────────────────────────────────────────────────────────────────

# Reasons of an exclusion (ADR-0090).  `baseline_out_of_scope` is only counted.
INVALID = "baseline_invalid"
OLDER_VERSION = "baseline_older_version"
RULE_REFUSED = "baseline_rule_refused"
ID_COLLISION = "baseline_id_collision"
REFS_CLOSURE = "baseline_refs_closure"

_ID = re.compile(r"[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_DETAIL_MAX = 300
_FIELD_MAX = 200                        # an id, a type or a name quoted back to the analyst
_REPORTS_LISTED = 10                    # in the message that asks for a choice
_MAX_JSON_OBJECTS = 50 * MAX_BASELINE_OBJECTS     # JSON objects however nested: a guard on memory, before the count
# The search for the objects the schemas refuse validates, at most, this many
# times the bytes it is given (one culprit costs a little under 3 times).
_VALIDATION_BUDGET_FACTOR = 3
_SCO_TYPES = frozenset(stix2_registry.STIX2_OBJ_MAPS["2.1"]["observables"])   # may lack spec_version
_RULE_TYPES = frozenset({"yara", "sigma", "suricata", "snort"})
_RULE_LIBRARY = {"yara": "yara-python", **{t: lib for t, (lib, _) in pattern_check._CHECKERS.items()}}
_TOO_DEEP = "too deeply nested to read"
_PATTERN_TOO_LONG = "pattern too long or too deeply nested to read"
_VALIDATION_BUNDLE_ID = "bundle--00000000-0000-4000-8000-000000000000"
_EPOCH = datetime.min.replace(tzinfo=UTC)


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _clip(text: str, limit: int = _FIELD_MAX) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _str(obj: object, key: str) -> str:
    return _text(field(obj, key))


def _exclusion(obj: Mapping[str, Any], reason: str, detail: str = "") -> dict[str, str]:
    return {"id": _clip(_text(obj.get("id"))), "type": _clip(_text(obj.get("type"))), "reason": reason,
            "detail": detail[:_DETAIL_MAX]}


def _modified(obj: Mapping[str, Any]) -> datetime:
    """`modified` as a UTC datetime; the epoch when it is missing or unreadable."""
    raw = obj.get("modified")
    try:
        ts = datetime.fromisoformat(raw) if isinstance(raw, str) else _EPOCH
        return (ts if ts.tzinfo else ts.replace(tzinfo=UTC)).astimezone(UTC)
    except (ValueError, OverflowError):
        return _EPOCH


def _id_problem(obj: Mapping[str, Any]) -> str | None:
    oid = obj.get("id")
    if not isinstance(oid, str):
        return "the id is missing or is not a string"
    if not isinstance(obj.get("type"), str):
        return "the type is missing or is not a string"
    if not _ID.fullmatch(oid):
        return f"the id {oid[:80]!r} is not <type>--<uuid>"
    return None


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _load(raw: bytes) -> tuple[dict, list[dict]]:
    """Steps 2 to 4: the bundle and its objects, or BaselineError."""
    seen = 0

    def count(node: dict) -> dict:
        nonlocal seen
        seen += 1
        if seen > _MAX_JSON_OBJECTS:
            raise BaselineError(f"the baseline holds more than {_MAX_JSON_OBJECTS} JSON objects")
        return node

    try:
        bundle = json.loads(raw, parse_constant=_no_constant, object_hook=count)    # UnicodeDecodeError is a ValueError
    except BaselineError:
        raise
    except ValueError as exc:
        raise BaselineError(f"not valid JSON: {exc}") from exc
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise BaselineError('not a STIX bundle: the top-level object must have "type": "bundle"')
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise BaselineError('not a usable STIX bundle: "objects" must be a non-empty list')
    if len(objects) > MAX_BASELINE_OBJECTS:
        raise BaselineError(f"the bundle holds {len(objects)} objects, more than the {MAX_BASELINE_OBJECTS} accepted")
    if not all(isinstance(o, dict) for o in objects):
        raise BaselineError('not a usable STIX bundle: every item of "objects" must be an object')
    if bundle.get("spec_version") == "2.0":
        raise BaselineError('STIX 2.0 bundle ("spec_version": "2.0"): only STIX 2.1 is accepted')
    old = [o for o in objects if o.get("spec_version") != "2.1"
           and not (o.get("spec_version") is None and _text(o.get("type")) in _SCO_TYPES)]
    if old:
        raise BaselineError(f'STIX 2.0 objects: {len(old)} object(s) without "spec_version": "2.1", '
                            f'first {_clip(_text(old[0].get("id")))!r}; only STIX 2.1 is accepted')
    return bundle, objects


def _scope(objects: Mapping[str, dict], root: str) -> set[str]:
    """`root` and, transitively, every object it references that the bundle holds;
    then every relationship between two of those, even one the Report does not list
    (CTIParsor keeps ATT&CK and composed edges out of its Report's object_refs: left
    out of scope, they came back from Stage 4 under new ids), with what it references."""
    def closure(start: str, seen: set[str]) -> None:
        seen.add(start)
        stack = [start]
        while stack:
            for ref in iter_refs(objects[stack.pop()]):
                if ref in objects and ref not in seen:
                    seen.add(ref)
                    stack.append(ref)

    seen: set[str] = set()
    closure(root, seen)
    for oid, obj in objects.items():
        if (oid not in seen and isinstance(obj, dict) and obj.get("type") == "relationship"
                and obj.get("source_ref") in seen and obj.get("target_ref") in seen):
            closure(oid, seen)
    return seen


def _failure(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


def _validate(objects: list[dict]) -> stage5_validation.ValidationResult:
    """Stage 5's validation of a bundle of `objects`, silently."""
    try:
        text = json.dumps({"type": "bundle", "id": _VALIDATION_BUNDLE_ID, "objects": objects})
        return stage5_validation.validate_bundle(text, quiet=True)
    except RecursionError:
        return stage5_validation.ValidationResult(stage5_validation.INVALID, [_TOO_DEEP])
    except Exception as exc:  # noqa: BLE001 — a validator that falls over refuses the objects
        return stage5_validation.ValidationResult(stage5_validation.INVALID, [_failure(exc)])


def _detail(oid: str, errors: list[str]) -> str:
    """The messages of the errors about `oid` (their prefix is its id), else all of them."""
    prefix = f"{oid}: "
    own = [e.removeprefix(prefix) for e in errors if e.startswith(prefix)]
    return "; ".join(own or errors)


def _split(items: list[tuple[dict, int]]) -> int:
    """Where to cut `items` so the two halves weigh about the same, never leaving one empty."""
    total = sum(size for _, size in items)
    running = 0
    for count, (_, size) in enumerate(items[:-1], 1):
        running += size
        if running * 2 >= total:
            return count
    return len(items) - 1


def _bisect(items: list[tuple[dict, int]], verdict: stage5_validation.ValidationResult, spent: list[int],
            limit: int) -> list[tuple[dict, str]]:
    """The objects of `items` (object, serialized size), a bundle the schemas
    refuse (`verdict`), that they refuse alone: each half is validated as a
    bundle and only a refused half is searched further.  Halves weigh the same in
    bytes, so one heavy object ends up alone and is not validated again at every
    level.  Nothing is found when the fault lies between objects that pass
    separately.  `spent` counts the bytes validated so far; past `limit` the
    search stops: objects that fail one by one make every half fail, and the cost
    would grow with their number."""
    if len(items) == 1:
        obj = items[0][0]
        return [(obj, _detail(obj["id"], verdict.errors))]
    middle = _split(items)
    found = []
    for half in (items[:middle], items[middle:]):
        spent[0] += sum(size for _, size in half)
        if spent[0] > limit:
            raise BaselineError(f"too many objects fail the STIX schemas to locate them ({spent[0]} bytes validated "
                                "on the search); fix the bundle")
        one = _validate([obj for obj, _ in half])
        if one.status == stage5_validation.INVALID:
            found += _bisect(half, one, spent, limit)
    return found


def _own(oid: str, errors: list[str]) -> set[str]:
    """The messages of the errors about `oid`, without their prefix."""
    prefix = f"{oid}: "
    return {e.removeprefix(prefix) for e in errors if e.startswith(prefix)}


def _schema_failures(objects: list[dict], warnings: list[str]) -> list[tuple[dict, str]]:
    """The objects the JSON schemas refuse, with the message.

    The bundle is validated once.  The validator starts each error with the id of
    the object it is about ("malware--…: 'is_family' is a required property"), but
    that id can come from another object's data (a list property holding a dict
    with an id and a type), so each object named is validated ALONE: it is a
    culprit only if it fails alone.  When every error is attributed and each is
    reproduced by the solo run of the object it names, everything is explained
    and that is all.  Otherwise (an error about no object, or one that is not
    reproduced: the signature of a borrowed id) what is not confirmed is
    validated once more, and searched by halves, within a budget, if that fails.
    """
    whole = _validate(objects)
    if whole.status == stage5_validation.UNVERIFIED:
        warnings.append("the STIX JSON schemas are not installed: the objects were checked by the stix2 library only")
        return []
    if whole.status != stage5_validation.INVALID:
        return []
    ids = {o["id"] for o in objects}
    attributed: dict[str, set[str]] = {}
    unattributed = False
    for error in whole.errors:
        prefix, separator, message = error.partition(": ")
        if separator and prefix in ids:
            attributed.setdefault(prefix, set()).add(message)
        else:
            unattributed = True
    explained = bool(attributed) and not unattributed
    failures = []
    for obj in objects:
        oid = obj["id"]
        if oid in attributed:
            alone = _validate([obj])
            if alone.status == stage5_validation.INVALID:
                failures.append((obj, _detail(oid, alone.errors)))
            explained = explained and attributed[oid] <= _own(oid, alone.errors)
    if explained:
        return failures
    confirmed = {obj["id"] for obj, _ in failures}
    rest = [obj for obj in objects if obj["id"] not in confirmed]
    verdict = whole if len(rest) == len(objects) else (_validate(rest) if rest else None)
    if verdict is not None and verdict.status == stage5_validation.INVALID:
        items = [(obj, len(json.dumps(obj))) for obj in rest]
        total = sum(size for _, size in items)
        slack = 2 * len(items).bit_length() * max(size for _, size in items)     # the halves are cut between objects
        failures += _bisect(items, verdict, [total], _VALIDATION_BUDGET_FACTOR * total + slack)
    if not failures:
        warnings.append("the bundle as a whole fails the STIX schemas although each object passes: "
                        + "; ".join(whole.errors)[:_DETAIL_MAX])
    return failures


def _rule_verdict(pattern_type: str, pattern: str) -> tuple[str, str | None]:
    """(status, message) of one quoted rule, in pattern_check's vocabulary."""
    if pattern_type != "yara":
        return pattern_check.check_pattern(pattern_type, pattern)
    status, error = yara_check.compile_status(pattern)       # as it is: a baseline object is not repaired
    verdict = {yara_check.COMPILES: pattern_check.ACCEPTED, yara_check.DOES_NOT_COMPILE: pattern_check.REFUSED}
    return verdict.get(status, pattern_check.UNVERIFIED), error


def _collision(obj: object, author: object) -> bool:
    """Does `obj` take an id CTIParsor emits, for something else?  The same
    marking states the same level, the same identity has the same name and
    class; the rest (description, timestamps, OpenCTI's extension) may differ."""
    oid = field(obj, "id")
    if oid == field(author, "id"):
        return any(field(obj, p) != field(author, p) for p in ("name", "identity_class"))
    return oid in _KNOWN_MARKINGS and _marking_states(obj) != {_KNOWN_MARKINGS[oid]}


def _check(in_scope: list[dict], warnings: list[str],
           validate: bool) -> tuple[dict[str, Any], list[tuple[dict, str, str]]]:
    """Steps 8 to 10.  Returns ({id: stix2 object} of the objects that stay,
    [(object, reason, detail)] of those that go)."""
    parsed: dict[str, Any] = {}
    dropped: list[tuple[dict, str, str]] = []
    for obj in in_scope:
        pattern = obj.get("pattern")
        if (obj.get("type") == "indicator" and obj.get("pattern_type") == "stix"
                and isinstance(pattern, str) and pattern_too_complex(pattern)):
            # stix2 would parse the pattern to check it: refused before it does.
            dropped.append((obj, INVALID, _PATTERN_TOO_LONG))
            continue
        try:
            parsed[obj["id"]] = stix2.parse(obj, allow_custom=True)
        except RecursionError:
            dropped.append((obj, INVALID, _PATTERN_TOO_LONG if obj.get("type") == "indicator" else _TOO_DEEP))
        except Exception as exc:  # noqa: BLE001 — stix2 raises its own errors, and others on hostile values
            dropped.append((obj, INVALID, _failure(exc)))
    if validate:
        for obj, message in _schema_failures([o for o in in_scope if o["id"] in parsed], warnings):
            del parsed[obj["id"]]
            dropped.append((obj, INVALID, message))
    else:
        warnings.append("the STIX schemas were not checked (validate=False): the objects were checked by the stix2 "
                        "library only")

    unchecked: Counter[str] = Counter()
    raw = {o["id"]: o for o in in_scope}
    for oid, stix_obj in list(parsed.items()):
        pattern_type = _str(stix_obj, "pattern_type")
        if field(stix_obj, "type") == "indicator" and pattern_type in _RULE_TYPES:
            status, error = _rule_verdict(pattern_type, _str(stix_obj, "pattern"))
            if status == pattern_check.REFUSED:
                del parsed[oid]
                dropped.append((raw[oid], RULE_REFUSED, error or ""))
            elif status == pattern_check.UNVERIFIED:
                unchecked[pattern_type] += 1
    for pattern_type, n in sorted(unchecked.items()):
        warnings.append(f"{_RULE_LIBRARY[pattern_type]} is not installed: {n} {pattern_type} rule(s) kept without a "
                        "check, and OpenCTI may refuse them")

    author = _authoring_identity()
    for oid, stix_obj in list(parsed.items()):
        if _collision(stix_obj, author):
            del parsed[oid]
            dropped.append((raw[oid], ID_COLLISION, "CTIParsor emits an object with this id"))
    return parsed, dropped


# ── The index ───────────────────────────────────────────────────────────────

# SDO type -> the EntityType value of its entry.  Stage 4 maps several legacy
# EntityTypes to attack-pattern; a baseline attack-pattern is a "ttp".
_ENTITY_OF_SDO = {
    "threat-actor": "threat_actor", "intrusion-set": "intrusion_set", "malware": "malware", "tool": "tool",
    "campaign": "campaign", "infrastructure": "infrastructure", "incident": "incident",
    "attack-pattern": "ttp", "vulnerability": "cve", "location": "location", "identity": "identity",
}
_HASH_PRIORITY = (("SHA-256", "sha256"), ("SHA-1", "sha1"), ("MD5", "md5"))
_MIN_FORM = 3                         # a form shorter than this would be found inside other words ("ab" in "table")


@dataclass
class _Draft:
    """An entry while the index is built: indicators and based-on join it."""
    order: int
    entry_id: str
    stix_type: str
    entity_type: str
    value: str
    keys: set[Key]
    weak_keys: set[Key]
    sco_id: str | None = None
    indicator_ids: list[str] = dataclass_field(default_factory=list)
    object_ids: list[str] = dataclass_field(default_factory=list)
    forms: list[str] = dataclass_field(default_factory=list)
    seen_forms: set[str] = dataclass_field(default_factory=set, repr=False)

    def __post_init__(self) -> None:
        forms, self.forms = self.forms, []
        self.add_forms(forms)

    def add_forms(self, forms: Iterable[str]) -> None:
        """Forms of three characters or more, each once (a set, not a scan of the list)."""
        for form in forms:
            if len(form) >= _MIN_FORM and form not in self.seen_forms:
                self.seen_forms.add(form)
                self.forms.append(form)

    def freeze(self) -> Entry:
        mitre = sorted(k[1] for k in self.keys if k[0] == "mitre")
        return Entry(self.entry_id, self.stix_type, self.entity_type, self.value, mitre[0] if mitre else None,
                     frozenset(self.keys), frozenset(self.weak_keys), self.sco_id, tuple(self.indicator_ids),
                     tuple(self.object_ids), tuple(self.forms))


def _best_hash(keys: Iterable[Key]) -> tuple[str, str] | None:
    """(EntityType value, digest) of the strongest hash among `keys`."""
    hashes = {(k[1], k[2]) for k in keys if k[0] == "hash"}
    for algo, entity_type in _HASH_PRIORITY:
        digests = sorted(d for a, d in hashes if a == algo)
        if digests:
            return entity_type, digests[0]
    return None


def _forms_of(keys: Iterable[Key]) -> list[str]:
    """The values an IoC is searched by in the text: every hash and observable it
    states.  An AS number is written "AS64500" or "AS 64500", never bare."""
    forms: list[str] = []
    for k in sorted(keys):
        if k[:2] == ("obs", "autonomous-system"):
            forms += [f"as{k[2]}", f"as {k[2]}"]
        elif k[0] in ("obs", "hash"):
            forms.append(k[-1])
    return forms


def _key_type(key: Key) -> str:
    """The observable type a key of an Indicator's pattern is about."""
    return "file" if key[0] in ("hash", "file_name") else key[1]


def _key_fits(key: Key, stix_type: str) -> bool:
    """May an entry of `stix_type` be found through `key`?  An observable key only
    designates an entry of its own type: the domain of a compound pattern is not
    the IP address next to it."""
    if key[0] == "obs":
        return key[1] == stix_type
    return key[0] != "hash" or stix_type == "file"


def _sco_draft(order: int, obj: object, strong: set[Key], weak: set[Key]) -> _Draft:
    sco_type, oid = _str(obj, "type"), _str(obj, "id")
    forms = _forms_of(strong)
    if sco_type == "file":
        name = _str(obj, "name").strip()
        entity_type, value = _best_hash(strong) or ("file", name)
        if not forms:
            forms = [name.casefold()]
    else:
        entity_type, raw = _ENTITY_OF_SCO[sco_type], str(field(obj, _SCO_VALUE_FIELD[sco_type])).strip()
        value = f"AS{raw}" if sco_type == "autonomous-system" else raw
    return _Draft(order, oid, sco_type, entity_type, value, set(strong), set(weak), sco_id=oid,
                  object_ids=[oid], forms=forms)


def _indicator_draft(order: int, entry_id: str, oid: str, stix_type: str, strong: set[Key],
                     weak: set[Key]) -> _Draft:
    """An entry made by an Indicator alone, for the keys of its pattern about one observable type."""
    forms = _forms_of(strong)
    if stix_type == "file":
        names = sorted(k[1] for k in weak)
        entity_type, value = _best_hash(strong) or ("file", names[0] if names else "")
        if not forms:
            forms = names
    else:
        entity_type = _ENTITY_OF_SCO[stix_type]
        value = sorted(k[2] for k in strong)[0]
        if stix_type == "autonomous-system":
            value = f"AS{value}"
    return _Draft(order, entry_id, stix_type, entity_type, value, strong | {("id", oid)}, set(weak),
                  indicator_ids=[oid], object_ids=[oid], forms=forms)


def _stix_types_in_order(pattern: str, types: Iterable[str]) -> list[str]:
    """`types`, the object types of a pattern's keys, in the order the pattern first names them."""
    wanted = set(types)
    return [t for t in Pattern(pattern).inspect().comparisons if t in wanted]


def _named_draft(order: int, obj: object, keys: set[Key]) -> _Draft:
    sdo_type, oid = _str(obj, "type"), _str(obj, "id")
    name = _str(obj, "name").strip()
    names = [name, *_strings(field(obj, "aliases")), *_strings(field(obj, "x_mitre_aliases"))]
    value = name or _str(obj, "country").strip().upper()
    return _Draft(order, oid, sdo_type, _ENTITY_OF_SDO[sdo_type], value, keys, set(), object_ids=[oid],
                  forms=[_norm_name(n) for n in names])


def _build_index(imported: Mapping[str, Any]) -> tuple[list[Entry], list[Relation], frozenset[str]]:
    """(entries, relations, passthrough ids) of the imported objects (guide 1.3).

    An Indicator whose pattern is about several observable types (`[ipv4-addr:…
    AND domain-name:…]`) belongs to one entry of each type: the keys of a type go
    to the entry of that type only, so a domain never resolves to the address
    beside it.  Its id is then in the `indicator_ids` and `object_ids` of every
    one of those entries, and the first of them (the order of the pattern) is
    the one its relations are routed to.  Every other object is in one entry or
    none.
    """
    drafts: list[_Draft] = []
    members: dict[str, list[_Draft]] = {}             # object id -> the entries it belongs to, the first is its own
    holder: dict[Key, _Draft] = {}                    # strong key -> the first entry that states it

    def register(draft: _Draft, oid: str, new_keys: Iterable[Key]) -> None:
        if draft.order == len(drafts):
            drafts.append(draft)
        members.setdefault(oid, []).append(draft)
        for key in new_keys:
            holder.setdefault(key, draft)

    def keyed(strong: set[Key], weak: set[Key]) -> bool:
        return bool({k for k in strong if k[0] != "id"} or weak)

    # 1. observables, one entry each
    for oid, obj in imported.items():
        if field(obj, "type") in _SCO_VALUE_FIELD or field(obj, "type") == "file":
            strong, weak = keys_for_object(obj)
            if keyed(strong, weak):
                draft = _sco_draft(len(drafts), obj, strong, weak)
                register(draft, oid, draft.keys)
    # 2. STIX-pattern indicators join, for each observable type they state, the
    #    entry of that type that shares a key, or the one their based-on names
    #    (a name-only `[file:name = …]` shares no strong key with its file),
    #    else make one
    based_on: dict[str, list[str]] = {}
    for obj in imported.values():
        if field(obj, "type") == "relationship" and field(obj, "relationship_type") == "based-on":
            based_on.setdefault(_str(obj, "source_ref"), []).append(_str(obj, "target_ref"))
    for oid, obj in imported.items():
        if field(obj, "type") != "indicator" or field(obj, "pattern_type") != "stix":
            continue
        pattern = _str(obj, "pattern")
        strong, weak = pattern_keys(pattern)
        groups: dict[str, tuple[set[Key], set[Key]]] = {}        # no key at all: copied as it is
        for k in strong:
            groups.setdefault(_key_type(k), (set(), set()))[0].add(k)
        for k in weak:
            groups.setdefault(_key_type(k), (set(), set()))[1].add(k)
        named = False                             # the first entry the Indicator makes is named by it
        for stix_type in _stix_types_in_order(pattern, groups) if len(groups) > 1 else groups:
            g_strong, g_weak = groups[stix_type]
            found = {id(holder[k]): holder[k] for k in g_strong if k in holder}
            if not found:
                # Only the one observable of this type the based-on names, and only
                # when it carries a key the pattern states (a based-on to another
                # value would otherwise move that value onto it).
                targets = {id(d): d for t in based_on.get(oid, ()) for d in members.get(t, ())
                           if d.stix_type == stix_type and d.sco_id == t}
                target = next(iter(targets.values())) if len(targets) == 1 else None
                if target is not None and (g_strong | g_weak) & (target.keys | target.weak_keys):
                    found = targets
            if found:
                draft = min(found.values(), key=lambda d: d.order)
                new_keys = (g_strong | {("id", oid)}) - draft.keys
                draft.keys |= new_keys
                draft.weak_keys |= g_weak
                draft.indicator_ids.append(oid)
                draft.object_ids.append(oid)
                draft.add_forms(_forms_of(g_strong))
            else:
                draft = _indicator_draft(len(drafts), f"{oid}#{stix_type}" if named else oid, oid, stix_type,
                                         g_strong, g_weak)
                named = True
                new_keys = draft.keys
            register(draft, oid, new_keys)
    # 3. a based-on inside one entry belongs to it
    for oid, obj in imported.items():
        if field(obj, "type") == "relationship" and field(obj, "relationship_type") == "based-on":
            ends = {id(d) for d in members.get(_str(obj, "target_ref"), ())}
            shared = [d for d in members.get(_str(obj, "source_ref"), ()) if id(d) in ends]
            if shared:
                shared[0].object_ids.append(oid)
                members[oid] = [shared[0]]
    # 4. named SDOs, the authors of the bundle apart
    authors = {_str(o, "created_by_ref") for o in imported.values()}
    for oid, obj in imported.items():
        sdo_type = field(obj, "type")
        if sdo_type not in _NAMED_STIX_TYPES or (sdo_type == "identity" and (
                oid in authors or field(obj, "identity_class") == "system")):
            continue
        strong, weak = keys_for_object(obj)
        if keyed(strong, weak):
            draft = _named_draft(len(drafts), obj, strong)
            register(draft, oid, draft.keys)
    # 5. the other relationships, their ends routed to entries
    relations = []
    for oid, obj in imported.items():
        if field(obj, "type") == "relationship" and oid not in members:
            src, dst = _str(obj, "source_ref"), _str(obj, "target_ref")
            relations.append(Relation(oid, _str(obj, "relationship_type"), src, dst,
                                      members[src][0].entry_id if src in members else None,
                                      members[dst][0].entry_id if dst in members else None))
    # 6. everything else is copied
    taken = set(members) | {r.stix_id for r in relations}
    return [d.freeze() for d in drafts], relations, frozenset(imported) - taken


# ── Intake ──────────────────────────────────────────────────────────────────

def intake(raw: bytes, *, report_id: str | None = None, preview: bool = False,
           validate: bool = True) -> tuple[BaselineIndex | None, Intake, dict]:
    """Check, scope and index a bundle.  Returns (index, intake, parsed bundle).

    Raises BaselineError when nothing can be used, and never anything else.
    With several reports and no `report_id`: preview=True (/inspect) returns
    (None, an Intake with needs_report_choice, the bundle); preview=False (job
    creation) raises.  With validate=False the JSON schemas are not run, only
    stix2 parses each object, and a warning says so.  Pure: the caller logs the
    exclusions.
    """
    try:
        return _intake(raw, report_id, preview, validate)
    except RecursionError as exc:
        raise BaselineError("the bundle is nested too deeply to be read") from exc


def _intake(raw: bytes, report_id: str | None, preview: bool,
            validate: bool) -> tuple[BaselineIndex | None, Intake, dict]:
    if len(raw) > MAX_BASELINE_BYTES:                                                    # 1
        raise BaselineError(f"the baseline is larger than {MAX_BASELINE_BYTES // (1024 * 1024)} MB")
    bundle, items = _load(raw)                                                           # 2-4
    sha256 = hashlib.sha256(raw).hexdigest()
    excluded: list[dict] = []
    excluded_ids: set[str] = set()
    warnings: list[str] = []

    objects: dict[str, dict] = {}                                                        # 5-6
    for obj in items:
        problem = _id_problem(obj)
        if problem:
            excluded.append(_exclusion(obj, INVALID, problem))
            excluded_ids.add(_text(obj.get("id")))
            continue
        older = obj
        known = objects.get(obj["id"])
        if known is None:
            objects[obj["id"]] = obj
            continue
        if _modified(obj) > _modified(known):
            objects[obj["id"]], older = obj, known
        excluded.append(_exclusion(older, OLDER_VERSION, "a version of this id modified later is in the bundle"))
    excluded_ids.discard("")

    reports = [{"id": o["id"], "name": _clip(_text(o.get("name"))),
                "published": o["published"] if isinstance(o.get("published"), str) else None,
                "refs": len(o["object_refs"]) if isinstance(o.get("object_refs"), list) else 0}
               for o in objects.values() if o["type"] == "report"]
    report_ids = {r["id"] for r in reports}
    chosen = report_id if report_id is not None else (reports[0]["id"] if len(reports) == 1 else None)   # 7
    if chosen is None and reports:
        if not preview:
            listed = ", ".join(f"{r['id']} ({r['name']!r})" for r in reports[:_REPORTS_LISTED])
            more = f", and {len(reports) - _REPORTS_LISTED} more" if len(reports) > _REPORTS_LISTED else ""
            raise BaselineError(f"the bundle holds {len(reports)} reports, name one to enrich: {listed}{more}")
        counts = {**Counter(o["type"] for o in objects.values()), "out_of_scope": 0, "dangling_refs": 0}
        return None, Intake(sha256, _text(bundle.get("id")), counts, excluded, warnings, reports,
                            needs_report_choice=True), bundle
    if chosen is not None and chosen not in report_ids:
        raise BaselineError(f"{_clip(chosen)!r} is not a report of the bundle")
    scope = set(objects) if chosen is None else _scope(objects, chosen)
    in_scope = [o for oid, o in objects.items() if oid in scope]

    parsed, dropped = _check(in_scope, warnings, validate)                                         # 8-10
    if chosen is not None and chosen not in parsed:
        detail = next(d for o, _, d in dropped if o["id"] == chosen)
        raise BaselineError(f"the report {chosen!r} is refused, and the scope starts from it: {detail}"[:_DETAIL_MAX])
    for obj, reason, detail in dropped:
        excluded.append(_exclusion(obj, reason, detail))
        excluded_ids.add(obj["id"])

    kept, cascaded = ref_closure(objects, set(parsed), excluded_ids,                     # 11
                                 protected=frozenset() if chosen is None else frozenset({chosen}))
    for oid, reason in cascaded.items():
        excluded.append(_exclusion(objects[oid], REFS_CLOSURE, reason.split(":", 1)[1]))
    imported = {oid: obj for oid, obj in parsed.items() if oid in kept}
    if chosen is not None:
        lost = {ref for ref in iter_refs(objects[chosen]) if ref in excluded_ids or ref in cascaded}
        if lost:
            warnings.append(f"the chosen report references {len(lost)} excluded object(s), which will be left out")
    all_ids = {_text(o.get("id")) for o in items}
    dangling = {ref for oid in imported for ref in iter_refs(objects[oid]) if ref not in all_ids}
    if dangling:
        warnings.append(f"{len(dangling)} reference(s) point at ids the bundle does not hold, "
                        f"e.g. {sorted(dangling)[0]}; kept, they dangled in the source")

    min_tlp, min_pap = _most_restrictive(                                                # 12
        imported.values(), {oid: o for oid, o in imported.items() if field(o, "type") == "marking-definition"},
        warnings)
    entries, relations, passthrough = _build_index(imported)                             # 13
    counts = {**Counter(field(o, "type") for o in imported.values()),
              "out_of_scope": len(objects) - len(scope), "dangling_refs": len(dangling)}
    summary = Intake(sha256, _text(bundle.get("id")), counts, excluded, warnings, reports, chosen,
                     False, min_tlp, min_pap)
    index = BaselineIndex(INDEX_VERSION, sha256, summary.bundle_id, entries, relations, frozenset(imported),
                          passthrough, tuple(oid for oid, o in imported.items() if field(o, "type") == "report"),
                          chosen)
    return index, summary, bundle


# ── Reconciliation (Stage 3r, ADR-0090 lot 3) ───────────────────────────────

# The key of a row in Reconciliation's maps: what `_save_entities` writes, folded.
def _row_key(entity_type: str, value: str) -> tuple[str, str]:
    return entity_type, " ".join(value.casefold().split())


def _rel_key(source_value: str, relationship_type: str, target_value: str) -> tuple[str, str, str]:
    return " ".join(source_value.casefold().split()), relationship_type, " ".join(target_value.casefold().split())


@dataclass
class ImportedEntity:
    """A row the job store gets from the baseline: an entry no extraction found."""
    value: str                     # Entry.value
    entity_type: str               # Entry.entity_type
    mitre_id: str | None           # Entry.mitre_id
    status: str                    # BASELINE_IN_TEXT or BASELINE_ONLY
    baseline_stix_id: str          # Entry.entry_id
    evidence_text: str | None = None   # BASELINE_IN_TEXT: the text found, as the report writes it
    evidence_start: int | None = None  # its offsets in the report text (None when not computable)
    evidence_end: int | None = None


@dataclass
class ImportedRelation:
    """A relationships row the job store gets from the baseline: a SRO no extraction found."""
    source_value: str              # the source entry's Entry.value
    relationship_type: str
    target_value: str              # the target entry's Entry.value
    status: str                    # BASELINE_IN_TEXT (both ends found in the report) or BASELINE_ONLY
    baseline_stix_id: str          # Relation.stix_id


@dataclass
class Reconciliation:
    """What Stage 3r found: the status of each row the run is about to write, and
    the rows the baseline adds.  The maps are keyed by `_row_key` / `_rel_key`;
    use the methods."""
    entity_status: dict[tuple[str, str], tuple[str, str | None]] = dataclass_field(default_factory=dict)
    relation_status: dict[tuple[str, str, str], tuple[str, str | None]] = dataclass_field(default_factory=dict)
    imported_entities: list[ImportedEntity] = dataclass_field(default_factory=list)
    imported_relations: list[ImportedRelation] = dataclass_field(default_factory=list)
    # entities_new, entities_matched, entities_baseline_in_text, entities_baseline_only,
    # relations_new, relations_matched, relations_baseline_in_text, relations_baseline_only
    stats: dict[str, int] = dataclass_field(default_factory=dict)

    def entity(self, entity_type: str, value: str) -> tuple[str, str | None]:
        """(status, baseline_stix_id) of an extracted row; (NEW, None) when unknown."""
        return self.entity_status.get(_row_key(entity_type, value), (NEW, None))

    def relation(self, source_value: str, relationship_type: str, target_value: str) -> tuple[str, str | None]:
        """(status, baseline_stix_id) of an extracted relationship; (NEW, None) when unknown."""
        return self.relation_status.get(_rel_key(source_value, relationship_type, target_value), (NEW, None))

    def in_text_entities(self) -> list[Any]:
        """The BASELINE_IN_TEXT imported entities as models.schemas.RawEntity
        (source SOURCE), for a run's Stage 4 to build what a finalize builds from
        their rows (ADR-0090 lot 4).  Types RawEntity does not know are skipped."""
        from models.schemas import EntityType, RawEntity

        out: list[Any] = []
        for row in self.imported_entities:
            if row.status != BASELINE_IN_TEXT:
                continue
            try:
                entity_type = EntityType(row.entity_type)
            except ValueError:
                continue
            out.append(RawEntity(value=row.value, entity_type=entity_type, mitre_id=row.mitre_id,
                                 source=SOURCE, confidence=1.0))
        return out


def _fold(value: str) -> str:
    """The folding `_row_key` and `_rel_key` apply to one value."""
    return " ".join(value.casefold().split())


def _is_word_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def _first_occurrence(low: str, forms: Iterable[str]) -> tuple[int, int] | None:
    """(start, end) of the earliest place in `low` (the lowercased report) where one of
    `forms` stands as a whole word: no letter, digit or "_" on either side.  Found with
    str.find, never with a pattern built from the baseline's text (untrusted)."""
    best: tuple[int, int] | None = None
    for form in forms:
        start = low.find(form)
        while start != -1:
            end = start + len(form)
            before = low[start - 1] if start else ""
            if not _is_word_char(before) and not _is_word_char(low[end:end + 1]):
                if best is None or start < best[0]:
                    best = (start, end)
                break
            start = low.find(form, start + 1)
    return best


def reconcile(raw_entities: Sequence[Any], llm_result: Any, report_text: str,
              index: BaselineIndex) -> Reconciliation:
    """Stage 3r: match a run's extractions to the analyst's baseline (ADR-0090 §7).
    Pure: no store, no network, no logging."""
    rec = Reconciliation()
    found: dict[str, str] = {}                     # entry_id -> MATCHED or BASELINE_IN_TEXT: the entries reached

    # Pass 1: the rows the run is about to write, with the values the worker stores.
    extracted: list[tuple[str, str, str | None]] = [(e.entity_type.value, e.value, e.mitre_id) for e in raw_entities]
    extracted += [("malware", name, None) for name in llm_result.malware_families]
    extracted += [("threat_actor", name, None) for name in llm_result.threat_actors]
    extracted += [("tool", name, None) for name in llm_result.tools]
    if llm_result.campaign_name:
        extracted.append(("campaign", llm_result.campaign_name, None))
    extracted += [("ttp", ttp.technique_name, ttp.mitre_id) for ttp in llm_result.ttps]
    extracted += [("ttp", held.name or held.attack_id, held.attack_id)
                  for held in getattr(llm_result, "ttp_review", None) or []]
    matched_rows: list[tuple[str, str]] = []       # (folded value, entry_id) of each MATCHED row
    for entity_type, value, mitre_id in extracted:
        strong, weak = keys_for_row(entity_type, value, mitre_id)
        entry = index.lookup(strong, ENTITY_TO_STIX.get(entity_type)) if strong else None
        if entry is None and weak:
            # A file named like exactly one baseline file is shown as that file;
            # Stage 4 merges it the same way (merge_baseline, I6).
            entry = index.lookup_weak(weak)
        key = _row_key(entity_type, value)
        if isinstance(entry, Entry):
            rec.entity_status[key] = (MATCHED, entry.entry_id)
            found[entry.entry_id] = MATCHED
            matched_rows.append((key[1], entry.entry_id))
        else:
            rec.entity_status.setdefault(key, (NEW, None))    # never over a MATCHED row of the same key

    # Pass 2: the baseline entries no extraction found, looked for in the report text.
    low = report_text.lower()
    offsets_ok = len(low) == len(report_text)      # lower() can change the length: then no offset is given
    for entry in index.entries:
        if entry.entry_id in found:
            continue
        place = _first_occurrence(low, entry.surface_forms)
        if place is None:
            rec.imported_entities.append(ImportedEntity(
                value=entry.value, entity_type=entry.entity_type, mitre_id=entry.mitre_id,
                status=BASELINE_ONLY, baseline_stix_id=entry.entry_id,
            ))
        else:
            start, end = place
            found[entry.entry_id] = BASELINE_IN_TEXT
            rec.imported_entities.append(ImportedEntity(
                value=entry.value, entity_type=entry.entity_type, mitre_id=entry.mitre_id,
                status=BASELINE_IN_TEXT, baseline_stix_id=entry.entry_id,
                evidence_text=report_text[start:end] if offsets_ok else None,
                evidence_start=start if offsets_ok else None,
                evidence_end=end if offsets_ok else None,
            ))

    # Pass 3: the extracted relationships, their ends resolved to baseline entries.  A
    # folded value of a MATCHED row names its entry, unless two entries share it; any
    # other folded surface form names its entry when it names exactly one.
    value_entry: dict[str, str] = {}
    clashes: set[str] = set()
    for folded, entry_id in matched_rows:
        if value_entry.setdefault(folded, entry_id) != entry_id:
            clashes.add(folded)
    for folded in clashes:
        del value_entry[folded]
    owners: dict[str, set[str]] = {}
    for entry in index.entries:
        for form in (*entry.surface_forms, entry.value):
            owners.setdefault(_fold(form), set()).add(entry.entry_id)
    form_entry = {form: next(iter(ids)) for form, ids in owners.items() if len(ids) == 1}

    def endpoint(value: str) -> str | None:
        folded = _fold(value)
        return value_entry.get(folded, form_entry.get(folded))

    by_ends: dict[tuple[str, str, str], Relation] = {}
    for base in index.relations:
        if base.source_entry is not None and base.target_entry is not None:
            by_ends.setdefault((base.source_entry, base.target_entry, base.relationship_type), base)
    found_relations: set[str] = set()
    for rel in [*llm_result.relationships, *(getattr(llm_result, "rel_review", None) or [])]:
        rel_key = _rel_key(rel.source_value, rel.relationship_type, rel.target_value)
        source, target = endpoint(rel.source_value), endpoint(rel.target_value)
        match: Relation | None = None
        if source is not None and target is not None:
            match = by_ends.get((source, target, rel.relationship_type))
        if match is None:
            rec.relation_status.setdefault(rel_key, (NEW, None))  # never over a MATCHED relation of the same key
        else:
            rec.relation_status[rel_key] = (MATCHED, match.stix_id)
            found_relations.add(match.stix_id)

    # Pass 4: the baseline relations no extraction found, both ends known.
    by_id = {entry.entry_id: entry for entry in index.entries}
    for base in index.relations:
        if base.stix_id in found_relations or base.source_entry is None or base.target_entry is None:
            continue
        both_found = base.source_entry in found and base.target_entry in found
        rec.imported_relations.append(ImportedRelation(
            source_value=by_id[base.source_entry].value,
            relationship_type=base.relationship_type,
            target_value=by_id[base.target_entry].value,
            status=BASELINE_IN_TEXT if both_found else BASELINE_ONLY,
            baseline_stix_id=base.stix_id,
        ))

    entity_counts = Counter(status for status, _ in rec.entity_status.values())
    imported_counts = Counter(row.status for row in rec.imported_entities)
    relation_counts = Counter(status for status, _ in rec.relation_status.values())
    imported_relation_counts = Counter(row.status for row in rec.imported_relations)
    rec.stats = {
        "entities_new": entity_counts[NEW], "entities_matched": entity_counts[MATCHED],
        "entities_baseline_in_text": imported_counts[BASELINE_IN_TEXT],
        "entities_baseline_only": imported_counts[BASELINE_ONLY],
        "relations_new": relation_counts[NEW], "relations_matched": relation_counts[MATCHED],
        "relations_baseline_in_text": imported_relation_counts[BASELINE_IN_TEXT],
        "relations_baseline_only": imported_relation_counts[BASELINE_ONLY],
    }
    return rec


# ── Merge (Stage 4, ADR-0090 lot 4) ─────────────────────────────────────────

@dataclass
class BaselineBuild:
    """What Stage 4 needs of the baseline (architecture §8).  `verbatim` is filled
    by Stage 4 (build_stix_bundle): the objects to write exactly as given, by id —
    every kept baseline object as received, and the chosen Report as re-issued.
    `serialize_bundle` writes them back; Stage 5 trusts the received ones."""
    index: BaselineIndex
    objects: Mapping[str, dict]                  # id -> object as received (job_baselines.bundle_json)
    excluded: frozenset[str] = frozenset()       # rejected by the analyst (finalize); intake exclusions are
                                                 # already out of index.imported_ids
    verbatim: dict[str, dict] = dataclass_field(default_factory=dict)
    trusted: frozenset[str] = frozenset()        # filled by Stage 4: the verbatim ids validated at intake
                                                 # (every kept one but the re-issued Report)


@dataclass
class MergeResult:
    """What `merge_baseline` did to Stage 4's object list."""
    kept: frozenset[str]                          # baseline ids now in the list (the chosen Report excluded)
    stated: frozenset[str]                        # kept ids the document states (go into the Report's refs)
    remap: dict[str, str]                         # CTIParsor object id -> the baseline id it became
    dropped: dict[str, str]                       # baseline id -> reason, not shipped (rejected / closure)
    removed_relationships: list[dict]             # CTIParsor SROs dropped: {"id", "reason", "kept"?}
    remapped_relationships: dict[str, tuple[str, str]]   # CTIParsor SRO id -> (source_ref, target_ref)


def _to_millis(moment: datetime) -> datetime:
    """`moment` in UTC, cut to the millisecond, the precision STIX writes."""
    moment = moment.astimezone(UTC)
    return moment.replace(microsecond=moment.microsecond // 1000 * 1000)


def _stix_time(moment: datetime) -> str:
    """`moment` as a STIX timestamp: 2026-10-25T10:00:00.000Z."""
    return _to_millis(moment).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _content_key(obj: object) -> tuple[str, ...] | None:
    """What makes two objects no index entry holds the same one: a course of
    action's name, a detection rule's type and text (whitespace folded).  None
    for any other object."""
    stix_type = field(obj, "type")
    if stix_type == "course-of-action":
        name = " ".join(_str(obj, "name").casefold().split())
        return (stix_type, name) if name else None
    if stix_type == "indicator" and field(obj, "pattern_type") not in (None, "stix"):
        text = " ".join(_str(obj, "pattern").split())
        return (stix_type, str(field(obj, "pattern_type")), text) if text else None
    return None


def _remap_target(obj: object, entry: Entry, kept: AbstractSet[str]) -> str | None:
    """The kept baseline id `obj` becomes, within the entry it matched: the Indicator
    for an Indicator, the observable for an observable of the entry's type, the
    entry's own object otherwise.  None when that object is not kept, and for an
    observable the entry holds no observable of (its id would name an Indicator)."""
    stix_type = field(obj, "type")
    if stix_type == "indicator":
        target = next((i for i in entry.indicator_ids if i in kept), None)
    elif stix_type == entry.stix_type and entry.sco_id:
        target = entry.sco_id
    elif stix_type in _SCO_VALUE_FIELD or stix_type == "file":
        return None
    else:
        target = entry.entry_id
    return target if target in kept else None


def _rewrite_ends(obj: Any, remap: Mapping[str, str]) -> Any:
    """`obj` with its top-level _ref / _refs properties read through `remap`; the object
    itself when none of them moves.  Rebuilt through its JSON, as stage4b's _clone_with."""
    changes: dict[str, Any] = {}
    for key, value in obj.items():
        if key.endswith("_ref") and isinstance(value, str) and value in remap:
            changes[key] = remap[value]
        elif key.endswith("_refs") and isinstance(value, list):
            if any(isinstance(v, str) and v in remap for v in value):
                changes[key] = [remap.get(v, v) if isinstance(v, str) else v for v in value]
    if not changes:
        return obj
    d = json.loads(obj.serialize())
    d.update(changes)
    return stix2.parse(d, allow_custom=True)


def merge_baseline(stix_objects: list, baseline: BaselineBuild) -> MergeResult:
    """Fold Stage 4's objects into the baseline, in place (architecture §8.2):
    the baseline's kept objects join the list, parsed; every CTIParsor object a
    kept entry matches is replaced by it and every reference to it rewritten;
    the CTIParsor relationships this makes self-loops or duplicates of a
    baseline one are dropped.  Baseline objects are never rewritten.  The
    chosen Report is not added: Stage 4 re-issues it."""
    index = baseline.index
    report = index.scope_report_id
    candidates = set(index.imported_ids) - ({report} if report else set())
    kept, dropped = ref_closure(baseline.objects, candidates, set(baseline.excluded))
    dropped.update({oid: "baseline_rejected" for oid in baseline.excluded if oid in index.imported_ids})
    kept = {oid for oid in kept if oid in baseline.objects}

    remap: dict[str, str] = {}
    for o in stix_objects:
        stix_type = field(o, "type")
        oid = _str(o, "id")
        if stix_type in {"relationship", "report", "marking-definition"} or oid in baseline.objects:
            continue
        strong, weak = keys_for_object(o)
        entry = index.lookup(strong, stix_type)
        name_only = entry is None and weak and all(k[0] == "id" for k in strong)
        if name_only and stix_type == "file":
            # A file known by its name alone: the one baseline file of that name,
            # as Stage 3r shows it (I6).  Two files of that name: no merge.
            entry = index.lookup_weak(weak)
        elif name_only and stix_type == "indicator":
            # Its name-only Indicator: the baseline's Indicator of the same pattern
            # keys in that file's entry, if it has one; a hash Indicator is not it.
            found = index.lookup_weak(weak)
            same = [i for i in (found.indicator_ids if found else ()) if i in kept
                    and pattern_keys(_str(baseline.objects[i], "pattern")) == (set(), set(weak))]
            if same and same[0] != oid:
                remap[oid] = same[0]
            continue
        if not isinstance(entry, Entry):
            continue
        target = _remap_target(o, entry, kept)
        if target is not None and target != oid:
            remap[oid] = target

    # Objects no entry holds: the one kept baseline object of the same content
    # stands in for CTIParsor's (a course of action, a quoted detection rule:
    # the round trip of lot 7 rebuilt them under new ids).  Two of them: no merge.
    twins: dict[tuple[str, ...], list[str]] = {}
    for oid in sorted(index.passthrough_ids & kept):
        key = _content_key(baseline.objects[oid])
        if key is not None:
            twins.setdefault(key, []).append(oid)
    for o in stix_objects:
        oid = _str(o, "id")
        key = _content_key(o)
        if key is not None and oid not in remap and oid not in baseline.objects and len(twins.get(key, ())) == 1:
            remap[oid] = twins[key][0]

    # A CTIParsor object whose id a kept baseline object holds is that object (SCO ids are
    # deterministic): the baseline one is written, the CTIParsor one is not.
    shared = {_str(o, "id") for o in stix_objects if _str(o, "id") in kept}   # stated by the document too
    rest = [o for o in stix_objects if field(o, "id") not in remap and field(o, "id") not in kept]
    parsed = [stix2.parse(baseline.objects[oid], allow_custom=True) for oid in sorted(kept)]
    seen: dict[tuple[Any, Any, Any], str] = {}           # (source, verb, target) -> the relationship kept for it
    for base in parsed:
        if field(base, "type") == "relationship":
            triple = (field(base, "source_ref"), field(base, "relationship_type"), field(base, "target_ref"))
            seen.setdefault(triple, _str(base, "id"))

    from pipeline.stage4b_graph_completion import stated_by_the_report

    out = list(parsed)
    removed: list[dict] = []
    remapped: dict[str, tuple[str, str]] = {}
    stated_relations: set[str] = set()
    for o in rest:
        moved = field(o, "source_ref") in remap or field(o, "target_ref") in remap
        new = _rewrite_ends(o, remap)
        if field(new, "type") != "relationship":
            out.append(new)
            continue
        oid = _str(new, "id")
        source, target = _str(new, "source_ref"), _str(new, "target_ref")
        triple = (source, field(new, "relationship_type"), target)
        if source == target:
            removed.append({"id": oid, "reason": "self_loop_after_baseline_merge"})
        elif triple in seen:
            removed.append({"id": oid, "reason": "duplicate_after_baseline_merge", "kept": seen[triple]})
            if seen[triple] in kept and stated_by_the_report(new):
                stated_relations.add(seen[triple])      # the document states the baseline's edge
        else:
            seen[triple] = oid
            out.append(new)
            if moved:
                remapped[oid] = (source, target)
    stix_objects[:] = out

    # What the document states of the baseline: the objects CTIParsor's became, by a
    # match or by sharing the id (a CTIParsor bundle given back as its own baseline),
    # and the edges CTIParsor built too and holds stated.  Two stated ends do not make
    # an edge stated: an ATT&CK or composed edge between them is not the report's word.
    stated = set(remap.values()) | shared | stated_relations
    return MergeResult(kept=frozenset(kept), stated=frozenset(stated), remap=remap, dropped=dropped,
                       removed_relationships=removed, remapped_relationships=remapped)


def reissue_report(original: dict, kept: AbstractSet[str], added: Sequence[str], enrichment: dict,
                   source_ref: dict | None, now: datetime) -> dict:
    """The chosen baseline Report as OpenCTI's upsert expects it (D1, architecture
    §8.3): only modified, object_refs, external_references and
    x_ctiparsor_enrichment change; confidence is never touched."""
    d = copy.deepcopy(original)
    refs = [r for r in original.get("object_refs", []) if r in kept]
    listed = set(refs)
    for r in added:
        if r not in listed:
            refs.append(r)
            listed.add(r)
    d["object_refs"] = refs
    stamp = _to_millis(now)
    prior = _to_millis(_modified(original))
    if prior >= stamp:                                # the clock is behind the Report: strictly after it
        stamp = prior + timedelta(milliseconds=1)
    d["modified"] = _stix_time(stamp)
    if source_ref is not None and source_ref not in original.get("external_references", []):
        # Not twice: a Report CTIParsor already re-issued, or built, carries it.
        d["external_references"] = [*original.get("external_references", []), source_ref]
    d["x_ctiparsor_enrichment"] = enrichment
    return d


def newest_versions(items: Iterable[Any]) -> dict[str, dict]:
    """The objects of a bundle by id, one version each: the one the intake keeps
    (the latest `modified`, the first of a tie)."""
    out: dict[str, dict] = {}
    for obj in items:
        if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
            continue
        known = out.get(obj["id"])
        if known is None or _modified(obj) > _modified(known):
            out[obj["id"]] = obj
    return out


def serialize_bundle(bundle: Any, verbatim: Mapping[str, dict] | None = None) -> str:
    """The bundle's JSON with every object of `verbatim` written as given, by id
    (invariant I2: a stix2 round trip alters foreign objects).  Without
    `verbatim`: exactly `bundle.serialize(pretty=True)`."""
    if not verbatim:
        return bundle.serialize(pretty=True)
    data = json.loads(bundle.serialize())
    data["objects"] = [verbatim.get(o["id"], o) for o in data["objects"]]
    text = json.dumps(data, indent=4, ensure_ascii=False)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate the baseline carried as a JSON escape has no UTF-8
        # form: the same JSON with every non-ASCII character escaped.
        return json.dumps(data, indent=4)
    return text


def validation_json(bundle_json: str, trusted: AbstractSet[str]) -> str:
    """`bundle_json` without the objects of `trusted` (validated at intake): what
    Stage 5 checks, so a 10 000-object baseline is not re-validated at every
    finalize.  Without `trusted`: `bundle_json` itself."""
    if not trusted:
        return bundle_json
    data = json.loads(bundle_json)
    data["objects"] = [o for o in data["objects"] if o.get("id") not in trusted]
    return json.dumps(data, indent=4, ensure_ascii=False)
