"""The bundle the release exports, projected into the in-house gold's layers.

`inhouse-score --from bundle` scores what an analyst receives (Stages 4 and 5)
instead of the runner's predictions.  `project` reads a serialized STIX bundle
and returns IoCs, entities, techniques and relations spelled as the gold spells
them.  It never executes a pattern; a STIX pattern is only parsed.  Standard
library and stix2patterns only: no pipeline module is imported.
"""
from __future__ import annotations

import re

from stix2patterns.exceptions import ParseException
from stix2patterns.v21.pattern import Pattern

# The SCO types that become a gold IoC type, and the property holding the value.
_SCO_TYPE = {"ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "domain-name": "domain", "url": "url",
             "email-addr": "email", "mac-addr": "mac_addr", "mutex": "mutex",
             "windows-registry-key": "registry_key", "autonomous-system": "asn", "file": "file"}
_SCO_FIELD = {"ipv4-addr": "value", "ipv6-addr": "value", "domain-name": "value", "url": "value",
              "email-addr": "value", "mac-addr": "value", "mutex": "name",
              "windows-registry-key": "key", "autonomous-system": "number", "file": "name"}
# The value property of any SCO an Indicator is based on (as `evaluation.__main__._SCO_VALUE`).
_VALUE_FIELD = {"file": "name", "windows-registry-key": "key", "user-account": "user_id", "mutex": "name"}
_HASH_TYPE = {"MD5": "md5", "SHA1": "sha1", "SHA256": "sha256"}
_ENTITY_TYPE = {"malware": "malware", "tool": "tool", "campaign": "campaign",
                "threat-actor": "threat_actor", "intrusion-set": "threat_actor"}
_ATTACK_SOURCES = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}
_ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CVE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_ESCAPE = re.compile(r"\\(.)")
# stix2patterns' parser is recursive: a pattern beyond these bounds is not handed
# to it (same values and count as pipeline/baseline_stix.py).
_MAX_PATTERN_CHARS = 65_536
_MAX_PATTERN_JOINERS = 256          # AND, OR, FOLLOWEDBY outside literals
_MAX_PATTERN_DEPTH = 64             # brackets and parentheses outside literals
_PATTERN_JOINERS = frozenset({"AND", "OR", "FOLLOWEDBY"})

Pair = tuple[str, str]


def _too_complex(pattern: str) -> bool:
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


def _literal(raw: str) -> str:
    """stix2patterns returns string literals WITH their quotes, numbers bare."""
    if len(raw) >= 2 and raw[0] == raw[-1] == "'":
        return _ESCAPE.sub(r"\1", raw[1:-1])
    return raw


def _hash_type(name: object) -> str | None:
    return _HASH_TYPE.get(re.sub(r"[-_\s'\"]", "", str(name)).upper())


def _list(v: object) -> list:
    return v if isinstance(v, list) else []


def _str(o: dict, key: str) -> str:
    v = o.get(key)
    return v if isinstance(v, str) else ""


def _typed(sco_type: str, value: object) -> Pair | None:
    gold_type = _SCO_TYPE[sco_type]
    if isinstance(value, bool) or not isinstance(value, str | int) or not str(value).strip():
        return None
    return gold_type, (f"AS{value}" if gold_type == "asn" else str(value))


def _sco_values(o: dict) -> list[Pair]:
    """The (gold type, value) pairs of one SCO or vulnerability; empty for any other object."""
    t = _str(o, "type")
    out: list[Pair] = []
    if t == "vulnerability":
        refs = [o.get("name", "")] + [r.get("external_id", "") for r in _list(o.get("external_references"))
                                       if isinstance(r, dict)]
        for ref in refs:
            if isinstance(ref, str) and _CVE.fullmatch(ref.strip()):
                out.append(("cve", ref.strip().upper()))
        return list(dict.fromkeys(out))
    if t not in _SCO_TYPE:
        return out
    pair = _typed(t, o.get(_SCO_FIELD[t]))
    if pair:
        out.append(pair)
    if t == "file" and isinstance(o.get("hashes"), dict):
        for algo, digest in o["hashes"].items():
            gold_type = _hash_type(algo)
            if gold_type and isinstance(digest, str) and digest.strip():
                out.append((gold_type, digest.strip()))
    return out


def _indicated_values(o: dict) -> list[Pair]:
    """What an Indicator based on this object alerts on: its IoC values, or for a
    type with no gold IoC type (a user-account, ...) its value under the STIX type."""
    out = _sco_values(o)
    t = _str(o, "type")
    if not out and t not in _SCO_TYPE and t != "vulnerability":
        value = o.get(_VALUE_FIELD.get(t, "value"))
        if t and isinstance(value, str) and value.strip():
            out.append((t, value))
    return out


def _pattern_values(pattern: object, pattern_type: object) -> tuple[list[Pair], list[Pair], str]:
    """(IoCs, indicated values, reason) of a pattern.  The IoCs are the `=`
    comparisons that map to a gold type; every `=` comparison is indicated.  The
    reason is set when the pattern gives nothing."""
    if pattern_type != "stix":
        return [], [], "rule pattern, not scored as an IoC"
    if not isinstance(pattern, str):
        return [], [], "pattern missing"
    if _too_complex(pattern):
        return [], [], "pattern too complex"
    try:
        comparisons = Pattern(pattern).inspect().comparisons
    except (ParseException, RecursionError) as exc:
        return [], [], f"STIX pattern does not parse: {type(exc).__name__}"
    iocs: list[Pair] = []
    indicated: list[Pair] = []
    for obj_type, items in comparisons.items():
        for path, op, raw in items:
            if op != "=":
                continue
            props, value = tuple(path), _literal(raw)
            pair: Pair | None = None
            if obj_type == "file" and len(props) == 2 and props[0] == "hashes":
                gold_type = _hash_type(props[1])
                pair = (gold_type, value) if gold_type else None
            elif obj_type in _SCO_TYPE and props == (_SCO_FIELD[obj_type],):
                pair = _typed(obj_type, value)
            if pair:
                iocs.append(pair)
                indicated.append(pair)
            else:
                indicated.append((obj_type, value))
    if not indicated:
        return [], [], "no equality comparison"
    return list(dict.fromkeys(iocs)), list(dict.fromkeys(indicated)), ""


def _names(o: dict) -> list[str]:
    forms = [o.get("name"), *_list(o.get("aliases")), *_list(o.get("x_mitre_aliases"))]
    return list(dict.fromkeys(f.strip() for f in forms if isinstance(f, str) and f.strip()))


def _attack_ids(o: dict) -> list[str]:
    ids = [r.get("external_id", "") for r in _list(o.get("external_references"))
           if isinstance(r, dict) and r.get("source_name") in _ATTACK_SOURCES]
    return list(dict.fromkeys(i.upper() for i in ids if isinstance(i, str) and _ATTACK_ID.match(i.upper())))


def _pairs(pairs: list[Pair]) -> list[dict]:
    return [{"type": t, "value": v} for t, v in dict.fromkeys(pairs)]


def project(bundle: dict) -> dict:
    """The bundle's content in the gold's layers (see the module docstring)."""
    out: dict = {"iocs": [], "indicated": [], "entities": [], "techniques": [], "relations": [],
                 "unsupported_patterns": [], "problems": []}
    if not isinstance(bundle, dict):
        out["problems"].append("bundle root is not an object")
        return out
    if not isinstance(bundle.get("objects"), list):
        out["problems"].append("bundle has no objects list")
        return out
    objs = [o for o in bundle["objects"] if isinstance(o, dict)]
    by_id = {o["id"]: o for o in objs if isinstance(o.get("id"), str)}
    iocs: list[Pair] = []
    indicated: list[Pair] = []
    entities: list[dict] = []
    techniques: list[str] = []
    unsupported: list[dict] = []
    based_on: dict[str, list[str]] = {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "based-on":
            based_on.setdefault(_str(o, "source_ref"), []).append(_str(o, "target_ref"))

    pattern_pairs: dict[str, list[Pair]] = {}
    for o in objs:
        t = _str(o, "type")
        iocs += _sco_values(o)
        if t in _ENTITY_TYPE:
            forms = _names(o)
            if forms:
                entities.append({"type": _ENTITY_TYPE[t], "forms": forms})
        elif t == "attack-pattern":
            techniques += _attack_ids(o)
        elif t == "indicator":
            found, shipped, reason = _pattern_values(o.get("pattern"), o.get("pattern_type"))
            pattern_pairs[_str(o, "id")] = shipped
            if reason:
                unsupported.append({"id": _str(o, "id"), "pattern_type": str(o.get("pattern_type")),
                                    "reason": reason})
            iocs += found
            indicated += shipped
            for ref in based_on.get(_str(o, "id"), []):
                indicated += _indicated_values(by_id.get(ref, {}))

    def ends(ref: object) -> list[str] | None:
        o = by_id.get(ref) if isinstance(ref, str) else None
        if o is None or not isinstance(ref, str):
            return None
        t = _str(o, "type")
        if t == "indicator":
            forms = [v for _, v in pattern_pairs.get(ref, [])]
            for target in based_on.get(ref, []):
                forms += [v for _, v in _sco_values(by_id.get(target, {}))]
        elif t == "attack-pattern":
            forms = [*_attack_ids(o), *_names(o)]
        else:
            forms = [v for _, v in _sco_values(o)] + _names(o)
        return list(dict.fromkeys(forms)) or [ref]

    relations = []
    for o in objs:
        if o.get("type") != "relationship":
            continue
        src, tgt = ends(o.get("source_ref")), ends(o.get("target_ref"))
        missing = [r for r, e in ((o.get("source_ref"), src), (o.get("target_ref"), tgt)) if e is None]
        if missing:
            out["problems"] += [f"unresolved reference {o.get('id')} -> {r}" for r in missing]
            continue
        # `based-on` is STIX plumbing between an Indicator and its SCO, not a verb of the guide.
        if o.get("relationship_type") == "based-on":
            continue
        relations.append({"source": src, "type": str(o.get("relationship_type", "")), "target": tgt})

    return {**out, "iocs": _pairs(iocs), "indicated": _pairs(indicated), "entities": entities,
            "techniques": list(dict.fromkeys(techniques)), "relations": relations,
            "unsupported_patterns": unsupported}
