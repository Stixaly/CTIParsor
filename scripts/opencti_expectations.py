"""What the OpenCTI check expects of what OpenCTI kept (ADR-0094 item 8).

scripts/opencti_import_check.py imports bundles into a throwaway OpenCTI and
reads the whole platform back after each one (every object and relationship,
with OpenCTI's own STIX export of it, `toStix`).  This module holds what is
then compared, so that the project's tests can check it without pycti or
OpenCTI: Python's standard library only.

* `Platform`: the platform as read back, indexed by every STIX id an object
  answers to (OpenCTI's standard id, the ids it stored from the bundles);
* `bundle_checks`, `reimport_checks`: the expectations on one bundle once it
  is imported, and once it is imported a second time; `final_checks`: every
  bundle's objects again, after the last import; `reading_checks`: every
  reading of the platform settled (`settle`);
* `transformations`: what OpenCTI holds differently from the bundle, field by
  field, with the whole values (informational: OpenCTI's defaults, its
  renames, what it drops); `cross_type_warnings`: one name held by objects of
  two types (a WARN, not a failure);
* `candidate_checks` and `main`: the report of a run, `report.json` and
  `report.md`, from the run's record (scripts/check_opencti_candidate.sh) and
  the check's results:

    python3 scripts/opencti_expectations.py report --run run.json --check check.json --out-dir DIR

  exit 0 when every expectation holds, 1 otherwise, 2 on a missing file.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

#: OpenCTI's property extension: the ids it stored from bundles, the files it holds.
OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
#: Bundle objects that are neither SDOs nor SCOs.
NOT_SDO_SCO = ("relationship", "marking-definition")
#: Compared on their own by the checks, or OpenCTI's bookkeeping: not a transformation.
UNCOMPARED = frozenset({"id", "spec_version", "extensions", "modified", "object_refs", "x_opencti_files"})
#: References compared once mapped to OpenCTI's standard ids.
REF_FIELDS = frozenset({"created_by_ref", "source_ref", "target_ref"})
TIMESTAMPS = frozenset({"created", "published", "valid_from", "valid_until", "first_seen", "last_seen",
                        "start_time", "stop_time", "first_observed", "last_observed"})
#: What OpenCTI adds to every object when the bundle leaves it out.
DEFAULTS = {"lang": "en", "revoked": False}
#: Types whose objects an analyst finds by name: one name under two of them is warned about.
NAMED_TYPES = frozenset({"threat-actor", "intrusion-set", "campaign", "malware", "tool", "attack-pattern",
                         "identity", "location", "vulnerability", "infrastructure", "course-of-action"})
_FRACTION = re.compile(r"(\.\d{3})\d*Z$")


def check(step: str, name: str, expected: str, observed: str, passed: bool, detail: Any = None) -> dict[str, Any]:
    return {"step": step, "check": name, "expected": expected, "observed": observed,
            "pass": bool(passed), "detail": detail}


def names_of(stix: dict[str, Any]) -> set[str]:
    """What an object is called: its name or value and aliases, case-folded; a nameless observable's hashes."""
    out: set[str] = set()
    for field in ("name", "value"):
        value = stix.get(field)
        if isinstance(value, str) and value.strip():
            out.add(value.strip().casefold())
    for field in ("aliases", "x_opencti_aliases"):
        for value in stix.get(field) or []:
            if isinstance(value, str) and value.strip():
                out.add(value.strip().casefold())
    if not out:
        out = {str(v).casefold() for v in (stix.get("hashes") or {}).values()}
    return out


def node(raw: dict[str, Any]) -> dict[str, Any]:
    """An object or relationship as the check reads it: its ids, its STIX export, its files."""
    stix = raw.get("toStix") or {}
    if isinstance(stix, str):
        stix = json.loads(stix)
    ext = (stix.get("extensions") or {}).get(OPENCTI_EXTENSION) or {}
    ids = {raw["standard_id"], *(raw.get("x_opencti_stix_ids") or []), *(ext.get("stix_ids") or [])}
    files = [{"name": f.get("name"), "mime_type": f.get("mime_type")} for f in ext.get("files") or []]
    return {"standard_id": raw["standard_id"], "entity_type": raw.get("entity_type"), "ids": ids,
            "stix": stix, "files": files}


def marking_node(raw: dict[str, Any]) -> dict[str, Any]:
    stix = {"type": "marking-definition", "name": raw.get("definition"),
            "definition_type": raw.get("definition_type")}
    return {"standard_id": raw["standard_id"], "entity_type": "Marking-Definition",
            "ids": {raw["standard_id"], *(raw.get("x_opencti_stix_ids") or [])}, "stix": stix, "files": []}


class Platform:
    """The platform as read back: objects, relationships and markings, by every id they answer to."""

    def __init__(self, objects: list[dict[str, Any]], relationships: list[dict[str, Any]],
                 markings: list[dict[str, Any]]) -> None:
        self.objects = [node(o) for o in objects]
        self.relationships = [node(r) for r in relationships]
        self.markings = [marking_node(m) for m in markings]
        self._by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for n in self.objects + self.relationships + self.markings:
            for stix_id in n["ids"]:
                self._by_id[stix_id].append(n)

    def by_id(self, stix_id: str) -> list[dict[str, Any]]:
        return list({n["standard_id"]: n for n in self._by_id.get(stix_id, [])}.values())

    def named(self, stix_type: str, names: set[str]) -> list[dict[str, Any]]:
        """The objects of this STIX type called by one of these names (name, value, alias or hash)."""
        return [n for n in self.objects if n["stix"].get("type") == stix_type and names_of(n["stix"]) & names]

    def resolve(self, obj: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        """The object OpenCTI holds for a bundle object, and how it was found: id, name, absent or ambiguous.

        By id first.  OpenCTI renames an object when a later object of the same
        type names it by one of its aliases, and its standard id follows the
        name: such an object is then found by its name or aliases only.
        """
        hits = self.by_id(obj["id"])
        if len(hits) == 1:
            return hits[0], "id"
        if hits:
            return None, "ambiguous"
        if obj.get("type") in NOT_SDO_SCO:
            return None, "absent"
        names = names_of(obj)
        same = self.named(obj["type"], names) if names else []
        if len(same) == 1:
            return same[0], "name"
        return None, "ambiguous" if same else "absent"

    def counts(self) -> dict[str, int]:
        """How many objects of each type, relationships of each type and attached files the platform holds."""
        out: Counter[str] = Counter(n["entity_type"] for n in self.objects)
        out.update(f"relationship:{n['stix'].get('relationship_type')}" for n in self.relationships)
        out["files"] = sum(len(n["files"]) for n in self.objects)
        return dict(sorted(out.items()))


def settle(read: Callable[[], Any], timeout: float, interval: float, *,
           clock: Callable[[], float] = time.monotonic,
           sleep: Callable[[float], None] = time.sleep) -> tuple[Any, bool]:
    """Read until two readings in a row agree; return the last reading and whether they did.

    OpenCTI indexes what it writes a moment later.  When the timeout ends
    before two readings agree, the last one comes back with False: the caller
    records it, and `reading_checks` fails on it.
    """
    deadline = clock() + timeout
    last: str | None = None
    while True:
        reading = read()
        key = json.dumps(reading, sort_keys=True, default=str)
        if key == last:
            return reading, True
        last = key
        if clock() >= deadline:
            return reading, False
        sleep(interval)


def _merged(objs: list[dict[str, Any]], resolved: dict[str, dict[str, Any] | None]) -> dict[str, list[str]]:
    """The OpenCTI objects that two or more of these bundle objects landed on, with the bundle's ids."""
    by_std: dict[str, list[str]] = defaultdict(list)
    for o in objs:
        n = resolved[o["id"]]
        if n is not None:
            by_std[n["standard_id"]].append(o["id"])
    return {std: sorted(ids) for std, ids in sorted(by_std.items()) if len(ids) > 1}


def _std(platform: Platform, resolved: dict[str, dict[str, Any] | None], stix_id: str) -> str | None:
    """OpenCTI's standard id for a STIX id: through the bundle object it names, else by id."""
    if stix_id in resolved:
        n = resolved[stix_id]
        return n["standard_id"] if n is not None else None
    hits = platform.by_id(stix_id)
    return hits[0]["standard_id"] if len(hits) == 1 else None


def _copies(platform: Platform, imported: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """For each object OpenCTI holds, the bundle objects of every import so far that landed on it."""
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for bundle in imported:
        for obj in bundle["objects"]:
            n, _ = platform.resolve(obj)
            if n is not None:
                out[n["standard_id"]].append(obj)
    return out


def _norm_text(value: Any) -> str:
    return "\n".join(line.rstrip() for line in str(value or "").replace("\r\n", "\n").split("\n")).strip()


def bundle_checks(step: str, label: str, bundle: dict[str, Any], imported: list[dict[str, Any]],
                  platform: Platform) -> list[dict[str, Any]]:
    """The expectations on a bundle OpenCTI imported (twice), against the platform read back.

    `imported` is every bundle imported so far, this one included: an object
    several bundles carry gets their authors and markings from all of them.
    Two objects or relationships of this bundle on one OpenCTI object (a merge
    OpenCTI made by name or alias) fail, and so does a Report reference merged
    into another.
    """
    objs = bundle["objects"]
    resolved_how = {o["id"]: platform.resolve(o) for o in objs}
    resolved = {i: n for i, (n, _) in resolved_how.items()}
    out: list[dict[str, Any]] = []

    lost = {i: how for i, (n, how) in resolved_how.items() if n is None}
    by_name = sorted(i for i, (_, how) in resolved_how.items() if how == "name")
    out.append(check(step, f"{label}: every object in OpenCTI, once", f"{len(objs)} of {len(objs)}",
                     f"{len(objs) - len(lost)} of {len(objs)}", not lost,
                     {"absent_or_ambiguous": lost, "found_by_name_or_alias": by_name}))

    rels = [o for o in objs if o["type"] == "relationship"]
    for kind, members, what in (("object", [o for o in objs if o["type"] != "relationship"], "OpenCTI object"),
                                ("relationship", rels, "OpenCTI relationship")):
        found = [o for o in members if resolved[o["id"]] is not None]
        merged = _merged(found, resolved)
        distinct = len(found) - sum(len(ids) - 1 for ids in merged.values())
        out.append(check(step, f"{label}: each {kind} on an {what} of its own",
                         f"{len(found)} on {len(found)}", f"{len(found)} on {distinct}", not merged, merged))

    dups: dict[str, list[str]] = {}
    named = [o for o in objs if o["type"] not in NOT_SDO_SCO and names_of(o)]
    for o in named:
        same = sorted({n["standard_id"] for n in platform.named(o["type"], names_of(o))})
        n = resolved[o["id"]]
        if len(same) != 1 or (n is not None and n["standard_id"] not in same):
            dups[o["id"]] = same
    out.append(check(step, f"{label}: no second object of the same type and name, value or alias",
                     f"{len(named)} with 1 match", f"{len(named) - len(dups)} with 1 match", not dups, dups))

    ends: Counter[tuple[Any, Any, Any]] = Counter(
        (n["stix"].get("relationship_type"), n["stix"].get("source_ref"), n["stix"].get("target_ref"))
        for n in platform.relationships)
    rel_dups: dict[str, int] = {}
    wrong_ends: dict[str, dict[str, Any]] = {}
    for r in rels:
        n = resolved[r["id"]]
        if n is None:
            continue
        stix = n["stix"]
        key = (stix.get("relationship_type"), stix.get("source_ref"), stix.get("target_ref"))
        if ends[key] > 1:
            rel_dups[r["id"]] = ends[key]
        named_ends = (r["relationship_type"], _std(platform, resolved, r["source_ref"]),
                      _std(platform, resolved, r["target_ref"]))
        if key != named_ends:
            wrong_ends[r["id"]] = {"bundle": list(named_ends), "opencti": list(key)}
    out.append(check(step, f"{label}: no second relationship of the same type between the same objects",
                     f"{len(rels)} once", f"{len(rels) - len(rel_dups)} once", not rel_dups, rel_dups))
    out.append(check(step, f"{label}: each relationship joins the objects the bundle names",
                     f"{len(rels)} joined", f"{len(rels) - len(wrong_ends)} joined", not wrong_ends, wrong_ends))

    copies = _copies(platform, imported)
    authored = [o for o in objs if o.get("created_by_ref")]
    wrong_author: dict[str, dict[str, Any]] = {}
    for o in authored:
        n = resolved[o["id"]]
        if n is None:
            continue
        want = sorted({_std(platform, resolved, c["created_by_ref"]) or c["created_by_ref"]
                       for c in copies[n["standard_id"]] if c.get("created_by_ref")})
        got = n["stix"].get("created_by_ref")
        if got not in want:
            wrong_author[o["id"]] = {"bundles": want, "opencti": got}
    out.append(check(step, f"{label}: each object's author (created_by_ref) attached",
                     f"{len(authored)} attached", f"{len(authored) - len(wrong_author)} attached",
                     not wrong_author, wrong_author))

    marked = [o for o in objs if o["type"] != "marking-definition"]
    wrong_marks: dict[str, dict[str, Any]] = {}
    for o in marked:
        n = resolved[o["id"]]
        if n is None:
            continue
        want_marks = {_std(platform, resolved, m) or m
                      for c in copies[n["standard_id"]] for m in c.get("object_marking_refs") or []}
        got_marks = set(n["stix"].get("object_marking_refs") or [])
        if want_marks != got_marks:
            wrong_marks[o["id"]] = {"bundles": sorted(want_marks), "opencti": sorted(got_marks)}
    out.append(check(step, f"{label}: each object's markings (TLP, PAP) as the bundles set them",
                     f"{len(marked)} as set", f"{len(marked) - len(wrong_marks)} as set",
                     not wrong_marks, wrong_marks))

    # The descriptions of objects and relationships (ADR-0093): a changed one is
    # recorded by `transformations`; an empty one where the bundle set one fails.
    emptied: list[str] = []
    described = 0
    for o in objs:
        n = resolved[o["id"]]
        if o["type"] in ("report", "marking-definition") or not _norm_text(o.get("description")):
            continue
        described += 1
        if n is not None and not _norm_text(n["stix"].get("description")):
            emptied.append(o["id"])
    out.append(check(step, f"{label}: no description emptied (objects and relationships)",
                     f"{described} with a description", f"{described - len(emptied)} with one",
                     not emptied, sorted(emptied)))

    for rep in (o for o in objs if o["type"] == "report"):
        n = resolved[rep["id"]]
        stix = n["stix"] if n is not None else {}
        refs = list(dict.fromkeys(rep.get("object_refs") or []))
        mapped = {i: _std(platform, resolved, i) or i for i in refs}
        held = set(stix.get("object_refs") or [])
        missing = sorted(i for i in refs if mapped[i] not in held)
        landed: dict[str, list[str]] = defaultdict(list)
        for i in refs:
            if mapped[i] in held:
                landed[mapped[i]].append(i)
        merged_refs = {std: sorted(ids) for std, ids in sorted(landed.items()) if len(ids) > 1}
        observed = f"{len(landed)} held"
        if merged_refs:
            observed += f" ({sum(len(ids) for ids in merged_refs.values())} merged into {len(merged_refs)})"
        out.append(check(step, f"{label}: the Report holds the bundle's references",
                         f"{len(refs)} references", observed,
                         n is not None and not missing and not merged_refs,
                         {"missing": missing, "merged": merged_refs}))
        if rep.get("description"):
            kept = n is not None and _norm_text(rep["description"]) == _norm_text(stix.get("description"))
            out.append(check(step, f"{label}: the Report's description kept",
                             f"{len(rep['description'])} characters",
                             "the same" if kept else f"{len(stix.get('description') or '')} characters, different",
                             kept))
        for f in rep.get("x_opencti_files") or []:
            attached = [a for a in (n["files"] if n is not None else []) if a["name"] == f.get("name")]
            ok = len(attached) == 1 and attached[0]["mime_type"] == f.get("mime_type")
            out.append(check(step, f"{label}: the Report's file attached once (x_opencti_files)",
                             f"{f.get('name')} ({f.get('mime_type')}), once",
                             ", ".join(f"{a['name']} ({a['mime_type']})" for a in attached) or "not attached",
                             ok))
        if "confidence" in rep:
            got_conf = stix.get("confidence")
            out.append(check(step, f"{label}: the Report's confidence kept", str(rep["confidence"]),
                             str(got_conf), got_conf == rep["confidence"]))
    return out


def reimport_checks(step: str, label: str, second: dict[str, Any], before: dict[str, int],
                    after: dict[str, int]) -> list[dict[str, Any]]:
    """A second import of the same bundle refuses nothing and adds nothing."""
    changed = {k: [before.get(k, 0), after.get(k, 0)] for k in sorted(set(before) | set(after))
               if before.get(k, 0) != after.get(k, 0)}
    return [
        check(step, f"{label}: nothing refused on a second import", "0 refused",
              f"{len(second['refused'])} refused of {second['objects']}", not second["refused"], second["refused"]),
        check(step, f"{label}: a second import adds nothing", "the same counts",
              "the same counts" if not changed else f"{len(changed)} counts changed", not changed, changed),
    ]


def final_checks(step: str, bundles: dict[str, dict[str, Any]], platform: Platform) -> list[dict[str, Any]]:
    """After the last import: every bundle's objects still there, each on an OpenCTI object of its own.

    A later import can rename an object, or merge it into another: what was
    found right after its own import is looked for again in the last reading.
    """
    out: list[dict[str, Any]] = []
    for label, bundle in bundles.items():
        objs = bundle["objects"]
        resolved_how = {o["id"]: platform.resolve(o) for o in objs}
        resolved = {i: n for i, (n, _) in resolved_how.items()}
        lost = {i: how for i, (n, how) in resolved_how.items() if n is None}
        merged = {**_merged([o for o in objs if o["type"] != "relationship"], resolved),
                  **_merged([o for o in objs if o["type"] == "relationship"], resolved)}
        observed = f"{len(objs) - len(lost)} of {len(objs)}"
        if merged:
            observed += f" ({sum(len(ids) for ids in merged.values())} merged into {len(merged)})"
        out.append(check(step, f"{label}: every object still in OpenCTI, on its own, after the last import",
                         f"{len(objs)} of {len(objs)}", observed, not lost and not merged,
                         {"absent_or_ambiguous": lost, "merged": merged}))
    return out


def reading_checks(step: str, readings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every reading of the platform settled: two in a row agreed before the poll's timeout."""
    unsettled = [r["label"] for r in readings if not r.get("settled")]
    return [check(step, "every reading of the platform settled (two in a row agree)",
                  f"{len(readings)} settled", f"{len(readings) - len(unsettled)} settled",
                  bool(readings) and not unsettled, unsettled)]


def cross_type_warnings(bundles: dict[str, dict[str, Any]], platform: Platform) -> list[dict[str, Any]]:
    """One name held by OpenCTI objects of two types, one of them from these bundles (APT29 twice).

    A WARN, not a failure: which type CTIParsor gives a name is a product
    decision, and OpenCTI keeps both.  Each warning lists the objects, their
    STIX type, OpenCTI's entity type and the bundles that put them there.
    """
    labels_of: dict[str, set[str]] = defaultdict(set)
    nodes: dict[str, dict[str, Any]] = {}
    for label, bundle in bundles.items():
        for o in bundle["objects"]:
            if o["type"] in NAMED_TYPES:
                n, _ = platform.resolve(o)
                if n is not None:
                    labels_of[n["standard_id"]].add(label)
                    nodes[n["standard_id"]] = n
    groups: dict[frozenset[str], set[str]] = {}
    for std, n in nodes.items():
        names = names_of(n["stix"])
        for m in platform.objects:
            other = m["stix"].get("type")
            shared = names_of(m["stix"]) & names
            if other in NAMED_TYPES and other != n["stix"].get("type") and shared:
                groups.setdefault(frozenset({std, m["standard_id"]}), set()).update(shared)
    by_std = {n["standard_id"]: n for n in platform.objects}
    out = []
    for key, names in sorted(groups.items(), key=lambda kv: (sorted(kv[1]), sorted(kv[0]))):
        out.append({"names": sorted(names), "objects": [
            {"standard_id": s, "type": by_std[s]["stix"].get("type"), "entity_type": by_std[s]["entity_type"],
             "name": by_std[s]["stix"].get("name"), "bundles": sorted(labels_of.get(s, set()))}
            for s in sorted(key)]})
    return out


def _comparable(field: str, value: Any) -> Any:
    if field in TIMESTAMPS:
        return _FRACTION.sub(r"\1Z", value) if isinstance(value, str) else value
    if isinstance(value, list):
        return sorted(json.dumps(v, sort_keys=True) for v in value)
    return value


def _list_diff(mine: list[Any], theirs: list[Any]) -> dict[str, list[Any]]:
    """What a list field lost and gained, element by element."""
    ours = {json.dumps(v, sort_keys=True): v for v in mine}
    other = {json.dumps(v, sort_keys=True): v for v in theirs}
    return {"removed": [ours[k] for k in sorted(set(ours) - set(other))],
            "added": [other[k] for k in sorted(set(other) - set(ours))]}


def transformations(bundle: dict[str, Any], platform: Platform) -> list[dict[str, Any]]:
    """Each field OpenCTI holds differently from the bundle: added, changed or absent, with the whole values.

    References are compared once mapped to OpenCTI's standard ids, timestamps to
    the millisecond OpenCTI keeps, lists as sets (a changed list also gets what
    it lost and gained, `diff`); `lang: en` and `revoked: false` added are
    OpenCTI's defaults and left out.  An object found by its name or alias, not
    its id, is listed with the field `(found by name or alias)`; an object not
    found, or found twice, with the field `(object)`, so that a later import
    that loses it shows in `later_changes`.
    """
    resolved_how = {o["id"]: platform.resolve(o) for o in bundle["objects"]}
    resolved = {i: n for i, (n, _) in resolved_how.items()}
    out: list[dict[str, Any]] = []
    for o in bundle["objects"]:
        if o["type"] == "marking-definition":
            continue
        n, how = resolved_how[o["id"]]
        if n is None:
            out.append({"id": o["id"], "type": o["type"], "field": "(object)", "change": how,
                        "bundle": o.get("name") or o.get("value") or o["id"], "opencti": None})
            continue
        if how == "name":
            out.append({"id": o["id"], "type": o["type"], "field": "(found by name or alias)", "change": "renamed",
                        "bundle": o.get("name") or o.get("value"),
                        "opencti": n["stix"].get("name") or n["stix"].get("value")})
        stix = n["stix"]
        for field in sorted((set(o) | set(stix)) - UNCOMPARED):
            mine, theirs = o.get(field), stix.get(field)
            if field in REF_FIELDS and mine is not None:
                mine = _std(platform, resolved, mine) or mine
            if field == "object_marking_refs" and mine is not None:
                mine = [_std(platform, resolved, m) or m for m in mine]
            if mine is None and field in DEFAULTS and theirs == DEFAULTS[field]:
                continue
            if _comparable(field, mine) == _comparable(field, theirs):
                continue
            change = "absent" if theirs is None else "added" if mine is None else "changed"
            entry: dict[str, Any] = {"id": o["id"], "type": o["type"], "field": field, "change": change,
                                     "bundle": mine, "opencti": theirs}
            if isinstance(mine, list) and isinstance(theirs, list):
                entry["diff"] = _list_diff(mine, theirs)
            out.append(entry)
    return out


def _key(t: dict[str, Any]) -> tuple[str, str, str]:
    return t["id"], t["field"], json.dumps(t["opencti"], sort_keys=True, default=str)


def later_changes(after: list[dict[str, Any]], final: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What the imports after a bundle changed in its objects: in the final reading, not right after its import."""
    seen = {_key(t) for t in after}
    return [t for t in final if _key(t) not in seen]


def summarize(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Transformations grouped by type, field and change, with how many objects and one example."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for t in entries:
        key = (t["type"], t["field"], t["change"])
        if key not in groups:
            example = {"id": t["id"], "bundle": t["bundle"], "opencti": t["opencti"]}
            if "diff" in t:
                example["diff"] = t["diff"]
            groups[key] = {"type": t["type"], "field": t["field"], "change": t["change"], "objects": 0,
                           "example": example}
        groups[key]["objects"] += 1
    return [groups[k] for k in sorted(groups)]


def candidate_checks(run: dict[str, Any], check_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Step 0: the bundles OpenCTI received are the ones the candidate produced, on its commit, validated.

    A job whose run config records no commit is read as `(none)`
    (scripts/check_opencti_candidate.sh): it fails the first check.
    """
    out: list[dict[str, Any]] = []
    cand = run.get("candidate") or {}
    commit = cand.get("commit") or ""
    revs = sorted(set(cand.get("job_git_revs") or []))
    out.append(check("0", "the candidate's jobs ran on the image's commit", commit or "a commit label",
                     ", ".join(revs) or "none recorded", bool(commit) and revs == [commit], revs))
    imported = (check_result.get("bundles") or {})
    for name, made in sorted((run.get("bundles") or {}).items()):
        out.append(check("0", f"{name}: Stage 5 validated it (X-Bundle-Validation)", "validated",
                         str(made.get("validation")), made.get("validation") == "validated"))
        got = (imported.get(name) or {}).get("sha256")
        out.append(check("0", f"{name}: the bundle OpenCTI received is the candidate's", made.get("sha256", "?")[:12],
                         (got or "not imported")[:12], got == made.get("sha256")))
    return out


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _preview(value: Any) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return text if len(text) <= 120 else text[:117] + "..."


def _provenance(run: dict[str, Any]) -> list[str]:
    """Where the bundles come from, and the checkout that ran the check."""
    lines = []
    source = run.get("bundles_from") or {}
    if source.get("dir"):
        earlier = source.get("earlier_run") or {}
        lines.append(f"- Bundles: **not produced by this run**: taken from `{source['dir']}`, whose record says "
                     f"image `{earlier.get('digest_ref', '?')}`, commit `{earlier.get('commit', '?')}`, "
                     f"{earlier.get('date', 'date unknown')}. The candidate above is the one that run recorded.")
    else:
        lines.append("- Bundles: produced by this run, through the candidate's API")
    checkout = run.get("checkout") or {}
    if checkout.get("commit"):
        dirty = checkout.get("dirty")
        state = ("tracked files modified" if dirty is True
                 else "no tracked file modified" if dirty is False else "state unknown")
        lines.append(f"- Checkout that ran the check (fixtures, expectations): `{checkout['commit']}`, {state}")
    else:
        lines.append("- Checkout that ran the check: unknown (not a git checkout, or git unavailable)")
    return lines


def summary_markdown(report: dict[str, Any]) -> str:
    run, result = report["run"], report["check"]
    checks = report["checks"]
    warnings = report.get("warnings") or []
    passed = sum(1 for c in checks if c["pass"])
    cand = run.get("candidate") or {}
    revs = ", ".join(f"`{r}`" for r in sorted(set(cand.get("job_git_revs") or []))) or "none"
    head = f"**{'PASS' if report['passed'] else 'FAIL'}**: {passed} of {len(checks)} expectations hold."
    if warnings:
        head += f" **{len(warnings)} WARN** (see Warnings)."
    lines = [f"# OpenCTI import of the candidate, {run.get('date', '?')}", "", head, "",
             "## Candidate", "",
             f"- Image: `{cand.get('digest_ref', '?')}` (given as `{cand.get('image', '?')}`)",
             f"- Commit: `{cand.get('commit', '?')}` (label `org.opencontainers.image.revision`); "
             f"the jobs' `git_rev`: {revs}",
             f"- Profile: {run.get('profile', '?')}",
             *_provenance(run), "",
             "## Consumer", "",
             f"- OpenCTI {(result.get('versions') or {}).get('opencti', '?')}, "
             f"pycti {(result.get('versions') or {}).get('pycti', '?')}",
             f"- Import path: {result.get('import_path', '?')}"]
    for image, digest in sorted((run.get("opencti") or {}).get("images", {}).items()):
        lines.append(f"- `{image}`: `{digest}`")
    lines += ["", "## Bundles", "",
              "| Bundle | Source | Objects | X-Bundle-Validation | sha256 |", "|---|---|---|---|---|"]
    for name, b in sorted((run.get("bundles") or {}).items()):
        source = b.get("source", "")
        if b.get("baseline"):
            source += f" on `{b['baseline']}`"
        lines.append(f"| {name} | {_cell(source)} | {b.get('objects')} | {b.get('validation')} | `{b.get('sha256')}` |")
    lines += ["", "## Expectations", "", "| Step | Check | Expected | Observed | Result |", "|---|---|---|---|---|"]
    for c in checks:
        lines.append(f"| {c['step']} | {_cell(c['check'])} | {_cell(c['expected'])} | {_cell(c['observed'])} "
                     f"| {'PASS' if c['pass'] else 'FAIL'} |")
    lines += ["", "## Warnings", ""]
    if not warnings:
        lines.append("None.")
    else:
        lines += ["One name held by OpenCTI objects of two types. Not a failure: which type CTIParsor gives a "
                  "name is a product decision, and OpenCTI keeps both objects.", "",
                  "| | Name | Objects: name (STIX type, OpenCTI type, from the bundles) |", "|---|---|---|"]
        for w in warnings:
            members = "; ".join(f"{m.get('name')} ({m['type']}, {m['entity_type']}, "
                                f"{', '.join(m['bundles']) or 'none of them'})" for m in w["objects"])
            lines.append(f"| WARN | {_cell(', '.join(w['names']))} | {_cell(members)} |")
    lines += ["", "## Refused by OpenCTI", ""]
    imports = result.get("imports") or []
    refused = [(i["label"], r) for i in imports for r in i.get("refused") or []]
    if not refused:
        lines.append(f"Nothing, in {len(imports)} imports.")
    for label, r in refused:
        lines.append(f"- {label}: `{r.get('id')}` ({r.get('type')}): {_cell(r.get('error', ''))[:300]}")
    lines += ["", "## What OpenCTI holds differently (informational)", "",
              "Field by field, each bundle against what OpenCTI exports for the same objects right after its "
              "import, then what the later imports changed in them. One example per row, cut to 120 characters "
              "(report.json holds every value whole); for a changed list, what it lost (`-`) and gained (`+`).", ""]
    for label, entries in (result.get("transformations") or {}).items():
        for title, rows in ((f"### {label}", entries.get("after_import") or []),
                            (f"### {label}: changed by the later imports", entries.get("later") or [])):
            lines += [title, ""]
            groups = summarize(rows)
            if not groups:
                lines += ["Nothing.", ""]
                continue
            lines += ["| Type | Field | Change | Objects | Example: bundle | Example: OpenCTI |",
                      "|---|---|---|---|---|---|"]
            for g in groups:
                ex = g["example"]
                if "diff" in ex:
                    mine = "- " + _preview(ex["diff"]["removed"]) if ex["diff"]["removed"] else "(nothing lost)"
                    theirs = "+ " + _preview(ex["diff"]["added"]) if ex["diff"]["added"] else "(nothing gained)"
                else:
                    mine, theirs = _preview(ex["bundle"]), _preview(ex["opencti"])
                lines.append(f"| {g['type']} | {_cell(g['field'])} | {g['change']} | {g['objects']} "
                             f"| {_cell(mine)} | {_cell(theirs)} |")
            lines.append("")
    durations = run.get("durations_s") or {}
    memory = run.get("memory_mb") or {}
    lines += ["## Run", "",
              "- Durations (s): " + ", ".join(f"{k} {v}" for k, v in durations.items()),
              f"- Memory (MB, `free -m`): total {memory.get('total', '?')}, used before OpenCTI "
              f"{memory.get('before_opencti', '?')}, peak used while it ran {memory.get('peak_used', '?')}",
              f"- Host: {run.get('host', '?')}", ""]
    return "\n".join(lines)


def build_report(run: dict[str, Any], check_result: dict[str, Any]) -> dict[str, Any]:
    checks = candidate_checks(run, check_result) + list(check_result.get("checks") or [])
    return {"passed": all(c["pass"] for c in checks) and bool(check_result.get("checks")),
            "checks": checks, "warnings": list(check_result.get("warnings") or []),
            "run": run, "check": check_result}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the report of an OpenCTI check (ADR-0094 item 8).")
    sub = parser.add_subparsers(dest="command", required=True)
    rep = sub.add_parser("report", help="report.json and report.md from the run's record and the check's results")
    rep.add_argument("--run", required=True, help="run.json, written by scripts/check_opencti_candidate.sh")
    rep.add_argument("--check", required=True, help="the JSON scripts/opencti_import_check.py wrote (--out)")
    rep.add_argument("--out-dir", required=True, help="where report.json and report.md go")
    args = parser.parse_args(argv)
    try:
        run = json.loads(Path(args.run).read_text(encoding="utf-8"))
        result = json.loads(Path(args.check).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"opencti_expectations: {exc}", file=sys.stderr)
        return 2
    report = build_report(run, result)
    out = Path(args.out_dir)
    (out / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    (out / "report.md").write_text(summary_markdown(report), encoding="utf-8")
    failed = [c for c in report["checks"] if not c["pass"]]
    for c in failed:
        print(f"FAIL  {c['step']}  {c['check']}: expected {c['expected']}, observed {c['observed']}")
    warnings = report["warnings"]
    for w in warnings:
        print("WARN  one name, two types: " + "; ".join(f"{m.get('name')} ({m['entity_type']})" for m in w["objects"]))
    warned = f", {len(warnings)} WARN" if warnings else ""
    print(f"{len(report['checks']) - len(failed)} of {len(report['checks'])} expectations hold{warned}: "
          f"{out / 'report.md'}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
