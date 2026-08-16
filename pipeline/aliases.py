"""
Alias canonicalisation for named entities (ADR-0012).

Problem observed via the grounding benchmark (tests/eval_pipeline.py -b grounding):
relationships like `OilRig targets Israel` are flagged as ungrounded because the
report text names the group by a DIFFERENT alias ("APT34"), while the pipeline
emitted the MITRE *canonical* name ("OilRig").  The relationship is real — only
the surface form differs.  The same mismatch inflates dedup (OilRig and APT34
become two separate STIX nodes).

This module builds an offline alias index from the shipped gazetteer
(pipeline/data/gazetteer.json), which already stores every MITRE surface form
(`name`) alongside its `canonical` name and `mitre_id`.  Entries that share a
`mitre_id` are aliases of one another.

Public API:
  mitre_id_for(name, stix_type=None)        -> canonical MITRE id ("G0049") or None
  canonical_name(name, stix_type=None)      -> canonical display name ("OilRig"); identity if unknown
  alias_surface_forms(name, stix_type=None) -> {every known surface form + the MITRE id}, lowercased

All lookups are case-insensitive.  Unknown names pass through unchanged, so this
is safe to apply blindly.

A surface form can denote several MITRE objects (23 in the shipped gazetteer:
"snake" is both the Turla group G0010 and the Uroburos malware S0022). Callers
should pass the STIX type they are about to create. An ambiguous form which the
type cannot narrow resolves to nothing and passes through unchanged (ADR-0021).
"""
from __future__ import annotations

import functools
import json
from pathlib import Path

_GAZETTEER = Path(__file__).parent / "data" / "gazetteer.json"
_MITRE_INDEX = Path(__file__).parent / "data" / "mitre_index.json"

#: STIX type -> the gazetteer `entity_type` values that may denote it.
#:
#: Used ONLY to break a tie between several MITRE ids sharing one surface form
#: (ADR-0021). It is never used to reject an unambiguous match, so a name the
#: extractor classified as `malware` while the gazetteer calls it a `tool` still
#: canonicalises exactly as before.
_STIX_TYPE_TO_ENTITY_TYPES: dict[str, frozenset[str]] = {
    "threat-actor": frozenset({"threat_actor"}),
    "intrusion-set": frozenset({"threat_actor"}),
    "malware": frozenset({"malware"}),
    "tool": frozenset({"tool"}),
}


@functools.lru_cache(maxsize=1)
def _load() -> tuple[
    dict[str, set[str]], dict[str, str], dict[str, set[str]], dict[str, str]
]:
    """Return (name2ids, id2canonical, id2surfaces, id2entity_type)."""
    name2ids: dict[str, set[str]] = {}
    id2canonical: dict[str, str] = {}
    id2surfaces: dict[str, set[str]] = {}
    id2entity_type: dict[str, str] = {}

    try:
        entries = json.loads(_GAZETTEER.read_text(encoding="utf-8"))
    except Exception:
        return name2ids, id2canonical, id2surfaces, id2entity_type

    for e in entries:
        if not isinstance(e, dict):
            continue
        mid = e.get("mitre_id")
        if not isinstance(mid, str) or not mid.strip():
            continue
        mid = mid.strip()
        name = (e.get("name") or "").lower().strip()
        canonical = (e.get("canonical") or "").strip()
        entity_type = e.get("entity_type")

        id2surfaces.setdefault(mid, set())
        if name:
            name2ids.setdefault(name, set()).add(mid)
            id2surfaces[mid].add(name)
        if canonical:
            c_lower = canonical.lower().strip()
            name2ids.setdefault(c_lower, set()).add(mid)
            id2surfaces[mid].add(c_lower)
            # First-seen canonical wins (gazetteer lists canonical consistently).
            id2canonical.setdefault(mid, canonical)

        if isinstance(entity_type, str) and entity_type.strip():
            id2entity_type[mid] = entity_type.lower().strip()

    return name2ids, id2canonical, id2surfaces, id2entity_type


def _resolve(name: str, stix_type: str | None) -> str | None:
    """The single MITRE id *name* denotes, or None when that is not decidable.

    An unambiguous surface form resolves whatever *stix_type* says; a form
    carried by several ids is narrowed by type, and resolves to None when the
    type is absent or still leaves more than one candidate (ADR-0021).
    """
    if not isinstance(name, str) or not name:
        return None
    key = name.lower().strip()
    if not key:
        return None
    name2ids, _, _, id2entity_type = _load()
    ids = name2ids.get(key)
    if not ids:
        return None
    if len(ids) == 1:
        return next(iter(ids))
    if stix_type is None or not isinstance(stix_type, str):
        return None
    wanted = _STIX_TYPE_TO_ENTITY_TYPES.get(stix_type.strip().lower())
    if not wanted:
        return None
    matches = sorted(i for i in ids if id2entity_type.get(i) in wanted)
    if len(matches) == 1:
        return matches[0]
    return None


def mitre_id_for(name: str, stix_type: str | None = None) -> str | None:
    """Canonical MITRE id for a name/alias, or None if unknown."""
    return _resolve(name, stix_type)


def canonical_name(name: str, stix_type: str | None = None) -> str:
    """Canonical display name for a name/alias; returns *name* unchanged if unknown."""
    if not name:
        return name
    mid = _resolve(name, stix_type)
    if mid:
        _, id2canonical, _, _ = _load()
        return id2canonical.get(mid, name)
    return name


def alias_surface_forms(name: str, stix_type: str | None = None) -> set[str]:
    """Every known surface form for *name* (all aliases sharing its MITRE id),
    plus the MITRE id itself, lowercased.  Always includes *name* itself."""
    forms = {name.lower().strip()} if isinstance(name, str) and name else set()
    mid = _resolve(name, stix_type)
    if mid:
        _, _, id2surfaces, _ = _load()
        forms |= id2surfaces.get(mid, set())
        forms.add(mid.lower())
    return forms


# ── MITRE ATT&CK technique name ↔ ID ──────────────────────────────────────────

@functools.lru_cache(maxsize=1)
def _load_techniques() -> tuple[dict[str, str], dict[str, str]]:
    """Return (technique-name->id, id->canonical-name) from mitre_index.json."""
    name2id: dict[str, str] = {}
    id2name: dict[str, str] = {}
    try:
        index = json.loads(_MITRE_INDEX.read_text(encoding="utf-8"))
    except Exception:
        return name2id, id2name
    for t in index.get("techniques", []):
        tid = (t.get("id") or "").strip()
        name = (t.get("name") or "").lower().strip()
        if tid and name:
            name2id.setdefault(name, tid)
            id2name.setdefault(tid.upper(), t["name"])
    return name2id, id2name


def technique_id_for(name: str) -> str | None:
    """MITRE ATT&CK / CAPEC id for a technique name, or None if unknown."""
    if not name:
        return None
    name2id, _ = _load_techniques()
    return name2id.get(name.lower().strip())


def technique_name_for(technique_id: str) -> str | None:
    """Canonical technique name for a MITRE id, or None if unknown."""
    if not technique_id:
        return None
    _, id2name = _load_techniques()
    return id2name.get(technique_id.upper().strip())
