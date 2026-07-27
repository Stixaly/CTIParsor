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
  mitre_id_for(name)        → canonical MITRE id ("G0049") or None
  canonical_name(name)      → canonical display name ("OilRig"); identity if unknown
  alias_surface_forms(name) → {every known surface form + the MITRE id}, lowercased

All lookups are case-insensitive.  Unknown names pass through unchanged, so this
is safe to apply blindly.
"""
from __future__ import annotations

import functools
import json
from pathlib import Path

_GAZETTEER = Path(__file__).parent / "data" / "gazetteer.json"
_MITRE_INDEX = Path(__file__).parent / "data" / "mitre_index.json"


@functools.lru_cache(maxsize=1)
def _load() -> tuple[dict[str, str], dict[str, str], dict[str, set[str]]]:
    """Return (name→id, id→canonical, id→{surface forms})."""
    name2id: dict[str, str] = {}
    id2canonical: dict[str, str] = {}
    id2surfaces: dict[str, set[str]] = {}

    try:
        entries = json.loads(_GAZETTEER.read_text(encoding="utf-8"))
    except Exception:
        return name2id, id2canonical, id2surfaces

    for e in entries:
        mid = e.get("mitre_id")
        if not mid:
            continue
        name = (e.get("name") or "").lower().strip()
        canonical = (e.get("canonical") or "").strip()

        id2surfaces.setdefault(mid, set())
        if name:
            name2id[name] = mid
            id2surfaces[mid].add(name)
        if canonical:
            name2id[canonical.lower().strip()] = mid
            id2surfaces[mid].add(canonical.lower().strip())
            # First-seen canonical wins (gazetteer lists canonical consistently).
            id2canonical.setdefault(mid, canonical)

    return name2id, id2canonical, id2surfaces


def mitre_id_for(name: str) -> str | None:
    """Canonical MITRE id for a name/alias, or None if unknown."""
    if not name:
        return None
    name2id, _, _ = _load()
    return name2id.get(name.lower().strip())


def canonical_name(name: str) -> str:
    """Canonical display name for a name/alias; returns *name* unchanged if unknown."""
    if not name:
        return name
    name2id, id2canonical, _ = _load()
    mid = name2id.get(name.lower().strip())
    return id2canonical.get(mid, name) if mid else name


def alias_surface_forms(name: str) -> set[str]:
    """Every known surface form for *name* (all aliases sharing its MITRE id),
    plus the MITRE id itself, lowercased.  Always includes *name* itself."""
    forms = {name.lower().strip()} if name else set()
    mid = mitre_id_for(name)
    if mid:
        _, _, id2surfaces = _load()
        forms |= id2surfaces.get(mid, set())
        forms.add(mid.lower())
    return forms


# ── MITRE ATT&CK technique name ↔ ID ──────────────────────────────────────────

@functools.lru_cache(maxsize=1)
def _load_techniques() -> tuple[dict[str, str], dict[str, str]]:
    """Return (technique-name→id, id→canonical-name) from mitre_index.json."""
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
