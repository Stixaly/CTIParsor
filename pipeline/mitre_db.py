"""
Lazy-loaded MITRE ATT&CK + CAPEC index.

Reads pipeline/data/mitre_index.json (built from enterprise-attack.json,
mobile-attack.json, ics-attack.json, and stix-capec.json) on first access and
caches the result for the lifetime of the process.
"""
from __future__ import annotations

import functools
import json
from pathlib import Path

# Initialize logging
from api.logging_config import get_logger
from pipeline import attack_data

logger = get_logger(__name__)

_INDEX_PATH = Path(__file__).parent / "data" / "mitre_index.json"


@functools.lru_cache(maxsize=1)
def _load() -> dict:
    # Resolved outside the try: an unknown ATTACK_RELEASE must reach the caller.
    path = attack_data.resolve(_INDEX_PATH)
    if not path.exists():
        return {"techniques": [], "tactics": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error(f"Could not load index: {e}")
        return {"techniques": [], "tactics": []}


def get_techniques() -> list[dict]:
    # .get() not [] — a valid-JSON-but-wrong-shape index (missing the key) would
    # otherwise KeyError-crash every caller (stage3c MITRE normalization, search).
    return _load().get("techniques", [])


def get_tactics() -> list[dict]:
    return _load().get("tactics", [])


def lookup_by_id(mitre_id: str) -> dict | None:
    """Return the index entry for a given ATT&CK / CAPEC ID (case-insensitive)."""
    mid = mitre_id.upper()
    for entry in get_tactics():
        if entry["id"].upper() == mid:
            return entry
    for entry in get_techniques():
        if entry["id"].upper() == mid:
            return entry
    return None


def search(query: str, limit: int = 15) -> list[dict]:
    """
    Search techniques and tactics by ID prefix or name substring.
    Tactics and ID-prefix matches are ranked first.
    """
    q = query.lower().strip()
    if not q:
        return []

    results: list[dict] = []
    seen: set[str] = set()

    all_entries = list(get_tactics()) + list(get_techniques())

    # 1. ID prefix matches
    for entry in all_entries:
        if entry["id"] in seen:
            continue
        if entry["id"].lower().startswith(q):
            results.append(entry)
            seen.add(entry["id"])

    # 2. Name contains
    for entry in all_entries:
        if entry["id"] in seen:
            continue
        if q in entry["name"].lower():
            results.append(entry)
            seen.add(entry["id"])

    return results[:limit]


_REVOKED_PATH = Path(__file__).parent / "data" / "attack_revoked.json"


@functools.lru_cache(maxsize=1)
def _revoked() -> dict:
    path = attack_data.resolve(_REVOKED_PATH)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(f"[mitre_db] {path.name} unreadable, revoked ids are not "
                       f"replaced: {type(exc).__name__}: {exc}")
        return {}


def replacement_for(mitre_id: str) -> str | None:
    """The active technique a revoked ATT&CK id was replaced by, or None
    (`scripts/build_indexes.py --only revoked`)."""
    table = {k.upper(): v for k, v in (_revoked().get("revoked_by") or {}).items()}
    return table.get((mitre_id or "").strip().upper())


def revoked_names() -> dict[str, str]:
    """Lower-cased name of a revoked Enterprise technique, no active one bearing
    it any more → its replacement's id ("impair defenses" → T1685)."""
    return dict(_revoked().get("names") or {})


def available() -> bool:
    """Return True if the index file exists."""
    return attack_data.resolve(_INDEX_PATH).exists()
