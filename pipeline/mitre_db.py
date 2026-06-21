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

logger = get_logger(__name__)

_INDEX_PATH = Path(__file__).parent / "data" / "mitre_index.json"


@functools.lru_cache(maxsize=1)
def _load() -> dict:
    if not _INDEX_PATH.exists():
        return {"techniques": [], "tactics": []}
    try:
        return json.loads(_INDEX_PATH.read_text(encoding="utf-8"))
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


def available() -> bool:
    """Return True if the index file exists."""
    return _INDEX_PATH.exists()
