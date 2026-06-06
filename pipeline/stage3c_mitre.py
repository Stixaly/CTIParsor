"""
Stage 3c — MITRE ATT&CK TTP normalization.

Problem: the LLM assigns ATT&CK technique IDs from memory, which leads to:
  - Wrong IDs for correct technique names (T1059 vs T1059.001)
  - Invented IDs that don't exist in the framework
  - Deprecated IDs from old ATT&CK versions
  - Paraphrased names that don't match canonical technique names

Solution: use the pre-built compact MITRE index (pipeline/data/mitre_index.json)
covering Enterprise, Mobile, ICS, and CAPEC, and fuzzy-match each extracted TTP
against all known technique/tactic names.  Three tiers:

  Score ≥ 85  → high confidence — use canonical name AND correct ID
  Score 70–84 → medium confidence — keep LLM name, override ID
  Score < 70  → low confidence — leave TTP unchanged (LLM guess)
"""

from __future__ import annotations

import re
import functools

from pipeline.stage3_llm import TTPExtracted

# Initialize logging
from api.logging_config import get_logger
logger = get_logger(__name__)

try:
    from rapidfuzz import fuzz, process as rfprocess
    _RAPIDFUZZ_AVAILABLE = True
except ImportError:
    _RAPIDFUZZ_AVAILABLE = False
    logger.warning("rapidfuzz not installed — MITRE normalization disabled. Run: pip install rapidfuzz")

# Fuzzy match thresholds
_HIGH_CONF   = 85
_MEDIUM_CONF = 70

# Matches ATT&CK technique IDs (t1234 / t1234.001) and tactic IDs (ta0006).
# The index stores everything lowercase, so we match 't1234', 'ta0001', etc.
# Pattern breakdown:
#   t           — all MITRE IDs start with T
#   (a\d{4}     — tactic: TA + exactly 4 digits
#    |\d{4}(\.\d{3})?)  — technique: T + 4 digits + optional sub-technique
_MITRE_ID_RE = re.compile(r'^t(a\d{4}|\d{4}(\.\d{3})?)$')


# ---------------------------------------------------------------------------
# Index building — lazy, cached
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def _load_index() -> dict[str, dict] | None:
    """
    Builds a lowercase-name / lowercase-ID → entry lookup from the compact
    MITRE index.  Covers enterprise, mobile, ICS, and CAPEC.
    """
    from pipeline.mitre_db import get_techniques, get_tactics, available

    if not available():
        return None

    index: dict[str, dict] = {}

    for entry in list(get_tactics()) + list(get_techniques()):
        mid  = entry["id"]
        name = entry["name"]
        url  = (
            f"https://attack.mitre.org/techniques/{mid.replace('.', '/')}/"
            if mid.startswith("T")
            else f"https://attack.mitre.org/tactics/{mid}/"
            if mid.startswith("TA")
            else ""
        )
        rec = {"id": mid, "name": name, "url": url}
        index[name.lower()] = rec
        index[mid.lower()]  = rec

    return index if index else None


def _resolve(technique_name: str, mitre_id: str | None) -> tuple[str, str | None, str | None]:
    """Returns (canonical_name, mitre_id, url) — falls back to input values."""
    index = _load_index()
    if not index or not _RAPIDFUZZ_AVAILABLE:
        return technique_name, mitre_id, None

    name_lower = technique_name.lower().strip()

    # 1. Try the provided MITRE ID first — it is the highest-authority signal.
    #    This prevents cross-domain name collisions (e.g. "Phishing" exists as
    #    T1566 in Enterprise and T1660 in Mobile; the ID breaks the tie).
    if mitre_id and mitre_id.lower() in index:
        e = index[mitre_id.lower()]
        return e["name"], e["id"], e["url"]

    # 2. Exact name match (only useful when no valid ID was provided)
    if name_lower in index:
        e = index[name_lower]
        return e["name"], e["id"], e["url"]

    # 3. Fuzzy match — only against name keys, not bare IDs
    name_keys = [k for k in index if not _MITRE_ID_RE.match(k)]

    match_result = rfprocess.extractOne(
        name_lower,
        name_keys,
        scorer=fuzz.WRatio,
    )

    if match_result is None:
        return technique_name, mitre_id, None

    best_key, score, _ = match_result

    if score >= _HIGH_CONF:
        e = index[best_key]
        return e["name"], e["id"], e["url"]

    if score >= _MEDIUM_CONF:
        e = index[best_key]
        return technique_name, e["id"], e["url"]

    return technique_name, mitre_id, None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_ttps(
    ttps: list[TTPExtracted],
    semantic_entities: list | None = None,
) -> list[TTPExtracted]:
    """
    Verifies and corrects MITRE ATT&CK IDs for every LLM-extracted TTP, then
    merges the results with any TTPs already found by Stage 2c semantic matching.

    De-duplication rules:
      • Semantic match wins over LLM for the same MITRE ID (higher precision).
      • LLM match is kept only when no semantic match covers the same technique.
      • Within each source, the entry with the longer description is kept.

    Returns the list unchanged if the MITRE index is unavailable.

    Args:
        ttps:              LLM-extracted TTPs from stage3_llm.
        semantic_entities: Optional RawEntity list from stage2c_ttp_semantic.
    """
    index = _load_index()
    if not index:
        logger.warning("MITRE index not found — ensure pipeline/data/mitre_index.json exists")
        return ttps

    normalized: dict[str, TTPExtracted] = {}

    # ── 1. Seed with semantic findings (highest precision) ──────────────────
    if semantic_entities:
        from models.schemas import RawEntity  # avoid circular import at module level
        for ent in semantic_entities:
            if not hasattr(ent, "mitre_id") or not ent.mitre_id:
                continue
            dedup_key = ent.mitre_id.lower()
            normalized[dedup_key] = TTPExtracted(
                technique_name=ent.value,
                mitre_id=ent.mitre_id,
                description=ent.context or "",  # evidence sentence stored as context
            )

    # ── 2. Resolve and merge LLM TTPs (skip if already covered) ────────────
    for ttp in ttps:
        canon_name, canon_id, _ = _resolve(ttp.technique_name, ttp.mitre_id)
        dedup_key = canon_id.lower() if canon_id else canon_name.lower()

        result_ttp = TTPExtracted(
            technique_name=canon_name,
            mitre_id=canon_id,
            description=ttp.description,
        )

        if dedup_key in normalized:
            # Keep whichever entry has the richer description
            existing = normalized[dedup_key]
            if len(result_ttp.description) > len(existing.description):
                normalized[dedup_key] = result_ttp
        else:
            normalized[dedup_key] = result_ttp

    return list(normalized.values())


def bundle_available() -> bool:
    """Returns True if the MITRE index has been built."""
    from pipeline.mitre_db import available
    return available()
