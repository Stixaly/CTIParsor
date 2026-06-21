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

import functools
import re

# Initialize logging
from api.logging_config import get_logger
from pipeline.stage3_llm import TTPExtracted

logger = get_logger(__name__)

try:
    from rapidfuzz import fuzz
    from rapidfuzz import process as rfprocess
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
    from pipeline.mitre_db import available, get_tactics, get_techniques

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

    Precision rules (ADR precision §2-3):
      • A *high-confidence* semantic match (cosine ≥ the model's high threshold)
        wins over the LLM for the same ID — it is the highest-precision signal.
      • A *medium-confidence* semantic match does NOT override the LLM: when both
        cover the same technique the LLM entry (context-validated, richer) is kept.
        Lower-precision signals must never silently beat higher-precision ones.
      • Parent/sub-technique subsumption: when a sub-technique (T1059.001) is
        present, its parent (T1059) is dropped — the specific entry is strictly
        more precise and the parent is redundant noise (Phase C).

    Returns the list unchanged if the MITRE index is unavailable.

    Args:
        ttps:              LLM-extracted TTPs from stage3_llm.
        semantic_entities: Optional RawEntity list from stage2c_ttp_semantic.
    """
    index = _load_index()
    if not index:
        logger.warning("MITRE index not found — ensure pipeline/data/mitre_index.json exists")
        return ttps

    # The high-confidence cut-point is model-specific; ask Stage 2c so the two
    # stages can never drift apart on what "high confidence" means.
    try:
        from pipeline.stage2c_ttp_semantic import high_confidence_threshold
        high_thresh = high_confidence_threshold()
    except Exception:
        high_thresh = 0.62

    normalized: dict[str, TTPExtracted] = {}
    semantic_high_keys: set[str] = set()   # keys a high-conf semantic match owns

    # ── 1. Seed with HIGH-confidence semantic findings only ─────────────────
    # Medium-confidence semantic matches are added later (step 3) and only when
    # the LLM has not already covered the technique — so they can never override
    # the LLM's context-aware judgement.
    if semantic_entities:
        for ent in semantic_entities:
            if not getattr(ent, "mitre_id", None):
                continue
            conf = float(getattr(ent, "confidence", 0.0) or 0.0)
            if conf < high_thresh:
                continue
            dedup_key = ent.mitre_id.lower()
            normalized[dedup_key] = TTPExtracted(
                technique_name=ent.value,
                mitre_id=ent.mitre_id,
                description=ent.context or "",  # evidence sentence stored as context
            )
            semantic_high_keys.add(dedup_key)

    # ── 2. Resolve and merge LLM TTPs ───────────────────────────────────────
    for ttp in ttps:
        canon_name, canon_id, _ = _resolve(ttp.technique_name, ttp.mitre_id)
        dedup_key = canon_id.lower() if canon_id else canon_name.lower()

        result_ttp = TTPExtracted(
            technique_name=canon_name,
            mitre_id=canon_id,
            description=ttp.description,
        )

        if dedup_key in semantic_high_keys:
            # A high-confidence semantic match owns this key — keep its canonical
            # name/ID, but adopt the LLM's description if it is richer.
            existing = normalized[dedup_key]
            if len(result_ttp.description) > len(existing.description):
                normalized[dedup_key] = TTPExtracted(
                    technique_name=existing.technique_name,
                    mitre_id=existing.mitre_id,
                    description=result_ttp.description,
                )
        elif dedup_key in normalized:
            if len(result_ttp.description) > len(normalized[dedup_key].description):
                normalized[dedup_key] = result_ttp
        else:
            normalized[dedup_key] = result_ttp

    # ── 3. Add MEDIUM-confidence semantic matches not covered by the LLM ─────
    if semantic_entities:
        for ent in semantic_entities:
            if not getattr(ent, "mitre_id", None):
                continue
            dedup_key = ent.mitre_id.lower()
            if dedup_key in normalized:
                continue
            normalized[dedup_key] = TTPExtracted(
                technique_name=ent.value,
                mitre_id=ent.mitre_id,
                description=ent.context or "",
            )

    return _subsume_parent_techniques(list(normalized.values()))


def _subsume_parent_techniques(ttps: list[TTPExtracted]) -> list[TTPExtracted]:
    """
    Drop a parent technique (T1059) when one of its sub-techniques (T1059.001)
    is also present.  The sub-technique is strictly more specific, so keeping the
    parent adds a redundant, lower-precision entry (Phase C).

    IDs are matched case-insensitively; only dotted ATT&CK technique IDs are
    considered (tactics 'TA…' and CAPEC 'CAPEC-…' are untouched).
    """
    present_ids = {
        t.mitre_id.upper() for t in ttps
        if t.mitre_id and _MITRE_ID_RE.match(t.mitre_id.lower())
    }
    parents_with_children = {
        mid.rsplit(".", 1)[0] for mid in present_ids if "." in mid
    }
    if not parents_with_children:
        return ttps

    return [
        t for t in ttps
        if not (t.mitre_id and t.mitre_id.upper() in parents_with_children)
    ]


@functools.lru_cache(maxsize=1)
def _tactics_by_id() -> dict[str, list[str]]:
    """Map each technique ID (upper-case) → its ATT&CK tactic (kill-chain) names.

    Used to give the Stage 3f verification prompt the expected tactic for a
    technique, so the fact-checker can also reject a technique whose tactic is
    inconsistent with how the text describes it (Phase B/C)."""
    from pipeline.mitre_db import get_techniques

    out: dict[str, list[str]] = {}
    for t in get_techniques():
        mid = t.get("id")
        tactics = t.get("tactics") or []
        if mid and tactics:
            out[mid.upper()] = list(tactics)
    return out


def tactics_for(mitre_id: str | None) -> list[str]:
    """Return the ATT&CK tactic name(s) for a technique ID, or [] if unknown."""
    if not mitre_id:
        return []
    return _tactics_by_id().get(mitre_id.upper(), [])


def bundle_available() -> bool:
    """Returns True if the MITRE index has been built."""
    from pipeline.mitre_db import available
    return available()
