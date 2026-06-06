"""
Stage 2b — Gazetteer-based Named Entity Recognition.

Scans a document for 1,792 known malware families, offensive tools, and APT group
names sourced from the MITRE ATT&CK Enterprise, Mobile, and ICS STIX bundles
(including all canonical names and aliases).

This deterministic approach has near-zero hallucination risk for *known* threat
actors and malware families, and complements:
  • Stage 2  — regex IoC extraction (IPs, hashes, domains, CVEs)
  • Stage 3  — LLM enrichment (relationships, novel/unnamed entities, campaign)

Paper basis: Arazzi et al. 2023 §8 — Dictionary-template-enhanced NER
(Dict+BiLSTM+CRF achieves 88.36% F1; gazetteer alone adds ~10–15 F1 points
 over generic spaCy NER on CTI text).

Index file: pipeline/data/gazetteer.json  (~194 KB, rebuilt by scripts/build_indexes.py)

Speed:
  The default path uses Aho-Corasick (pyahocorasick) for O(text_len) multi-pattern
  search — ~50× faster than the previous regex approach for a 1 792-entry gazetteer
  on 100k-char documents.  Falls back to the regex path if pyahocorasick is not
  installed (pip install pyahocorasick).
"""
from __future__ import annotations

import re
import json
import functools
from pathlib import Path

from models.schemas import RawEntity, EntityType

# Initialize logging
from api.logging_config import get_logger
logger = get_logger(__name__)

_INDEX_PATH = Path(__file__).parent / "data" / "gazetteer.json"

# Names shorter than this threshold are skipped (too ambiguous for word-boundary matching)
_MIN_NAME_LEN = 4

# ── Optional Aho-Corasick dependency ─────────────────────────────────────────

try:
    import ahocorasick as _ac
    _AHO_AVAILABLE = True
except ImportError:
    _ac = None          # type: ignore[assignment]
    _AHO_AVAILABLE = False


# ── Gazetteer loading ─────────────────────────────────────────────────────────

@functools.lru_cache(maxsize=1)
def _load() -> list[dict]:
    """
    Loads the gazetteer index once and caches it.
    Entries are pre-sorted longest-first so 'Lazarus Group' matches before 'Lazarus'.
    """
    if not _INDEX_PATH.exists():
        logger.warning("gazetteer.json not found — skipping gazetteer NER. Run: python scripts/build_indexes.py")
        return []
    try:
        return json.loads(_INDEX_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error(f"Could not load gazetteer: {e}")
        return []


# ── Aho-Corasick automaton (built once, cached) ───────────────────────────────

@functools.lru_cache(maxsize=1)
def _build_automaton():
    """
    Build an Aho-Corasick automaton from the gazetteer name keys.

    Each automaton node stores a *list* of gazetteer entries that share the
    same lowercase match key (multiple aliases can map to the same string, e.g.
    both "lazarus" and "apt38" resolve to different canonicals).

    Returns None if pyahocorasick is not installed.
    """
    if not _AHO_AVAILABLE:
        return None

    entries = _load()
    if not entries:
        return None

    A = _ac.Automaton()
    for entry in entries:
        name_key = entry["name"]            # lowercase match string
        if len(name_key) < _MIN_NAME_LEN:
            continue
        if name_key in A:
            A.get(name_key).append(entry)
        else:
            A.add_word(name_key, [entry])

    A.make_automaton()
    return A


# ── Public API ────────────────────────────────────────────────────────────────

def match_gazetteer(text: str) -> list[RawEntity]:
    """
    Scan *text* for known malware families, tools, and APT group names.

    Uses Aho-Corasick if available (O(text_len + matches)); falls back to the
    regex approach (O(N × text_len)) when pyahocorasick is not installed.

    Returns one RawEntity per unique canonical name found.  Longer names are
    matched first to prevent 'Lazarus' from shadowing 'Lazarus Group'.
    Spans already claimed by a longer match are not re-matched.

    Confidence:
      0.92 — exact canonical name match
      0.88 — alias match (non-canonical name)
    """
    automaton = _build_automaton()
    if automaton is not None:
        return _match_aho(text, automaton)
    return _match_regex(text)


def _is_word_char(ch: str) -> bool:
    """Return True for characters that cannot border a standalone entity name."""
    return ch.isalnum() or ch == '-'


def _match_aho(text: str, automaton) -> list[RawEntity]:
    """
    Aho-Corasick path — O(text_len + match_count).

    The automaton finds all keyword occurrences in one pass; we then verify
    word boundaries and apply longest-match-wins span claiming.
    """
    text_lower = text.lower()
    text_len   = len(text_lower)

    # Collect all candidates (may include overlapping shorter names)
    # Format: (start, end_exclusive, entry, name_len)
    candidates: list[tuple[int, int, dict, int]] = []

    for end_idx, entry_list in automaton.iter(text_lower):
        for entry in entry_list:
            name_key = entry["name"]
            name_len = len(name_key)
            start    = end_idx - name_len + 1
            end      = end_idx + 1          # exclusive

            # Word-boundary check — same semantics as the regex (?<![a-zA-Z0-9\-])
            before_ok = (start == 0 or not _is_word_char(text_lower[start - 1]))
            after_ok  = (end >= text_len   or not _is_word_char(text_lower[end]))
            if not before_ok or not after_ok:
                continue

            candidates.append((start, end, entry, name_len))

    # Longest match first (same as the pre-sorted regex path)
    candidates.sort(key=lambda x: (-x[3], x[0]))

    # Span claiming — identical logic to the regex version
    seen_canonicals: set[str] = set()
    claimed: list[tuple[int, int]] = []
    results: list[RawEntity] = []

    for start, end, entry, _ in candidates:
        canonical       = entry["canonical"]
        canonical_lower = canonical.lower()

        if canonical_lower in seen_canonicals:
            continue
        if any(s <= start < e2 or s < end <= e2 for s, e2 in claimed):
            continue

        claimed.append((start, end))
        seen_canonicals.add(canonical_lower)

        ctx_start = max(0, start - 60)
        ctx_end   = min(len(text), end + 60)
        context   = text[ctx_start:ctx_end].strip()

        is_alias   = entry["name"] != canonical_lower
        confidence = 0.88 if is_alias else 0.92

        try:
            etype = EntityType(entry["entity_type"])
        except ValueError:
            continue

        results.append(RawEntity(
            value=canonical,
            entity_type=etype,
            context=context,
            confidence=confidence,
            mitre_id=entry.get("mitre_id"),
            source="gazetteer",
        ))

    return results


def _match_regex(text: str) -> list[RawEntity]:
    """
    Regex fallback path — O(N × text_len).  Used when pyahocorasick is absent.
    Semantically identical to the original implementation.
    """
    entries = _load()
    if not entries:
        return []

    text_lower = text.lower()
    results: list[RawEntity] = []
    seen_canonicals: set[str] = set()
    claimed: list[tuple[int, int]] = []

    for entry in entries:
        name_key  = entry["name"]
        canonical = entry["canonical"]
        etype_str = entry["entity_type"]
        mitre_id  = entry.get("mitre_id")

        canonical_lower = canonical.lower()
        if canonical_lower in seen_canonicals:
            continue
        if len(name_key) < _MIN_NAME_LEN:
            continue

        pattern = r'(?<![a-zA-Z0-9\-])' + re.escape(name_key) + r'(?![a-zA-Z0-9\-])'
        for m in re.finditer(pattern, text_lower):
            start, end = m.start(), m.end()
            if any(s <= start < e2 or s < end <= e2 for s, e2 in claimed):
                continue
            claimed.append((start, end))
            seen_canonicals.add(canonical_lower)

            ctx_start = max(0, start - 60)
            ctx_end   = min(len(text), end + 60)
            context   = text[ctx_start:ctx_end].strip()

            is_alias   = name_key != canonical_lower
            confidence = 0.88 if is_alias else 0.92

            try:
                etype = EntityType(etype_str)
            except ValueError:
                continue

            results.append(RawEntity(
                value=canonical,
                entity_type=etype,
                context=context,
                confidence=confidence,
                mitre_id=mitre_id,
                source="gazetteer",
            ))
            break

    return results


def available() -> bool:
    """Return True if the gazetteer index file exists."""
    return _INDEX_PATH.exists()
