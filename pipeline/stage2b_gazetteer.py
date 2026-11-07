"""
Stage 2b — Gazetteer-based Named Entity Recognition.

Scans a document for 1,827 name variants — 1,114 unique malware families,
offensive tools and APT groups — sourced from the MITRE ATT&CK Enterprise,
Mobile, and ICS STIX bundles (all canonical names plus their aliases).

This deterministic approach has near-zero hallucination risk for *known* threat
actors and malware families, and complements:
  • Stage 2  — regex IoC extraction (IPs, hashes, domains, CVEs)
  • Stage 3  — LLM enrichment (relationships, novel/unnamed entities, campaign)

Paper basis: Arazzi et al. 2023 §8 — Dictionary-template-enhanced NER
(Dict+BiLSTM+CRF achieves 88.36% F1; gazetteer alone adds ~10–15 F1 points
 over generic spaCy NER on CTI text).

Index file: pipeline/data/gazetteer.json  (~275 KB, rebuilt by scripts/build_indexes.py)

Speed:
  The default path uses Aho-Corasick (pyahocorasick) for O(text_len) multi-pattern
  search — ~50× faster than the previous regex approach at this gazetteer size
  on 100k-char documents.  Falls back to the regex path if pyahocorasick is not
  installed (pip install pyahocorasick).
"""
from __future__ import annotations

import bisect
import functools
import json
import re
from collections.abc import Callable
from pathlib import Path

from models.schemas import EntityType, RawEntity
from pipeline import attack_data, gazetteer_policy
from pipeline.env_flags import env_bool
from pipeline.gazetteer_policy import Judgement
from pipeline.overrides import drop_denied, promoted_entries

_SKIP_HEAVY = env_bool("SKIP_HEAVY_MODELS")

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
    Loads the gazetteer index once and caches it, plus every term the analysts
    promoted (ADR-0052, `entity_overrides` rows with action=promote).
    Entries are sorted longest-first so 'Lazarus Group' matches before 'Lazarus'.
    """
    path = attack_data.resolve(_INDEX_PATH)
    if not path.exists():
        logger.warning("gazetteer.json not found — skipping gazetteer NER. Run: python scripts/build_indexes.py")
        return []
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error(f"Could not load gazetteer: {e}")
        return []
    promoted = promoted_entries()
    if promoted:
        entries = entries + promoted
        entries.sort(key=lambda e: -len(e["name"]))
    return entries


# ── Aho-Corasick automaton (built once, cached) ───────────────────────────────

@functools.lru_cache(maxsize=1)
def _build_automaton():
    """
    Build an Aho-Corasick automaton from the gazetteer name keys.
    Returns None when SKIP_HEAVY_MODELS=1 or pyahocorasick is unavailable.

    Each automaton node stores a *list* of gazetteer entries that share the
    same lowercase match key (multiple aliases can map to the same string, e.g.
    both "lazarus" and "apt38" resolve to different canonicals).

    Returns None if pyahocorasick is not installed.
    """
    if _SKIP_HEAVY or not _AHO_AVAILABLE:
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
    """What Stage 2b emits; see match_gazetteer_traced."""
    return match_gazetteer_traced(text)[0]


@functools.lru_cache(maxsize=1)
def _policy_index() -> gazetteer_policy.Index:
    return gazetteer_policy.build_index(_load())


_Judge = Callable[[dict, int, int], Judgement | None]


def _trace_item(entry: dict, text: str, start: int, end: int, verdict: Judgement) -> dict:
    return {"form": entry["name"], "surface": text[start:end], "start": start, "end": end,
            "canonical": entry["canonical"], "entity_type": entry["entity_type"],
            "mitre_id": entry.get("mitre_id"), "decision": verdict.decision,
            "outcome": verdict.outcome, "reason": verdict.reason, "rule": verdict.rule}


def match_gazetteer_traced(text: str, policy_mode: str | None = None) -> tuple[list[RawEntity], list[dict]]:
    """
    Scan *text* for known malware families, tools, and APT group names, and
    say what the ordinary-word policy makes of each occurrence it concerns
    (pipeline/gazetteer_policy.py; `policy_mode` overrides GAZETTEER_POLICY).

    Uses Aho-Corasick if available (O(text_len + matches)); falls back to the
    regex approach (O(N × text_len)) when pyahocorasick is not installed.

    Returns one RawEntity per unique canonical name found.  Longer names are
    matched first to prevent 'Lazarus' from shadowing 'Lazarus Group'.
    Spans already claimed by a longer match are not re-matched.

    Confidence:
      0.92 — exact canonical name match
      0.88 — alias match (non-canonical name)

    The trace lists occurrences the policy has an opinion on.  Shadow mode
    emits exactly what "off" would and traces the emitted occurrences; apply
    mode withholds every occurrence the policy does not resolve, before it
    claims a span or a canonical name (so a later, qualifying mention of the
    same name is still found), and traces each one it withheld or let through.
    An ambiguous occurrence is traced once per identity it could be.
    """
    pmode = policy_mode or gazetteer_policy.mode()
    index = _policy_index() if pmode != "off" else None

    def judge(entry: dict, start: int, end: int) -> Judgement | None:
        if index is None or gazetteer_policy.is_promoted(entry):
            return None       # an analyst's promotion matches as before
        occurrence = gazetteer_policy.Occurrence(text, start, end, entry["name"],
                                                 gazetteer_policy.identity(entry))
        return gazetteer_policy.judge(occurrence, index)

    trace: list[dict] = []
    use = judge if pmode != "off" else None
    automaton = _build_automaton()
    if automaton is not None:
        found = _match_aho(text, automaton, use, pmode == "apply", trace)
    else:
        found = _match_regex(text, use, pmode == "apply", trace)
    return drop_denied(found), trace


def _is_word_char(ch: str) -> bool:
    """Return True for characters that cannot border a standalone entity name."""
    return ch.isalnum() or ch == '-'


def _lower_index_map(text: str) -> list[int]:
    """Map each index of `text.lower()` to the index of the character in `text`
    that produced it.  `str.lower()` is NOT length-preserving (U+0130 lowercases
    to two code points), so a match offset in the lowered text does not name the
    same offset in the original text -- spans and context must go through this
    map."""
    index_map: list[int] = []
    for i, ch in enumerate(text):
        index_map.extend([i] * len(ch.lower()))
    return index_map


class _Claims:
    """The spans already claimed, kept sorted so a lookup is O(log n).

    Claims never overlap (a candidate that overlaps one is refused, and the
    candidates come longest first), except an EXACTLY equal span claimed by a
    different entity_type: homonyms such as Machete G0095 group / S0409
    malware.  Sorted by start, the ends are then sorted too, so the claims that
    can overlap [start, end) are the ones just before the insertion point of
    `end`.  A list scanned for every candidate was quadratic in the number of
    repeated mentions (#351), which #318 claims one span each.
    """

    __slots__ = ("_spans",)

    def __init__(self) -> None:
        self._spans: list[tuple[int, int, str]] = []

    def blocks(self, start: int, end: int, entity_type: str) -> bool:
        """True when [start, end) overlaps a claimed span.  An EXACTLY equal
        span claimed by a different entity_type does not block; any other
        overlap does."""
        i = bisect.bisect_left(self._spans, (end,)) - 1
        while i >= 0:
            s, e2, t = self._spans[i]
            if e2 <= start:
                return False
            if not (s == start and e2 == end and t != entity_type):
                return True
            i -= 1
        return False

    def add(self, start: int, end: int, entity_type: str) -> None:
        bisect.insort(self._spans, (start, end, entity_type))


def _match_aho(text: str, automaton, judge: _Judge | None = None, apply: bool = False,
               trace: list[dict] | None = None) -> list[RawEntity]:
    """
    Aho-Corasick path — O(text_len + match_count).

    The automaton finds all keyword occurrences in one pass; we then verify
    word boundaries and apply longest-match-wins span claiming.
    """
    text_lower = text.lower()
    index_map  = _lower_index_map(text)

    # Collect all candidates (may include overlapping shorter names)
    # Format: (start, end_exclusive, entry, name_len) — in ORIGINAL text coords
    candidates: list[tuple[int, int, dict, int]] = []

    for end_idx, entry_list in automaton.iter(text_lower):
        for entry in entry_list:
            name_key = entry["name"]
            name_len = len(name_key)
            start    = end_idx - name_len + 1
            end      = end_idx + 1          # exclusive, lowered coords
            if end > len(index_map):
                continue
            # lower() is not length-preserving: convert to original coords.
            o_start = index_map[start]
            o_end   = index_map[end - 1] + 1

            # Word-boundary check — same semantics as the regex, on the
            # original text (the lowered char can differ, e.g. U+0130).
            before_ok = (o_start == 0 or not _is_word_char(text[o_start - 1]))
            after_ok  = (o_end >= len(text) or not _is_word_char(text[o_end]))
            if not before_ok or not after_ok:
                continue

            candidates.append((o_start, o_end, entry, o_end - o_start))

    # Longest match first (same as the pre-sorted regex path)
    candidates.sort(key=lambda x: (-x[3], x[0]))

    # Span claiming — identical logic to the regex version
    seen_canonicals: set[tuple[str, str]] = set()
    claimed = _Claims()
    results: list[RawEntity] = []

    for start, end, entry, _ in candidates:
        canonical       = entry["canonical"]
        canonical_lower = canonical.lower()
        # Identity is (canonical, entity_type): ATT&CK reuses names across
        # object kinds (Machete G0095 group vs S0409 malware, ...).
        seen_key        = (canonical_lower, entry["entity_type"])

        if claimed.blocks(start, end, entry["entity_type"]):
            continue
        if seen_key in seen_canonicals:
            # Already emitted once: still claim the span -- a repeated mention
            # must block shorter aliases of OTHER entries inside it from
            # matching as false positives -- but trace and emit nothing.
            claimed.add(start, end, entry["entity_type"])
            continue
        verdict = judge(entry, start, end) if judge else None
        if verdict is not None and verdict.withheld and apply:
            if trace is not None:
                trace.append(_trace_item(entry, text, start, end, verdict))
            continue          # claims neither the span nor the name
        if verdict is not None and (verdict.decision or verdict.withheld) and trace is not None:
            trace.append(_trace_item(entry, text, start, end, verdict))

        claimed.add(start, end, entry["entity_type"])
        seen_canonicals.add(seen_key)

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


def _match_regex(text: str, judge: _Judge | None = None, apply: bool = False,
                 trace: list[dict] | None = None) -> list[RawEntity]:
    """
    Regex fallback path — O(N × text_len).  Used when pyahocorasick is absent.
    Semantically identical to the original implementation.
    """
    entries = _load()
    if not entries:
        return []

    text_lower = text.lower()
    index_map  = _lower_index_map(text)
    results: list[RawEntity] = []
    seen_canonicals: set[tuple[str, str]] = set()
    claimed = _Claims()

    for entry in entries:
        name_key  = entry["name"]
        canonical = entry["canonical"]
        etype_str = entry["entity_type"]
        mitre_id  = entry.get("mitre_id")

        canonical_lower = canonical.lower()
        # Identity is (canonical, entity_type): ATT&CK reuses names across
        # object kinds (Machete G0095 group vs S0409 malware, ...).
        seen_key = (canonical_lower, etype_str)
        if len(name_key) < _MIN_NAME_LEN:
            continue

        # Word-boundary lookarounds — kept Unicode-consistent with the
        # Aho-Corasick path's _is_word_char (alnum-or-hyphen).  An ASCII-only
        # class ([a-zA-Z0-9]) would diverge from the automaton near accented
        # letters: e.g. "Café" before a name would be a boundary under ASCII but
        # not under isalnum(), so the two paths returned different matches.
        # [^\W_] = Unicode word char minus underscore (i.e. letters/digits); the
        # extra (?<!-)/(?!-) clauses add hyphen, matching _is_word_char exactly.
        pattern = (
            r'(?<![^\W_])(?<!-)'
            + re.escape(name_key)
            + r'(?![^\W_])(?!-)'
        )
        for m in re.finditer(pattern, text_lower):
            if m.end() > len(index_map):
                continue
            # Convert the lowered-text offsets to original-text coordinates
            # (lower() is not length-preserving, e.g. U+0130).
            start = index_map[m.start()]
            end   = index_map[m.end() - 1] + 1
            # The lookarounds ran on the lowered text, where U+0130 becomes
            # "i" + a combining dot that is not a word char: check the
            # boundaries again on the original text, as the Aho path does (#350).
            if (start > 0 and _is_word_char(text[start - 1])) or \
                    (end < len(text) and _is_word_char(text[end])):
                continue
            if claimed.blocks(start, end, etype_str):
                continue
            if seen_key in seen_canonicals:
                # Already emitted once: still claim the span -- a repeated
                # mention must block shorter aliases of OTHER entries inside
                # it -- but trace and emit nothing.
                claimed.add(start, end, etype_str)
                continue
            verdict = judge(entry, start, end) if judge else None
            if verdict is not None and verdict.withheld and apply:
                if trace is not None:
                    trace.append(_trace_item(entry, text, start, end, verdict))
                continue      # the next occurrence may qualify
            if verdict is not None and (verdict.decision or verdict.withheld) and trace is not None:
                trace.append(_trace_item(entry, text, start, end, verdict))
            claimed.add(start, end, etype_str)
            seen_canonicals.add(seen_key)

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

    return results


def available() -> bool:
    """Return True if the gazetteer index file exists."""
    return attack_data.resolve(_INDEX_PATH).exists()


# ---------------------------------------------------------------------------
# ExtractionStage class wrapper (pipeline.base)
# ---------------------------------------------------------------------------

from pipeline.base import BaseExtractionStage  # noqa: E402


class GazetteerStage(BaseExtractionStage):
    """Stage-2b MITRE gazetteer as an ExtractionStage implementation."""

    name = "gazetteer"

    def __init__(self, config=None) -> None:
        pass

    def available(self) -> bool:
        return attack_data.resolve(_INDEX_PATH).exists() and not _SKIP_HEAVY

    def extract(self, text: str) -> list[RawEntity]:
        return match_gazetteer(text)
