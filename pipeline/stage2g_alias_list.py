"""
Stage 2g — Alias-list extraction (regex, deterministic).

Motivation (found on a real report, 2026-09-20): a sentence like

    "Static Tundra (aka Berserk Bear, Ghost Blizzard, Sandworm Team,
    Seashell Blizzard)"

names five distinct threat-actor aliases in one breath. Neither the MITRE
gazetteer (Stage 2b), CyNER (Stage 2d), nor GLiNER (Stage 2e) split this kind
of construct — each treats it as prose around whichever single name it
already knows, so only the LLM at Stage 3 (which sees the whole sentence,
not just a fixed-vocabulary lookup) was recovering the other aliases, and
only on the chunks it happened to process thoroughly.

This stage complements the dictionary/model-based stages with a fifth,
purely syntactic one: it looks for the explicit "X (aka Y, Z, W)" / "X, also
known as Y, Z and W" construct itself, regardless of whether any of the
named aliases are in any gazetteer. It runs deterministically, with no
model and no network call, so it costs nothing extra and never blocks on
GPU/model availability the way Stage 2d/2e do.

Scope (deliberate): every entity this stage emits — the anchor and every
alias — is typed THREAT_ACTOR. This is the overwhelmingly dominant use of
the "aka" construct in CTI reporting (rebrand/vendor-naming convergence:
Microsoft "Weather" names, CrowdStrike "Animal" names, Secureworks names,
etc. for the same intrusion set); malware aliasing is comparatively rare and
already partly handled by CyNER's own comma-splitting (ADR-0050 step 1) when
it appears inside one recognised span. A future extension could infer
MALWARE from context cues, but that was not observed often enough in this
corpus to justify the added false-positive risk yet.

Confidence is deliberately below the other stages' typical values (0.55) —
this is a syntactic heuristic with no learned model backing it, so it is
meant to land in the analyst's review queue rather than auto-promote. The
cutoff is registered with the same ADR-0051 calibration mechanism as every
other stage, so real accept/reject decisions can raise or lower it over
time exactly like GLiNER's or CyNER's thresholds.
"""
from __future__ import annotations

from models.schemas import EntityType, RawEntity
from pipeline.overrides import drop_denied
from pipeline.regex_safety import compile_pattern
from pipeline.thresholds import get_threshold

# ── Patterns ──────────────────────────────────────────────────────────────────

# A Title-Case phrase of 1-4 words -- the shape of a group/actor name.
# Allows apostrophes, hyphens, ampersands and periods so "U.S." / "Kimsuky-
# affiliated" style tokens don't break the match.
_WORD = r"[A-Z][\w'&.-]*"
_ANCHOR = rf"(?:{_WORD}(?:[ \t]+{_WORD}){{0,3}})"

# Marker phrase, matched case-insensitively via a scoped inline flag so it
# does not loosen the Title-Case requirement on _WORD above.
_MARKER = r"(?i:also\s+known\s+as|a\.k\.a\.|aka|tracked\s+as|formerly\s+known\s+as|formerly)"

# "Static Tundra (aka Berserk Bear, Ghost Blizzard, ...)"
_PAREN_PATTERN = compile_pattern(
    rf"(?P<anchor>{_ANCHOR})\s*\(\s*{_MARKER}\s*[:,]?\s*(?P<aliases>[^)]{{3,200}})\)"
)

# "Static Tundra, also known as Berserk Bear, Ghost Blizzard and Sandworm."
# The alias run is capped at 8 repeats -- a generous bound for a real alias
# list that also keeps the match width fixed rather than unbounded.
_INLINE_PATTERN = compile_pattern(
    rf"(?P<anchor>{_ANCHOR}),?\s+{_MARKER}\s+"
    rf"(?P<aliases>{_ANCHOR}(?:\s*(?:,|/|\band\b|\bor\b)\s*{_ANCHOR}){{0,8}})"
)

_ALIAS_SPLIT_RE = compile_pattern(r",|/|\band\b|\bor\b")

# Leftover marker fragments that can survive splitting on a malformed match
# (e.g. the marker phrase itself captured as part of the alias run).
_STOPWORDS = frozenset({
    "aka", "a.k.a", "a.k.a.", "also", "known", "as", "tracked", "formerly",
    "the", "and", "or",
})

_DEFAULT_CONFIDENCE = 0.55


def _clean_alias(raw: str) -> str | None:
    value = raw.strip(" \t\n\r.,;:'\"()")
    if len(value) < 3:
        return None
    if value.lower() in _STOPWORDS:
        return None
    if not value[0].isupper():
        return None
    return value


def _split_aliases(raw: str) -> list[str]:
    out: list[str] = []
    for part in _ALIAS_SPLIT_RE.split(raw):
        cleaned = _clean_alias(part)
        if cleaned is not None:
            out.append(cleaned)
    return out


def extract_alias_list_entities(text: str) -> list[RawEntity]:
    """
    Scan *text* for explicit "X (aka Y, Z)" / "X, also known as Y and Z"
    constructs and emit one THREAT_ACTOR RawEntity per name mentioned
    (anchor included), deduplicated by value.

    Returns [] if the text contains no such construct — this stage never
    raises and never needs a model, so it is always `available()`.
    """
    cutoff = get_threshold("alias_list", EntityType.THREAT_ACTOR.value, _DEFAULT_CONFIDENCE)
    if _DEFAULT_CONFIDENCE < cutoff:
        return []

    seen: set[str] = set()
    results: list[RawEntity] = []

    for pattern in (_PAREN_PATTERN, _INLINE_PATTERN):
        for m in pattern.finditer(text):
            anchor = _clean_alias(m.group("anchor"))
            aliases = _split_aliases(m.group("aliases"))
            if anchor is None or not aliases:
                continue

            ctx_start = max(0, m.start() - 30)
            ctx_end = min(len(text), m.end() + 30)
            context = text[ctx_start:ctx_end].strip()

            for name in [anchor] + aliases:
                key = name.lower()
                if key in seen:
                    continue
                seen.add(key)
                results.append(RawEntity(
                    value=name,
                    entity_type=EntityType.THREAT_ACTOR,
                    context=context[:200],
                    confidence=_DEFAULT_CONFIDENCE,
                    source="alias_list",
                ))

    return drop_denied(results)


def available() -> bool:
    """Always available — pure regex, no model, no network."""
    return True


# ---------------------------------------------------------------------------
# ExtractionStage class wrapper — consumed by pipeline.registry
# ---------------------------------------------------------------------------

from pipeline.base import BaseExtractionStage  # noqa: E402


class AliasListStage(BaseExtractionStage):
    """Stage-2g alias-list extractor as an ExtractionStage implementation."""

    name = "alias_list"

    def __init__(self, config=None) -> None:
        pass

    def available(self) -> bool:
        return True

    def extract(self, text: str) -> list[RawEntity]:
        return extract_alias_list_entities(text)
