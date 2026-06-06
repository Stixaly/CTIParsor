"""
Stage 3b — Post-LLM hallucination filter.

Problem: the LLM sometimes returns entity names (malware families, threat actors,
tool names, campaign names) that do not appear in the source text at all.  This
stage verifies each returned name against the chunk that produced it using a fast
sliding-window fuzzy match (rapidfuzz).

Why fuzzy (not exact)?
  - OCR errors: "APT29" → "APT2 9"
  - Hyphenation: "CobaltStrike" → "Cobalt Strike"
  - Minor spelling variants across aliases

What is intentionally NOT filtered:
  - TTPs — technique names are frequently paraphrased; a valid TTP may not share
    exact tokens with the source text.  Validation is done later via MITRE ATT&CK
    normalization (stage3c).
  - Relationships — validated transitively (both endpoints are already filtered).
  - Sectors / countries — short generic words match too many things; keep as-is.
  - IoC associations — IoC values are already validated by regex extraction;
    malware names in ioc_associations are checked via the malware_families pass.
"""

from __future__ import annotations

import re
from pipeline.stage3_llm import LLMEnrichmentResult

# Initialize logging
from api.logging_config import get_logger
logger = get_logger(__name__)

try:
    from rapidfuzz import fuzz
    _RAPIDFUZZ_AVAILABLE = True
except ImportError:
    _RAPIDFUZZ_AVAILABLE = False
    logger.warning("rapidfuzz not installed — hallucination filter disabled. Run: pip install rapidfuzz")


# Similarity thresholds by name length.
# Short names (≤5 chars) get a high bar because they false-positive easily
# ("FIN7" → "fina" in "financial").  Longer names can tolerate more fuzz.
_THRESHOLD_SHORT  = 92   # names 3–5 chars (e.g. FIN7, APT, UNC)
_THRESHOLD_MEDIUM = 80   # names 6–9 chars (e.g. LummaC2, APT29, Lazarus)
_THRESHOLD_LONG   = 75   # names ≥10 chars (e.g. Cobalt Strike, SilverFish)

# Names shorter than this are never fuzzy-matched (exact only).
_MIN_NAME_LENGTH = 3


def _threshold_for(name: str) -> int:
    """Returns the appropriate fuzzy similarity threshold based on name length."""
    n = len(name)
    if n <= 5:
        return _THRESHOLD_SHORT    # e.g. FIN7, APT1
    if n <= 9:
        return _THRESHOLD_MEDIUM   # e.g. APT29, LummaC2
    return _THRESHOLD_LONG         # e.g. Cobalt Strike, SilverFish


def _name_in_text(name: str, text: str, threshold: int | None = None) -> bool:
    """
    Returns True if `name` can be found in `text` with sufficient similarity.

    Strategy:
    1. Exact substring match (fast path — covers most cases).
    2. Sliding window fuzzy match of the same character width as the name
       (catches OCR artifacts, hyphenation differences, minor typos).
       Threshold scales with name length to avoid short-name false positives.

    Args:
        name:      entity name to search for
        text:      source chunk text
        threshold: override similarity threshold (0–100); auto-selected if None
    """
    if not name or len(name) < _MIN_NAME_LENGTH:
        return True   # too short to meaningfully reject

    name_lower = name.lower().strip()
    text_lower = text.lower()

    # For short names (≤5 chars), use word-boundary regex to avoid false positives
    # like "FIN" matching inside "financial", or "APT" in "chapter".
    if len(name_lower) <= 5:
        pattern = r'(?<![a-z0-9])' + re.escape(name_lower) + r'(?![a-z0-9])'
        if re.search(pattern, text_lower):
            return True
    else:
        # Longer names: simple substring is safe and fast
        if name_lower in text_lower:
            return True

    if not _RAPIDFUZZ_AVAILABLE:
        return False   # without rapidfuzz, only exact matching is available

    effective_threshold = threshold if threshold is not None else _threshold_for(name_lower)

    # Sliding window fuzzy match (same width as the name)
    w = len(name_lower)
    if w > len(text_lower):
        return False

    for i in range(len(text_lower) - w + 1):
        window = text_lower[i : i + w]
        if fuzz.ratio(name_lower, window) >= effective_threshold:
            return True

    return False


def validate_llm_result(
    result: LLMEnrichmentResult,
    chunk_text: str,
    doc_context: str = "",
    ner_allow_list: set[str] | None = None,
) -> LLMEnrichmentResult:
    """
    Removes entity names from an LLM result that cannot be located in the
    source text.  Returns a new LLMEnrichmentResult with only verified entries.

    Two-tier search:
      1. chunk_text — the raw 3 000-char chunk the LLM enriched.
      2. doc_context — the document-level entity summary injected as a preamble
         into every LLM call (built from gazetteer + CyNER + GLiNER, covers the
         full document).  Entities present there are real by construction:
         the LLM was explicitly told about them and correctly recalled the name.

    Without tier-2, multi-chunk reports drop real entities whose names only
    appear in other chunks (e.g. a threat-actor named in the intro that is only
    referenced obliquely in the IoC appendix chunk being processed).

    Args:
        result:      raw output from enrich_chunk()
        chunk_text:  the source chunk that produced this result
        doc_context: document-level entity summary (pass-through from enrich_chunk)

    Returns:
        Filtered LLMEnrichmentResult
    """
    def _keep(name: str) -> bool:
        # Tier 0 — O(1) set lookup: confirmed by high-precision NER (gazetteer /
        # CyNER / GLiNER / semantic TTP) across the full document.  If it's in
        # the allow-list it is definitely real — skip the expensive fuzzy scan.
        if ner_allow_list and name.lower() in ner_allow_list:
            return True
        # Tier 1 — fuzzy match against this chunk's text
        if _name_in_text(name, chunk_text):
            return True
        # Tier 2 — present in the document-level context the LLM received?
        # Entities in the context were found by high-precision NER across the
        # whole document, so they are definitely real even if not in this chunk.
        if doc_context and _name_in_text(name, doc_context):
            return True
        logger.debug(f"Dropped hallucinated entity: '{name}'")
        return False

    filtered_actors  = [a for a in result.threat_actors   if _keep(a)]
    filtered_malware = [m for m in result.malware_families if _keep(m)]
    filtered_tools   = [t for t in result.tools            if _keep(t)]

    # Campaign names need special treatment: the LLM often *expands* a short
    # name found in the text into a longer compound descriptor.
    # Example: source has "GREYVIBE", LLM outputs "GREYVIBE Ukraine Targeting Campaign".
    # The full expanded string never appears verbatim in any chunk, so _keep()
    # would always drop it — but it's a real name constructed from real context.
    #
    # Fallback: if _keep() fails on the full name, accept the campaign if ANY
    # significant word (≥ 5 chars, not a generic noun) from the name appears
    # in the chunk text or doc_context.  This preserves real names while still
    # blocking pure inventions that share no vocabulary with the source.
    _CAMPAIGN_STOPWORDS = frozenset({
        "campaign", "attack", "operation", "activity", "threat", "targeting",
        "based", "using", "group", "actor", "cluster", "intrusion",
    })

    def _keep_campaign(name: str) -> bool:
        if _keep(name):
            return True
        # Word-level fallback — at least one significant keyword must appear in text
        keywords = [
            w for w in name.split()
            if len(w) >= 5 and w.lower().rstrip(".,;:") not in _CAMPAIGN_STOPWORDS
        ]
        search_corpus = chunk_text + " " + doc_context
        if keywords and any(_name_in_text(kw, search_corpus) for kw in keywords):
            return True
        logger.debug(f"Dropped campaign (no keyword match): '{name}'")
        return False

    campaign = result.campaign_name
    if campaign and not _keep_campaign(campaign):
        campaign = None

    # Build the set of names that were confirmed hallucinations (present in the
    # original LLM output but not found in the source text).  Remove any
    # relationship whose source or target is a confirmed hallucination —
    # keeping them would produce dangling edges in the STIX bundle.
    hallucinated: set[str] = set()
    for name in result.threat_actors:
        if name not in filtered_actors:
            hallucinated.add(name.lower())
    for name in result.malware_families:
        if name not in filtered_malware:
            hallucinated.add(name.lower())
    for name in result.tools:
        if name not in filtered_tools:
            hallucinated.add(name.lower())
    if result.campaign_name and campaign is None:
        hallucinated.add(result.campaign_name.lower())

    filtered_rels = [
        r for r in result.relationships
        if r.source_value.lower() not in hallucinated
        and r.target_value.lower() not in hallucinated
    ]

    return LLMEnrichmentResult(
        threat_actors=filtered_actors,
        malware_families=filtered_malware,
        tools=filtered_tools,
        # TTPs: not filtered here — handled by stage3c MITRE normalization
        ttps=result.ttps,
        relationships=filtered_rels,
        ioc_associations=result.ioc_associations,
        targeted_sectors=result.targeted_sectors,
        targeted_countries=result.targeted_countries,
        campaign_name=campaign,
        course_of_action=result.course_of_action,
    )
