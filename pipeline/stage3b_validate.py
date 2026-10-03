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

# Initialize logging
from api.logging_config import get_logger
from pipeline.stage3_llm import LLMEnrichmentResult

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

# Fuzzy matching is for what it was written for — a multi-word name that OCR
# or a line break split or hyphenated ("Cobalt- Strike", "CobaltStrike") —
# and for nothing else.  A fuzzy window of the name's own width accepts the
# *neighbouring* identifier: UNC4763 or UNC4737 for UNC4736, APT2 for APT28,
# BlackBasta for BlackCat (ratio 80 against the 75 threshold) — measured by
# the October 2026 audit — and a wrong attribution is the costliest error a
# CTI extractor can make.  So a name with a digit, a name under 8 characters
# and a single-token name are matched exactly, on word boundaries, or not at
# all; a long name's digits (none, by construction) must equal the window's.
_FUZZY_MIN_LENGTH = 8
_DIGITS = re.compile(r"\d+")
_TOKEN_SPLIT = re.compile(r"[\s\-_/]+")


def _fuzzy_allowed(name_lower: str) -> bool:
    """True for a long, multi-token name without digits."""
    if len(name_lower) < _FUZZY_MIN_LENGTH or _DIGITS.search(name_lower):
        return False
    return len([t for t in _TOKEN_SPLIT.split(name_lower) if t]) >= 2


def _threshold_for(name: str) -> int:
    """Returns the appropriate fuzzy similarity threshold based on name length."""
    n = len(name)
    if n <= 5:
        return _THRESHOLD_SHORT    # e.g. FIN7, APT1 — exact only since the audit
    if n <= 9:
        return _THRESHOLD_MEDIUM   # e.g. Cobalt-S (hyphenated 8–9 char names)
    return _THRESHOLD_LONG         # e.g. Cobalt Strike, Mustang Panda


def _name_in_text(name: str, text: str, threshold: int | None = None) -> bool:
    """
    Returns True if `name` can be found in `text` with sufficient similarity.

    Strategy:
    1. Exact match on word boundaries, whatever the length: "APT29" is not
       in "APT290", "FIN" is not in "financial".
    2. For a multi-word name without digits only: a sliding-window fuzzy
       match of the same character width (OCR artefacts, hyphenation, line
       breaks), with the threshold scaled by length and the window's digits
       required to equal the name's.  Identifiers (UNC4736, APT28, TA505,
       Storm-0558), short names and single tokens never get this step.

    Args:
        name:      entity name to search for
        text:      source chunk text
        threshold: override similarity threshold (0–100); auto-selected if None
    """
    if not name or len(name) < _MIN_NAME_LENGTH:
        return True   # too short to meaningfully reject

    name_lower = name.lower().strip()
    text_lower = text.lower()

    pattern = r'(?<![a-z0-9])' + re.escape(name_lower) + r'(?![a-z0-9])'
    if re.search(pattern, text_lower):
        return True

    if not _RAPIDFUZZ_AVAILABLE or not _fuzzy_allowed(name_lower):
        return False

    effective_threshold = threshold if threshold is not None else _threshold_for(name_lower)

    # Sliding window fuzzy match, the name's width, aligned on words: the
    # window starts where a word starts and runs to the end of the word it
    # would otherwise cut.  A window free to start mid-word slid past a
    # digit ("o Mustang Pan" for "Mustang Pand4") and defeated the digit check.
    w = len(name_lower)
    n = len(text_lower)
    if w > n:
        return False

    name_digits = _DIGITS.findall(name_lower)
    for i in range(n - w + 1):
        if i > 0 and text_lower[i - 1].isalnum():
            continue                       # not the start of a word
        j = i + w
        while j < n and text_lower[j].isalnum():
            j += 1                         # finish the word the window cut
        window = text_lower[i:j]
        if _DIGITS.findall(window) != name_digits:
            continue
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
