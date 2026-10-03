"""
Stage 3d — Self-Verification of LLM Relationship Claims.

Based on the aCTIon paper (NEC Labs, 2023 — ADR-004 P3-A):
  "Automated CTI Report Analysis Using LLMs"
  Two-stage pipeline: extraction → self-verification.

Problem this solves:
  Stage 3 LLM extracts relationships in a single pass and accepts its own output
  without checking whether each claim is actually supported by the source text.
  In the aCTIon paper benchmark, ~27% of extracted relationships had NO textual
  support (hallucinations from the LLM's training data, not the document).

How it works:
  After enrich_chunk() produces a LLMEnrichmentResult, this module sends a SECOND
  LLM call with:
    • The original text chunk (the whole report for the document-level pass)
    • The numbered list of extracted relationships
  The LLM must quote the EXACT sentence from the text that supports each claim.
  If no such sentence exists, the claim is marked unverified and discarded.
  On the whole report, a second sentence may only say who the first one's
  subject is (see _VERIFY_SYSTEM_DOCUMENT).

Results (aCTIon paper, 204 CTI reports):
  Without verification: ~27% hallucinated relationships
  With verification:    ~8%  hallucinated relationships
  Relationship precision: 73% → 88%

Cost:
  Adds 1 extra LLM call per chunk that has ≥1 relationship extracted.
  In practice: ~1.4× total LLM calls (not 2×), because many chunks produce
  no relationships and are skipped.

Configuration (via .env):
  ENABLE_STIX_VERIFICATION=true   — enable verification (default: false)
  STIX_VERIFY_MIN_RELS=1          — only verify chunks with ≥N relationships
                                    (skip low-yield chunks, default: 1)
  STIX_VERIFY_BATCH_SIZE=40       — claims per verification call

Design note — circular import avoidance:
  stage3_llm.py imports stage3d_verify.py (deferred, inside enrich_chunk).
  stage3d_verify.py receives _call_llm as a parameter rather than importing
  it from stage3_llm.py, avoiding any circular dependency.
"""
from __future__ import annotations

from typing import Callable

# Initialize logging
from api.logging_config import get_logger
from pipeline.env_flags import env_bool, env_int
from pipeline.llm_parse import fit_report, parse_numbered_claims

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_VERIFY_ENABLED = env_bool("ENABLE_STIX_VERIFICATION")
_VERIFY_MIN_RELS = env_int("STIX_VERIFY_MIN_RELS", default=1)
# Claims per verification call.  Each answer carries a quote, so a document-
# level pass with 100+ claims would outgrow the output-token ceiling in one
# call — and a truncated answer keeps every claim unverified.
_VERIFY_BATCH = env_int("STIX_VERIFY_BATCH_SIZE", default=40)


def verify_enabled() -> bool:
    """Return True if self-verification is enabled via ENABLE_STIX_VERIFICATION."""
    return _VERIFY_ENABLED


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_VERIFY_SYSTEM = """\
You are a strict CTI fact-checker.

For each numbered relationship claim, find the EXACT sentence in the provided
text that directly and unambiguously supports it.

Rules:
- Mark verified=true ONLY if a single sentence in the text clearly states
  this relationship (not implied, not paraphrased from training knowledge).
- If the sentence is slightly different from the claim but clearly supports it,
  still mark verified=true and quote the closest sentence.
- If no sentence supports the claim — even loosely — mark verified=false.
- Set quote to null when verified=false.
- Return ONLY valid JSON, no surrounding text or markdown fences.
"""

# The document-level pass (ADR-0057) exists to connect facts stated far apart,
# so a one-sentence rule would reject it wholesale.  Two sentences count only
# when the second just says who the first one's subject is — a chain through
# a third entity stays unsupported.
_VERIFY_SYSTEM_DOCUMENT = """\
You are a strict CTI fact-checker.

The text is a WHOLE report.  For each numbered relationship claim, find the
text that directly and unambiguously supports it.

Rules:
- Mark verified=true when ONE sentence in the text clearly states the
  relationship (not implied, not paraphrased from training knowledge).
- Also mark verified=true when TWO sentences state it together, but only in
  this way: one sentence states the relationship, and the other only says who
  a pronoun, alias or description in it refers to (for example "The group
  deployed X" and, elsewhere, "the group, tracked as APT29, ...").  Quote both
  sentences, joined by " [...] ".
- A chain through a third entity is NOT support: "A uses B" and "B contacts C"
  do not support "A contacts C", nor "A owns C".
- If nothing in the text supports the claim, mark verified=false.
- Set quote to null when verified=false.
- Return ONLY valid JSON, no surrounding text or markdown fences.
"""

_VERIFY_USER_TEMPLATE = """\
Text excerpt:
---
{text}
---

Verify each relationship claim against the text above.
For each claim, find the supporting sentence (exact quote) or mark it unverified.

Claims:
{claims}

Return a JSON array — one object per claim:
[
  {{"n": 1, "verified": true, "quote": "exact sentence from text"}},
  {{"n": 2, "verified": false, "quote": null}},
  ...
]"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_relationships(
    text: str,
    result,                          # LLMEnrichmentResult — avoid import cycle
    llm_fn: Callable[[str, str], str],
    *,
    enabled: bool | None = None,
    max_prompt_chars: int | None = None,
    document: bool = False,
) -> object:
    """
    Run a self-verification pass on the relationships in *result*.

    `enabled` is the caller's decision (the orchestrator's 3d switch); None
    falls back to ENABLE_STIX_VERIFICATION.  It used to be the environment
    only, so a run that asked for 3d with the variable unset silently got none.

    Args:
        text:    The text the claims were extracted from — a chunk, or the
                 whole report for the document-level pass.  All of it is sent:
                 a claim is only checkable against text the verifier sees.
                 (It used to be cut at 3 500 characters, which removed every
                 document-level claim supported further down, and the tail of
                 the 4 000/5 000-character chunks of long reports.)
        result:  LLMEnrichmentResult from enrich_chunk().
        llm_fn:  The _call_llm() callable from stage3_llm — passed in to avoid
                 circular imports.
        max_prompt_chars: the prompt limit `llm_fn` applies.  Past it the TEXT
                 is cut here, so the claims after it always reach the model.
        document: `text` is a whole report — accept the two-sentence support
                 that `_VERIFY_SYSTEM_DOCUMENT` describes.

    Returns:
        A new LLMEnrichmentResult with only verified relationships.
        Unverified relationships are removed.
        Verified relationships have their evidence_text updated with the
        supporting quote from the text.

    Claims are verified in batches of STIX_VERIFY_BATCH_SIZE.  A batch's claims
    are kept unverified when its call fails or its answer cannot be parsed.
    The result is returned unchanged when verification is disabled or there
    are fewer than STIX_VERIFY_MIN_RELS relationships.
    """
    if not (_VERIFY_ENABLED if enabled is None else enabled):
        return result

    rels = result.relationships
    if not rels or len(rels) < _VERIFY_MIN_RELS:
        return result

    system = _VERIFY_SYSTEM_DOCUMENT if document else _VERIFY_SYSTEM
    quote_cap = 1_000 if document else 500
    batch_size = max(1, _VERIFY_BATCH)
    verified_rels = []
    removed = 0
    for start in range(0, len(rels), batch_size):
        kept, dropped = _verify_batch(text, rels[start:start + batch_size], llm_fn,
                                      system, max_prompt_chars, quote_cap)
        verified_rels.extend(kept)
        removed += dropped

    if removed:
        logger.info(
            f"Verification: removed {removed}/{len(rels)} "
            f"unsupported relationships ({len(verified_rels)} kept)"
        )
    else:
        logger.info(f"All {len(rels)} relationships verified")

    return result.model_copy(update={"relationships": verified_rels})


def _verify_batch(text: str, rels: list, llm_fn: Callable[[str, str], str], system: str,
                  max_prompt_chars: int | None, quote_cap: int) -> tuple[list, int]:
    """Verify one batch of claims; return (kept relationships, number removed)."""
    from pipeline import llm_stats

    # Build numbered claims list  (compact — saves tokens)
    claims_str = "\n".join(
        f'{i + 1}. "{r.source_value}" {r.relationship_type} "{r.target_value}"'
        for i, r in enumerate(rels)
    )
    prompt, spotlight = fit_report(_VERIFY_USER_TEMPLATE, text, max_prompt_chars, claims=claims_str)

    raw = llm_fn(f"{system}\n\n{spotlight}", prompt)
    if not raw:
        # LLM call failed — keep the batch (safe fallback)
        logger.warning("Verification LLM call failed — keeping these relationships")
        llm_stats.bump("rel_verification_failed")
        return list(rels), 0

    verifications = parse_numbered_claims(raw, len(rels))
    if verifications is None:
        logger.warning("Could not parse verification response — keeping these relationships")
        llm_stats.bump("rel_verification_unparsed")
        return list(rels), 0
    llm_stats.bump("rel_verification_ok")

    kept = []
    removed = 0
    for i, rel in enumerate(rels):
        v = verifications.get(i + 1)

        # If the LLM didn't return an entry for this claim, default to keeping it
        if v is None:
            kept.append(rel)
            continue

        if v.get("verified", True):
            # Update evidence_text with the LLM's quoted sentence (if available)
            quote = v.get("quote")
            if quote and isinstance(quote, str) and quote.strip():
                rel = rel.model_copy(update={"evidence_text": quote.strip()[:quote_cap]})
            kept.append(rel)
        else:
            removed += 1
    return kept, removed


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

