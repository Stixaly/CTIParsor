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
    • The original text chunk
    • The numbered list of extracted relationships
  The LLM must quote the EXACT sentence from the text that supports each claim.
  If no such sentence exists, the claim is marked unverified and discarded.

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

Design note — circular import avoidance:
  stage3_llm.py imports stage3d_verify.py (deferred, inside enrich_chunk).
  stage3d_verify.py receives _call_llm as a parameter rather than importing
  it from stage3_llm.py, avoiding any circular dependency.
"""
from __future__ import annotations

import os
import json
from typing import Callable

# Initialize logging
from api.logging_config import get_logger
logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_VERIFY_ENABLED = os.getenv("ENABLE_STIX_VERIFICATION", "false").lower() in (
    "true", "1", "yes",
)
_VERIFY_MIN_RELS = int(os.getenv("STIX_VERIFY_MIN_RELS", "1"))


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
) -> object:
    """
    Run a self-verification pass on the relationships in *result*.

    Args:
        text:    The source CTI text chunk that was fed to enrich_chunk().
        result:  LLMEnrichmentResult from enrich_chunk().
        llm_fn:  The _call_llm() callable from stage3_llm — passed in to avoid
                 circular imports.

    Returns:
        A new LLMEnrichmentResult with only verified relationships.
        Unverified relationships are removed.
        Verified relationships have their evidence_text updated with the
        supporting quote from the text.

    Falls back to returning the original result unchanged if:
        - Verification is disabled (ENABLE_STIX_VERIFICATION=false)
        - Fewer than STIX_VERIFY_MIN_RELS relationships to verify
        - The LLM returns no valid response
        - The response cannot be parsed as valid JSON
    """
    if not _VERIFY_ENABLED:
        return result

    rels = result.relationships
    if not rels or len(rels) < _VERIFY_MIN_RELS:
        return result

    # Build numbered claims list  (compact — saves tokens)
    claims_lines = [
        f'{i + 1}. "{r.source_value}" {r.relationship_type} "{r.target_value}"'
        for i, r in enumerate(rels)
    ]
    claims_str = "\n".join(claims_lines)

    # Cap text to 3 500 chars — verification needs the full context but long
    # chunks were already split by stage1, so this cap is rarely hit.
    prompt = _VERIFY_USER_TEMPLATE.format(
        text=text[:3_500],
        claims=claims_str,
    )

    raw = llm_fn(_VERIFY_SYSTEM, prompt)
    if not raw:
        # LLM call failed — keep all relationships (safe fallback)
        logger.warning("Verification LLM call failed — keeping all relationships")
        return result

    verifications = _parse_verification_response(raw, len(rels))
    if verifications is None:
        logger.warning("Could not parse verification response — keeping all relationships")
        return result

    # ── Apply verification results ────────────────────────────────────────────
    verified_rels = []
    removed       = 0

    for i, rel in enumerate(rels):
        claim_num = i + 1
        v = verifications.get(claim_num)

        # If the LLM didn't return an entry for this claim, default to keeping it
        if v is None:
            verified_rels.append(rel)
            continue

        if v.get("verified", True):
            # Update evidence_text with the LLM's quoted sentence (if available)
            quote = v.get("quote")
            if quote and isinstance(quote, str) and quote.strip():
                rel = rel.model_copy(update={"evidence_text": quote.strip()[:500]})
            verified_rels.append(rel)
        else:
            removed += 1

    if removed:
        logger.info(
            f"Verification: removed {removed}/{len(rels)} "
            f"unsupported relationships ({len(verified_rels)} kept)"
        )
    else:
        logger.info(f"All {len(rels)} relationships verified")

    return result.model_copy(update={"relationships": verified_rels})


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def _parse_verification_response(raw: str, count: int) -> dict[int, dict] | None:
    """
    Parse the LLM verification response into {claim_num → verification_dict}.

    The expected format is a JSON array:
      [{"n": 1, "verified": true, "quote": "..."}, ...]

    Returns None if no valid JSON array can be found in the response.
    """
    decoder = json.JSONDecoder()

    # Scan for the first valid JSON array in the response
    for i, ch in enumerate(raw):
        if ch == "[":
            try:
                arr, _ = decoder.raw_decode(raw, i)
                if not isinstance(arr, list):
                    continue

                result: dict[int, dict] = {}
                for item in arr:
                    if not isinstance(item, dict):
                        continue
                    n = item.get("n")
                    # Accept both int and float (e.g. 1.0) — LLMs occasionally
                    # serialise integers as JSON floats.
                    if isinstance(n, (int, float)) and n == int(n) and 1 <= int(n) <= count:
                        result[int(n)] = item

                # Return even if partial (some claims missing — handled by caller)
                return result if result else None

            except json.JSONDecodeError:
                continue

    return None
