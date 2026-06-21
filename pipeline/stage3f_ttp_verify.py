"""
Stage 3f — Self-Verification of LLM TTP Claims (ADR precision §3).

Companion to Stage 3d (which verifies *relationships*).  Stage 3d cut relationship
hallucination 27%→8% by forcing the LLM to quote a supporting sentence; TTPs had
no equivalent gate, so an LLM-guessed technique whose name merely fuzzy-matched a
real ATT&CK entry in Stage 3c was accepted even when the text never described it.

Problem this solves:
  Stage 3 asks the LLM for "MITRE ATT&CK TTPs that require contextual understanding".
  The LLM sometimes pattern-matches a technique from its training knowledge of the
  named malware/actor rather than from the document in front of it.  Stage 3c only
  checks that the *name/ID is real*, not that the *text supports it*.

How it works:
  After enrich_chunk() produces a result, this module sends a SECOND LLM call with:
    • the original text chunk
    • the numbered list of extracted TTPs (name + ID + expected ATT&CK tactic)
  The LLM must quote the EXACT sentence describing each technique's use.  A claim
  with no supporting sentence — or one whose described behaviour does not fit the
  technique's tactic — is marked unverified and discarded.

Scope — only single-signal TTPs are verified:
  TTPs already corroborated by a high-confidence Stage 2c semantic match (passed in
  as `corroborated_ids`) are trusted and skipped, so the extra call only scrutinises
  the LLM-only claims that carry the hallucination risk.  This keeps the cost
  profile close to Stage 3d's (~1.4× calls, not 2×).

Configuration (via .env):
  ENABLE_TTP_VERIFICATION=true   — enable verification (default: false)
  TTP_VERIFY_MIN=1               — only verify when ≥N unverified TTPs (default: 1)

Design note — circular import avoidance:
  stage3_llm.py imports this module lazily (inside enrich_chunk); this module
  receives _call_llm as a parameter rather than importing it, mirroring 3d.
"""
from __future__ import annotations

import json
import math
import os
from typing import Callable

from api.logging_config import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_VERIFY_ENABLED = os.getenv("ENABLE_TTP_VERIFICATION", "false").lower() in (
    "true", "1", "yes",
)
_VERIFY_MIN = int(os.getenv("TTP_VERIFY_MIN", "1"))


def verify_enabled() -> bool:
    """Return True if TTP self-verification is enabled via ENABLE_TTP_VERIFICATION."""
    return _VERIFY_ENABLED


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_VERIFY_SYSTEM = """\
You are a strict MITRE ATT&CK fact-checker.

For each numbered technique claim, find the EXACT sentence in the provided text
that describes the adversary USING that technique.

Rules:
- Mark verified=true ONLY if a sentence in the text describes behaviour that
  clearly matches this technique (and its tactic), not merely the technique's
  name or a generic mention.
- Do NOT rely on outside knowledge of the named malware/actor — judge ONLY from
  the text provided.
- If a sentence supports the claim, set verified=true and quote that sentence.
- If no sentence in the text describes this technique being used — even loosely —
  mark verified=false.
- Set quote to null when verified=false.
- Return ONLY valid JSON, no surrounding text or markdown fences.
"""

_VERIFY_USER_TEMPLATE = """\
Text excerpt:
---
{text}
---

Verify each MITRE ATT&CK technique claim against the text above.
For each claim, find the sentence that describes this technique being used
(exact quote) or mark it unverified.

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

def verify_ttps(
    text: str,
    result,                          # LLMEnrichmentResult — avoid import cycle
    llm_fn: Callable[[str, str], str],
    corroborated_ids: set[str] | None = None,
) -> object:
    """
    Run a self-verification pass on the TTPs in *result*.

    Args:
        text:             The source CTI text chunk fed to enrich_chunk().
        result:           LLMEnrichmentResult from enrich_chunk().
        llm_fn:           The _call_llm() callable from stage3_llm (passed in to
                          avoid a circular import).
        corroborated_ids: MITRE IDs already confirmed by a high-confidence
                          Stage 2c semantic match — these are trusted and skipped.

    Returns:
        A new LLMEnrichmentResult; TTPs whose use is not supported by a quoted
        sentence are removed.  Verified TTPs keep their description (augmented
        with the supporting quote when one was returned and the description was
        empty).

    Falls back to returning the original result unchanged when verification is
    disabled, there is nothing to verify, or the LLM response cannot be parsed.
    """
    if not _VERIFY_ENABLED:
        return result

    ttps = list(result.ttps)
    if not ttps:
        return result

    corro = {c.upper() for c in (corroborated_ids or set())}

    # Split into trusted (corroborated) and to-verify (single-signal) TTPs,
    # preserving order so the numbered claim list lines up with `to_verify`.
    trusted: list = []
    to_verify: list = []
    for t in ttps:
        if t.mitre_id and t.mitre_id.upper() in corro:
            trusted.append(t)
        else:
            to_verify.append(t)

    if len(to_verify) < _VERIFY_MIN:
        return result

    # Build numbered claims, annotated with the expected tactic so the checker
    # can also reject a technique whose described behaviour fits a wrong tactic.
    from pipeline.stage3c_mitre import tactics_for

    claims_lines = []
    for i, t in enumerate(to_verify):
        tactics = tactics_for(t.mitre_id)
        tactic_hint = f" [tactic: {', '.join(tactics)}]" if tactics else ""
        ident = f" ({t.mitre_id})" if t.mitre_id else ""
        claims_lines.append(f'{i + 1}. "{t.technique_name}"{ident}{tactic_hint}')
    claims_str = "\n".join(claims_lines)

    prompt = _VERIFY_USER_TEMPLATE.format(text=text[:3_500], claims=claims_str)

    raw = llm_fn(_VERIFY_SYSTEM, prompt)
    if not raw:
        logger.warning("TTP verification LLM call failed — keeping all TTPs")
        return result

    verifications = _parse_verification_response(raw, len(to_verify))
    if verifications is None:
        logger.warning("Could not parse TTP verification response — keeping all TTPs")
        return result

    kept_verified: list = []
    removed = 0
    for i, t in enumerate(to_verify):
        v = verifications.get(i + 1)
        # No entry for this claim → default to keeping it (safe fallback).
        if v is None or v.get("verified", True):
            quote = v.get("quote") if v else None
            if quote and isinstance(quote, str) and quote.strip() and not t.description.strip():
                t = t.model_copy(update={"description": quote.strip()[:500]})
            kept_verified.append(t)
        else:
            removed += 1

    if removed:
        logger.info(
            f"TTP verification: removed {removed}/{len(to_verify)} "
            f"unsupported TTPs ({len(trusted)} corroborated kept)"
        )
    else:
        logger.info(f"All {len(to_verify)} single-signal TTPs verified")

    return result.model_copy(update={"ttps": trusted + kept_verified})


# ---------------------------------------------------------------------------
# Response parser  (shared shape with stage3d_verify)
# ---------------------------------------------------------------------------

def _parse_verification_response(raw: str, count: int) -> dict[int, dict] | None:
    """
    Parse the LLM verification response into {claim_num → verification_dict}.

    Expected format — a JSON array:
      [{"n": 1, "verified": true, "quote": "..."}, ...]

    Returns None if no valid JSON array can be found in the response.
    """
    decoder = json.JSONDecoder()

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
                    # Accept int or whole-number float; exclude bool and non-finite.
                    if (isinstance(n, (int, float))
                            and not isinstance(n, bool)
                            and math.isfinite(n)
                            and n == int(n)
                            and 1 <= int(n) <= count):
                        result[int(n)] = item

                return result if result else None

            except json.JSONDecodeError:
                continue

    return None
