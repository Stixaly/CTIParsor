"""
Stage 3e — cross-model consensus (anti-hallucination).

Runs the same chunk through a SECOND LLM provider and uses agreement as a trust
signal.  This is a stronger, cheaper alternative to single-model self-verification
(Stage 3d): a model is a poor judge of its own hallucination, but two *different*
models disagreeing is a real signal.

Reconciliation operates on relationships only — the highest-hallucination-risk
output — keyed exactly like ``_merge_results`` in stage3_llm:
    (source_value.lower(), relationship_type, target_value.lower())

Opt-in via ENABLE_CONSENSUS=true; the second provider is CONSENSUS_PROVIDER.
"""
from __future__ import annotations

import os

from api.logging_config import get_logger
from models.schemas import EvidenceLabel
from pipeline.stage3_llm import LLMEnrichmentResult

logger = get_logger(__name__)

# Confidence adjustments applied during reconciliation.
_AGREE_BOOST   = 0.10   # both models proposed the relationship
_SINGLE_PENALTY = 0.20  # only the primary model proposed it


def consensus_enabled() -> bool:
    """True when cross-model consensus is switched on and a 2nd provider is set."""
    if os.getenv("ENABLE_CONSENSUS", "false").strip().lower() != "true":
        return False
    second = os.getenv("CONSENSUS_PROVIDER", "").strip().lower()
    primary = os.getenv("LLM_PROVIDER", "anthropic").strip().lower()
    if not second:
        logger.warning("[Stage 3e] ENABLE_CONSENSUS=true but CONSENSUS_PROVIDER is unset — disabled.")
        return False
    if second == primary:
        logger.warning(
            "[Stage 3e] CONSENSUS_PROVIDER == LLM_PROVIDER (%s) — consensus needs two "
            "different models; disabled.", second,
        )
        return False
    return True


def consensus_provider() -> str:
    return os.getenv("CONSENSUS_PROVIDER", "").strip().lower()


def reconcile(
    primary: LLMEnrichmentResult,
    secondary: LLMEnrichmentResult,
) -> LLMEnrichmentResult:
    """Keep all of ``primary`` but re-grade its relationships using ``secondary``.

    - A relationship both models proposed gets a confidence boost.
    - A relationship only the primary proposed loses confidence and, if it was
      labelled "observed", is downgraded to "reported" so it can no longer
      auto-promote in the review UI on a single model's word.
    """
    sec_keys = {
        (r.source_value.lower(), r.relationship_type, r.target_value.lower())
        for r in secondary.relationships
    }

    agreed = 0
    for rel in primary.relationships:
        key = (rel.source_value.lower(), rel.relationship_type, rel.target_value.lower())
        if key in sec_keys:
            rel.confidence = min(1.0, rel.confidence + _AGREE_BOOST)
            agreed += 1
        else:
            rel.confidence = max(0.0, rel.confidence - _SINGLE_PENALTY)
            if rel.evidence_label == EvidenceLabel.OBSERVED:
                rel.evidence_label = EvidenceLabel.REPORTED

    logger.info(
        "[Stage 3e] consensus: %d/%d relationships corroborated by %s",
        agreed, len(primary.relationships), consensus_provider() or "secondary",
    )
    return primary
