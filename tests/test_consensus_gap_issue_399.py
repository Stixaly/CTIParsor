"""Issue #399 — a secondary model's `gap` is not a corroboration.

`gap` means the model could not find the claim in the text (EvidenceLabel.GAP),
so agreeing on a triplet with a `gap` label is no evidence for it.  When every
secondary proposal for a triplet is `gap`, the primary relationship keeps its
confidence and its label; any non-gap proposal still corroborates it.
"""
from models.schemas import EvidenceLabel
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted
from pipeline.stage3e_consensus import reconcile


def _primary(label=EvidenceLabel.OBSERVED):
    return LLMEnrichmentResult(
        relationships=[
            RelationshipExtracted(source_value="APT29", relationship_type="uses",
                                  target_value="Cobalt Strike", confidence=0.80,
                                  evidence_label=label),
        ]
    )


def _secondary(*labels):
    return LLMEnrichmentResult(
        relationships=[
            RelationshipExtracted(source_value="apt29", relationship_type="uses",
                                  target_value="cobalt strike", confidence=0.70,
                                  evidence_label=label)
            for label in labels
        ]
    )


def test_gap_only_secondary_is_neutral_issue_399(caplog):  # issue_399
    with caplog.at_level("INFO"):
        result = reconcile(_primary(), _secondary(EvidenceLabel.GAP))
    rel = result.relationships[0]

    # No bonus and no penalty: the primary keeps its confidence and its label.
    assert round(rel.confidence, 2) == 0.80
    assert rel.evidence_label == EvidenceLabel.OBSERVED
    # Not a corroboration, so the log counts it as 0.
    assert "0/1 relationships corroborated" in caplog.text


def test_non_gap_secondary_still_corroborates_issue_399_control():
    # Control: one proposal that is not `gap` is a real corroboration.
    result = reconcile(_primary(), _secondary(EvidenceLabel.GAP, EvidenceLabel.OBSERVED))
    rel = result.relationships[0]

    assert round(rel.confidence, 2) == 0.90
    assert rel.evidence_label == EvidenceLabel.OBSERVED


def test_absent_from_secondary_is_still_penalised_issue_399_control():
    # Control: a triplet the secondary does not propose at all keeps the penalty
    # and the observed -> reported downgrade.
    primary = LLMEnrichmentResult(
        relationships=[
            RelationshipExtracted(source_value="APT29", relationship_type="targets",
                                  target_value="Ministry X", confidence=0.80,
                                  evidence_label=EvidenceLabel.OBSERVED),
        ]
    )
    result = reconcile(primary, _secondary(EvidenceLabel.GAP))
    rel = result.relationships[0]

    assert round(rel.confidence, 2) == 0.60
    assert rel.evidence_label == EvidenceLabel.REPORTED
