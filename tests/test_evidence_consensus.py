"""Tests for evidence labels (Feature 1) and cross-model consensus (Feature 3)."""
import stix2

from models.schemas import EvidenceLabel
from pipeline.stage3_llm import (
    LLMEnrichmentResult,
    RelationshipExtracted,
    _normalize_llm_json,
)
from pipeline.stage3e_consensus import reconcile
from pipeline.stage4_stix_mapping import build_stix_bundle


# ── Feature 1 — evidence labels ────────────────────────────────────────────

def test_relationship_default_label_is_reported():
    rel = RelationshipExtracted(source_value="A", relationship_type="uses", target_value="B")
    assert rel.evidence_label == EvidenceLabel.REPORTED


def test_normalize_coerces_unknown_label_and_keeps_relationship():
    out = _normalize_llm_json(
        {"relationships": [{"source": "A", "type": "uses", "target": "B", "evidence_label": "HIGH"}]}
    )
    assert len(out["relationships"]) == 1
    assert out["relationships"][0]["evidence_label"] == "reported"


def test_evidence_label_becomes_stix_custom_property():
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"],
        malware_families=["Cobalt Strike"],
        relationships=[
            RelationshipExtracted(
                source_value="APT29",
                relationship_type="uses",
                target_value="Cobalt Strike",
                confidence=0.9,
                evidence_label=EvidenceLabel.OBSERVED,
            )
        ],
    )
    bundle = build_stix_bundle([], llm, "test_report", report_text="APT29 used Cobalt Strike.")
    assert isinstance(bundle, stix2.Bundle)
    rels = [o for o in bundle.objects if o.get("type") == "relationship"]
    assert rels, "no relationship object produced"
    assert any(getattr(r, "x_evidence_label", None) == "observed" for r in rels)


# ── Feature 3 — consensus reconciliation ───────────────────────────────────

def test_consensus_boosts_agreement_and_penalizes_single_model():
    primary = LLMEnrichmentResult(
        relationships=[
            RelationshipExtracted(source_value="A", relationship_type="uses", target_value="B",
                                  confidence=0.80, evidence_label=EvidenceLabel.OBSERVED),
            RelationshipExtracted(source_value="C", relationship_type="targets", target_value="D",
                                  confidence=0.80, evidence_label=EvidenceLabel.OBSERVED),
        ]
    )
    secondary = LLMEnrichmentResult(
        relationships=[
            RelationshipExtracted(source_value="A", relationship_type="uses", target_value="B",
                                  confidence=0.70),
        ]
    )
    result = reconcile(primary, secondary)
    agreed, single = result.relationships[0], result.relationships[1]

    # Corroborated by both models → confidence boosted, strong label kept
    assert round(agreed.confidence, 2) == 0.90
    assert agreed.evidence_label == EvidenceLabel.OBSERVED

    # Proposed by one model only → confidence penalized, downgraded from observed
    assert round(single.confidence, 2) == 0.60
    assert single.evidence_label == EvidenceLabel.REPORTED
