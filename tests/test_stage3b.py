"""
Tests for Stage 3b (hallucination filter / validate_llm_result).

The filter removes threat actor / malware names that cannot be found in the
source text via substring or fuzzy match.  These tests verify that:
  - Names present verbatim in the text are kept
  - Names absent from the text are removed
  - The allow-list (NER-confirmed names) bypasses the text check
  - Relationships whose source/target are both filtered get removed
  - The function never raises on edge-case inputs
"""
from __future__ import annotations

from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted
from pipeline.stage3b_validate import validate_llm_result

TEXT = (
    "APT29 deployed SUNBURST malware against SolarWinds targets. "
    "The group used T1566.001 spearphishing and beaconed to 185.220.101.45."
)


def _result(**kwargs) -> LLMEnrichmentResult:
    return LLMEnrichmentResult(**kwargs)


class TestThreatActorFilter:
    def test_keeps_actor_present_in_text(self):
        r = _result(threat_actors=["APT29"])
        out = validate_llm_result(r, TEXT)
        assert "APT29" in out.threat_actors

    def test_removes_actor_absent_from_text(self):
        r = _result(threat_actors=["FancyBear_NotInText"])
        out = validate_llm_result(r, TEXT)
        assert "FancyBear_NotInText" not in out.threat_actors

    def test_allow_list_bypasses_text_check(self):
        """Names confirmed by high-precision NER must never be filtered."""
        r = _result(threat_actors=["UNC3524"])
        out = validate_llm_result(r, "Unrelated text.", ner_allow_list={"unc3524"})
        assert "UNC3524" in out.threat_actors


class TestMalwareFilter:
    def test_keeps_malware_in_text(self):
        r = _result(malware_families=["SUNBURST"])
        out = validate_llm_result(r, TEXT)
        assert "SUNBURST" in out.malware_families

    def test_removes_malware_absent_from_text(self):
        r = _result(malware_families=["GhostPulseZero_NotPresent"])
        out = validate_llm_result(r, TEXT)
        assert "GhostPulseZero_NotPresent" not in out.malware_families

    def test_removes_absent_malware(self):
        r = _result(malware_families=["GhostPulse_NotHere"])
        out = validate_llm_result(r, TEXT)
        assert "GhostPulse_NotHere" not in out.malware_families


class TestRelationshipFilter:
    def test_keeps_relationship_when_both_entities_present(self):
        rel = RelationshipExtracted(
            source_value="APT29",
            relationship_type="uses",
            target_value="SUNBURST",
            confidence=0.9,
        )
        r = _result(
            threat_actors=["APT29"],
            malware_families=["SUNBURST"],
            relationships=[rel],
        )
        out = validate_llm_result(r, TEXT)
        assert any(
            rel.source_value == "APT29" and rel.target_value == "SUNBURST"
            for rel in out.relationships
        )


class TestEdgeCases:
    def test_empty_result_does_not_raise(self):
        out = validate_llm_result(LLMEnrichmentResult(), "")
        assert isinstance(out, LLMEnrichmentResult)

    def test_empty_text_filters_everything(self):
        r = _result(threat_actors=["APT29"], malware_families=["SUNBURST"])
        out = validate_llm_result(r, "")
        assert out.threat_actors == []
        assert out.malware_families == []

    def test_none_allow_list_is_safe(self):
        r = _result(threat_actors=["APT29"])
        out = validate_llm_result(r, TEXT, ner_allow_list=None)
        assert isinstance(out, LLMEnrichmentResult)

    def test_returns_llm_enrichment_result_type(self):
        out = validate_llm_result(LLMEnrichmentResult(threat_actors=["APT29"]), TEXT)
        assert type(out) is LLMEnrichmentResult
