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


class TestRelationshipEndpointRecall:
    """#320: the endpoint filter must not drop endpoints the text only carries
    defanged, or that only the NER knows, while still rejecting inventions."""

    DOC = "WellMess beaconed to evil[.]com. APT29 operated it."

    @staticmethod
    def _rel(src, tgt, kind="communicates-with"):
        return RelationshipExtracted(source_value=src, relationship_type=kind, target_value=tgt)

    def test_defanged_ioc_endpoint_is_kept(self):
        r = _result(relationships=[self._rel("WellMess", "evil.com")])
        out = validate_llm_result(r, self.DOC)
        assert [(x.source_value, x.target_value) for x in out.relationships] == [("WellMess", "evil.com")]

    def test_ner_known_endpoint_is_kept(self):
        r = _result(relationships=[self._rel("APT29", "T1566")])
        assert validate_llm_result(r, self.DOC).relationships == []
        out = validate_llm_result(r, self.DOC, ner_allow_list={"t1566"})
        assert len(out.relationships) == 1

    def test_invented_endpoint_is_rejected(self):
        r = _result(relationships=[self._rel("WellMess", "invented.example")])
        assert validate_llm_result(r, self.DOC, ner_allow_list={"apt29"}).relationships == []

    def test_short_invented_endpoint_inside_a_word_is_rejected(self):
        # "mes" occurs only inside "WellMess": a substring is not a mention.
        r = _result(relationships=[self._rel("WellMess", "mes")])
        assert validate_llm_result(r, self.DOC).relationships == []

    def test_hallucinated_entity_endpoint_is_rejected(self):
        r = _result(malware_families=["Ghostly"],
                    relationships=[self._rel("Ghostly", "evil.com")])
        assert validate_llm_result(r, self.DOC).relationships == []

    def test_review_lists_are_preserved(self):
        from pipeline.stage3_llm import RelationshipReview
        from pipeline.stage3f_ttp_select import TtpReview
        r = _result(
            relationships=[self._rel("WellMess", "evil.com")],
            ttp_review=[TtpReview(attack_id="T1566", reason="undecided")],
            rel_review=[RelationshipReview(source_value="a", relationship_type="uses",
                                           target_value="b", reason="x")],
        )
        out = validate_llm_result(r, self.DOC)
        assert len(out.ttp_review) == 1 and len(out.rel_review) == 1


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
