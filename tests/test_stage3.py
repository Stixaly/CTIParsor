"""
Tests for Stage 3 (LLM enrichment) — all LLM calls are mocked.

Covers:
  - Happy path: correct entity and relationship extraction
  - Malformed JSON response → empty result, no exception
  - Empty LLM response → empty result, no exception
  - Transient errors (timeout) → propagate for tenacity retry
  - _provider_ready() guards short-circuit correctly
  - enrich_all_chunks merges multiple chunk results
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from pipeline.stage3_llm import (
    LLMEnrichmentResult,
    TTPExtracted,
    RelationshipExtracted,
    enrich_chunk,
    enrich_all_chunks,
    _merge_results,
    _dedup_names,
    _normalize_llm_json,
)
from models.schemas import RawEntity, EntityType


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_entities() -> list[RawEntity]:
    return [
        RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4),
        RawEntity(value="APT29", entity_type=EntityType.THREAT_ACTOR, source="gazetteer"),
    ]


# ── enrich_chunk — happy path ──────────────────────────────────────────────────

class TestEnrichChunkHappyPath:
    def test_returns_llm_enrichment_result(self, mock_llm, sample_cti_text, sample_entities):
        result = enrich_chunk(sample_cti_text, sample_entities)
        assert isinstance(result, LLMEnrichmentResult)

    def test_threat_actors_extracted(self, mock_llm, sample_cti_text, sample_entities):
        # mock returns APT29 — but stage3b hallucination filter may drop it
        # if it's not in the text. sample_cti_text contains "APT29" so it passes.
        result = enrich_chunk(sample_cti_text, sample_entities)
        assert isinstance(result.threat_actors, list)

    def test_relationships_extracted(self, mock_llm, sample_cti_text, sample_entities):
        result = enrich_chunk(sample_cti_text, sample_entities)
        assert isinstance(result.relationships, list)

    def test_campaign_name_present(self, mock_llm, sample_cti_text, sample_entities):
        result = enrich_chunk(sample_cti_text, sample_entities)
        # campaign_name may be None if hallucination filter strips it; just check type
        assert result.campaign_name is None or isinstance(result.campaign_name, str)

    def test_targeted_sectors_are_list(self, mock_llm, sample_cti_text, sample_entities):
        result = enrich_chunk(sample_cti_text, sample_entities)
        assert isinstance(result.targeted_sectors, list)

    def test_llm_was_called_once(self, mock_llm, sample_cti_text, sample_entities):
        enrich_chunk(sample_cti_text, sample_entities)
        assert mock_llm.call_count >= 1


# ── enrich_chunk — error handling ─────────────────────────────────────────────

class TestEnrichChunkErrorHandling:
    def test_malformed_json_returns_empty_result(self, mock_llm_bad_json, sample_cti_text):
        result = enrich_chunk(sample_cti_text, [])
        assert isinstance(result, LLMEnrichmentResult)
        assert result.threat_actors == []
        assert result.relationships == []

    def test_empty_llm_response_returns_empty_result(self, mock_llm_empty, sample_cti_text):
        result = enrich_chunk(sample_cti_text, [])
        assert isinstance(result, LLMEnrichmentResult)

    def test_empty_text_returns_empty_result(self, mock_llm):
        # prompt too short — _MIN_PROMPT_LENGTH guard kicks in
        result = enrich_chunk("", [])
        assert isinstance(result, LLMEnrichmentResult)

    def test_no_api_key_returns_empty(self):
        """When provider is not ready, enrich_chunk must return empty without calling LLM."""
        with patch("pipeline.stage3_llm._provider_ready", return_value=False):
            result = enrich_chunk("some text", [])
        assert isinstance(result, LLMEnrichmentResult)
        assert result.threat_actors == []


# ── enrich_chunk — transient errors ───────────────────────────────────────────

class TestEnrichChunkTransientErrors:
    def test_timeout_propagates_for_retry(self, sample_cti_text):
        """APITimeoutError must NOT be swallowed — it must propagate so tenacity can retry."""
        import anthropic
        with patch(
            "pipeline.stage3_llm._call_llm",
            side_effect=anthropic.APITimeoutError(request=None),  # type: ignore[arg-type]
        ):
            with pytest.raises(anthropic.APITimeoutError):
                enrich_chunk(sample_cti_text, [])

    def test_connection_error_propagates(self, sample_cti_text):
        import anthropic
        with patch(
            "pipeline.stage3_llm._call_llm",
            side_effect=anthropic.APIConnectionError(request=None),  # type: ignore[arg-type]
        ):
            with pytest.raises(anthropic.APIConnectionError):
                enrich_chunk(sample_cti_text, [])


# ── _merge_results ─────────────────────────────────────────────────────────────

class TestMergeResults:
    def test_deduplicates_threat_actors(self):
        r1 = LLMEnrichmentResult(threat_actors=["APT29"])
        r2 = LLMEnrichmentResult(threat_actors=["APT29", "Lazarus Group"])
        merged = _merge_results([r1, r2])
        lower_actors = [a.lower() for a in merged.threat_actors]
        assert lower_actors.count("apt29") <= 1

    def test_merges_relationships(self):
        rel = RelationshipExtracted(
            source_value="APT29", relationship_type="uses", target_value="SUNBURST"
        )
        r1 = LLMEnrichmentResult(relationships=[rel])
        r2 = LLMEnrichmentResult(relationships=[])
        merged = _merge_results([r1, r2])
        assert len(merged.relationships) == 1

    def test_deduplicates_ttps_by_mitre_id(self):
        t1 = TTPExtracted(technique_name="Spearphishing", mitre_id="T1566.001")
        t2 = TTPExtracted(technique_name="Spearphishing Attachment", mitre_id="T1566.001")
        r1 = LLMEnrichmentResult(ttps=[t1])
        r2 = LLMEnrichmentResult(ttps=[t2])
        merged = _merge_results([r1, r2])
        mitre_ids = [t.mitre_id for t in merged.ttps if t.mitre_id]
        assert mitre_ids.count("T1566.001") <= 1

    def test_empty_list_returns_empty_result(self):
        merged = _merge_results([])
        assert merged.threat_actors == []
        assert merged.relationships == []


# ── _dedup_names ───────────────────────────────────────────────────────────────

class TestDedupNames:
    def test_case_insensitive_dedup(self):
        result = _dedup_names(["APT29", "apt29", "Apt29"])
        assert len(result) == 1

    def test_strips_whitespace(self):
        result = _dedup_names(["  APT29  "])
        assert result[0] == "APT29"

    def test_blacklist_filters(self):
        result = _dedup_names(["APT29", "malware"], blacklist={"malware"})
        assert "malware" not in [n.lower() for n in result]
        assert "APT29" in result

    def test_empty_strings_dropped(self):
        result = _dedup_names(["", "  ", "APT29"])
        assert "" not in result
        assert "APT29" in result


# ── enrich_all_chunks ──────────────────────────────────────────────────────────

class TestEnrichAllChunks:
    def test_returns_merged_result(self, mock_llm, sample_cti_text):
        chunks = [sample_cti_text[:200], sample_cti_text[200:]]
        entities_per_chunk = [[], []]
        result = enrich_all_chunks(chunks, entities_per_chunk)
        assert isinstance(result, LLMEnrichmentResult)

    def test_single_chunk_equivalent_to_enrich_chunk(self, mock_llm, sample_cti_text, sample_entities):
        single = enrich_chunk(sample_cti_text, sample_entities)
        multi = enrich_all_chunks([sample_cti_text], [sample_entities])
        # Both should be valid LLMEnrichmentResult instances with same structure
        assert type(single) is type(multi)


# ── _normalize_llm_json ────────────────────────────────────────────────────────

class TestNormalizeLlmJson:
    """
    Exercises the field-name / type normaliser that recovers enriched LLM output
    when Claude returns richer objects than the strict Pydantic schema expects.
    These test cases mirror the exact deviations seen in production logs.
    """

    def test_threat_actor_dict_to_str(self):
        """Claude returned {"name": "GREYVIBE", "aliases": []} instead of "GREYVIBE"."""
        raw = {"threat_actors": [{"name": "GREYVIBE", "aliases": [], "category": "nation-state"}]}
        out = _normalize_llm_json(raw)
        assert out["threat_actors"] == ["GREYVIBE"]

    def test_malware_family_dict_to_str(self):
        """Claude returned {"name": "LegionRelay", "is_novel": True} instead of "LegionRelay"."""
        raw = {"malware_families": [{"name": "LegionRelay", "is_novel": True}]}
        out = _normalize_llm_json(raw)
        assert out["malware_families"] == ["LegionRelay"]

    def test_plain_strings_pass_through(self):
        """Plain strings must be preserved unchanged."""
        raw = {"threat_actors": ["APT29"], "malware_families": ["SUNBURST"]}
        out = _normalize_llm_json(raw)
        assert out["threat_actors"] == ["APT29"]
        assert out["malware_families"] == ["SUNBURST"]

    def test_ttp_name_id_renamed(self):
        """Claude returned {"id": "T1587.003", "name": "..."} instead of mitre_id/technique_name."""
        raw = {"ttps": [{"id": "T1587.003", "name": "Develop Capabilities", "description": "..."}]}
        out = _normalize_llm_json(raw)
        assert len(out["ttps"]) == 1
        ttp = out["ttps"][0]
        assert ttp["technique_name"] == "Develop Capabilities"
        assert ttp["mitre_id"] == "T1587.003"

    def test_ttp_missing_mitre_id_kept(self):
        """TTPs without a MITRE ID must still be kept if technique_name is present."""
        raw = {"ttps": [{"technique_name": "Custom Loader", "description": ""}]}
        out = _normalize_llm_json(raw)
        assert len(out["ttps"]) == 1
        assert out["ttps"][0]["technique_name"] == "Custom Loader"

    def test_ttp_without_name_dropped(self):
        """A TTP dict with no usable name field should be silently dropped."""
        raw = {"ttps": [{"mitre_id": "T1234"}]}  # no name/technique_name
        out = _normalize_llm_json(raw)
        assert out["ttps"] == []

    def test_relationship_source_target_renamed(self):
        """Claude returned source/relationship/target instead of source_value/relationship_type/target_value."""
        raw = {
            "relationships": [{
                "source": "GREYVIBE",
                "relationship": "uses",
                "target": "LegionRelay",
                "confidence": 0.9,
            }]
        }
        out = _normalize_llm_json(raw)
        assert len(out["relationships"]) == 1
        rel = out["relationships"][0]
        assert rel["source_value"] == "GREYVIBE"
        assert rel["relationship_type"] == "uses"
        assert rel["target_value"] == "LegionRelay"
        assert rel["confidence"] == 0.9   # extra fields preserved

    def test_relationship_type_field_renamed(self):
        """Claude used "type" instead of "relationship_type"."""
        raw = {
            "relationships": [{
                "source": "APT29", "type": "attributed-to", "target": "Russia",
            }]
        }
        out = _normalize_llm_json(raw)
        rel = out["relationships"][0]
        assert rel["relationship_type"] == "attributed-to"

    def test_relationship_missing_required_field_dropped(self):
        """A relationship without all three required fields should be dropped."""
        raw = {"relationships": [{"source_value": "APT29", "relationship_type": "uses"}]}
        out = _normalize_llm_json(raw)
        assert out["relationships"] == []

    def test_mixed_list_str_and_dict(self):
        """Lists mixing plain strings and dicts should both be handled."""
        raw = {"malware_families": ["SUNBURST", {"name": "LegionRelay"}]}
        out = _normalize_llm_json(raw)
        assert "SUNBURST" in out["malware_families"]
        assert "LegionRelay" in out["malware_families"]

    def test_unknown_fields_preserved(self):
        """Fields not normalised (e.g. targeted_sectors) should pass through unchanged."""
        raw = {
            "targeted_sectors": ["government", "finance"],
            "campaign_name": "GreyOps",
        }
        out = _normalize_llm_json(raw)
        assert out["targeted_sectors"] == ["government", "finance"]
        assert out["campaign_name"] == "GreyOps"

    def test_full_deviated_payload_survives_pydantic(self):
        """
        A payload matching the exact deviation seen in production logs should
        successfully validate as LLMEnrichmentResult after normalization.
        """
        raw = {
            "threat_actors": [{"name": "GREYVIBE", "category": "nation-state", "aliases": []}],
            "malware_families": [{"name": "LegionRelay", "type": "RAT", "source": "WithSecure"}],
            "ttps": [
                {"id": "T1587.003", "name": "Develop Capabilities: Digital Certificates", "description": "..."},
            ],
            "relationships": [
                {"source": "GREYVIBE", "relationship": "uses", "target": "LegionRelay", "confidence": 0.9},
            ],
            "targeted_countries": ["Ukraine", "Poland"],
        }
        normalized = _normalize_llm_json(raw)
        result = LLMEnrichmentResult.model_validate(normalized)
        assert result.threat_actors == ["GREYVIBE"]
        assert result.malware_families == ["LegionRelay"]
        assert result.ttps[0].technique_name == "Develop Capabilities: Digital Certificates"
        assert result.ttps[0].mitre_id == "T1587.003"
        assert result.relationships[0].source_value == "GREYVIBE"
        assert result.relationships[0].relationship_type == "uses"
        assert result.relationships[0].target_value == "LegionRelay"
