import stix2
from models.schemas import RawEntity, EntityType
from pipeline.stage3_llm import LLMEnrichmentResult, TTPExtracted, RelationshipExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle


def _make_minimal_llm_result() -> LLMEnrichmentResult:
    return LLMEnrichmentResult(
        threat_actors=["APT29"],
        malware_families=["WellMess"],
        tools=["Cobalt Strike"],
        ttps=[TTPExtracted(technique_name="Spearphishing Attachment", mitre_id="T1566.001")],
        relationships=[
            RelationshipExtracted(
                source_value="APT29",
                relationship_type="uses",
                target_value="WellMess",
                confidence=0.9,
            )
        ],
        targeted_sectors=["government"],
        targeted_countries=["France"],
        campaign_name=None,
    )


def test_bundle_is_stix_bundle():
    entities = [RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4)]
    bundle = build_stix_bundle(entities, _make_minimal_llm_result(), "test_report")
    assert isinstance(bundle, stix2.Bundle)


def test_bundle_contains_threat_actor():
    bundle = build_stix_bundle([], _make_minimal_llm_result(), "test_report")
    types = [obj.get("type") for obj in bundle.objects]
    assert "threat-actor" in types


def test_bundle_contains_malware():
    bundle = build_stix_bundle([], _make_minimal_llm_result(), "test_report")
    types = [obj.get("type") for obj in bundle.objects]
    assert "malware" in types


def test_bundle_contains_relationship():
    bundle = build_stix_bundle([], _make_minimal_llm_result(), "test_report")
    types = [obj.get("type") for obj in bundle.objects]
    assert "relationship" in types


def test_bundle_contains_attack_pattern():
    bundle = build_stix_bundle([], _make_minimal_llm_result(), "test_report")
    types = [obj.get("type") for obj in bundle.objects]
    assert "attack-pattern" in types


def test_ipv4_becomes_sco():
    entities = [RawEntity(value="1.2.3.4", entity_type=EntityType.IPV4)]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "test")
    types = [obj.get("type") for obj in bundle.objects]
    assert "ipv4-addr" in types


def test_cve_becomes_vulnerability():
    entities = [RawEntity(value="CVE-2021-40444", entity_type=EntityType.CVE)]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "test")
    types = [obj.get("type") for obj in bundle.objects]
    assert "vulnerability" in types


def test_report_object_present():
    bundle = build_stix_bundle([], _make_minimal_llm_result(), "my_report")
    reports = [obj for obj in bundle.objects if obj.get("type") == "report"]
    assert len(reports) == 1
    assert reports[0]["name"] == "my_report"
