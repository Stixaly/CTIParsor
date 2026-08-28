"""A relationship from an object to itself must never reach the bundle."""
from __future__ import annotations

from models.schemas import EntityType, RawEntity
from pipeline.stage3_llm import (
    LLMEnrichmentResult,
    RelationshipExtracted,
    TTPExtracted,
)
from pipeline.stage4_stix_mapping import build_stix_bundle


def _rels(bundle) -> list:
    """Every relationship object in the bundle."""
    return [o for o in bundle.objects if getattr(o, "type", "") == "relationship"]


def test_alias_pair_does_not_produce_a_self_edge():
    """Two aliases of the same actor must not create a self-edge."""
    llm = LLMEnrichmentResult(
        threat_actors=["APT34", "OilRig"],
        relationships=[
            RelationshipExtracted(
                source_value="APT34",
                relationship_type="uses",
                target_value="OilRig",
                confidence=0.9,
            )
        ],
    )
    bundle = build_stix_bundle([], llm, "self_edge_alias")
    actors = [o for o in bundle.objects if getattr(o, "type", "") == "threat-actor"]
    assert len(actors) == 1
    assert all(r.source_ref != r.target_ref for r in _rels(bundle))


def test_identical_endpoints_produce_no_edge():
    """Identical source and target values must not create a self-edge."""
    llm = LLMEnrichmentResult(
        malware_families=["EXARAMEL"],
        relationships=[
            RelationshipExtracted(
                source_value="EXARAMEL",
                relationship_type="drops",
                target_value="EXARAMEL",
                confidence=0.9,
            )
        ],
    )
    bundle = build_stix_bundle([], llm, "self_edge_literal")
    assert all(r.source_ref != r.target_ref for r in _rels(bundle))


def test_no_self_edge_in_any_bundle_built_here():
    """No emission path in stage4 should produce a self-edge."""
    llm = LLMEnrichmentResult(
        threat_actors=["Sandworm Team"],
        malware_families=["EXARAMEL"],
        tools=["Cobalt Strike"],
        ttps=[TTPExtracted(technique_name="Spearphishing Attachment", mitre_id="T1566.001")],
        relationships=[
            RelationshipExtracted(
                source_value="Sandworm Team",
                relationship_type="uses",
                target_value="EXARAMEL",
                confidence=0.9,
            ),
            RelationshipExtracted(
                source_value="Sandworm Team",
                relationship_type="related-to",
                target_value="Sandworm Team",
                confidence=0.9,
            ),
        ],
        targeted_countries=["Ukraine"],
        targeted_sectors=["energy"],
    )
    entities = [
        RawEntity(value="185.200.177.10", entity_type=EntityType.IPV4, context="", confidence=0.9),
        RawEntity(value="evil.example.com", entity_type=EntityType.DOMAIN, context="", confidence=0.9),
    ]
    bundle = build_stix_bundle(entities, llm, "self_edge_rich")
    rels = _rels(bundle)
    assert all(r.source_ref != r.target_ref for r in rels)
    assert len(rels) >= 1


def test_legitimate_edge_between_two_objects_survives():
    """A valid edge between two distinct objects must be preserved."""
    llm = LLMEnrichmentResult(
        threat_actors=["Sandworm Team"],
        malware_families=["EXARAMEL"],
        relationships=[
            RelationshipExtracted(
                source_value="Sandworm Team",
                relationship_type="uses",
                target_value="EXARAMEL",
                confidence=0.9,
            )
        ],
    )
    bundle = build_stix_bundle([], llm, "normal_edge")
    assert any(
        r.source_ref != r.target_ref and r.relationship_type == "uses" for r in _rels(bundle)
    )
