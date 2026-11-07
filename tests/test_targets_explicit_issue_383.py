"""An explicit `targets` row the LLM wrote keeps its quote and confidence when
the targeted-country / sector product would build the same edge, and resolves
its country or sector when only the targeted lists name it (issue #383).
"""
import pytest

from models.schemas import EntityType, RawEntity
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle

QUOTE = "APT29 has targeted French government ministries since 2023."


def _build(llm, entities=()):
    ledger = MappingLedger()
    bundle = build_stix_bundle(list(entities), llm, "rpt", ledger=ledger)
    return bundle, ledger.to_dict()


def _targets_edges(bundle, source: str, target: str) -> list:
    names = {o.id: o.get("name") for o in bundle.objects}
    return [o for o in bundle.objects
            if o.get("type") == "relationship" and o.relationship_type == "targets"
            and names.get(o.source_ref) == source and names.get(o.target_ref) == target]


def _explicit(target: str, confidence: float = 0.4) -> RelationshipExtracted:
    return RelationshipExtracted(source_value="APT29", relationship_type="targets",
                                 target_value=target, confidence=confidence, evidence_text=QUOTE)


@pytest.mark.parametrize("ner_found_it", [False, True], ids=["list_only", "ner_entity_too"])
def test_an_explicit_targets_row_keeps_its_quote_and_confidence_issue_383(ner_found_it):
    """The product builds APT29 -> France from the list with no quote, and the
    row's 0.4 was lost; the row now takes over the product's edge, with both."""
    llm = LLMEnrichmentResult(threat_actors=["APT29"], targeted_countries=["France"],
                              relationships=[_explicit("France")])
    entities = [RawEntity(value="France", entity_type=EntityType.LOCATION)] if ner_found_it else []

    bundle, ledger = _build(llm, entities)

    [edge] = _targets_edges(bundle, "APT29", "France")
    assert (edge.confidence, edge.x_evidence_text) == (40, QUOTE)
    assert ledger["objects"][edge.id]["origin"] == "extracted"
    [row] = [r for r in ledger["relationships"] if r["target_value"] == "France"]
    assert (row["outcome"], row["stix_id"]) == ("merged", edge.id)


def test_an_explicit_targets_row_to_a_listed_sector_keeps_its_quote_issue_383():
    llm = LLMEnrichmentResult(threat_actors=["APT29"], targeted_sectors=["Government"],
                              relationships=[_explicit("Government")])

    bundle, _ = _build(llm)

    [edge] = _targets_edges(bundle, "APT29", "Government")
    assert (edge.confidence, edge.x_evidence_text) == (40, QUOTE)


def test_the_targets_product_alone_still_builds_its_edges_issue_383():
    """Control: with no explicit row, the lists still build the product's edges,
    unquoted and with the ledger's `targeted_location` origin."""
    llm = LLMEnrichmentResult(threat_actors=["APT29"], targeted_countries=["France"],
                              targeted_sectors=["Government"])

    bundle, ledger = _build(llm)

    [edge] = _targets_edges(bundle, "APT29", "France")
    assert edge.get("x_evidence_text") is None
    assert ledger["objects"][edge.id]["origin"] == "targeted_location"
    assert len(_targets_edges(bundle, "APT29", "Government")) == 1
