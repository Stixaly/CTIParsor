"""Baseline merge and reconciliation, issues #413 to #415 (ADR-0090, lot 4 and 3r).

#413: a baseline object the document states is listed by the re-issued Report even
when the analyst's Report did not list it, and added_refs counts what the Report gained.
#414: an inferred edge whose premise became a duplicate of a baseline edge names that edge.
#415: a baseline actor is found in the text by the MITRE name of its intrusion-set.

The OpenCTI fixture and its scenario are the ones of tests/test_baseline_e2e.py and
tests/test_baseline_merge.py; the pins of tests/test_stage4_reference.py apply to the
end-to-end cases.
"""
from __future__ import annotations

import json

import pytest
import stix2

from pipeline import baseline_stix as bs
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import LLMEnrichmentResult
from tests.test_baseline_e2e import (
    INTRUSION_SET,
    OPENCTI_SCENARIO,
    RAW,
    REPORT,
    WELLMESS,
    _baseline_of,
    _build,
    _by_type,
)
from tests.test_baseline_merge import APT29
from tests.test_baseline_merge import _build as merge_build
from tests.test_stage4_reference import _stage4_defaults

SRO_USES = "relationship--fd3e7a73-f3b2-485d-a28b-111fadd6bea1"


@pytest.fixture(autouse=True)
def stage4_pinned():
    with _stage4_defaults():
        yield


# ── #413 ────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def report_without_the_actor():
    """The OpenCTI baseline whose Report does not list its intrusion-set, the document naming it.
    Returns (the bundle, the ledger, the Report's refs as the analyst left them)."""
    raw = json.loads(RAW)
    for o in raw["objects"]:
        if o["type"] == "report":
            o["object_refs"] = [r for r in o["object_refs"] if r != INTRUSION_SET]
    listed = set(next(o for o in raw["objects"] if o["type"] == "report")["object_refs"])
    baseline = _baseline_of(raw)
    ledger = MappingLedger()
    bundle = json.loads(bs.serialize_bundle(_build(OPENCTI_SCENARIO, baseline, ledger), baseline.verbatim))
    return bundle, ledger.to_dict(), listed


def test_a_baseline_object_the_document_states_is_listed_by_the_reissued_report_issue_413(
        report_without_the_actor):
    bundle, _, _ = report_without_the_actor
    (report,) = _by_type(bundle["objects"], "report")
    assert INTRUSION_SET in report["object_refs"]
    assert WELLMESS in report["object_refs"]                  # control: what the Report listed stays


def test_added_refs_counts_the_refs_the_reissued_report_gained_issue_413(report_without_the_actor):
    bundle, led, listed = report_without_the_actor
    (report,) = _by_type(bundle["objects"], "report")
    gained = [r for r in report["object_refs"] if r not in listed]
    assert INTRUSION_SET in gained
    assert len(gained) == len(set(gained))
    assert led["objects"][REPORT]["added_refs"] == len(gained)


# ── #414 ────────────────────────────────────────────────────────────────────

def test_an_inferred_edge_names_the_baseline_edge_its_premise_became_issue_414():
    build = merge_build()
    actor = stix2.ThreatActor(name="APT29")
    wellmess = stix2.Malware(name="WellMess", is_family=True)
    sunburst = stix2.Malware(name="SUNBURST", is_family=True)
    uses = stix2.Relationship(source_ref=actor.id, relationship_type="uses", target_ref=wellmess.id)
    inferred = stix2.Relationship(source_ref=actor.id, relationship_type="related-to", target_ref=sunburst.id,
                                  x_inferred_from=[uses.id], allow_custom=True)
    objects = [actor, wellmess, sunburst, uses, inferred]

    result = bs.merge_baseline(objects, build)

    assert result.removed_relationships == [
        {"id": uses.id, "reason": "duplicate_after_baseline_merge", "kept": SRO_USES}]
    (written,) = [o for o in objects if o.id == inferred.id]
    assert written.x_inferred_from == [SRO_USES]


def test_an_inferred_edge_whose_premise_ships_keeps_its_premise_issue_414():
    build = merge_build()
    actor = stix2.ThreatActor(name="APT29")
    sunburst = stix2.Malware(name="SUNBURST", is_family=True)
    other = stix2.Malware(name="GoldenSpy", is_family=True)
    uses = stix2.Relationship(source_ref=actor.id, relationship_type="uses", target_ref=sunburst.id)
    inferred = stix2.Relationship(source_ref=sunburst.id, relationship_type="related-to", target_ref=other.id,
                                  x_inferred_from=[uses.id], allow_custom=True)
    objects = [actor, sunburst, other, uses, inferred]

    bs.merge_baseline(objects, build)

    (written,) = [o for o in objects if o.id == inferred.id]
    assert written.x_inferred_from == [uses.id]


# ── #415 ────────────────────────────────────────────────────────────────────

def _renamed_actor_index() -> bs.BaselineIndex:
    """The OpenCTI fixture with its intrusion-set named by one of its MITRE aliases only."""
    raw = json.loads(RAW)
    for o in raw["objects"]:
        if o["id"] == APT29:
            o["name"] = "Midnight Blizzard"
            o.pop("aliases", None)
    index, _, _ = bs.intake(json.dumps(raw).encode(), validate=False)
    assert index is not None
    return index


def test_a_baseline_actor_is_found_by_the_mitre_name_of_its_intrusion_set_issue_415():
    rec = bs.reconcile([], LLMEnrichmentResult(), "APT29 was active.", _renamed_actor_index())
    row = {r.baseline_stix_id: r for r in rec.imported_entities}[APT29]
    assert (row.status, row.evidence_text) == (bs.BASELINE_IN_TEXT, "APT29")


def test_a_baseline_actor_is_still_found_by_its_own_name_issue_415():
    rec = bs.reconcile([], LLMEnrichmentResult(), "Midnight Blizzard was active.", _renamed_actor_index())
    row = {r.baseline_stix_id: r for r in rec.imported_entities}[APT29]
    assert row.status == bs.BASELINE_IN_TEXT
