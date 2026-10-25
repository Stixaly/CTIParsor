"""Stage 4 merges a baseline (ADR-0090, lot 4): the kept objects join the bundle
as received, the chosen Report is re-issued, and the ledger says what happened.

merge_baseline and reissue_report are replaced by fakes here (pipeline.baseline_stix
is patched on its module, Stage 4 imports them when it runs): these tests pin
what Stage 4 does with their results, not what they do.
"""
from __future__ import annotations

import copy
import json
import uuid
from datetime import datetime, timezone

import pytest
import stix2

from pipeline import baseline_stix as bs
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted
from pipeline.stage4_stix_mapping import _tlp_marking, build_stix_bundle
from tests import stage4_reference as ref

STAMP = "2026-01-01T00:00:00.000Z"
SHA256 = "ab" * 32
BUNDLE_ID = f"bundle--{uuid.uuid4()}"
REPORT_ID = f"report--{uuid.uuid4()}"
MALWARE_ID = f"malware--{uuid.uuid4()}"
DROPPED_ID = f"indicator--{uuid.uuid4()}"


def _baseline_report() -> dict:
    return {"type": "report", "spec_version": "2.1", "id": REPORT_ID, "created": STAMP,
            "modified": STAMP, "published": STAMP, "name": "Baseline report",
            "object_refs": [MALWARE_ID]}


def _baseline_malware() -> dict:
    return {"type": "malware", "spec_version": "2.1", "id": MALWARE_ID, "created": STAMP,
            "modified": STAMP, "name": "Kept Baseline Malware", "is_family": True}


def _baseline(scope: str | None = REPORT_ID) -> bs.BaselineBuild:
    index = bs.BaselineIndex(
        version=1, sha256=SHA256, bundle_id=BUNDLE_ID, entries=[], relations=[],
        imported_ids=frozenset({REPORT_ID, MALWARE_ID}),
        passthrough_ids=frozenset({REPORT_ID, MALWARE_ID}),
        report_ids=(REPORT_ID,), scope_report_id=scope,
    )
    return bs.BaselineBuild(index=index, objects={REPORT_ID: _baseline_report(),
                                                  MALWARE_ID: _baseline_malware()})


def _llm() -> LLMEnrichmentResult:
    return LLMEnrichmentResult(
        threat_actors=["APT29"],
        malware_families=["WellMess"],
        relationships=[RelationshipExtracted(source_value="APT29", relationship_type="uses",
                                             target_value="WellMess", confidence=0.9)],
    )


def _build(baseline=None, *, ledger=None, **kw):
    ledger = MappingLedger() if ledger is None else ledger
    bundle = build_stix_bundle([], _llm(), "r", report_text="APT29 used WellMess.",
                               ledger=ledger, baseline=baseline, **kw)
    return bundle, ledger


def _fake_merge(stix_objects, baseline):
    """Keeps the baseline malware, drops one baseline indicator, remaps nothing."""
    stix_objects.append(stix2.parse(baseline.objects[MALWARE_ID], allow_custom=True))
    return bs.MergeResult(kept=frozenset({MALWARE_ID}), stated=frozenset({MALWARE_ID}),
                          remap={}, dropped={DROPPED_ID: "baseline_rejected"},
                          removed_relationships=[], remapped_relationships={})


def _remap_merge(stix_objects, baseline):
    """As _fake_merge, but the CTIParsor malware becomes the baseline one and the
    relationship that named it is rewired onto the baseline malware."""
    dup = next(o.id for o in stix_objects if o.type == "malware")
    rel = next(o for o in stix_objects if o.type == "relationship")
    stix_objects[:] = [o for o in stix_objects if o.id != dup]
    stix_objects.append(stix2.parse(baseline.objects[MALWARE_ID], allow_custom=True))
    return bs.MergeResult(kept=frozenset({MALWARE_ID}), stated=frozenset({MALWARE_ID}),
                          remap={dup: MALWARE_ID}, dropped={DROPPED_ID: "baseline_rejected"},
                          removed_relationships=[],
                          remapped_relationships={rel.id: (rel.source_ref, MALWARE_ID)})


@pytest.fixture
def fake_merge(monkeypatch):
    monkeypatch.setattr(bs, "merge_baseline", _fake_merge)


@pytest.fixture
def fake_reissue(monkeypatch):
    """Records each call; re-issues like reissue_report does, minus the timestamps."""
    calls: list[dict] = []

    def reissue(original, kept, added, enrichment, source_ref, now):
        calls.append({"kept": set(kept), "added": list(added), "enrichment": enrichment,
                      "source_ref": source_ref, "now": now})
        d = copy.deepcopy(original)
        d["object_refs"] = [r for r in original["object_refs"] if r in kept] + list(added)
        d["x_ctiparsor_enrichment"] = enrichment
        return d

    monkeypatch.setattr(bs, "reissue_report", reissue)
    return calls


def test_without_baseline_the_build_is_unchanged():
    """baseline=None builds the bundle that an absent argument builds (invariant I1)."""
    t0 = datetime.now(timezone.utc)
    ledger_a, ledger_b = MappingLedger(), MappingLedger()
    absent = build_stix_bundle([], _llm(), "r", report_text="APT29 used WellMess.", ledger=ledger_a)
    none = build_stix_bundle([], _llm(), "r", report_text="APT29 used WellMess.", ledger=ledger_b,
                             baseline=None)
    t1 = datetime.now(timezone.utc)
    assert ref.canonical(absent.serialize(pretty=True), ledger_a.to_dict(), t0, t1) == \
        ref.canonical(none.serialize(pretty=True), ledger_b.to_dict(), t0, t1)
    assert "x_ctiparsor_enrichment" not in none.serialize()


def test_chosen_report_is_reissued_in_place_of_a_ctiparsor_report(fake_merge, fake_reissue):
    baseline = _baseline()
    bundle, _ = _build(baseline, original_filename="report.pdf", source_hash=SHA256)

    reports = [o for o in bundle.objects if o.type == "report"]
    assert [r.id for r in reports] == [REPORT_ID]
    assert reports[0]["x_ctiparsor_enrichment"]["baseline_bundle_id"] == BUNDLE_ID

    call = fake_reissue[0]
    actor_id = next(o.id for o in bundle.objects if o.type == "threat-actor")
    rel_ids = {o.id for o in bundle.objects if o.type == "relationship"}
    assert actor_id in call["added"]
    assert rel_ids <= set(call["added"])
    assert MALWARE_ID not in call["added"]
    assert call["source_ref"]["source_name"] == "original_document"
    assert call["source_ref"]["hashes"] == {"SHA-256": SHA256}

    assert baseline.verbatim[REPORT_ID]["id"] == REPORT_ID
    assert baseline.verbatim[REPORT_ID]["x_ctiparsor_enrichment"] == call["enrichment"]
    assert baseline.verbatim[MALWARE_ID] == _baseline_malware()
    assert baseline.trusted == {MALWARE_ID}


def test_without_a_chosen_report_ctiparsor_builds_its_own(fake_merge, fake_reissue):
    baseline = _baseline(scope=None)
    bundle, _ = _build(baseline)

    reports = [o for o in bundle.objects if o.type == "report"]
    assert len(reports) == 1
    assert reports[0].id != REPORT_ID
    assert reports[0]["x_ctiparsor_enrichment"]["counts"] == {
        "baseline_kept": 1, "baseline_stated": 1, "baseline_dropped": 1, "merged_into_baseline": 0,
    }
    assert MALWARE_ID in reports[0].object_refs
    assert fake_reissue == []
    assert set(baseline.verbatim) == {MALWARE_ID}


def test_kept_baseline_object_is_not_stamped(fake_merge, fake_reissue):
    bundle, _ = _build(_baseline(), tlp_level="AMBER")
    malware = next(o for o in bundle.objects if o.id == MALWARE_ID)
    assert "object_marking_refs" not in malware
    assert "created_by_ref" not in malware

    actor = next(o for o in bundle.objects if o.type == "threat-actor")
    assert _tlp_marking("AMBER").id in actor.object_marking_refs
    assert actor.created_by_ref


def test_ledger_records_the_merge_without_writing_changes(monkeypatch, fake_reissue):
    monkeypatch.setattr(bs, "merge_baseline", _remap_merge)
    _, ledger = _build(_baseline())
    d = ledger.to_dict()

    assert d["objects"][MALWARE_ID]["origin"] == "baseline"
    assert {"stix_id": DROPPED_ID, "kind": "baseline", "reason": "baseline_rejected"} in d["removed"]

    (entity,) = [e for e in d["entities"] if e["value"] == "WellMess"]
    assert entity["outcome"] == "merged"
    assert entity["reason"] == "baseline_match"
    assert entity["stix_id"] == MALWARE_ID

    (edge,) = [e for e in d["relationships"] if e["relationship_type"] == "uses"]
    assert edge["target_ref"] == MALWARE_ID
    assert all(not e["changes"] for e in d["relationships"])


def test_baseline_marking_definition_appears_once(monkeypatch, fake_reissue):
    tlp = _tlp_marking("AMBER")

    def merge(stix_objects, baseline):
        for oid in (MALWARE_ID, tlp.id):
            stix_objects.append(stix2.parse(baseline.objects[oid], allow_custom=True))
        return bs.MergeResult(kept=frozenset({MALWARE_ID, tlp.id}), stated=frozenset({MALWARE_ID}),
                              remap={}, dropped={}, removed_relationships=[],
                              remapped_relationships={})

    monkeypatch.setattr(bs, "merge_baseline", merge)
    baseline = _baseline()
    baseline.objects[tlp.id] = json.loads(tlp.serialize())
    bundle, _ = _build(baseline, tlp_level="AMBER")
    assert [o.id for o in bundle.objects].count(tlp.id) == 1
