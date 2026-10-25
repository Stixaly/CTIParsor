"""
The pure parts of the round trip (scripts/baseline_round_trip.py, ADR-0090 lot 7: A2
end to end).  Tested here: which rows ship, the Stage 4 inputs a job's rows make
(the rejections filter the JSON fields), the comparison with the baseline (lost,
altered, added, duplicated by type and name), and one offline build of an enriched
bundle over the OpenCTI fixture.

Fast, no database: the baseline is tests/fixtures/baselines/opencti_report.json and
its report text; the job rows are hand-built.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from pipeline import baseline_stix as bs
from pipeline.stage3_llm import LLMEnrichmentResult
from scripts.baseline_round_trip import (
    added_objects,
    altered_ids,
    build_enriched,
    canonical,
    compare,
    duplicates_of_baseline,
    job_inputs,
    lost_ids,
    named_key,
    ships,
)

BASELINES = Path(__file__).parent / "fixtures" / "baselines"


def _fixture_objects() -> dict[str, dict]:
    bundle = json.loads((BASELINES / "opencti_report.json").read_text(encoding="utf-8"))
    return {o["id"]: o for o in bundle["objects"]}


def _row(entity_type: str, value: str, accepted: int | None = 1, source: str = "ioc", mitre_id=None) -> dict:
    return {"value": value, "entity_type": entity_type, "context": "", "confidence": 0.9, "mitre_id": mitre_id,
            "accepted": accepted, "source": source}


def test_a_row_ships_when_accepted_or_unreviewed_and_not_held():
    assert ships({"accepted": 1})
    assert ships({"accepted": None, "held_reason": None})
    assert not ships({"accepted": 0})
    assert not ships({"accepted": None, "held_reason": "bulk"})


def test_the_rejected_countries_and_locations_leave_the_stage_4_inputs():
    llm = LLMEnrichmentResult(targeted_countries=["Brazil", "France"]).model_dump_json()
    job = {"llm_result_json": llm, "id": "job-a"}
    entities = [_row("ipv4", "198.18.12.77"),
                _row("ipv4", "198.18.12.78", accepted=0),           # rejected: not raw, not in any list
                _row("location", "France", accepted=0)]              # rejected: the country goes

    inputs = job_inputs(job, entities, [])

    assert [e.value for e in inputs["raw_entities"]] == ["198.18.12.77"]
    assert inputs["llm_result"].targeted_countries == ["Brazil"]
    assert inputs["entity_rows"] == 1


def test_a_relationship_row_is_read_with_its_legacy_dates():
    job = {"llm_result_json": None, "id": "job-b"}
    rels = [{"source_value": "WellMess", "relationship_type": "uses", "target_value": "198.18.12.77",
             "confidence": 0.8, "accepted": 1, "evidence_text": "uses it", "evidence_label": None,
             "start_time": None, "stop_time": None}]

    inputs = job_inputs(job, [], rels)

    (rel,) = inputs["llm_result"].relationships
    assert (rel.source_value, rel.relationship_type, rel.target_value) == ("WellMess", "uses", "198.18.12.77")
    assert rel.evidence_label == "reported"


def test_a_malware_row_goes_through_the_named_lists_not_the_raw_entities():
    job = {"llm_result_json": None, "id": "job-c"}

    inputs = job_inputs(job, [_row("malware", "WellMess")], [])

    assert inputs["raw_entities"] == []                                # a malware name goes through the named lists


def test_a_name_and_a_value_are_compared_folded_and_relationships_are_not_compared():
    assert named_key({"type": "malware", "name": "  WellMess "}) == ("malware", "wellmess")
    assert named_key({"type": "ipv4-addr", "value": "198.18.12.77"}) == ("ipv4-addr", "198.18.12.77")
    assert named_key({"type": "file", "hashes": {"SHA-256": "ab"}}) is None     # hash only: nothing to compare
    assert named_key({"type": "relationship", "name": "uses"}) is None


def test_lost_altered_and_added_are_read_against_the_baseline_objects():
    baseline = _fixture_objects()
    malware = next(o for o in baseline.values() if o["type"] == "malware")
    report = next(o for o in baseline.values() if o["type"] == "report")
    removed = next(o for o in baseline.values() if o["type"] == "ipv4-addr")

    enriched = copy.deepcopy(baseline)
    del enriched[removed["id"]]
    enriched[report["id"]] = {**report, "object_refs": report["object_refs"][:-1]}     # the re-issued Report
    twin = {"type": "malware", "id": "malware--11111111-1111-4111-8111-111111111111", "name": malware["name"].upper(),
            "spec_version": "2.1", "created": malware["created"], "modified": malware["modified"],
            "is_family": True}
    enriched[twin["id"]] = twin
    enriched["ipv4-addr--22222222-2222-4222-8222-222222222222"] = {
        "type": "ipv4-addr", "id": "ipv4-addr--22222222-2222-4222-8222-222222222222", "value": "203.0.113.9"}

    assert lost_ids(baseline, enriched) == [removed["id"]]
    assert altered_ids(baseline, enriched) == [report["id"]]
    assert set(added_objects(baseline, enriched)) == {twin["id"], "ipv4-addr--22222222-2222-4222-8222-222222222222"}
    dups = duplicates_of_baseline(baseline, added_objects(baseline, enriched))
    assert [(d["id"], d["baseline_ids"]) for d in dups] == [(twin["id"], [malware["id"]])]


def test_canonical_json_ignores_the_order_of_the_keys():
    assert canonical({"b": 1, "a": {"y": 2, "x": 1}}) == canonical({"a": {"x": 1, "y": 2}, "b": 1})


def test_an_offline_build_over_the_fixture_keeps_every_baseline_object_verbatim_but_the_report():
    raw = (BASELINES / "opencti_report.json").read_bytes()
    report_text = (BASELINES / "opencti_report.txt").read_text(encoding="utf-8")
    job = {"id": "00000000-0000-4000-8000-0000000000aa", "original_filename": "opencti_report.txt",
           "bundle_json": raw.decode("utf-8"), "llm_result_json": LLMEnrichmentResult().model_dump_json(),
           "report_text": report_text, "tlp_level": None, "pap_level": None}
    inputs = job_inputs(job, [_row("ipv4", "198.18.12.77")], [])

    built = build_enriched(job, inputs, None)
    cmp = compare(built["baseline"].objects, built["bundle_json"])

    assert cmp["lost"] == []
    assert set(cmp["altered"]) <= {o["id"] for o in built["baseline"].objects.values() if o["type"] == "report"}
    assert built["verdict"].status in {"validated", "unverified"}
    assert isinstance(built["baseline"].index, bs.BaselineIndex)
