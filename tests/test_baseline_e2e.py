"""End to end: the baseline merge of Stage 4 (ADR-0090, lot 4).

The real build_bundle, merge_baseline, reissue_report and serialize_bundle run,
on the real intake of the bundles they write; the audit invariants of
scripts/audit_bundle_invariants.py judge the results.  The finalize test runs
re_run_final_stages on the job store; Stage 5's validator stands in there, as in
tests/test_baseline_finalize.py.  The environment is pinned as in
tests/test_stage4_reference.py, so the developer's .env does not change a result.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

import pytest
import stix2

import api.worker as worker
from api.baseline_store import intake_json
from api.paths import uploads_dir
from api.routes._common import tlp_at_least
from pipeline import baseline_stix
from pipeline.baseline_stix import BaselineBuild
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage5_validation import VALIDATED, ValidationResult, validate_bundle
from scripts import audit_bundle_invariants as audit
from tests import stage4_reference as ref
from tests.test_stage4_reference import _stage4_defaults

BASELINES = Path(__file__).parent / "fixtures" / "baselines"
RAW = (BASELINES / "opencti_report.json").read_bytes()
OPENCTI_TEXT = (BASELINES / "opencti_report.txt").read_text(encoding="utf-8")
SHA256 = "9f2b6c1d4a7e3085b1d6f4e2a9c37d58e0b4a1f6c2d93e7a5b80c4d1f6e3a972"

# Objects and relationships of the OpenCTI fixture, by id.
REPORT = "report--8bfd99f1-1304-415f-9ea8-597445d831da"
INTRUSION_SET = "intrusion-set--4f4f0eaf-960c-43f3-9319-4fb9a8d3ae7c"
WELLMESS = "malware--ce12e6b1-5ad7-4fc6-a2ed-2a3ca268a445"
IP = "ipv4-addr--dac4ca46-8fa0-52fb-94df-2a9acd2636bf"
REL_USES_WELLMESS = "relationship--fd3e7a73-f3b2-485d-a28b-111fadd6bea1"
REL_INDICATES_WELLMESS = "relationship--75b18d1d-5f66-4989-a19f-33ebd8c660f6"
IDENTITY = "identity--7b24b13f-17ba-4194-b6ae-4b1d3423bf15"

# What the analyst's run reads from the report: the alias of the intrusion-set, its malware, the edge between them.
OPENCTI_SCENARIO = {
    "report_name": "Cozy Bear weekly note",
    "report_text": OPENCTI_TEXT,
    "original_filename": "opencti_report.txt",
    "entities": [{"value": SHA256, "entity_type": "sha256"}],
    "llm_result": {
        "threat_actors": ["Cozy Bear"],
        "malware_families": ["SUNBURST"],
        "relationships": [{"source_value": "Cozy Bear", "relationship_type": "uses", "target_value": "SUNBURST"}],
    },
}

# A document that states nothing the baseline does not already hold.
EMPTY_DOCUMENT = {
    "report_name": "Nothing new",
    "report_text": "Nothing the baseline does not hold.",
    "original_filename": "empty.txt",
    "entities": [],
    "llm_result": {"threat_actors": [], "malware_families": [], "relationships": []},
}


@pytest.fixture(scope="module", autouse=True)
def stage4_pinned():
    with _stage4_defaults():
        yield


def _received() -> dict[str, dict]:
    """The OpenCTI baseline's objects as received, by id: a fresh parse, the reference of I2."""
    return {o["id"]: o for o in json.loads(RAW)["objects"]}


def _build(scenario: dict, baseline: BaselineBuild | None = None,
           ledger: MappingLedger | None = None) -> stix2.Bundle:
    """build_bundle on a scenario's inputs, as tests/stage4_reference.build runs it (no long-distance answer)."""
    from models.schemas import RawEntity
    from pipeline.orchestrator import build_bundle
    from pipeline.stage3_llm import LLMEnrichmentResult
    from pipeline.temporal import Anchor

    assert "long_distance_answer" not in scenario
    anchor = scenario.get("document_anchor")
    source = scenario.get("source_bytes")
    return build_bundle(
        [RawEntity.model_validate(e) for e in scenario["entities"]],
        LLMEnrichmentResult.model_validate(scenario["llm_result"]),
        report_name=scenario["report_name"],
        report_text=scenario["report_text"],
        original_filename=scenario["original_filename"],
        source_hash=scenario.get("source_hash"),
        source_bytes=source.encode("utf-8") if source else None,
        policy=scenario.get("policy"),
        tlp_level=scenario.get("tlp"),
        pap_level=scenario.get("pap"),
        cve_metadata=scenario.get("cve_metadata") or {},
        graph_completion=True,
        long_distance=False,
        ledger=MappingLedger() if ledger is None else ledger,
        document_anchor=Anchor.model_validate(anchor) if anchor else None,
        baseline=baseline,
    )


def _when(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _by_type(objects: list[dict], stix_type: str) -> list[dict]:
    return [o for o in objects if o["type"] == stix_type]


def _baseline_of(raw: dict, excluded: frozenset[str] = frozenset()) -> BaselineBuild:
    """The BaselineBuild of a baseline bundle, read by the intake as the job store reads it."""
    index, _, _ = baseline_stix.intake(json.dumps(raw).encode(), validate=False)
    assert index is not None
    return BaselineBuild(index=index, objects={o["id"]: o for o in raw["objects"]}, excluded=excluded)


# ── 1. Round trip: CTIParsor's bundle, given back as its own baseline ───────

@pytest.fixture(scope="module")
def apt_round_trip():
    scenario = ref.load_scenario("apt_report")
    first_json = baseline_stix.serialize_bundle(_build(scenario))
    index, _, _ = baseline_stix.intake(first_json.encode(), validate=False)
    assert index is not None
    baseline = BaselineBuild(index=index, objects={o["id"]: o for o in json.loads(first_json)["objects"]})
    second_json = baseline_stix.serialize_bundle(_build(scenario, baseline), baseline.verbatim)
    return json.loads(first_json), json.loads(second_json), second_json


def test_a_round_trip_has_the_same_objects_and_one_reissued_report(apt_round_trip):
    first, second, _ = apt_round_trip
    ids_second = [o["id"] for o in second["objects"]]
    assert set(ids_second) == {o["id"] for o in first["objects"]}
    assert len(ids_second) == len(set(ids_second))
    (first_report,) = _by_type(first["objects"], "report")
    (report,) = _by_type(second["objects"], "report")
    assert report["id"] == first_report["id"]


def test_a_round_trip_writes_every_object_as_it_was_first_built(apt_round_trip):
    first, second, _ = apt_round_trip
    by_id = {o["id"]: o for o in second["objects"]}
    for o in first["objects"]:
        if o["type"] != "report":
            assert by_id[o["id"]] == o, o["id"]


def test_a_round_trip_report_keeps_every_reference_of_the_first_one(apt_round_trip):
    first, second, _ = apt_round_trip
    (first_report,) = _by_type(first["objects"], "report")
    (report,) = _by_type(second["objects"], "report")
    assert set(first_report["object_refs"]) <= set(report["object_refs"])


def test_a_round_trip_bundle_is_not_invalid(apt_round_trip):
    _, _, second_json = apt_round_trip
    assert validate_bundle(second_json).status in ("validated", "unverified")


def test_a_round_trip_ledgers_each_object_it_ships_from_the_baseline_as_the_baselines():
    scenario = ref.load_scenario("apt_report")
    first_json = baseline_stix.serialize_bundle(_build(scenario))
    index, _, _ = baseline_stix.intake(first_json.encode(), validate=False)
    assert index is not None
    baseline = BaselineBuild(index=index, objects={o["id"]: o for o in json.loads(first_json)["objects"]})
    ledger = MappingLedger()

    bundle = _build(scenario, baseline, ledger=ledger)

    shipped = {o.id for o in bundle.objects if hasattr(o, "id")}
    kept = [oid for oid in baseline.objects if oid in shipped and oid != index.scope_report_id]
    assert len(kept) > 1
    led = ledger.to_dict()
    assert {led["objects"][oid]["origin"] for oid in kept} == {"baseline"}
    assert [e for e in led["entities"] if e.get("stix_id") in kept and e["outcome"] == "emitted"] == []
    assert [r for r in led["relationships"] if r.get("stix_id") in kept and r["outcome"] == "emitted"] == []


# ── 2. I2 on the OpenCTI fixture ─────────────────────────────────────────────

@pytest.fixture(scope="module")
def opencti_merged():
    index, _, _ = baseline_stix.intake(RAW, validate=False)
    assert index is not None
    baseline = BaselineBuild(index=index, objects={o["id"]: o for o in json.loads(RAW)["objects"]})
    text = baseline_stix.serialize_bundle(_build(OPENCTI_SCENARIO, baseline), baseline.verbatim)
    return json.loads(text)


def test_a_threat_actor_named_in_the_baseline_becomes_its_intrusion_set(opencti_merged):
    objects = opencti_merged["objects"]
    assert not [o for o in _by_type(objects, "threat-actor") if o.get("name") == "APT29"]
    assert not [o for o in _by_type(objects, "threat-actor") if o.get("name") == "Cozy Bear"]


def test_the_edge_to_the_new_malware_starts_at_the_intrusion_set(opencti_merged):
    objects = opencti_merged["objects"]
    (sunburst,) = [o for o in _by_type(objects, "malware") if o["name"] == "SUNBURST"]
    (edge,) = [o for o in _by_type(objects, "relationship")
               if o["relationship_type"] == "uses" and o["target_ref"] == sunburst["id"]]
    assert edge["source_ref"] == INTRUSION_SET


def test_every_kept_baseline_object_is_written_as_received_with_its_provenance(opencti_merged):
    received = _received()
    by_id = {o["id"]: o for o in opencti_merged["objects"]}
    kept = [oid for oid in received if oid in by_id and oid != REPORT]
    assert {INTRUSION_SET, WELLMESS, IP} <= set(kept)
    for oid in kept:
        assert by_id[oid] == received[oid], oid
        assert by_id[oid].get("created_by_ref") == received[oid].get("created_by_ref"), oid
        assert by_id[oid].get("object_marking_refs") == received[oid].get("object_marking_refs"), oid


def test_the_one_report_is_the_fixture_report_reissued(opencti_merged):
    received_report = _received()[REPORT]
    reports = _by_type(opencti_merged["objects"], "report")
    assert [r["id"] for r in reports] == [REPORT]
    (report,) = reports
    for key in ("confidence", "created", "created_by_ref", "object_marking_refs"):
        assert report[key] == received_report[key], key
    assert _when(report["modified"]) > _when(received_report["modified"])
    assert "x_ctiparsor_enrichment" in report


def test_the_reissued_report_states_the_new_malware(opencti_merged):
    objects = opencti_merged["objects"]
    (report,) = _by_type(objects, "report")
    (sunburst,) = [o for o in _by_type(objects, "malware") if o["name"] == "SUNBURST"]
    assert sunburst["id"] in report["object_refs"]


# ── 3. A baseline without a report ───────────────────────────────────────────

@pytest.fixture(scope="module")
def opencti_without_report():
    raw = json.loads(RAW)
    raw["objects"] = [o for o in raw["objects"] if o["type"] != "report"]
    index, _, _ = baseline_stix.intake(json.dumps(raw).encode(), validate=False)
    assert index is not None and index.scope_report_id is None
    baseline = BaselineBuild(index=index, objects={o["id"]: o for o in raw["objects"]})
    return json.loads(baseline_stix.serialize_bundle(_build(OPENCTI_SCENARIO, baseline), baseline.verbatim))


def test_without_a_baseline_report_ctiparsor_builds_its_own_with_the_enrichment(opencti_without_report):
    (report,) = _by_type(opencti_without_report["objects"], "report")
    assert report["id"] != REPORT
    assert "x_ctiparsor_enrichment" in report


def test_the_own_report_states_the_intrusion_set_and_not_the_baseline_only_objects(opencti_without_report):
    objects = opencti_without_report["objects"]
    by_id = {o["id"]: o for o in objects}
    (report,) = _by_type(objects, "report")
    assert IP in by_id                                   # kept from the baseline, the text does not name it
    assert INTRUSION_SET in report["object_refs"]
    assert IP not in report["object_refs"]


# ── 4. The audit invariants on the bundles of 1 to 3 ─────────────────────────

def test_the_audit_invariants_hold_on_the_round_trip_and_both_baselines(apt_round_trip, opencti_merged,
                                                                       opencti_without_report):
    _, second, _ = apt_round_trip
    bundles = [("apt_report_round_trip", second), ("opencti_merged", opencti_merged),
               ("opencti_without_report", opencti_without_report)]
    # check_orphan_objects is left out: it flags the edges Stage 4 keeps outside its
    # Report on purpose (audit B 8.4.2), 13 of them in a plain build without any baseline.
    failures = [(f.name, f.status, f.count, f.detail) for f in audit.run_all(bundles)
                if f.status != "OK" and f.name != "check_orphan_objects"]
    assert failures == []


# ── 5. Finalize: a rejected baseline object leaves the bundle ────────────────

@pytest.fixture()
def db(temp_db):
    uploads_dir().mkdir(parents=True)        # under tmp_path (conftest)
    return temp_db


def _job(db, job_id: str = "j1", *, pipeline_mode: str = "full", report_text: str = "APT29 used WellMess.") -> str:
    ts = db.now_iso()
    with db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, pipeline_mode, report_text, created_at, "
                     "updated_at) VALUES (?,?,?,?,?,?,?)",
                     (job_id, "APT report.txt", "reviewing", pipeline_mode, report_text, ts, ts))
        conn.commit()
    return job_id


def _store_baseline(db, job_id: str, *, validated: int = 1):
    """A job_baselines row from the OpenCTI fixture, written as the HTTP request writes it."""
    index, intake, _ = baseline_stix.intake(RAW, validate=False)
    ts = db.now_iso()
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO job_baselines (job_id, sha256, size_bytes, report_id, bundle_json, index_json, "
            "intake_json, validated, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (job_id, intake.sha256, len(RAW), intake.scope_report_id, RAW.decode("utf-8"), index.to_json(),
             intake_json(intake), validated, ts, ts))
        conn.commit()
    return index


def _entity(db, job_id, value, etype, *, accepted=1, status=None, bid=None, source="llm"):
    with db.get_conn() as conn:
        conn.execute("INSERT INTO entities (id, job_id, value, entity_type, accepted, source, enrichment_status, "
                     "baseline_stix_id) VALUES (?,?,?,?,?,?,?,?)",
                     (f"{job_id}-{etype}-{value}", job_id, value, etype, accepted, source, status, bid))
        conn.commit()


def _row(db, job_id: str = "j1") -> dict:
    with db.get_conn() as conn:
        return dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())


def _stage5(monkeypatch) -> None:
    """Stage 5's validation stands in: every bundle is valid."""
    monkeypatch.setattr("pipeline.stage5_validation.validate_bundle",
                        lambda text: ValidationResult(VALIDATED, []))


def test_a_rejected_baseline_object_leaves_with_its_relationships_and_is_ledgered(db, monkeypatch):
    _job(db, pipeline_mode="enrich", report_text=OPENCTI_TEXT)
    _store_baseline(db, "j1")
    _entity(db, "j1", "APT29", "threat_actor", status="matched", bid=INTRUSION_SET)
    _entity(db, "j1", "WellMess", "malware", accepted=0, status=baseline_stix.BASELINE_ONLY, bid=WELLMESS,
            source=baseline_stix.SOURCE)
    _stage5(monkeypatch)

    worker.re_run_final_stages("j1", quick=True)

    row = _row(db)
    objects = json.loads(row["bundle_json"])["objects"]
    by_id = {o["id"]: o for o in objects}
    assert WELLMESS not in by_id
    assert {REL_USES_WELLMESS, REL_INDICATES_WELLMESS}.isdisjoint(by_id)
    assert not [o for o in _by_type(objects, "relationship") if WELLMESS in (o["source_ref"], o["target_ref"])]
    assert WELLMESS not in by_id[REPORT]["object_refs"]
    assert set(by_id[REPORT]["object_refs"]) <= set(by_id)
    assert by_id[INTRUSION_SET] == _received()[INTRUSION_SET]
    ledger = json.loads(row["bundle_ledger_json"])
    assert [r for r in ledger["removed"] if r["stix_id"] == WELLMESS] == [
        {"stix_id": WELLMESS, "kind": "baseline", "reason": "baseline_rejected"}]


# ── 6. A chosen Report with no reference left ────────────────────────────────

def test_a_chosen_report_whose_references_all_leave_is_not_re_issued(caplog):
    raw = json.loads(RAW)
    next(o for o in raw["objects"] if o["id"] == REPORT)["object_refs"] = [WELLMESS]   # it lists one malware
    baseline = _baseline_of(raw, excluded=frozenset({WELLMESS}))                       # which the analyst rejects
    ledger = MappingLedger()

    with caplog.at_level(logging.WARNING):
        bundle = _build(EMPTY_DOCUMENT, baseline, ledger=ledger)
    objects = json.loads(baseline_stix.serialize_bundle(bundle, baseline.verbatim))["objects"]

    by_id = {o["id"]: o for o in objects}
    assert _by_type(objects, "report") == []                                  # no Report with the chosen id, nor any
    assert IDENTITY in by_id                                                  # kept, though the Report does not list it
    assert WELLMESS not in by_id                                              # the rejected malware does not
    assert {"stix_id": REPORT, "kind": "baseline", "reason": "baseline_report_empty"} in ledger.to_dict()["removed"]
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("is not re-issued" in m for m in warnings)


def test_an_enrich_build_without_a_baseline_report_that_states_nothing_ships_no_report(caplog):
    raw = json.loads(RAW)
    raw["objects"] = [o for o in raw["objects"] if o["type"] != "report"]
    baseline = _baseline_of(raw)

    with caplog.at_level(logging.WARNING):
        bundle = _build(EMPTY_DOCUMENT, baseline)
    objects = json.loads(baseline_stix.serialize_bundle(bundle, baseline.verbatim))["objects"]

    assert _by_type(objects, "report") == []
    assert INTRUSION_SET in {o["id"] for o in objects}                        # the kept baseline objects ship
    assert "no Report" in caplog.text
    assert "is not re-issued" not in caplog.text


# ── 7. The ledger's outside_report ───────────────────────────────────────────

def test_a_kept_object_the_chosen_report_lists_and_the_document_does_not_state_is_not_outside_it():
    ledger = MappingLedger()
    baseline = _baseline_of(json.loads(RAW))

    _build(OPENCTI_SCENARIO, baseline, ledger=ledger)
    objects = ledger.to_dict()["objects"]

    for oid in (WELLMESS, IP, REL_USES_WELLMESS):                             # listed by the Report, not stated
        assert "outside_report" not in objects[oid], oid
    assert objects[IDENTITY]["outside_report"] is True                        # neither listed nor stated


# ── 8. A TLP:GREEN baseline in a TLP:AMBER job ───────────────────────────────

def _green_baseline() -> dict:
    """The OpenCTI fixture with its TLP:AMBER marking turned into OpenCTI's
    TLP:GREEN (the standard id, as OpenCTI exports it) on every object."""
    amber = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    raw = json.loads(RAW)
    for o in raw["objects"]:
        if o["id"] == amber:
            o.update(id=stix2.TLP_GREEN.id, name="TLP:GREEN")
        if "object_marking_refs" in o:
            o["object_marking_refs"] = [stix2.TLP_GREEN.id if r == amber else r for r in o["object_marking_refs"]]
    return raw


def test_a_green_baseline_in_an_amber_job_ships_both_tlp_definitions_each_on_its_own_objects():
    """D2 lets a job be more restrictive than its baseline; I2 keeps the baseline's
    markings on its objects.  The bundle then holds two TLP definitions: the
    baseline's GREEN on the objects it keeps, the job's AMBER on what CTIParsor
    builds, never both on one object."""
    raw = _green_baseline()
    index, summary, _ = baseline_stix.intake(json.dumps(raw).encode(), validate=False)
    assert index is not None
    assert summary.min_tlp == "GREEN" and tlp_at_least("AMBER", summary.min_tlp)   # D2 accepts the job
    baseline = BaselineBuild(index=index, objects={o["id"]: o for o in raw["objects"]})

    bundle = _build({**OPENCTI_SCENARIO, "tlp": "AMBER"}, baseline)
    objects = json.loads(baseline_stix.serialize_bundle(bundle, baseline.verbatim))["objects"]

    tlp = {o["id"] for o in _by_type(objects, "marking-definition") if o.get("definition_type", "").casefold() == "tlp"}
    assert tlp == {stix2.TLP_GREEN.id, stix2.TLP_AMBER.id}
    received = {o["id"]: o for o in raw["objects"]}
    marked = [o for o in objects if "object_marking_refs" in o]
    for o in marked:
        expected = [stix2.TLP_GREEN.id] if o["id"] in received else [stix2.TLP_AMBER.id]
        assert o["object_marking_refs"] == expected, o["id"]
    assert REPORT in {o["id"] for o in marked}                                # re-issued with its own GREEN
    assert any(o["id"] not in received for o in marked)                       # CTIParsor built something
