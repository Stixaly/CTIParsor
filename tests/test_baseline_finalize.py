"""The baseline's share of Stage 4 and 5 (ADR-0090, lot 4): what a run and a
finalize give `build_bundle`, what they store and what they validate, and what
their build record names.  `build_bundle` is faked in the enrich tests, so
what it receives is what is checked; the full-job test runs the real Stage 4.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import stix2

import api.worker as worker
from api.baseline_store import baseline_sha256, intake_json, load_baseline, objects_by_id
from api.paths import uploads_dir
from api.run_config import build_record, run_build_record
from pipeline import baseline_stix
from pipeline.baseline_stix import BaselineBuild
from pipeline.stage5_validation import VALIDATED, ValidationResult

BASELINES = Path(__file__).parent / "fixtures" / "baselines"
RAW = (BASELINES / "opencti_report.json").read_bytes()
BASELINE_OBJECTS = {o["id"]: o for o in json.loads(RAW)["objects"]}

# Objects and relationships of the OpenCTI fixture, by id.
REPORT = "report--8bfd99f1-1304-415f-9ea8-597445d831da"
INTRUSION_SET = "intrusion-set--4f4f0eaf-960c-43f3-9319-4fb9a8d3ae7c"
WELLMESS = "malware--ce12e6b1-5ad7-4fc6-a2ed-2a3ca268a445"
IP = "ipv4-addr--dac4ca46-8fa0-52fb-94df-2a9acd2636bf"
REL_MATCHED = "relationship--fa5f98bc-0a81-4516-a4d7-cdf4bb46be3f"

# Baseline ids the job's rows point at, with the decisions that decide them.
IMPORTED = "malware--7a1e0c3d-0000-4000-8000-000000000001"
REJECTED = "malware--7a1e0c3d-0000-4000-8000-000000000002"
PENDING = "malware--7a1e0c3d-0000-4000-8000-000000000003"
MIXED = "malware--7a1e0c3d-0000-4000-8000-000000000004"
REL_IMPORTED = "relationship--7a1e0c3d-0000-4000-8000-000000000005"
REL_REJECTED = "relationship--7a1e0c3d-0000-4000-8000-000000000006"


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
    """A job_baselines row from the OpenCTI fixture, written as the HTTP request writes it.
    Returns the index it stored."""
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


def _relation(db, job_id, rid, source_value, rel_type, target_value, *, accepted=1, status=None, bid=None):
    with db.get_conn() as conn:
        conn.execute("INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value, accepted, "
                     "enrichment_status, baseline_stix_id) VALUES (?,?,?,?,?,?,?,?)",
                     (rid, job_id, source_value, rel_type, target_value, accepted, status, bid))
        conn.commit()


def _row(db, job_id: str = "j1") -> dict:
    with db.get_conn() as conn:
        return dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())


def _sha(db, job_id: str = "j1") -> str:
    with db.get_conn() as conn:
        return conn.execute("SELECT sha256 FROM job_baselines WHERE job_id=?", (job_id,)).fetchone()["sha256"]


def _names(bundle_json: str, stix_type: str) -> list[str]:
    return sorted(o["name"] for o in json.loads(bundle_json)["objects"] if o["type"] == stix_type)


def _bundle(*objects) -> stix2.Bundle:
    return stix2.Bundle(stix2.v21.Malware(name="Fresh", is_family=False), *objects, allow_custom=True)


def _stage5(monkeypatch) -> list[str]:
    """Stage 5's validation stands in: every bundle is valid; the texts it was given are returned."""
    texts: list[str] = []

    def validate(text):
        texts.append(text)
        return ValidationResult(VALIDATED, [])

    monkeypatch.setattr("pipeline.stage5_validation.validate_bundle", validate)
    return texts


def _stage4(monkeypatch, calls: list[dict], *, verbatim=None, trusted=frozenset()):
    """build_bundle stands in: it records what it received, sets what Stage 4 sets on the
    baseline (`verbatim`, `trusted`) and returns a small bundle.  As Stage 4's merge does,
    the verbatim objects are in the bundle too, parsed; serialize_bundle writes them back as received."""
    def build_bundle(entities, llm_result, **kwargs):
        calls.append({"entities": entities, "llm_result": llm_result, **kwargs})
        if kwargs["baseline"] is None:
            return _bundle()
        kwargs["baseline"].verbatim.update(verbatim or {})
        kwargs["baseline"].trusted = trusted
        return _bundle(*(stix2.parse(json.dumps(o), allow_custom=True) for o in (verbatim or {}).values()))

    monkeypatch.setattr(worker, "build_bundle", build_bundle)


def _enrich_job(db, monkeypatch, *, verbatim=None, trusted=frozenset()):
    """An enrich job whose rows cover each case the finalize decides: imported rows
    (baseline_only, baseline_in_text), an object all of whose rows are rejected, one
    with a pending row, one with an accepted row, and new rows of the analyst."""
    _job(db, pipeline_mode="enrich", report_text="APT29 used WellMess.")
    _store_baseline(db, "j1")
    _entity(db, "j1", "APT29", "threat_actor", status="matched", bid=INTRUSION_SET)
    _entity(db, "j1", "WellMess", "malware", status="baseline_in_text", bid=WELLMESS)
    _entity(db, "j1", "Imported", "malware", status="baseline_only", bid=IMPORTED)
    _entity(db, "j1", "198.18.12.77", "ipv4", status="baseline_only", bid=IP)
    _entity(db, "j1", "203.0.113.9", "ipv4", status="new")
    _entity(db, "j1", "SUNBURST", "malware")
    _entity(db, "j1", "Gone", "malware", accepted=0, status="matched", bid=REJECTED)
    _entity(db, "j1", "GonePeer", "malware", accepted=0, status="matched", bid=REJECTED)
    _entity(db, "j1", "Pending", "malware", accepted=None, status="matched", bid=PENDING)
    _entity(db, "j1", "PendingPeer", "malware", accepted=0, status="matched", bid=PENDING)
    _entity(db, "j1", "Mixed", "malware", accepted=1, status="matched", bid=MIXED)
    _entity(db, "j1", "MixedPeer", "malware", accepted=0, status="matched", bid=MIXED)
    _relation(db, "j1", "r-matched", "APT29", "uses", "WellMess", status="matched", bid=REL_MATCHED)
    _relation(db, "j1", "r-imported", "Imported", "uses", "APT29", status="baseline_only", bid=REL_IMPORTED)
    _relation(db, "j1", "r-in-text", "APT29", "uses", "198.18.12.77", status="baseline_in_text", bid=REL_IMPORTED)
    _relation(db, "j1", "r-rejected-1", "APT29", "targets", "Gone", accepted=0, status="matched", bid=REL_REJECTED)
    _relation(db, "j1", "r-rejected-2", "APT29", "targets", "GonePeer", accepted=0, status="matched",
              bid=REL_REJECTED)
    calls: list[dict] = []
    _stage4(monkeypatch, calls, verbatim=verbatim, trusted=trusted)
    texts = _stage5(monkeypatch)
    return calls, texts


# ── The finalize: a full job ─────────────────────────────────────────────────

def test_a_full_job_is_finalized_as_before(db, monkeypatch):
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")
    _entity(db, "j1", "SUNBURST", "malware")
    built: list[tuple[dict, object]] = []
    real = worker.build_bundle

    def spy(entities, llm_result, **kwargs):
        bundle = real(entities, llm_result, **kwargs)
        built.append((kwargs, bundle))
        return bundle

    monkeypatch.setattr(worker, "build_bundle", spy)
    texts = _stage5(monkeypatch)

    worker.re_run_final_stages("j1", quick=True)

    kwargs, bundle = built[0]
    row = _row(db)
    assert kwargs["baseline"] is None
    assert row["bundle_json"] == bundle.serialize(pretty=True) == texts[0]     # no verbatim, nothing trusted
    assert _names(row["bundle_json"], "malware") == ["SUNBURST"]
    assert "baseline_sha256" not in json.loads(row["bundle_build_json"])


# ── The finalize: an enrich job ──────────────────────────────────────────────

def test_stage_4_gets_the_baseline_index_and_its_objects_as_received(db, monkeypatch):
    calls, _ = _enrich_job(db, monkeypatch)

    worker.re_run_final_stages("j1", quick=True)

    build = calls[0]["baseline"]
    assert isinstance(build, BaselineBuild)
    assert build.index.to_json() == baseline_stix.intake(RAW, validate=False)[0].to_json()
    assert build.objects == BASELINE_OBJECTS


def test_an_object_leaves_only_when_all_its_rows_are_rejected(db, monkeypatch):
    calls, _ = _enrich_job(db, monkeypatch)

    worker.re_run_final_stages("j1", quick=True)

    # REJECTED: two rejected rows.  PENDING: one rejected, one pending (it ships).  MIXED: one rejected, one accepted.
    # REL_REJECTED: two rejected relationship rows.  REL_IMPORTED is not rejected.
    assert calls[0]["baseline"].excluded == frozenset({REJECTED, REL_REJECTED})


def test_the_imported_rows_are_not_stage_4_inputs(db, monkeypatch):
    calls, _ = _enrich_job(db, monkeypatch)

    worker.re_run_final_stages("j1", quick=True)

    entities, llm_result = calls[0]["entities"], calls[0]["llm_result"]
    assert sorted(e.value for e in entities) == ["203.0.113.9"]                    # 198.18.12.77 is baseline_only
    assert "Imported" not in llm_result.malware_families                           # nor a named list
    assert {"WellMess", "SUNBURST", "Pending", "Mixed"} <= set(llm_result.malware_families)   # baseline_in_text kept
    assert "Gone" not in llm_result.malware_families                              # rejected, as before
    assert "APT29" in llm_result.threat_actors
    assert [(r.source_value, r.target_value) for r in llm_result.relationships] == [("APT29", "WellMess")]


def test_the_bundle_is_written_with_the_verbatim_objects_and_checked_without_the_trusted_ones(db, monkeypatch):
    verbatim = {REPORT: BASELINE_OBJECTS[REPORT], WELLMESS: BASELINE_OBJECTS[WELLMESS]}
    _, texts = _enrich_job(db, monkeypatch, verbatim=verbatim, trusted=frozenset({WELLMESS}))

    worker.re_run_final_stages("j1", quick=True)

    stored = json.loads(_row(db)["bundle_json"])["objects"]
    assert BASELINE_OBJECTS[REPORT] in stored and BASELINE_OBJECTS[WELLMESS] in stored      # as given
    stored_ids = {o["id"] for o in stored}
    checked_ids = {o["id"] for o in json.loads(texts[0])["objects"]}
    assert stored_ids - checked_ids == {WELLMESS}                                # the trusted one is not checked
    assert REPORT in checked_ids                                                 # the re-issued Report is


def test_the_build_record_names_the_baseline_it_was_merged_with(db, monkeypatch):
    _enrich_job(db, monkeypatch)

    worker.re_run_final_stages("j1", quick=False)

    build = json.loads(_row(db)["bundle_build_json"])
    assert build["baseline_sha256"] == _sha(db) and build["kind"] == "finalize"


def test_an_enrich_job_without_its_baseline_is_built_without_it_and_its_imported_rows(db, monkeypatch, caplog):
    calls: list[dict] = []
    _stage4(monkeypatch, calls)
    _job(db, pipeline_mode="enrich")
    _entity(db, "j1", "APT29", "threat_actor")
    _entity(db, "j1", "WellMess", "malware", status=baseline_stix.BASELINE_ONLY,
            bid="malware--00000000-0000-4000-8000-000000000001",
            source=baseline_stix.SOURCE)

    worker.re_run_final_stages("j1", quick=True)       # no 500: the queue-refused case

    assert len(calls) == 1 and calls[0]["baseline"] is None
    assert "WellMess" not in calls[0]["llm_result"].malware_families
    assert "holds no baseline" in caplog.text


# ── The run ──────────────────────────────────────────────────────────────────

class _RunResult:
    def __init__(self, bundle, baseline_build=None):
        self.bundle, self.baseline_build = bundle, baseline_build
        self.ledger, self.validation, self.validation_errors = None, None, []

    def stage_report(self):
        return []


def _run(monkeypatch, result=None) -> list:
    """_run_pipeline with run_document faked: the Documents it received."""
    received: list = []

    def run_document(document, options, hooks):
        received.append(document)
        return result if result is not None else _RunResult(_bundle())

    monkeypatch.setattr(worker, "run_document", run_document)
    worker._run_pipeline("j1", str(uploads_dir() / "j1.txt"), "APT report.txt")
    return received


def test_a_run_gets_the_baseline_index_and_its_objects(db, monkeypatch):
    _job(db, pipeline_mode="enrich")
    index = _store_baseline(db, "j1")

    (document,) = _run(monkeypatch)

    assert document.baseline.to_json() == index.to_json()
    assert document.baseline_objects == BASELINE_OBJECTS


def test_a_full_run_gets_no_baseline(db, monkeypatch):
    _job(db)
    (document,) = _run(monkeypatch)
    assert document.baseline is None and document.baseline_objects is None


def test_a_run_writes_its_bundle_with_the_verbatim_objects_of_its_stage_4(db, monkeypatch):
    _job(db, pipeline_mode="enrich")
    index = _store_baseline(db, "j1")
    written: list = []

    def spy(bundle, verbatim=None):
        written.append(verbatim)
        return '{"spied": true}'

    monkeypatch.setattr(baseline_stix, "serialize_bundle", spy)
    build = BaselineBuild(index=index, objects=BASELINE_OBJECTS, verbatim={WELLMESS: BASELINE_OBJECTS[WELLMESS]})

    _run(monkeypatch, _RunResult(_bundle(), build))

    assert written == [build.verbatim]
    assert _row(db)["bundle_json"] == '{"spied": true}'


def test_a_full_run_writes_its_bundle_with_no_verbatim_objects(db, monkeypatch):
    _job(db)
    written: list = []

    def spy(bundle, verbatim=None):
        written.append(verbatim)
        return bundle.serialize(pretty=True)

    monkeypatch.setattr(baseline_stix, "serialize_bundle", spy)

    _run(monkeypatch)

    assert written == [None]


def test_a_run_records_the_baseline_it_was_merged_with(db, monkeypatch):
    _job(db, pipeline_mode="enrich")
    _store_baseline(db, "j1")

    _run(monkeypatch)

    build = json.loads(_row(db)["bundle_build_json"])
    assert build["kind"] == "run" and build["baseline_sha256"] == _sha(db)


# ── The build record ─────────────────────────────────────────────────────────

def test_a_build_record_carries_the_baseline_sha256_of_an_enrich_job():
    record = build_record(None, kind="finalize", baseline_sha256="ab" * 32)
    assert record["baseline_sha256"] == "ab" * 32 and record["kind"] == "finalize"


def test_a_build_record_of_a_full_job_has_no_baseline_key():
    assert "baseline_sha256" not in build_record(None, kind="quick")


def test_a_run_build_record_carries_the_baseline_sha256_only_when_there_is_one():
    assert run_build_record(None, baseline_sha256="cd" * 32)["baseline_sha256"] == "cd" * 32
    assert "baseline_sha256" not in run_build_record(None)


# ── The loaders ──────────────────────────────────────────────────────────────

def test_load_baseline_gives_the_index_and_the_objects_of_an_enrich_job(db):
    _job(db, pipeline_mode="enrich")
    index = _store_baseline(db, "j1")

    loaded_index, objects = load_baseline("j1")

    assert loaded_index.to_json() == index.to_json() and objects == BASELINE_OBJECTS


def test_load_baseline_and_its_sha256_are_none_for_a_full_job(db):
    _job(db)
    _store_baseline(db, "j1")                    # a row a full job never gets; the mode decides
    assert load_baseline("j1") is None and baseline_sha256("j1") is None


def test_baseline_sha256_is_the_stored_one(db):
    _job(db, pipeline_mode="enrich")
    _store_baseline(db, "j1")
    assert baseline_sha256("j1") == _sha(db) and len(baseline_sha256("j1")) == 64


def test_objects_by_id_gives_the_latest_version_of_an_id_the_intake_keeps():
    older = {"type": "malware", "id": WELLMESS, "modified": "2026-03-01T00:00:00.000Z", "name": "older"}
    newer = {"type": "malware", "id": WELLMESS, "modified": "2026-03-10T00:00:00.000Z", "name": "newer"}
    bundle_json = json.dumps({"type": "bundle", "objects": [newer, older]})

    assert objects_by_id(bundle_json)[WELLMESS] == newer


def test_objects_by_id_skips_what_is_not_an_object_with_a_string_id_and_keeps_the_first_of_a_tie():
    first = {"type": "malware", "id": WELLMESS, "modified": "2026-03-10T00:00:00.000Z", "name": "first"}
    second = {"type": "malware", "id": WELLMESS, "modified": "2026-03-10T00:00:00.000Z", "name": "second"}
    items = ["malware", 3, {"type": "malware"}, {"type": "malware", "id": 7}, first, second]
    bundle_json = json.dumps({"type": "bundle", "objects": items})

    assert objects_by_id(bundle_json) == {WELLMESS: first}
