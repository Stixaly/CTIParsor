"""The worker's part of a baseline (ADR-0090, lot 2): the JSON-schema validation
the HTTP request does not run, before the pipeline starts.  The pipeline itself
is faked (`run_document`): in this lot an enrich job still runs in full mode.
"""
from __future__ import annotations

import io
import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

import api.worker as worker
from api.paths import uploads_dir

BASELINES = Path(__file__).parent / "fixtures" / "baselines"
_REPORT = b"APT29 deployed SUNBURST and contacted 185.220.101.45 for C2.\n"
_TS = "2026-03-02T08:14:55.213Z"
_WARNING = "dropped invalid STIX object"


class _Result:
    bundle = None
    ledger = None
    validation = None
    validation_errors: list[str] = []

    def stage_report(self):
        return []


@pytest.fixture()
def client(temp_db_client, monkeypatch):
    import api.main

    api.main.limiter.reset()
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "1")
    uploads_dir().mkdir(parents=True, exist_ok=True)
    with patch("api.worker.run_pipeline_async", return_value="started"):
        yield temp_db_client


@pytest.fixture()
def pipeline(monkeypatch):
    """`run_document`, replaced: the calls it received."""
    calls: list[object] = []

    def run_document(document, options, hooks):
        calls.append(document)
        return _Result()

    monkeypatch.setattr(worker, "run_document", run_document)
    return calls


def _bundle(*objects: dict) -> bytes:
    return json.dumps({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-0000000000cc",
                       "objects": list(objects)}).encode("utf-8")


def _malware(n: int, name: str, **props) -> dict:
    return {"type": "malware", "spec_version": "2.1", "id": f"malware--{n:08x}-0000-4000-8000-000000000000",
            "created": _TS, "modified": _TS, "name": name, "is_family": True, **props}


def _create(client, baseline: bytes) -> str:
    resp = client.post("/api/upload", files={"file": ("report.txt", io.BytesIO(_REPORT), "text/plain"),
                                             "baseline_stix": ("b.json", io.BytesIO(baseline), "application/json")})
    assert resp.status_code == 200, resp.text
    return resp.json()["job_id"]


def _run(job_id: str) -> None:
    worker._run_pipeline(job_id, str(uploads_dir() / f"{job_id}.txt"), "report.txt")


def _baseline(db, job_id: str) -> dict:
    with db.get_conn() as conn:
        return dict(conn.execute("SELECT * FROM job_baselines WHERE job_id=?", (job_id,)).fetchone())


def _status(db, job_id: str) -> str:
    with db.get_conn() as conn:
        return conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()["status"]


def _events(db, job_id: str) -> list[tuple[str, dict]]:
    with db.get_conn() as conn:
        rows = conn.execute("SELECT event_type, data FROM progress_events WHERE job_id=? ORDER BY id",
                            (job_id,)).fetchall()
    return [(r["event_type"], json.loads(r["data"])) for r in rows]


def test_the_worker_validates_the_baseline_before_the_pipeline_starts(client, temp_db, pipeline):
    raw = (BASELINES / "opencti_report.json").read_bytes()
    job_id = _create(client, raw)
    before = _baseline(temp_db, job_id)
    assert before["validated"] == 0

    _run(job_id)

    after = _baseline(temp_db, job_id)
    assert after["validated"] == 1 and after["updated_at"] >= before["updated_at"]
    assert after["bundle_json"] == raw.decode("utf-8") and after["sha256"] == before["sha256"]
    assert json.loads(after["intake_json"])["excluded"] == [] and json.loads(after["index_json"])["version"] == 1
    assert len(pipeline) == 1                          # the pipeline ran (in full mode: lot 3 reads the baseline)
    assert client.get(f"/api/jobs/{job_id}").json()["enrichment"]["validated"] is True


def test_an_object_only_the_schemas_refuse_is_excluded_by_the_worker_with_a_warning(client, temp_db, pipeline, caplog):
    good = _malware(1, "GoodWare")
    bad = _malware(2, "BadLang", lang="not a lang!")       # stix2 accepts it, the JSON schemas do not
    malformed = {**_malware(3, "Malformed"), "id": "malware--not-a-uuid"}
    job_id = _create(client, _bundle(good, bad, malformed))

    request = json.loads(_baseline(temp_db, job_id)["intake_json"])
    assert [e["id"] for e in request["excluded"]] == [malformed["id"]] and request["counts"]["malware"] == 2
    assert bad["id"] in json.loads(_baseline(temp_db, job_id)["index_json"])["imported_ids"]

    caplog.clear()
    with caplog.at_level(logging.INFO):
        _run(job_id)

    lines = [r.getMessage() for r in caplog.records if _WARNING in r.getMessage()]
    assert len(lines) == 1 and f"job {job_id}: {_WARNING} {bad['id']} (malware): baseline_invalid — " in lines[0]
    assert "RFC 5646" in lines[0]
    row = _baseline(temp_db, job_id)
    intake = json.loads(row["intake_json"])
    assert {e["id"] for e in intake["excluded"]} == {malformed["id"], bad["id"]} and intake["counts"]["malware"] == 1
    assert json.loads(row["index_json"])["imported_ids"] == [good["id"]] and row["validated"] == 1
    assert len(pipeline) == 1

    caplog.clear()
    with caplog.at_level(logging.INFO):
        worker.validate_in_worker(job_id)             # a job run again (a requeue) does not repeat the warnings
    assert _WARNING not in caplog.text


def test_a_baseline_the_worker_cannot_use_fails_the_job_with_the_reason(client, temp_db, pipeline):
    bundle = json.loads((BASELINES / "opencti_report.json").read_bytes())
    for obj in bundle["objects"]:
        if obj["type"] == "report":
            obj["lang"] = "not a lang!"                    # the chosen Report itself fails the schemas
    job_id = _create(client, json.dumps(bundle).encode("utf-8"))

    _run(job_id)

    assert _status(temp_db, job_id) == "failed" and pipeline == []
    event, data = _events(temp_db, job_id)[-1]
    assert event == "done" and data["status"] == "failed"
    assert "is refused, and the scope starts from it" in data["error"] and "RFC 5646" in data["error"]
    assert _baseline(temp_db, job_id)["validated"] == 0


def test_a_full_job_is_not_touched(client, temp_db, pipeline):
    resp = client.post("/api/upload", files={"file": ("report.txt", io.BytesIO(_REPORT), "text/plain")})
    job_id = resp.json()["job_id"]
    _run(job_id)
    assert len(pipeline) == 1 and _status(temp_db, job_id) == "failed"      # no bundle from the fake run
    with temp_db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM job_baselines").fetchone()["n"] == 0


def test_an_enrich_job_without_its_baseline_fails(client, temp_db, pipeline):
    ts = temp_db.now_iso()
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, pipeline_mode, created_at, updated_at) "
                     "VALUES ('j1', 'report.txt', 'queued', 'enrich', ?, ?)", (ts, ts))
        conn.commit()
    _run("j1")
    assert _status(temp_db, "j1") == "failed" and pipeline == []
    assert "holds no baseline" in _events(temp_db, "j1")[-1][1]["error"]


def test_a_baseline_the_worker_cannot_use_is_a_warning_not_an_error(client, temp_db, pipeline, caplog):
    bundle = json.loads((BASELINES / "opencti_report.json").read_bytes())
    for obj in bundle["objects"]:
        if obj["type"] == "report":
            obj["lang"] = "not a lang!"
    job_id = _create(client, json.dumps(bundle).encode("utf-8"))
    with caplog.at_level(logging.INFO):
        _run(job_id)
    (record,) = [r for r in caplog.records if "the baseline cannot be used" in r.getMessage()]
    assert record.levelno == logging.WARNING and record.exc_info is None and "RFC 5646" in record.getMessage()
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_a_validated_baseline_is_not_validated_again(client, temp_db, pipeline, monkeypatch):
    job_id = _create(client, (BASELINES / "opencti_report.json").read_bytes())
    _run(job_id)
    stamp = _baseline(temp_db, job_id)["updated_at"]

    def boom(*args, **kwargs):
        raise AssertionError("the baseline was read again")

    monkeypatch.setattr("api.baseline_store.baseline_stix.intake", boom)
    _run(job_id)                                     # a requeue, a lease reclaimed, a crash-resume
    assert _baseline(temp_db, job_id)["updated_at"] == stamp and len(pipeline) == 2


def test_the_worker_logs_a_long_list_of_exclusions_in_part(client, temp_db, pipeline, caplog):
    good = _malware(1, "GoodWare")
    bad = [_malware(n, f"Bad{n}", lang="not a lang!") for n in range(2, 207)]
    job_id = _create(client, _bundle(good, *bad))
    caplog.clear()
    with caplog.at_level(logging.INFO):
        _run(job_id)
    assert len([r for r in caplog.records if _WARNING in r.getMessage()]) == 200
    assert f"job {job_id}: … and 5 more excluded object(s), listed in the job's intake" in caplog.text
