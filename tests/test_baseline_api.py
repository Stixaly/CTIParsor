"""A STIX bundle the analyst already holds (ADR-0090, lot 2): the flag, POST
/api/baselines/inspect, the three ingestion routes with a baseline, what the job
store keeps, and the rows imported from it.

The worker is stubbed (start_job imports run_pipeline_async from api.worker on
each call), so no job runs: the schema validation a worker does is in
tests/test_baseline_worker.py.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import stix2

from api import baseline_store
from api.paths import uploads_dir
from pipeline import decisions, web_capture
from pipeline.baseline_stix import MAX_BASELINE_BYTES, MAX_BASELINE_OBJECTS

BASELINES = Path(__file__).parent / "fixtures" / "baselines"
_REPORT = b"APT29 deployed SUNBURST and contacted 185.220.101.45 for C2.\n"
_TEXT = _REPORT.decode()
_WARNING = "dropped invalid STIX object"


def _fixture(name: str) -> bytes:
    return (BASELINES / name).read_bytes()


@pytest.fixture()
def client(temp_db_client, monkeypatch):
    """The test client with the mode on and the worker stubbed."""
    import api.main

    api.main.limiter.reset()                  # 10/minute is shared by every test
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "1")
    uploads_dir().mkdir(parents=True, exist_ok=True)
    with patch("api.worker.run_pipeline_async", return_value="started") as spawn:
        temp_db_client.spawn = spawn          # type: ignore[attr-defined]
        yield temp_db_client


def _upload(client, baseline: bytes | None = None, **form):
    files = {"file": ("report.txt", io.BytesIO(_REPORT), "text/plain")}
    if baseline is not None:
        files["baseline_stix"] = ("bundle.json", io.BytesIO(baseline), "application/json")
    return client.post("/api/upload", files=files, data=form)


def _inspect(client, baseline: bytes, **form):
    return client.post("/api/baselines/inspect", files={"file": ("b.json", io.BytesIO(baseline), "application/json")},
                       data=form)


def _text(client, baseline: bytes | None, **extra):
    body = {"text": _TEXT, **extra}
    if baseline is not None:
        body["baseline_bundle"] = baseline.decode("utf-8")
    return client.post("/api/ingest/text", json=body)


def _rows(db, sql: str, *params) -> list[dict]:
    with db.get_conn() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def _job(db, job_id: str) -> dict:
    (row,) = _rows(db, "SELECT * FROM jobs WHERE id=?", job_id)
    return row


def _baseline_row(db, job_id: str) -> dict:
    (row,) = _rows(db, "SELECT * FROM job_baselines WHERE job_id=?", job_id)
    return row


def _no_job(db) -> bool:
    return not _rows(db, "SELECT id FROM jobs") and not _rows(db, "SELECT job_id FROM job_baselines")


def _bundle(*objects: dict) -> bytes:
    return json.dumps({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-0000000000bb",
                       "objects": list(objects)}).encode("utf-8")


# ── The flag ─────────────────────────────────────────────────────────────────

def test_status_says_whether_the_mode_is_on_and_its_limits(client, monkeypatch):
    assert client.get("/api/baselines/status").json() == {
        "enabled": True, "max_bytes": MAX_BASELINE_BYTES, "max_objects": MAX_BASELINE_OBJECTS}
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "false")
    assert client.get("/api/baselines/status").json()["enabled"] is False


@pytest.mark.parametrize("value, on", [(None, True), ("false", False), ("0", False)])
def test_the_mode_is_on_unless_the_flag_says_false(client, monkeypatch, value, on):
    """ADR-0090 accepted: on by default, `STIX_ENRICHMENT_ENABLED=false` (or 0) turns it off."""
    if value is None:
        monkeypatch.delenv("STIX_ENRICHMENT_ENABLED")
    else:
        monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", value)
    assert client.get("/api/baselines/status").json()["enabled"] is on


def test_with_the_mode_off_every_baseline_is_a_400_and_nothing_is_stored(client, temp_db, monkeypatch):
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "false")
    opencti = _fixture("opencti_report.json")
    for resp in (_inspect(client, opencti), _upload(client, opencti), _text(client, opencti),
                 client.post("/api/ingest/url", json={"url": "https://example.com/", "baseline_bundle": "{}"})):
        assert resp.status_code == 400
        assert resp.json()["detail"] == "STIX enrichment is not enabled on this server"
    assert _no_job(temp_db) and not list(uploads_dir().iterdir())
    client.spawn.assert_not_called()


def test_with_the_mode_off_a_request_without_a_baseline_is_unchanged(client, monkeypatch):
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "false")
    assert _upload(client).status_code == 200
    assert _text(client, None).status_code == 200


def test_a_report_id_alone_is_refused(client, temp_db):
    resp = _upload(client, baseline_report_id="report--daaf07ee-a8da-4ace-ae5b-0dde5deeb9ef")
    assert resp.status_code == 400 and "needs a baseline" in resp.json()["detail"]
    assert _text(client, None, baseline_report_id="report--x").status_code == 400
    assert _no_job(temp_db)


# ── POST /api/baselines/inspect ──────────────────────────────────────────────

def test_inspect_summarises_a_valid_bundle(client):
    raw = _fixture("opencti_report.json")
    resp = _inspect(client, raw)
    assert resp.status_code == 200
    body = resp.json()
    assert body["sha256"] == hashlib.sha256(raw).hexdigest()
    assert body["counts"]["intrusion-set"] == 1 and body["counts"]["report"] == 1
    assert body["scope_report_id"] == "report--8bfd99f1-1304-415f-9ea8-597445d831da"
    assert [r["id"] for r in body["reports"]] == [body["scope_report_id"]]
    assert body["needs_report_choice"] is False
    assert body["min_tlp"] == "AMBER"


def test_inspect_lists_the_reports_when_the_bundle_holds_several(client):
    raw = _fixture("two_reports.json")
    body = _inspect(client, raw).json()
    assert body["needs_report_choice"] is True and body["scope_report_id"] is None
    assert len(body["reports"]) == 2
    chosen = body["reports"][0]["id"]

    body = _inspect(client, raw, report_id=chosen).json()
    assert body["needs_report_choice"] is False and body["scope_report_id"] == chosen
    assert body["counts"]["report"] == 1


def test_inspect_refuses_what_cannot_be_read(client):
    stix20 = _inspect(client, _fixture("stix20.json"))
    assert stix20.status_code == 400 and "2.0" in stix20.json()["detail"]
    unknown = _inspect(client, _fixture("two_reports.json"), report_id="report--nope")
    assert unknown.status_code == 400 and "not a report of the bundle" in unknown.json()["detail"]
    assert _inspect(client, b"not json").status_code == 400
    assert _inspect(client, b"[]").status_code == 400
    utf16 = _inspect(client, _fixture("opencti_report.json").decode().encode("utf-16"))
    assert utf16.status_code == 400 and "UTF-8" in utf16.json()["detail"]


def test_inspect_refuses_a_bundle_over_the_limit_with_413(client):
    resp = _inspect(client, b" " * (MAX_BASELINE_BYTES + 1))
    assert resp.status_code == 413
    assert _inspect(client, b" " * MAX_BASELINE_BYTES).status_code == 400      # at the limit: read, and not a bundle


def test_inspect_stores_nothing_and_logs_nothing(client, temp_db, caplog):
    with caplog.at_level(logging.DEBUG):
        resp = _inspect(client, _fixture("invalid_objects.json"))
    assert resp.status_code == 200 and resp.json()["excluded"]
    assert _no_job(temp_db) and not list(uploads_dir().iterdir())
    assert "[baseline]" not in caplog.text


# ── POST /api/upload ─────────────────────────────────────────────────────────

def test_an_upload_with_a_baseline_makes_an_enrich_job_and_stores_the_bundle(client, temp_db):
    raw = _fixture("opencti_report.json")
    seen = {}

    def spawn(job_id, *_):
        seen["baseline"] = _rows(temp_db, "SELECT job_id FROM job_baselines WHERE job_id=?", job_id)
        return "started"

    client.spawn.side_effect = spawn
    resp = _upload(client, raw)
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    assert seen["baseline"], "the baseline is stored before the worker can start"

    job = _job(temp_db, job_id)
    assert job["pipeline_mode"] == "enrich" and job["tlp_level"] == "AMBER"       # the baseline's minimum
    row = _baseline_row(temp_db, job_id)
    assert row["sha256"] == hashlib.sha256(raw).hexdigest() and row["size_bytes"] == len(raw)
    assert row["report_id"] == "report--8bfd99f1-1304-415f-9ea8-597445d831da"
    assert row["bundle_json"] == raw.decode("utf-8") and row["validated"] == 0
    assert json.loads(row["index_json"])["version"] == 1
    assert json.loads(row["intake_json"])["sha256"] == row["sha256"]
    assert (uploads_dir() / f"{job_id}.txt").read_bytes() == _REPORT


def test_an_upload_without_a_baseline_stays_in_full_mode(client, temp_db):
    job_id = _upload(client).json()["job_id"]
    assert _job(temp_db, job_id)["pipeline_mode"] == "full"
    assert not _rows(temp_db, "SELECT job_id FROM job_baselines")


def test_an_unusable_baseline_fails_the_upload_before_the_report_is_written(client, temp_db):
    resp = _upload(client, _fixture("stix20.json"))
    assert resp.status_code == 400
    assert _no_job(temp_db) and not list(uploads_dir().iterdir())
    client.spawn.assert_not_called()


def test_an_upload_refuses_a_baseline_over_the_limit_with_413(client, temp_db):
    resp = _upload(client, b" " * (MAX_BASELINE_BYTES + 1))
    assert resp.status_code == 413 and _no_job(temp_db) and not list(uploads_dir().iterdir())


def test_objects_left_out_are_logged_once_each_after_the_job_is_stored(client, temp_db, caplog):
    raw = _fixture("invalid_objects.json")
    excluded = _inspect(client, raw).json()["excluded"]
    assert excluded
    with caplog.at_level(logging.INFO):
        job_id = _upload(client, raw).json()["job_id"]

    lines = [r for r in caplog.records if _WARNING in r.getMessage()]
    assert len(lines) == len(excluded) and all(r.levelno == logging.WARNING for r in lines)
    for item in excluded:
        assert any(f"job {job_id}: {_WARNING} {item['id']} ({item['type']}): {item['reason']} — {item['detail']}"
                   in r.getMessage() for r in lines), item
    assert json.loads(_baseline_row(temp_db, job_id)["intake_json"])["excluded"] == excluded


def test_a_baseline_with_several_reports_needs_the_one_to_enrich(client, temp_db):
    raw = _fixture("two_reports.json")
    resp = _upload(client, raw)
    assert resp.status_code == 400 and not list(uploads_dir().iterdir())
    for report in ("daaf07ee-a8da-4ace-ae5b-0dde5deeb9ef", "bee50ac0-42cd-4813-98b3-02d6d948b618"):
        assert f"report--{report}" in resp.json()["detail"]
    assert _no_job(temp_db)

    chosen = "report--bee50ac0-42cd-4813-98b3-02d6d948b618"
    job_id = _upload(client, raw, baseline_report_id=chosen).json()["job_id"]
    row = _baseline_row(temp_db, job_id)
    intake = json.loads(row["intake_json"])
    assert row["report_id"] == chosen and intake["scope_report_id"] == chosen
    assert intake["counts"]["malware"] == 1 and intake["counts"]["report"] == 1      # Report A and WellMess are out
    assert intake["counts"]["out_of_scope"] == 2


def test_a_report_the_bundle_does_not_hold_is_a_400(client, temp_db):
    resp = _upload(client, _fixture("two_reports.json"), baseline_report_id="report--nope")
    assert resp.status_code == 400 and _no_job(temp_db)


# ── The job's TLP and PAP against the baseline's (D2) ────────────────────────

def test_a_tlp_lower_than_the_baselines_is_refused_before_anything_is_stored(client, temp_db):
    raw = _fixture("opencti_report.json")                    # TLP:AMBER
    for low in ("GREEN", "clear", "white"):
        resp = _upload(client, raw, tlp_level=low)
        assert resp.status_code == 400 and "AMBER" in resp.json()["detail"], low
    assert _text(client, raw, tlp_level="green").status_code == 400
    assert _no_job(temp_db) and not list(uploads_dir().iterdir())
    client.spawn.assert_not_called()


def test_no_tlp_takes_the_baselines_minimum_and_a_higher_one_is_kept(client, temp_db, monkeypatch):
    monkeypatch.delenv("STIX_TLP", raising=False)           # the server default is then AMBER
    raw = _fixture("opencti_report.json")
    assert _job(temp_db, _upload(client, raw).json()["job_id"])["tlp_level"] == "AMBER"
    assert _job(temp_db, _upload(client, raw, tlp_level="amber").json()["job_id"])["tlp_level"] == "AMBER"
    assert _job(temp_db, _upload(client, raw, tlp_level="TLP:RED").json()["job_id"])["tlp_level"] == "RED"
    assert _job(temp_db, _upload(client, raw, tlp_level="amber+strict").json()["job_id"])["tlp_level"] == "AMBER+STRICT"


def test_no_tlp_is_never_less_than_the_full_mode_would_give(client, temp_db, monkeypatch):
    """The minimum of the baseline and the server default (STIX_TLP), the more restrictive."""
    malware = {"type": "malware", "spec_version": "2.1", "id": "malware--5b7a4c1e-93b7-4c52-9c21-4b3c1f2a7a01",
               "created": "2026-03-02T08:14:55.213Z", "modified": "2026-03-02T08:14:55.213Z", "name": "WellMess",
               "is_family": True, "object_marking_refs": [stix2.TLP_WHITE.id]}
    clear, amber = _bundle(malware), _fixture("opencti_report.json")
    assert _inspect(client, clear).json()["min_tlp"] == "CLEAR"

    def tlp(raw: bytes, **form) -> str:
        return _job(temp_db, _upload(client, raw, **form).json()["job_id"])["tlp_level"]

    monkeypatch.delenv("STIX_TLP", raising=False)
    assert tlp(clear) == "AMBER"                              # not CLEAR: full mode would mark AMBER
    monkeypatch.setenv("STIX_TLP", "GREEN")
    assert tlp(clear) == "GREEN" and tlp(amber) == "AMBER"
    monkeypatch.setenv("STIX_TLP", "RED")
    assert tlp(clear) == "RED" and tlp(amber) == "RED"
    assert tlp(clear, tlp_level="clear") == "CLEAR"           # the analyst's own choice, as in full mode


def test_the_pap_follows_the_same_rule(client, temp_db):
    marking = {"type": "marking-definition", "spec_version": "2.1",
               "id": "marking-definition--0f3b1f3a-5a0e-4b71-9d57-0c2f6d1f0a11",
               "created": "2026-03-02T08:14:55.213Z", "name": "PAP:AMBER", "definition_type": "statement",
               "definition": {"statement": "PAP:AMBER"}}
    malware = {"type": "malware", "spec_version": "2.1", "id": "malware--5b7a4c1e-93b7-4c52-9c21-4b3c1f2a7a01",
               "created": "2026-03-02T08:14:55.213Z", "modified": "2026-03-02T08:14:55.213Z", "name": "WellMess",
               "is_family": True, "object_marking_refs": [marking["id"]]}
    raw = _bundle(marking, malware)
    assert _upload(client, raw, pap_level="green").status_code == 400
    assert _job(temp_db, _upload(client, raw).json()["job_id"])["pap_level"] == "AMBER"
    assert _job(temp_db, _upload(client, raw, pap_level="red").json()["job_id"])["pap_level"] == "RED"


# ── NUL and lone surrogates ──────────────────────────────────────────────────

def _hostile_bundle() -> bytes:
    """The OpenCTI fixture plus a malware whose name, and an object whose id, hold a NUL and
    a lone surrogate, written as JSON escapes; the report's name too."""
    bundle = json.loads(_fixture("opencti_report.json"))
    for obj in bundle["objects"]:
        if obj["type"] == "report":
            obj["name"] = "Report \x00 \ud800"
            obj["object_refs"].append("malware--5b7a4c1e-93b7-4c52-9c21-4b3c1f2a7a02")
    bundle["objects"] += [
        {"type": "malware", "spec_version": "2.1", "id": "malware--5b7a4c1e-93b7-4c52-9c21-4b3c1f2a7a02",
         "created": "2026-03-02T08:14:55.213Z", "modified": "2026-03-02T08:14:55.213Z",
         "name": "Evil\x00Ware\ud800", "is_family": True},
        {"type": "malware", "spec_version": "2.1", "id": "malware--bad\x00\ud800",
         "created": "2026-03-02T08:14:55.213Z", "modified": "2026-03-02T08:14:55.213Z", "name": "x", "is_family": True},
    ]
    raw = json.dumps(bundle, ensure_ascii=True).encode("ascii")
    assert b"\\u0000" in raw and b"\\ud800" in raw
    return raw


def test_a_nul_and_a_lone_surrogate_in_a_baseline_are_stored_and_read_back(client, temp_db, caplog):
    raw = _hostile_bundle()
    inspected = _inspect(client, raw)
    assert inspected.status_code == 200
    with caplog.at_level(logging.INFO):
        resp = _upload(client, raw)
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    row = _baseline_row(temp_db, job_id)
    assert row["bundle_json"] == raw.decode("ascii")
    assert "Evil\x00Ware" in row["index_json"] or "Evil\\u0000Ware" in row["index_json"]
    job = client.get(f"/api/jobs/{job_id}")
    assert job.status_code == 200
    (bad,) = [e for e in job.json()["enrichment"]["intake"]["excluded"] if e["reason"] == "baseline_invalid"]
    assert bad["id"] == "malware--bad\x00�"                       # the surrogate cannot be encoded: U+FFFD
    assert client.get(f"/api/jobs/{job_id}/baseline").content == raw
    assert "\x00" not in caplog.text and "\ud800" not in caplog.text
    assert _WARNING in caplog.text


def test_a_baseline_that_is_not_text_is_a_400_not_a_500(client, temp_db):
    # A lone surrogate escape in the request's own JSON: the text it makes cannot be a file's content.
    body = rb'{"text": "%s", "baseline_bundle": "{\"type\": \"bundle\"} \ud800"}' % _REPORT.strip()
    resp = client.post("/api/ingest/text", content=body, headers={"content-type": "application/json"})
    assert resp.status_code == 400 and "UTF-8" in resp.json()["detail"]
    assert _no_job(temp_db)


# ── POST /api/ingest/text and /api/ingest/url ────────────────────────────────

def test_pasted_text_with_a_baseline_makes_an_enrich_job(client, temp_db):
    raw = _fixture("opencti_report.json")
    resp = _text(client, raw)
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    assert _job(temp_db, job_id)["pipeline_mode"] == "enrich"
    assert _baseline_row(temp_db, job_id)["bundle_json"] == raw.decode("utf-8")
    assert _text(client, _fixture("stix20.json")).status_code == 400
    assert len(_rows(temp_db, "SELECT id FROM jobs")) == 1


def test_a_baseline_is_read_on_its_own_threads(client, monkeypatch):
    """Not in asyncio's default executor, which `start_job` shares (a read may wait for a slot)."""
    import threading

    from api.routes import ingest

    names = []

    def spy(raw, report_id):
        names.append(threading.current_thread().name)
        return None

    monkeypatch.setattr(ingest, "read_baseline", spy)
    assert _text(client, _fixture("opencti_report.json")).status_code == 200
    assert names and all(n.startswith("baseline") for n in names)


def test_pasted_text_with_two_reports_needs_the_choice(client, temp_db):
    raw = _fixture("two_reports.json")
    assert _text(client, raw).status_code == 400
    chosen = "report--daaf07ee-a8da-4ace-ae5b-0dde5deeb9ef"
    job_id = _text(client, raw, baseline_report_id=chosen).json()["job_id"]
    assert _baseline_row(temp_db, job_id)["report_id"] == chosen


@pytest.fixture()
def capture(client, monkeypatch):
    """The URL capture, replaced: the tests say whether it was called."""
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", lambda url: url)
    mock = MagicMock(side_effect=web_capture.CaptureError("the page is not captured in this test"))
    monkeypatch.setattr(web_capture, "capture_url_to_pdf", mock)
    return mock


def test_a_url_with_an_invalid_baseline_is_a_400_before_the_capture(client, capture):
    for body in ({"baseline_bundle": _fixture("stix20.json").decode()},
                 {"baseline_bundle": _fixture("opencti_report.json").decode(), "tlp_level": "green"},
                 {"baseline_bundle": _fixture("two_reports.json").decode()}):
        resp = client.post("/api/ingest/url", json={"url": "https://example.com/report", **body})
        assert resp.status_code == 400, body
    capture.assert_not_called()


def test_a_url_with_a_valid_baseline_reaches_the_capture(client, capture):
    resp = client.post("/api/ingest/url", json={
        "url": "https://example.com/report", "baseline_bundle": _fixture("opencti_report.json").decode()})
    assert resp.status_code == 502                                  # the capture ran, and the stub failed it
    capture.assert_called_once()


# ── What a job shows, and deleting it ────────────────────────────────────────

def _insert_entity(db, eid: str, job_id: str, status: str | None, *, value: str = "APT29",
                   entity_type: str = "intrusion_set", accepted: int | None = None):
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO entities (id, job_id, value, entity_type, accepted, enrichment_status, baseline_stix_id) "
            "VALUES (?,?,?,?,?,?,?)",
            (eid, job_id, value, entity_type, accepted, status, f"intrusion-set--{eid}" if status else None))
        conn.commit()


def _insert_relationship(db, rid: str, job_id: str, status: str | None):
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value, "
            "enrichment_status, baseline_stix_id) VALUES (?,?,?,?,?,?,?)",
            (rid, job_id, "APT29", "uses", "WellMess", status, f"relationship--{rid}" if status else None))
        conn.commit()


def test_a_job_says_its_mode_and_an_enrich_job_its_baseline(client, temp_db):
    full = _upload(client).json()["job_id"]
    enrich = _upload(client, _fixture("invalid_objects.json")).json()["job_id"]

    assert client.get(f"/api/jobs/{full}").json()["pipeline_mode"] == "full"
    assert "enrichment" not in client.get(f"/api/jobs/{full}").json()
    modes = {j["id"]: j["pipeline_mode"] for j in client.get("/api/jobs").json()}
    assert modes == {full: "full", enrich: "enrich"}

    body = client.get(f"/api/jobs/{enrich}").json()
    assert body["pipeline_mode"] == "enrich"
    assert body["enrichment"]["validated"] is False
    assert body["enrichment"]["counts"] == {"entities": {}, "relationships": {}}
    assert body["enrichment"]["intake"]["excluded"] and body["enrichment"]["intake"]["counts"]["malware"] == 1
    assert "bundle_json" not in json.dumps(body)

    _insert_entity(temp_db, "e1", enrich, "baseline_only")
    _insert_entity(temp_db, "e2", enrich, "baseline_only", value="WellMess", entity_type="malware")
    _insert_entity(temp_db, "e3", enrich, "new", value="SUNBURST", entity_type="malware")
    _insert_entity(temp_db, "e4", enrich, None, value="manual", entity_type="malware")
    _insert_relationship(temp_db, "r1", enrich, "matched")
    counts = client.get(f"/api/jobs/{enrich}").json()["enrichment"]["counts"]
    assert counts == {"entities": {"baseline_only": 2, "new": 1}, "relationships": {"matched": 1}}


def test_the_original_file_can_be_downloaded(client):
    raw = _fixture("opencti_report.json")
    enrich = _upload(client, raw).json()["job_id"]
    resp = client.get(f"/api/jobs/{enrich}/baseline")
    assert resp.status_code == 200 and resp.content == raw
    assert resp.headers["content-type"].startswith("application/json")
    assert "attachment" in resp.headers["content-disposition"]
    assert client.get(f"/api/jobs/{_upload(client).json()['job_id']}/baseline").status_code == 404
    assert client.get("/api/jobs/missing/baseline").status_code == 404


def test_deleting_a_job_deletes_its_baseline(client, temp_db):
    keep = _upload(client, _fixture("opencti_report.json")).json()["job_id"]
    gone = _upload(client, _fixture("opencti_report.json")).json()["job_id"]
    assert client.delete(f"/api/jobs/{gone}").status_code == 200
    assert [r["job_id"] for r in _rows(temp_db, "SELECT job_id FROM job_baselines")] == [keep]


def test_the_retention_sweep_deletes_the_baseline_too(client, temp_db):
    from api.routes.jobs import sweep_expired_jobs

    job_id = _upload(client, _fixture("opencti_report.json")).json()["job_id"]
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE jobs SET updated_at='2000-01-01T00:00:00+00:00', status='for_review' WHERE id=?",
                     (job_id,))
        conn.commit()
    assert sweep_expired_jobs(retention_days=1) == 1
    assert not _rows(temp_db, "SELECT job_id FROM job_baselines")


# ── Rows imported from the baseline ──────────────────────────────────────────

@pytest.fixture()
def enrich_job(client, temp_db):
    job_id = _upload(client, _fixture("opencti_report.json")).json()["job_id"]
    _insert_entity(temp_db, "imported", job_id, "baseline_only")
    _insert_entity(temp_db, "in-text", job_id, "baseline_in_text", value="WellMess", entity_type="malware")
    _insert_entity(temp_db, "extracted", job_id, "matched", value="SUNBURST", entity_type="malware")
    _insert_relationship(temp_db, "r-imported", job_id, "baseline_only")
    _insert_relationship(temp_db, "r-extracted", job_id, "new")
    return job_id


def test_the_review_sees_how_each_row_relates_to_the_baseline(client, enrich_job):
    entities = {e["id"]: e for e in client.get(f"/api/jobs/{enrich_job}/entities").json()}
    assert entities["imported"]["enrichment_status"] == "baseline_only"
    assert entities["imported"]["baseline_stix_id"] == "intrusion-set--imported"
    rels = {r["id"]: r for r in client.get(f"/api/jobs/{enrich_job}/relationships").json()}
    assert rels["r-imported"]["enrichment_status"] == "baseline_only"
    assert rels["r-extracted"]["enrichment_status"] == "new"
    manual = client.post(f"/api/jobs/{enrich_job}/entities", json={"value": "X", "entity_type": "malware"}).json()
    assert manual["enrichment_status"] is None and manual["baseline_stix_id"] is None


@pytest.mark.parametrize("entity_id", ["imported", "in-text"])
@pytest.mark.parametrize("edit", [{"value": "APT-29"}, {"entity_type": "threat_actor"}, {"mitre_id": "G0016"}])
def test_an_imported_entity_is_never_edited(client, enrich_job, entity_id, edit):
    resp = client.patch(f"/api/jobs/{enrich_job}/entities/{entity_id}", json=edit)
    assert resp.status_code == 409 and "accept or reject" in resp.json()["detail"]
    row = next(e for e in client.get(f"/api/jobs/{enrich_job}/entities").json() if e["id"] == entity_id)
    assert (row["value"], row["mitre_id"]) in {("APT29", None), ("WellMess", None)}


def test_an_imported_entity_is_accepted_or_rejected_and_never_deleted(client, enrich_job):
    url = f"/api/jobs/{enrich_job}/entities/imported"
    assert client.patch(url, json={"accepted": False}).json()["accepted"] is False
    assert client.patch(url, json={"accepted": True}).json()["accepted"] is True
    assert client.patch(url, json={"accepted": None}).json()["accepted"] is None
    assert client.patch(url, json={"value": "APT29", "entity_type": "intrusion_set"}).status_code == 200   # no change
    resp = client.delete(url)
    assert resp.status_code == 409 and "reject it instead" in resp.json()["detail"]
    assert any(e["id"] == "imported" for e in client.get(f"/api/jobs/{enrich_job}/entities").json())


def test_an_extracted_entity_is_edited_and_deleted_as_before(client, enrich_job):
    url = f"/api/jobs/{enrich_job}/entities/extracted"
    assert client.patch(url, json={"value": "SUNBURST.B"}).json()["value"] == "SUNBURST.B"
    assert client.delete(url).status_code == 200


def test_the_bulk_routes_still_decide_imported_rows(client, enrich_job):
    resp = client.post(f"/api/jobs/{enrich_job}/entities/bulk",
                       json={"entity_type": "intrusion_set", "action": "reject", "scope": "all"})
    assert resp.json()["updated"] == 1
    assert client.post(f"/api/jobs/{enrich_job}/entities/accept-pending").json()["accepted"] == 2
    resp = client.post(f"/api/jobs/{enrich_job}/relationships/bulk", json={"ids": ["r-imported"], "action": "reject"})
    assert resp.json()["updated"] == 1


@pytest.mark.parametrize("edit", [{"source_value": "APT28"}, {"relationship_type": "targets"},
                                  {"target_value": "SUNBURST"}, {"start_time": "2024-01"}, {"stop_time": None}])
def test_an_imported_relationship_is_never_edited(client, enrich_job, edit):
    resp = client.patch(f"/api/jobs/{enrich_job}/relationships/r-imported", json=edit)
    assert resp.status_code == 409 and "accept or reject" in resp.json()["detail"]


def test_an_imported_relationship_is_accepted_or_rejected_and_never_deleted(client, enrich_job):
    url = f"/api/jobs/{enrich_job}/relationships/r-imported"
    assert client.patch(url, json={"accepted": False}).json()["accepted"] is False
    assert client.patch(url, json={"evidence_text": "quoted"}).json()["evidence_text"] == "quoted"
    unchanged = {"relationship_type": "uses", "source_value": "APT29"}
    assert client.patch(url, json=unchanged).status_code == 200
    resp = client.delete(url)
    assert resp.status_code == 409 and "reject it instead" in resp.json()["detail"]


def test_an_extracted_relationship_is_edited_and_deleted_as_before(client, enrich_job):
    url = f"/api/jobs/{enrich_job}/relationships/r-extracted"
    assert client.patch(url, json={"relationship_type": "targets", "start_time": "2024-01"}).status_code == 200
    assert client.delete(url).status_code == 200


def test_the_origin_of_the_baseline_is_the_servers_to_write():
    assert decisions.BASELINE_STIX == "baseline_stix"
    assert decisions.BASELINE_STIX not in decisions.CLIENT_ORIGINS
    assert decisions.BASELINE_STIX not in decisions.HUMAN_ORIGINS


def test_a_client_cannot_claim_the_baseline_origin(client, enrich_job):
    resp = client.patch(f"/api/jobs/{enrich_job}/entities/extracted",
                        json={"accepted": True, "decision_origin": decisions.BASELINE_STIX})
    assert resp.status_code == 400


# ── Cheap refusals first ─────────────────────────────────────────────────────

@pytest.fixture()
def reads(monkeypatch):
    """`baseline_stix.intake`, spied: the tests say whether a baseline was parsed."""
    from pipeline import baseline_stix

    spy = MagicMock(side_effect=baseline_stix.intake)
    monkeypatch.setattr("api.routes._common.baseline_stix.intake", spy)
    return spy


def test_a_short_text_is_refused_before_the_baseline_is_read(client, reads):
    baseline = _fixture("opencti_report.json").decode()
    resp = client.post("/api/ingest/text", json={"text": "hi", "baseline_bundle": baseline})
    assert resp.status_code == 400 and "too short" in resp.json()["detail"]
    reads.assert_not_called()


def test_a_report_over_its_limit_is_refused_before_the_baseline_is_read(client, temp_db, reads, monkeypatch):
    monkeypatch.setattr("api.routes.upload._MAX_BYTES", 16)
    resp = _upload(client, _fixture("opencti_report.json"))
    assert resp.status_code == 413 and "File too large" in resp.json()["detail"]
    reads.assert_not_called()
    assert _no_job(temp_db)


def test_with_the_mode_off_a_baseline_is_refused_without_being_read(client, monkeypatch):
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "false")
    read = MagicMock()
    monkeypatch.setattr("api.routes.upload.read_baseline_file", read)
    assert _upload(client, _fixture("opencti_report.json")).status_code == 400
    read.assert_not_called()


@pytest.mark.parametrize("failing", ["read_baseline", "baseline_markings"])
def test_whatever_stops_an_upload_takes_the_report_file_with_it(client, monkeypatch, failing):
    """Not only a refusal: a marking that cannot be resolved, a bug."""
    monkeypatch.setattr(f"api.routes.upload.{failing}", MagicMock(side_effect=RuntimeError("boom")))
    with pytest.raises(RuntimeError, match="boom"):
        _upload(client, _fixture("opencti_report.json"))
    assert not list(uploads_dir().iterdir())
    client.spawn.assert_not_called()


def test_a_refused_baseline_takes_the_report_file_with_it(client, temp_db):
    assert _upload(client, _fixture("stix20.json")).status_code == 400
    assert _upload(client, _fixture("opencti_report.json"), tlp_level="green").status_code == 400
    assert not list(uploads_dir().iterdir()) and _no_job(temp_db)


def test_the_content_length_limit_grows_with_the_mode_only(client, monkeypatch):
    """The report and the baseline share one multipart: with the mode on the header may hold both."""
    monkeypatch.setattr("api.routes.upload._MAX_BYTES", 400)
    files = {"file": ("report.txt", io.BytesIO(_REPORT), "text/plain"), "junk": ("j.bin", io.BytesIO(b"x" * 2000))}
    assert client.post("/api/upload", files=files).status_code == 200
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "false")
    files = {"file": ("report.txt", io.BytesIO(_REPORT), "text/plain"), "junk": ("j.bin", io.BytesIO(b"x" * 2000))}
    assert client.post("/api/upload", files=files).status_code == 413


@pytest.mark.parametrize("blank", ["", "  \n\t "])
def test_a_blank_baseline_is_no_baseline(client, temp_db, monkeypatch, blank):
    for flag in (True, False):
        if not flag:
            monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "false")
        body = {"text": _TEXT, "baseline_bundle": blank, "baseline_report_id": " "}
        resp = client.post("/api/ingest/text", json=body)
        assert resp.status_code == 200 and _job(temp_db, resp.json()["job_id"])["pipeline_mode"] == "full"
        resp = _upload(client, blank.encode(), baseline_report_id="")
        assert resp.status_code == 200 and _job(temp_db, resp.json()["job_id"])["pipeline_mode"] == "full"
    assert not _rows(temp_db, "SELECT job_id FROM job_baselines")


# ── A queue that is full ─────────────────────────────────────────────────────

def test_a_job_the_queue_rejects_keeps_no_baseline(temp_db_client, temp_db, monkeypatch):
    """The real `run_pipeline_async`, with a queue of one that is taken."""
    import api.main

    api.main.limiter.reset()
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "1")
    monkeypatch.setattr("api.worker._QUEUE_MAX_DEPTH", 1)
    uploads_dir().mkdir(parents=True, exist_ok=True)
    ts = temp_db.now_iso()
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES ('waiting', 'r.txt', 'queued', ?, ?)", (ts, ts))
        conn.commit()

    resp = _upload(temp_db_client, _fixture("opencti_report.json"))

    assert resp.status_code == 503 and "queue is full" in resp.json()["detail"]
    (failed,) = _rows(temp_db, "SELECT id, status, pipeline_mode FROM jobs WHERE id <> 'waiting'")
    assert (failed["status"], failed["pipeline_mode"]) == ("failed", "enrich")
    assert not _rows(temp_db, "SELECT job_id FROM job_baselines")


# ── Reading several bundles at once ──────────────────────────────────────────

def test_a_third_bundle_waits_for_a_slot_then_is_a_503(client, temp_db, capture, monkeypatch):
    from api.routes import _common

    monkeypatch.setattr(_common, "_INTAKE_WAIT_S", 0.05)
    raw = _fixture("opencti_report.json")
    held = [_common._INTAKE_SLOTS.acquire(), _common._INTAKE_SLOTS.acquire()]
    try:
        url = {"url": "https://example.com/r", "baseline_bundle": raw.decode()}
        for resp in (_inspect(client, raw), _upload(client, raw), _text(client, raw),
                     client.post("/api/ingest/url", json=url)):
            assert resp.status_code == 503 and "Busy reading" in resp.json()["detail"]
    finally:
        for _ in held:
            _common._INTAKE_SLOTS.release()
    assert _no_job(temp_db) and not list(uploads_dir().iterdir())
    capture.assert_not_called()
    assert _inspect(client, raw).status_code == 200                       # the slots were given back


def test_a_slot_is_given_back_when_the_bundle_is_refused(client):
    from api.routes import _common

    for _ in range(4):
        assert _inspect(client, _fixture("stix20.json")).status_code == 400
    assert _common._INTAKE_SLOTS.acquire(timeout=0) and _common._INTAKE_SLOTS.acquire(timeout=0)
    _common._INTAKE_SLOTS.release()
    _common._INTAKE_SLOTS.release()


# ── A long list of exclusions ────────────────────────────────────────────────

def _many_invalid(n: int) -> bytes:
    """One valid malware and `n` objects whose id is not a UUID."""
    good = {"type": "malware", "spec_version": "2.1", "id": "malware--5b7a4c1e-93b7-4c52-9c21-4b3c1f2a7a01",
            "created": "2026-03-02T08:14:55.213Z", "modified": "2026-03-02T08:14:55.213Z", "name": "WellMess",
            "is_family": True}
    return _bundle(good, *({**good, "id": f"malware--bad{i}"} for i in range(n)))


def test_a_long_list_of_exclusions_is_logged_and_shown_in_part_and_kept_whole(client, caplog):
    listed = baseline_store.EXCLUDED_LISTED
    with caplog.at_level(logging.INFO):
        job_id = _upload(client, _many_invalid(listed + 5)).json()["job_id"]

    lines = [r.getMessage() for r in caplog.records if _WARNING in r.getMessage()]
    assert len(lines) == listed
    (summary,) = [r.getMessage() for r in caplog.records if "more excluded object(s)" in r.getMessage()]
    assert f"job {job_id}: … and 5 more excluded object(s), listed in the job's intake" in summary

    shown = client.get(f"/api/jobs/{job_id}").json()["enrichment"]["intake"]
    assert len(shown["excluded"]) == listed and shown["excluded_total"] == listed + 5
    whole = client.get(f"/api/jobs/{job_id}/baseline/intake")
    assert whole.status_code == 200 and len(whole.json()["excluded"]) == listed + 5
    assert "excluded_total" not in whole.json()


def test_a_short_list_is_logged_in_full_without_a_summary(client, caplog):
    with caplog.at_level(logging.INFO):
        job_id = _upload(client, _many_invalid(3)).json()["job_id"]
    assert len([r for r in caplog.records if _WARNING in r.getMessage()]) == 3
    assert "more excluded" not in caplog.text
    assert client.get(f"/api/jobs/{job_id}").json()["enrichment"]["intake"]["excluded_total"] == 3


def test_the_whole_intake_is_a_404_for_a_job_without_a_baseline(client):
    full = _upload(client).json()["job_id"]
    assert client.get(f"/api/jobs/{full}/baseline/intake").status_code == 404
    assert client.get("/api/jobs/missing/baseline/intake").status_code == 404


def test_the_baseline_goes_with_its_job_even_without_the_explicit_delete(client, temp_db):
    job_id = _upload(client, _fixture("opencti_report.json")).json()["job_id"]
    with temp_db.get_conn() as conn:
        conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))
        conn.commit()
    assert not _rows(temp_db, "SELECT job_id FROM job_baselines")
