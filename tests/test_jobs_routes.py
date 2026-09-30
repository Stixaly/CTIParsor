"""api/routes/jobs.py — job listing, status, finalize, delete, retention sweep,
source file and bundle endpoints, against a disposable PostgreSQL schema."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from api.routes import jobs as jobs_routes


@pytest.fixture()
def dirs(tmp_path, monkeypatch):
    """uploads/ and output/ (and the worker's bundle path) redirected to tmp_path."""
    uploads, output = tmp_path / "uploads", tmp_path / "output"
    uploads.mkdir()
    output.mkdir()
    monkeypatch.setattr(jobs_routes, "_UPLOADS_DIR", uploads)
    monkeypatch.setattr(jobs_routes, "_OUTPUT_DIR", output)
    monkeypatch.setattr("api.worker._ROOT", tmp_path)
    return uploads, output


def _add_job(db, job_id: str, *, filename: str = "report.pdf", status: str = "for_review",
             updated_at: str | None = None, **cols) -> None:
    ts = updated_at or db.now_iso()
    fields = {"id": job_id, "original_filename": filename, "status": status,
              "created_at": ts, "updated_at": ts, **cols}
    with db.get_conn() as conn:
        conn.execute(
            f"INSERT INTO jobs ({', '.join(fields)}) VALUES ({', '.join('?' for _ in fields)})",
            tuple(fields.values()),
        )
        conn.commit()


def _add_rows(db, job_id: str) -> None:
    with db.get_conn() as conn:
        conn.execute("INSERT INTO entities (id, job_id, value, entity_type) VALUES (?,?,?,?)",
                     (f"{job_id}_e", job_id, "APT29", "threat-actor"))
        conn.execute("INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value) "
                     "VALUES (?,?,?,?,?)", (f"{job_id}_r", job_id, "APT29", "uses", "SUNBURST"))
        conn.execute("INSERT INTO progress_events (job_id, event_type, data, created_at) VALUES (?,?,?,?)",
                     (job_id, "stage", "{}", db.now_iso()))
        conn.commit()


def _count(db, table: str, job_id: str) -> int:
    column = "id" if table == "jobs" else "job_id"
    with db.get_conn() as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {column}=?", (job_id,)).fetchone()[0]


# ── List / get / patch ───────────────────────────────────────────────────────

def test_jobs_are_listed_newest_first(temp_db_client, temp_db):
    _add_job(temp_db, "old", updated_at="2026-01-01T00:00:00+00:00")
    _add_job(temp_db, "new", tlp_level="AMBER", updated_at="2026-02-01T00:00:00+00:00")

    jobs = temp_db_client.get("/api/jobs").json()

    assert [j["id"] for j in jobs] == ["new", "old"]
    assert jobs[0]["tlp_level"] == "AMBER" and set(jobs[0]) == {
        "id", "original_filename", "status", "tlp_level", "pap_level", "created_at", "updated_at"}


def test_a_job_reports_its_entity_and_relationship_counts(temp_db_client, temp_db):
    _add_job(temp_db, "j1", report_text="the text")
    _add_rows(temp_db, "j1")

    body = temp_db_client.get("/api/jobs/j1").json()

    assert body["report_text"] == "the text"
    assert (body["entity_count"], body["relationship_count"]) == (1, 1)
    assert temp_db_client.get("/api/jobs/nope").status_code == 404


def test_the_status_can_be_set_to_a_known_value_only(temp_db_client, temp_db):
    _add_job(temp_db, "j1")

    assert temp_db_client.patch("/api/jobs/j1", json={"status": "completed"}).json() == {"status": "completed"}
    assert temp_db_client.get("/api/jobs/j1").json()["status"] == "completed"
    assert temp_db_client.patch("/api/jobs/j1", json={"status": "done"}).status_code == 400
    assert temp_db_client.patch("/api/jobs/nope", json={"status": "failed"}).status_code == 404


# ── Finalize ─────────────────────────────────────────────────────────────────

def test_finalize_rebuilds_the_bundle_and_reports_its_size(temp_db_client, temp_db):
    _add_job(temp_db, "j1", status="reviewing")

    with patch("api.routes.jobs.re_run_final_stages", return_value='{"type": "bundle"}') as rerun:
        resp = temp_db_client.post("/api/jobs/j1/finalize?quick=true")

    assert resp.json() == {"status": "reviewing", "bundle_size": 18}
    rerun.assert_called_once_with("j1", skip_rescan=True)


def test_a_failed_finalize_is_a_500(temp_db_client, temp_db):
    _add_job(temp_db, "j1")
    with patch("api.routes.jobs.re_run_final_stages", return_value=None) as rerun:
        assert temp_db_client.post("/api/jobs/j1/finalize").status_code == 500
    rerun.assert_called_once_with("j1", skip_rescan=False)


def test_finalizing_an_unknown_job_is_a_404(temp_db_client):
    with patch("api.routes.jobs.re_run_final_stages") as rerun:
        assert temp_db_client.post("/api/jobs/nope/finalize").status_code == 404
    rerun.assert_not_called()


# ── Delete ───────────────────────────────────────────────────────────────────

def test_delete_removes_the_rows_and_every_file_of_the_job(temp_db_client, temp_db, dirs):
    uploads, output = dirs
    _add_job(temp_db, "j1", filename="APT report (v2).pdf")
    _add_job(temp_db, "j2", filename="APT report (v2).pdf")
    _add_rows(temp_db, "j1")
    (uploads / "meta").mkdir()
    files = [
        uploads / "j1.pdf", uploads / "j1.txt", uploads / "meta" / "j1.json",
        output / "APT_report__v2__j1_bundle.json", output / "APT_report__v2__j1_bundle_invalid.json",
        output / "APT_report__v2__bundle.json",                 # legacy, pre-job-scoped name
        output / "j1_stage3.ckpt.json", output / "j1_stage3.ckpt.tmp",
    ]
    keep = [uploads / "j2.pdf", output / "APT_report__v2__j2_bundle.json"]
    for f in files + keep:
        f.write_text("x")

    assert temp_db_client.delete("/api/jobs/j1").json() == {"deleted": "j1"}

    assert [f for f in files if f.exists()] == []
    assert all(f.exists() for f in keep)
    assert [_count(temp_db, t, "j1") for t in ("jobs", "entities", "relationships", "progress_events")] == [0] * 4
    assert _count(temp_db, "jobs", "j2") == 1


def test_deleting_an_unknown_job_is_a_404(temp_db_client, dirs):
    assert temp_db_client.delete("/api/jobs/nope").status_code == 404


# ── Retention sweep ──────────────────────────────────────────────────────────

def _days_ago(n: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def test_the_sweep_is_off_by_default(temp_db, dirs):
    _add_job(temp_db, "ancient", updated_at=_days_ago(900))
    assert jobs_routes.sweep_expired_jobs() == 0
    assert jobs_routes.sweep_expired_jobs(retention_days=0) == 0
    assert _count(temp_db, "jobs", "ancient") == 1


def test_the_sweep_deletes_stale_jobs_but_never_active_ones(temp_db, dirs):
    uploads, _ = dirs
    _add_job(temp_db, "stale", status="completed", updated_at=_days_ago(40))
    _add_job(temp_db, "stuck", status="uploaded", updated_at=_days_ago(40))
    _add_job(temp_db, "running", status="processing", updated_at=_days_ago(40))
    _add_job(temp_db, "waiting", status="queued", updated_at=_days_ago(40))
    _add_job(temp_db, "fresh", status="completed", updated_at=_days_ago(2))
    (uploads / "stale.pdf").write_text("x")

    assert jobs_routes.sweep_expired_jobs(retention_days=30) == 2

    remaining = {j for j in ("stale", "stuck", "running", "waiting", "fresh") if _count(temp_db, "jobs", j)}
    assert remaining == {"running", "waiting", "fresh"}
    assert not (uploads / "stale.pdf").exists()


def test_the_sweep_survives_a_job_that_cannot_be_deleted(temp_db, dirs, monkeypatch):
    _add_job(temp_db, "a", status="failed", updated_at=_days_ago(10))
    _add_job(temp_db, "b", status="failed", updated_at=_days_ago(10))
    real_delete = jobs_routes._delete_job

    def flaky(job_id):
        if job_id == "a":
            raise OSError("disk gone")
        return real_delete(job_id)

    monkeypatch.setattr(jobs_routes, "_delete_job", flaky)
    assert jobs_routes.sweep_expired_jobs(retention_days=1) == 1
    assert _count(temp_db, "jobs", "a") == 1 and _count(temp_db, "jobs", "b") == 0


def test_the_sweep_uses_the_configured_retention(temp_db, dirs, monkeypatch):
    _add_job(temp_db, "stale", status="completed", updated_at=_days_ago(8))
    monkeypatch.setattr(jobs_routes, "JOB_RETENTION_DAYS", 7)
    assert jobs_routes.sweep_expired_jobs() == 1


def test_the_sweep_survives_an_unreachable_store(monkeypatch):
    def down():
        raise ConnectionError("database is down")

    monkeypatch.setattr(jobs_routes, "get_conn", down)
    assert jobs_routes.sweep_expired_jobs(retention_days=1) == 0


# ── Source file ──────────────────────────────────────────────────────────────

def test_the_source_prefers_the_pdf_and_never_serves_a_partial_capture(temp_db_client, temp_db, dirs):
    uploads, _ = dirs
    _add_job(temp_db, "j1", filename="https://example.com/a")
    (uploads / "j1.txt").write_text("ingested text")
    (uploads / "j1.pdf").write_bytes(b"%PDF-1.4 rendered page")

    resp = temp_db_client.get("/api/jobs/j1/source")

    assert resp.status_code == 200 and resp.content == b"%PDF-1.4 rendered page"
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.headers["content-disposition"] == 'inline; filename="j1.pdf"'

    (uploads / "j1.pdf").unlink()
    (uploads / "j1.pdf.part").write_bytes(b"half")
    resp = temp_db_client.get("/api/jobs/j1/source")
    assert resp.content == b"ingested text" and resp.headers["content-type"].startswith("text/plain")


def test_an_unknown_suffix_is_served_as_octet_stream(temp_db_client, temp_db, dirs):
    uploads, _ = dirs
    _add_job(temp_db, "j1")
    (uploads / "j1.zzunknown").write_bytes(b"\0\1")
    assert temp_db_client.get("/api/jobs/j1/source").headers["content-type"] == "application/octet-stream"


def test_a_missing_or_partial_source_is_a_404(temp_db_client, temp_db, dirs):
    uploads, _ = dirs
    _add_job(temp_db, "j1")
    assert temp_db_client.get("/api/jobs/j1/source").status_code == 404
    (uploads / "j1.part").write_bytes(b"half")
    assert temp_db_client.get("/api/jobs/j1/source").status_code == 404
    assert temp_db_client.get("/api/jobs/nope/source").status_code == 404


# ── Bundle and ledger ────────────────────────────────────────────────────────

def test_the_bundle_is_returned_as_json(temp_db_client, temp_db):
    bundle = {"type": "bundle", "id": "bundle--1", "objects": []}
    _add_job(temp_db, "j1", bundle_json=json.dumps(bundle))
    assert temp_db_client.get("/api/jobs/j1/bundle").json() == bundle


@pytest.mark.parametrize("cols,status", [
    ({}, 404),                                  # not built yet
    ({"bundle_json": "{broken"}, 500),
])
def test_a_missing_or_corrupt_bundle(temp_db_client, temp_db, cols, status):
    _add_job(temp_db, "j1", **cols)
    assert temp_db_client.get("/api/jobs/j1/bundle").status_code == status
    assert temp_db_client.get("/api/jobs/nope/bundle").status_code == 404


def test_the_ledger_is_returned_as_json(temp_db_client, temp_db):
    _add_job(temp_db, "j1", bundle_json="{}", bundle_ledger_json='{"entities": []}')
    assert temp_db_client.get("/api/jobs/j1/bundle/ledger").json() == {"entities": []}


@pytest.mark.parametrize("cols,status", [
    ({}, 404),                                                  # no bundle
    ({"bundle_json": "{}"}, 404),                               # bundle without a ledger
    ({"bundle_json": "{}", "bundle_ledger_json": "{oops"}, 500),
])
def test_a_missing_or_corrupt_ledger(temp_db_client, temp_db, cols, status):
    _add_job(temp_db, "j1", **cols)
    assert temp_db_client.get("/api/jobs/j1/bundle/ledger").status_code == status
    assert temp_db_client.get("/api/jobs/nope/bundle/ledger").status_code == 404
