"""Four API defects from the issue tracker: #758, #759, #764, #765.

A NUL byte or a lone UTF-16 surrogate in a bulk id (#758) or in an upload's file name (#759) is refused
before PostgreSQL sees it (422, 400); an entity created while its job is deleted (#764) and a status
PATCH whose job is deleted between its read and its write (#765) answer 404, not 500 or 409."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

import api.routes.entities as entities_route
import api.routes.jobs as jobs_route
from api.paths import uploads_dir


@pytest.fixture()
def job(temp_db) -> str:
    ts = temp_db.now_iso()
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES ('j1', 'r.pdf', 'reviewing', ?, ?)", (ts, ts))
        conn.execute("INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value, accepted) "
                     "VALUES ('r1', 'j1', 'APT29', 'uses', 'WellMess', NULL)")
        conn.commit()
    return "j1"


def _post_json(client, url: str, body: dict):
    # The body is sent with \u escapes, so the server receives the NUL or the lone surrogate itself.
    return client.post(url, content=json.dumps(body), headers={"Content-Type": "application/json"})


def _accepted(db, rel_id: str = "r1"):
    with db.get_conn() as conn:
        return conn.execute("SELECT accepted FROM relationships WHERE id=?", (rel_id,)).fetchone()["accepted"]


# ── #758: a bulk id that PostgreSQL cannot store is a 422, and nothing is written ─────────────

@pytest.mark.parametrize("bad_id", ["a\x00", "\ud800"])
def test_a_bulk_id_postgresql_cannot_store_is_refused(temp_db, temp_db_client, job, bad_id):
    r = _post_json(temp_db_client, "/api/jobs/j1/relationships/bulk", {"ids": ["r1", bad_id], "action": "accept"})
    assert r.status_code == 422
    assert _accepted(temp_db) is None


def test_a_bulk_of_storable_ids_still_accepts(temp_db_client, job):
    r = _post_json(temp_db_client, "/api/jobs/j1/relationships/bulk", {"ids": ["r1"], "action": "accept"})
    assert r.status_code == 200
    assert r.json()["updated"] == 1


# ── #759: a file name PostgreSQL cannot store is a 400, and no file is left in uploads/ ──────

def test_an_upload_name_with_a_nul_is_refused_before_anything_is_written(temp_db_client):
    uploads_dir().mkdir(parents=True, exist_ok=True)
    # httpx would send a NUL in a file name as the text "%00", so the multipart body is written by hand.
    body = (b'--b\r\nContent-Disposition: form-data; name="file"; filename="rapport\x00.txt"\r\n'
            b'Content-Type: text/plain\r\n\r\nAPT29 used WellMess.\r\n--b--\r\n')
    headers = {"Content-Type": "multipart/form-data; boundary=b"}
    with patch("api.worker.run_pipeline_async", return_value="started") as spawn:
        r = temp_db_client.post("/api/upload", content=body, headers=headers)
    assert r.status_code == 400
    assert list(uploads_dir().iterdir()) == []
    spawn.assert_not_called()


# ── #764: an entity added to a job deleted meanwhile is a 404 ───────────────────────────────

def test_an_entity_for_a_job_deleted_before_the_insert_is_404(temp_db_client, job, monkeypatch):
    real_require_job = entities_route.require_job

    def delete_after_the_check(conn, job_id):
        real_require_job(conn, job_id)
        conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))

    monkeypatch.setattr(entities_route, "require_job", delete_after_the_check)
    r = temp_db_client.post("/api/jobs/j1/entities", json={"value": "WellMess", "entity_type": "malware"})
    assert r.status_code == 404


# ── #765: a status PATCH whose job is deleted before its UPDATE is a 404, not a 409 ─────────

def test_a_completed_patch_for_a_job_deleted_before_its_update_is_404(temp_db_client, temp_db, job, monkeypatch):
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE jobs SET bundle_json='{}' WHERE id='j1'")
        conn.commit()
    real_get_conn = jobs_route.get_conn

    class DeletedBeforeTheUpdate:
        """Forwards to the job store, and deletes the job as another process would just before the status UPDATE."""

        def __init__(self, conn):
            self._conn = conn

        def __enter__(self):
            self._conn.__enter__()
            return self

        def __exit__(self, *exc):
            return self._conn.__exit__(*exc)

        def __getattr__(self, name):
            return getattr(self._conn, name)

        def execute(self, sql, params=None):
            if sql.startswith("UPDATE jobs SET status"):
                self._conn.execute("DELETE FROM jobs WHERE id=?", ("j1",))
                self._conn.commit()
            return self._conn.execute(sql, params)

    monkeypatch.setattr(jobs_route, "get_conn", lambda: DeletedBeforeTheUpdate(real_get_conn()))
    r = temp_db_client.patch("/api/jobs/j1", json={"status": "completed"})
    assert r.status_code == 404
