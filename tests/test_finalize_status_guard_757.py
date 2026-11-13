"""POST /api/jobs/{id}/finalize refuses a job the worker has not finished (#757).

A job that is uploaded, queued or processing is refused with 409 before any
rebuild, and the publication of a rebuild is guarded by the job's status too.
A job deleted between the route's read and the publication answers 404, and
nothing is written for it.  Each race is driven from a second connection in a
thread, at a point the test chooses (the bundle build hook)."""
from __future__ import annotations

import threading

import pytest

import api.worker as worker
from api.paths import output_dir, uploads_dir

REFUSED = ("uploaded", "queued", "processing")
STORED_BUNDLE = '{"before": true}'


@pytest.fixture()
def db(temp_db):
    uploads_dir().mkdir(parents=True, exist_ok=True)     # under tmp_path (conftest)
    output_dir().mkdir(parents=True, exist_ok=True)
    return temp_db


def _add_job(db, job_id: str = "j1", *, status: str = "reviewing", **cols) -> None:
    ts = db.now_iso()
    fields = {"id": job_id, "original_filename": "APT report.txt", "status": status,
              "created_at": ts, "updated_at": ts, "report_text": "APT29 used SUNBURST.", **cols}
    with db.get_conn() as conn:
        conn.execute(f"INSERT INTO jobs ({', '.join(fields)}) VALUES ({', '.join('?' for _ in fields)})",
                     tuple(fields.values()))
        conn.commit()


def _stored(db, job_id: str = "j1") -> dict | None:
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    return dict(row) if row else None


def _in_another_connection(db, statement: str) -> None:
    """Run one write on a thread with its own connection, and wait for it."""
    errors: list[BaseException] = []

    def write():
        try:
            with db.get_conn() as conn:
                conn.execute(statement)
                conn.commit()
        except BaseException as exc:      # noqa: BLE001 — handed to the test thread
            errors.append(exc)
        finally:
            db.reset_connections()

    thread = threading.Thread(target=write, daemon=True)
    thread.start()
    thread.join(60)
    assert not thread.is_alive() and not errors, errors


def _spy_on_builds(monkeypatch) -> list[int]:
    """Counts the bundle builds; the build itself runs unchanged."""
    real = worker.build_bundle
    calls: list[int] = []

    def build(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(worker, "build_bundle", build)
    return calls


def _export_files(job_id: str = "j1") -> list:
    return sorted(output_dir().glob(f"*{job_id}*"))


# ── The refusal: before any work, and nothing written ──────────────────────

@pytest.mark.parametrize("quick", [True, False], ids=["quick", "full"])
@pytest.mark.parametrize("status", REFUSED)
def test_a_job_the_worker_has_not_finished_is_refused_and_nothing_is_written(
        db, temp_db_client, monkeypatch, status, quick):
    _add_job(db, status=status, bundle_json=STORED_BUNDLE, bundle_validation="unverified",
             bundle_build_json='{"kind": "run"}')
    before = _stored(db)
    builds = _spy_on_builds(monkeypatch)

    resp = temp_db_client.post(f"/api/jobs/j1/finalize?quick={'true' if quick else 'false'}")

    assert resp.status_code == 409
    assert status in resp.json()["detail"]
    assert builds == []                                             # no rebuild at all
    after = _stored(db)
    for column in ("status", "bundle_json", "bundle_ledger_json", "bundle_validation", "bundle_validation_errors",
                   "bundle_build_json", "bundle_review_revision", "review_revision", "updated_at"):
        assert after[column] == before[column], column
    assert _export_files() == []


# ── The states the worker does not hold still finalize ─────────────────────

@pytest.mark.parametrize("status", ["for_review", "reviewing"])
def test_a_quick_finalize_keeps_the_status_and_a_full_one_completes(db, temp_db_client, status):
    _add_job(db, status=status)

    quick = temp_db_client.post("/api/jobs/j1/finalize?quick=true")
    assert quick.status_code == 200 and quick.json()["status"] == status
    assert _stored(db)["bundle_json"] is not None

    full = temp_db_client.post("/api/jobs/j1/finalize")
    assert full.status_code == 200 and full.json()["status"] == "completed"
    assert _stored(db)["status"] == "completed"


def test_the_worker_takes_the_job_after_a_refused_finalize_and_a_later_finalize_works(db, temp_db_client):
    from api import queue_loop

    _add_job(db, status="queued")
    uploads_dir().joinpath("j1.txt").write_text("APT29 used SUNBURST.", encoding="utf-8")
    assert temp_db_client.post("/api/jobs/j1/finalize").status_code == 409
    assert _stored(db)["status"] == "queued"

    assert queue_loop.claim_next_queued("worker-a") is not None          # the refusal left the queue alone
    assert _stored(db)["status"] == "processing"
    assert temp_db_client.post("/api/jobs/j1/finalize").status_code == 409

    assert worker._finalize_job("j1", "for_review", "worker-a", bundle_json=None)   # the worker's own end
    resp = temp_db_client.post("/api/jobs/j1/finalize")
    assert resp.status_code == 200 and resp.json()["status"] == "completed"


# ── A race: the worker claims the job between the read and the publication ─

def test_a_job_claimed_during_the_rebuild_is_refused_and_the_worker_keeps_it(db, temp_db_client, monkeypatch):
    _add_job(db, status="reviewing", bundle_json=STORED_BUNDLE, bundle_validation="unverified")
    real = worker.build_bundle

    def claim_then_build(*args, **kwargs):
        # The worker takes the job (a second connection) after the rebuild read the rows.
        _in_another_connection(db, "UPDATE jobs SET status='processing', worker_id='worker-b' WHERE id='j1'")
        return real(*args, **kwargs)

    monkeypatch.setattr(worker, "build_bundle", claim_then_build)

    resp = temp_db_client.post("/api/jobs/j1/finalize")

    assert resp.status_code == 409
    row = _stored(db)
    assert row["status"] == "processing" and row["worker_id"] == "worker-b"    # not overwritten
    assert row["bundle_json"] == STORED_BUNDLE                                 # not published
    assert row["bundle_review_revision"] is None
    assert _export_files() == []


# ── Deletion: 404, never a 500 and never a success for a job that is gone ──

def test_a_job_deleted_after_the_route_read_it_is_a_404(db, temp_db_client, monkeypatch):
    _add_job(db, status="reviewing")
    from api.routes import jobs as jobs_routes
    real_require = jobs_routes.require_job

    def read_then_delete(conn, job_id):
        real_require(conn, job_id)
        _in_another_connection(db, "DELETE FROM jobs WHERE id='j1'")

    monkeypatch.setattr(jobs_routes, "require_job", read_then_delete)

    resp = temp_db_client.post("/api/jobs/j1/finalize")

    assert resp.status_code == 404
    assert _stored(db) is None
    assert _export_files() == []


@pytest.mark.parametrize("quick", [True, False], ids=["quick", "full"])
def test_a_job_deleted_during_the_rebuild_is_a_404_and_no_file_comes_back(db, temp_db_client, monkeypatch, quick):
    _add_job(db, status="reviewing")
    real = worker.build_bundle

    def delete_then_build(*args, **kwargs):
        _in_another_connection(db, "DELETE FROM jobs WHERE id='j1'")
        return real(*args, **kwargs)

    monkeypatch.setattr(worker, "build_bundle", delete_then_build)

    resp = temp_db_client.post(f"/api/jobs/j1/finalize?quick={'true' if quick else 'false'}")

    assert resp.status_code == 404
    assert _stored(db) is None
    assert _export_files() == []
