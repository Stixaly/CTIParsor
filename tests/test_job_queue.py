import threading
from pathlib import Path

import pytest

import api.worker as worker
from api.db import get_conn


@pytest.fixture
def setup_db(temp_db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolated database, plus an uploads/ root under tmp_path.

    temp_db (tests/conftest.py) repoints api.db.DB_PATH at a throwaway
    file and runs the real migrations, so the worker and these tests share one
    schema.  A hand-written CREATE TABLE here would silently relax constraints
    the real schema enforces -- jobs.updated_at is NOT NULL -- and, worse,
    leave the test bodies talking to the developer's cti_stix.db.
    """
    monkeypatch.setattr(worker, "_ROOT", tmp_path)
    (tmp_path / "uploads").mkdir(exist_ok=True)
    return temp_db


def test_queue_full_never_emits_done(setup_db, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(worker, "_try_acquire_job_slot", lambda: False)
    monkeypatch.setattr(worker, "_count_queued", lambda: 1)
    monkeypatch.setattr(worker, "_QUEUE_MAX_DEPTH", 10)

    emitted = []
    def mock_emit(job_id, event_type, data):
        emitted.append((job_id, event_type, data))
    monkeypatch.setattr(worker, "emit_progress", mock_emit)

    def mock_set_status(job_id, status):
        pass
    monkeypatch.setattr(worker, "set_job_status", mock_set_status)

    worker.run_pipeline_async("job1", "/tmp/file", "file.txt")

    assert not any(event_type == "done" for _, event_type, _ in emitted), "Bug: 'done' event was emitted"
    assert any(event_type == "queued" for _, event_type, _ in emitted), "Expected 'queued' event"


def test_queue_full_returns_queued(setup_db, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(worker, "_try_acquire_job_slot", lambda: False)
    monkeypatch.setattr(worker, "_count_queued", lambda: 1)
    monkeypatch.setattr(worker, "_QUEUE_MAX_DEPTH", 10)
    monkeypatch.setattr(worker, "emit_progress", lambda *a, **k: None)
    monkeypatch.setattr(worker, "set_job_status", lambda *a, **k: None)

    result = worker.run_pipeline_async("job1", "/tmp/file", "file.txt")
    assert result == "queued"


def test_queue_over_max_depth_returns_rejected(setup_db, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(worker, "_try_acquire_job_slot", lambda: False)
    monkeypatch.setattr(worker, "_count_queued", lambda: 2)
    monkeypatch.setattr(worker, "_QUEUE_MAX_DEPTH", 2)

    statuses = []
    def mock_set_status(job_id, status):
        statuses.append(status)
    monkeypatch.setattr(worker, "set_job_status", mock_set_status)
    monkeypatch.setattr(worker, "emit_progress", lambda *a, **k: None)

    result = worker.run_pipeline_async("job1", "/tmp/file", "file.txt")
    assert result == "rejected"
    assert "failed" in statuses


def test_claim_next_queued_is_atomic(setup_db, monkeypatch: pytest.MonkeyPatch):
    conn = get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)",
        ('j1', 'f1.txt', 'queued', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z'),
    )
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)",
        ('j2', 'f2.txt', 'queued', '2024-01-01T00:00:01Z', '2024-01-01T00:00:01Z'),
    )
    conn.commit()

    uploads_dir = worker._ROOT / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    (uploads_dir / "j1.txt").touch()
    (uploads_dir / "j2.txt").touch()

    results = []
    lock = threading.Lock()

    def claim():
        res = worker._claim_next_queued()
        with lock:
            results.append(res)

    threads = [threading.Thread(target=claim) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successful_claims = [r for r in results if r is not None]
    assert len(successful_claims) <= 2

    claimed_ids = [r[0] for r in successful_claims]
    assert len(claimed_ids) == len(set(claimed_ids)), "Duplicate claims detected"


def test_claim_skips_job_whose_upload_vanished(setup_db, monkeypatch: pytest.MonkeyPatch):
    conn = get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)",
        ('j1', 'f1.txt', 'queued', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z'),
    )
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)",
        ('j2', 'f2.txt', 'queued', '2024-01-01T00:00:01Z', '2024-01-01T00:00:01Z'),
    )
    conn.commit()

    uploads_dir = worker._ROOT / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    # j1 file is missing, j2 file exists
    (uploads_dir / "j2.txt").touch()

    emitted = []
    def mock_emit(job_id, event_type, data):
        emitted.append((job_id, event_type, data))
    monkeypatch.setattr(worker, "emit_progress", mock_emit)
    monkeypatch.setattr(worker, "set_job_status", lambda *a, **k: None)

    result = worker._claim_next_queued()

    assert result is not None
    assert result[0] == "j2"
    assert any(
        job_id == "j1" and event_type == "done" and data.get("status") == "failed"
        for job_id, event_type, data in emitted
    )


def test_requeue_orphans_resets_processing(setup_db, monkeypatch: pytest.MonkeyPatch):
    conn = get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)",
        ('j1', 'f1.txt', 'processing', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z'),
    )
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)",
        ('j2', 'f2.txt', 'processing', '2024-01-01T00:00:01Z', '2024-01-01T00:00:01Z'),
    )
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)",
        ('j3', 'f3.txt', 'for_review', '2024-01-01T00:00:02Z', '2024-01-01T00:00:02Z'),
    )
    conn.commit()

    count = worker.requeue_orphans()
    assert count == 2

    conn = get_conn()
    row1 = conn.execute("SELECT status FROM jobs WHERE id='j1'").fetchone()
    row2 = conn.execute("SELECT status FROM jobs WHERE id='j2'").fetchone()
    row3 = conn.execute("SELECT status FROM jobs WHERE id='j3'").fetchone()

    assert row1["status"] == "queued"
    assert row2["status"] == "queued"
    assert row3["status"] == "for_review"
