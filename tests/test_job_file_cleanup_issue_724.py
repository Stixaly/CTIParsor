"""A job's files are removed after its rows are gone, and a failure there is resumed (#724).

The DELETE of a job commits the row deletes first and unlinks the files afterwards.
A filesystem error after the commit used to leave the files with no row to retry
from.  The cleanup intent is now written in the same transaction as the deletes
(table job_file_cleanups, migration 22), and the intent is retried at start-up,
on each retention sweep, and by a DELETE of the same job id.

The filesystem faults below are injected by replacing Path.unlink, so no real
file outside tmp_path is touched."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from api.paths import output_dir, uploads_dir
from api.routes import jobs as jobs_routes


@pytest.fixture()
def dirs():
    """uploads/ and output/, both under tmp_path (tests/conftest.py)."""
    uploads, output = uploads_dir(), output_dir()
    uploads.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    (uploads / "meta").mkdir(exist_ok=True)
    return uploads, output


def _add_job(db, job_id: str, *, filename: str = "APT report.pdf", status: str = "for_review") -> None:
    ts = db.now_iso()
    with db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES (?,?,?,?,?)", (job_id, filename, status, ts, ts))
        conn.execute("INSERT INTO entities (id, job_id, value, entity_type) VALUES (?,?,?,?)",
                     (f"{job_id}_e", job_id, "APT29", "threat-actor"))
        conn.commit()


def _job_files(uploads: Path, output: Path, job_id: str) -> dict[str, Path]:
    """One file of every family the DELETE removes, named the way the worker names them."""
    return {
        "source": uploads / f"{job_id}.pdf",
        "meta": uploads / "meta" / f"{job_id}.json",
        "bundle": output / f"APT_report_{job_id}_bundle.json",
        "bundle_invalid": output / f"APT_report_{job_id}_bundle_invalid.json",
        "legacy_bundle": output / "APT_report_bundle.json",
        "checkpoint": output / f"{job_id}_stage3.ckpt.json",
        "checkpoint_tmp": output / f"{job_id}_stage3.ckpt.tmp",
    }


def _make_job_files(db, uploads: Path, output: Path, job_id: str) -> dict[str, Path]:
    _add_job(db, job_id)
    files = _job_files(uploads, output, job_id)
    for path in files.values():
        path.write_text("x")
    return files


def _count(db, table: str, job_id: str) -> int:
    column = "id" if table == "jobs" else "job_id"
    with db.get_conn() as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {column}=?", (job_id,)).fetchone()[0]


def _intents(db, job_id: str) -> list[str]:
    with db.get_conn() as conn:
        return [r[0] for r in conn.execute(
            "SELECT path FROM job_file_cleanups WHERE job_id=? ORDER BY id", (job_id,)).fetchall()]


_REAL_UNLINK = Path.unlink
FAMILIES = ["source", "meta", "bundle", "bundle_invalid", "legacy_bundle", "checkpoint", "checkpoint_tmp"]


class _Crash(BaseException):
    """Stands for the process dying: not an Exception, so no handler in the cleanup code catches it."""


def _fail_unlink_of(monkeypatch, names: set[str]) -> None:
    """Every unlink of a file whose name is in `names` raises PermissionError, as on a locked file."""
    def failing(self, missing_ok=False):
        if self.name in names:
            raise PermissionError(13, "Permission denied", str(self))
        return _REAL_UNLINK(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", failing)


def _restore_unlink(monkeypatch) -> None:
    monkeypatch.setattr(Path, "unlink", _REAL_UNLINK)


def test_a_failing_unlink_after_the_commit_is_resumed_by_a_second_delete(temp_db_client, temp_db, dirs,
                                                                         monkeypatch):
    """(#724, reproduction) The row goes, one file cannot be unlinked: the DELETE must
    say so (200, files_pending), and a second DELETE of the same id must finish the
    job's files.  Before the fix the first DELETE raised PermissionError (500) after
    the commit, nothing recorded the leftover file, and no later call could reach it."""
    uploads, output = dirs
    files = _make_job_files(temp_db, uploads, output, "j1")
    _fail_unlink_of(monkeypatch, {files["bundle"].name})

    resp = temp_db_client.delete("/api/jobs/j1")

    assert resp.status_code == 200 and resp.json() == {"deleted": "j1", "files_pending": 1}
    assert _count(temp_db, "jobs", "j1") == 0
    assert files["bundle"].exists()
    assert not any(p.exists() for k, p in files.items() if k != "bundle")

    _restore_unlink(monkeypatch)
    again = temp_db_client.delete("/api/jobs/j1")

    assert again.status_code == 404
    assert not any(p.exists() for p in files.values())


@pytest.mark.parametrize("family", FAMILIES)
def test_a_failing_unlink_of_each_family_is_recorded_and_a_retry_removes_the_file(temp_db, dirs, monkeypatch,
                                                                                  family):
    """(#724) One file family at a time refuses to be removed.  The job's rows and every other
    file go; the refused file keeps an intent row naming its canonical path; once the fault is
    gone, one retry removes it and the intent with it."""
    uploads, output = dirs
    files = _make_job_files(temp_db, uploads, output, "j1")
    _fail_unlink_of(monkeypatch, {files[family].name})

    assert jobs_routes._delete_job("j1") is True

    assert _count(temp_db, "jobs", "j1") == 0
    assert [k for k, p in files.items() if p.exists()] == [family]
    assert _intents(temp_db, "j1") == [str(files[family].resolve())]

    _restore_unlink(monkeypatch)
    assert jobs_routes.retry_pending_cleanups() == 0
    assert not any(p.exists() for p in files.values())
    assert _intents(temp_db, "j1") == []


def test_a_crash_after_the_commit_is_resumed_by_the_next_pass(temp_db, dirs, monkeypatch):
    """(#724) The process dies between the commit and the first unlink.  The rows are gone,
    the intents of all seven files are committed, and the next pass removes every file."""
    uploads, output = dirs
    files = _make_job_files(temp_db, uploads, output, "j1")

    def dies(self, missing_ok=False):
        raise _Crash()

    monkeypatch.setattr(Path, "unlink", dies)
    with pytest.raises(_Crash):
        jobs_routes._delete_job("j1")

    assert _count(temp_db, "jobs", "j1") == 0 and _count(temp_db, "entities", "j1") == 0
    assert all(p.exists() for p in files.values())
    assert len(_intents(temp_db, "j1")) == len(FAMILIES)

    _restore_unlink(monkeypatch)
    jobs_routes.retry_pending_cleanups()
    assert not any(p.exists() for p in files.values()) and _intents(temp_db, "j1") == []


def test_a_crash_between_two_unlinks_is_resumed_without_error_on_the_removed_file(temp_db, dirs, monkeypatch):
    """(#724) The process dies after the second file is removed: the intent of the first is already
    gone, the others are still recorded, and the next pass finishes them."""
    uploads, output = dirs
    files = _make_job_files(temp_db, uploads, output, "j1")
    calls = []

    def dies_on_the_second(self, missing_ok=False):
        calls.append(self.name)
        if len(calls) == 2:
            raise _Crash()
        return _REAL_UNLINK(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", dies_on_the_second)
    with pytest.raises(_Crash):
        jobs_routes._delete_job("j1")

    assert len(_intents(temp_db, "j1")) == len(FAMILIES) - 1
    assert sum(p.exists() for p in files.values()) == len(FAMILIES) - 1

    _restore_unlink(monkeypatch)
    jobs_routes.retry_pending_cleanups()
    assert not any(p.exists() for p in files.values()) and _intents(temp_db, "j1") == []


def test_a_repeated_delete_is_idempotent_and_a_same_named_job_is_untouched(temp_db_client, temp_db, dirs,
                                                                           monkeypatch):
    """(#724) j1 leaves a refused bundle behind.  A second job with the same report name is created
    with its own job-scoped files; the retry and a repeated DELETE of j1 remove j1's file and
    nothing of j2's, and the repeated DELETE answers 404 as for any unknown id."""
    uploads, output = dirs
    files = _make_job_files(temp_db, uploads, output, "j1")
    files["legacy_bundle"].unlink()
    _fail_unlink_of(monkeypatch, {files["bundle"].name})
    assert temp_db_client.delete("/api/jobs/j1").json() == {"deleted": "j1", "files_pending": 1}

    _add_job(temp_db, "j2")
    other = _job_files(uploads, output, "j2")
    del other["legacy_bundle"]
    for path in other.values():
        path.write_text("other")

    _restore_unlink(monkeypatch)
    assert temp_db_client.delete("/api/jobs/j1").status_code == 404
    assert temp_db_client.delete("/api/jobs/j1").status_code == 404
    assert not files["bundle"].exists()
    assert all(p.read_text() == "other" for p in other.values())
    assert _count(temp_db, "jobs", "j2") == 1 and _intents(temp_db, "j1") == []


def test_a_retention_sweep_resumes_the_removal_even_with_retention_off(temp_db, dirs, monkeypatch):
    """(#724) The sweep retries the recorded files first, whether or not JOB_RETENTION_DAYS is set."""
    uploads, output = dirs
    files = _make_job_files(temp_db, uploads, output, "j1")
    _fail_unlink_of(monkeypatch, {files["checkpoint"].name})
    jobs_routes._delete_job("j1")
    assert files["checkpoint"].exists()

    _restore_unlink(monkeypatch)
    assert jobs_routes.sweep_expired_jobs() == 0
    assert not files["checkpoint"].exists() and _intents(temp_db, "j1") == []


def test_a_start_up_resumes_the_removal_an_earlier_run_could_not_finish(temp_db, dirs, monkeypatch):
    """(#724) The API's start-up runs the same pass before it serves a request."""
    from fastapi.testclient import TestClient

    import api.main

    uploads, output = dirs
    files = _make_job_files(temp_db, uploads, output, "j1")
    _fail_unlink_of(monkeypatch, {files["bundle"].name})
    jobs_routes._delete_job("j1")
    assert files["bundle"].exists()

    _restore_unlink(monkeypatch)
    with patch("api.main.init_db"), patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app):
            pass
    assert not files["bundle"].exists() and _intents(temp_db, "j1") == []


def test_a_path_outside_the_job_directories_is_never_removed(temp_db, dirs, tmp_path):
    """(#724) A record whose path is not directly in uploads, uploads/meta or output is dropped
    and the file it names is left alone."""
    uploads, _ = dirs
    outside = tmp_path / "outside.txt"
    nested = uploads / "nested" / "j9.pdf"
    nested.parent.mkdir()
    for path in (outside, nested):
        path.write_text("keep")
    with temp_db.get_conn() as conn:
        for path in (outside, nested):
            conn.execute("INSERT INTO job_file_cleanups (job_id, path, created_at, updated_at) VALUES (?,?,?,?)",
                         ("j9", str(path), temp_db.now_iso(), temp_db.now_iso()))
        conn.commit()

    assert jobs_routes.retry_pending_cleanups() == 0

    assert outside.read_text() == "keep" and nested.read_text() == "keep"
    assert _intents(temp_db, "j9") == []


def test_the_plan_names_only_this_jobs_files(temp_db, dirs):
    """(#724) The plan of one job holds its own files that exist, and no other job's file or directory."""
    uploads, output = dirs
    files = _make_job_files(temp_db, uploads, output, "j1")
    for path in _job_files(uploads, output, "j2").values():
        path.write_text("other")
    (uploads / "j1.d").mkdir()

    planned = jobs_routes._job_file_paths("j1", "APT report.pdf")

    assert sorted(planned) == sorted(p.resolve() for p in files.values())


def test_a_plan_that_cannot_be_made_deletes_nothing(temp_db, dirs, monkeypatch):
    """(#724) If the files cannot be listed before the transaction, the job's rows stay: no
    deletion is committed without the record of its files."""
    uploads, output = dirs
    files = _make_job_files(temp_db, uploads, output, "j1")

    def unlistable(job_id, original_filename):
        raise OSError("uploads not readable")

    monkeypatch.setattr(jobs_routes, "_job_file_paths", unlistable)
    with pytest.raises(OSError):
        jobs_routes._delete_job("j1")

    assert _count(temp_db, "jobs", "j1") == 1 and _count(temp_db, "entities", "j1") == 1
    assert all(p.exists() for p in files.values())
