"""scripts/audit_store_invariants.py: a stored bundle is never built from a
newer revision than its job's (ADR-0086)."""
from __future__ import annotations

from scripts.audit_store_invariants import check_bundle_revision, run_all


def _job(db, job_id: str, review_revision: int, bundle_review_revision: int | None) -> None:
    ts = db.now_iso()
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, updated_at, "
            "review_revision, bundle_review_revision) VALUES (?,?,?,?,?,?,?)",
            (job_id, "report.txt", "reviewing", ts, ts, review_revision, bundle_review_revision))
        conn.commit()


def _jobs(db) -> None:
    _job(db, "nobundle", 2, None)       # no bundle: not counted
    _job(db, "current0", 3, 3)          # built from the job's current rows
    _job(db, "behind00", 2, 1)          # rows written since: stale, not ahead


def test_a_bundle_ahead_of_its_jobs_revision_fails(temp_db):
    _jobs(temp_db)
    _job(temp_db, "ahead-01", 1, 4)

    finding = check_bundle_revision(temp_db.get_conn())

    assert (finding.name, finding.severity, finding.status) == ("job.bundle_revision", "error", "FAIL")
    assert (finding.count, finding.total) == (1, 3)
    assert "ahead-01 4>1" in finding.detail


def test_no_bundle_ahead_of_its_job_passes(temp_db):
    _jobs(temp_db)

    finding = check_bundle_revision(temp_db.get_conn())

    assert (finding.status, finding.count, finding.total) == ("OK", 0, 2)


def test_the_bundle_revision_check_is_part_of_the_audit(temp_db):
    assert "job.bundle_revision" in [f.name for f in run_all(temp_db.get_conn())]
