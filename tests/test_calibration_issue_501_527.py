"""Issues #501 and #527: calibration reads an override without a crash, and
applies its proposals all or none.

#501: `calibrate()` evaluated the stage default before looking up the stored
override, so a source with no calibrated stage raised ValueError even when an
override for it existed.  #527: `apply_proposals` ran one autocommit INSERT per
proposal, so a failure part-way left the earlier rows written.  Runs on the
isolated `temp_db` fixture.
"""
from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest

from pipeline import calibration as cal


def _seed(db, source: str, entity_type: str, rows: list[tuple[float, int]]) -> None:
    conn = db.get_conn()
    now = db.now_iso()
    job_id = f"job-{uuid4().hex[:8]}"
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
        (job_id, f"{job_id}.pdf", "for_review", now, now),
    )
    conn.executemany(
        "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, source, "
        "decision_origin) VALUES (?,?,?,?,?,?,?,?,?)",
        [(str(uuid4()), job_id, f"e{i}", entity_type, "", conf, acc, source, "human")
         for i, (conf, acc) in enumerate(rows)],
    )
    conn.commit()


def test_an_override_for_a_source_without_a_stage_default_is_used_issue_501(temp_db):
    _seed(temp_db, "other_source", "tool", [(0.7, 1), (0.6, 0), (0.8, 1)])
    conn = temp_db.get_conn()
    cal.set_override(conn, "other_source", "tool", 0.5, temp_db.now_iso())

    proposals = cal.calibrate(conn, min_samples=1, sources=("other_source",))
    assert [(p.source, p.entity_type, p.current) for p in proposals] == [("other_source", "tool", 0.5)]


def test_a_failed_write_leaves_no_earlier_proposal_applied_issue_527(temp_db):
    conn = temp_db.get_conn()
    good = cal.Proposal(source="gliner", entity_type="malware", current=0.40, target_precision=0.9,
                        sample_size=640, status="ok", proposed=0.60)
    # entity_type is NOT NULL: the second INSERT fails in the database itself.
    broken = cal.Proposal(source="gliner", entity_type=None, current=0.40, target_precision=0.9,
                          sample_size=640, status="ok", proposed=0.70)

    with pytest.raises(psycopg.IntegrityError):
        cal.apply_proposals(conn, [good, broken], temp_db.now_iso())
    assert cal.list_overrides(conn) == []
