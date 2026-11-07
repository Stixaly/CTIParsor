"""Calibration reads of non-finite confidences and empty filters (issue #401).

A NaN or infinite `entities.confidence` must not reach the isotonic fit, and an
empty `sources` or `origins` must read nothing instead of sending `IN ()`, which
PostgreSQL rejects.  Runs on the isolated `temp_db` fixture.
"""
from __future__ import annotations

import math
from uuid import uuid4

from pipeline import calibration as cal


def _seed(db, rows: list[tuple[str, str, float, int]]) -> None:
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
        [(str(uuid4()), job_id, f"e{i}", etype, "", conf, int(acc), source, "human")
         for i, (source, etype, conf, acc) in enumerate(rows)],
    )
    conn.commit()


def test_non_finite_confidence_is_not_read_issue_401(temp_db):
    # NaN and both infinities are decided rows with a stored score; they are
    # skipped, and the finite rows around them are read as before.
    _seed(temp_db, [
        ("cyner", "PERSON", 0.50, 0),
        ("cyner", "PERSON", 0.90, 1),
        ("cyner", "PERSON", float("nan"), 1),
        ("cyner", "PERSON", float("inf"), 0),
        ("cyner", "PERSON", float("-inf"), 1),
    ])

    grouped = cal.load_decisions(temp_db.get_conn(), sources=("cyner",), origins=("human",))
    points = grouped[("cyner", "PERSON")]
    assert points == [(0.50, False), (0.90, True)]
    assert all(math.isfinite(score) for score, _ in points)


def test_empty_sources_or_origins_read_nothing_issue_401(temp_db):
    _seed(temp_db, [("gliner", "malware", 0.70, 1)])
    conn = temp_db.get_conn()

    assert cal.load_decisions(conn, sources=(), origins=("human",)) == {}
    assert cal.load_decisions(conn, sources=("gliner",), origins=()) == {}
    assert cal.excluded_decisions(conn, sources=()) == {}

    # The same store with the filters filled in still reads the row.
    assert cal.load_decisions(conn, sources=("gliner",), origins=("human",)) == {
        ("gliner", "malware"): [(0.70, True)],
    }
