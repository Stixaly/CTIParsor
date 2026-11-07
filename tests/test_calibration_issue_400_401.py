"""Calibration reads of non-finite confidences and empty filters (issue #401),
and the support behind a proposed cutoff (issue #400).

A NaN or infinite `entities.confidence` must not reach the isotonic fit, and an
empty `sources` or `origins` must read nothing instead of sending `IN ()`, which
PostgreSQL rejects.  A proposed cutoff's support counts only the decisions of
its calibrated band, below AUTO_ACCEPT_LEVEL.  Runs on the isolated `temp_db`
fixture.
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


# ── Support behind a proposed cutoff (issue #400) ────────────────────────────

# 0.40–0.79: one accepted and four refused at each score, a 20 % band.
_LOW_BAND = [(s / 100, ok) for s in range(40, 80) for ok in (True, False, False, False, False)]


def test_support_counts_only_the_calibrated_band_issue_400():
    # One accepted decision at 0.85, below AUTO_ACCEPT_LEVEL, and twenty accepted
    # at 0.95, which the worker accepts on its own.  The cutoff 0.85 rests on the
    # one decision of its own band: it is not validated by the auto-accepted rows.
    points = _LOW_BAND + [(0.85, True)] + [(0.95, True)] * 20
    p = cal.propose("cyner", "tool", 0.70, points, target_precision=0.9, min_samples=50)
    assert p.status == "target_unreachable"
    assert p.proposed is None


def test_a_band_with_enough_support_of_its_own_is_still_proposed_issue_400():
    # The same shape with twenty decisions inside the calibrated band: the
    # cutoff 0.85 is proposed as before.
    points = _LOW_BAND + [(0.85, True)] * 20 + [(0.95, True)] * 20
    p = cal.propose("cyner", "tool", 0.70, points, target_precision=0.9, min_samples=50)
    assert p.status == "ok"
    assert p.proposed == 0.85


def test_a_cutoff_above_auto_accept_stays_above_auto_accept_issue_400():
    # The first clean band starts at 0.92, so the calibrated band is empty, and
    # five decisions are under min_block_samples whichever way they are counted.
    # The status is still above_auto_accept, not target_unreachable: the check
    # runs before the support check.
    points = _LOW_BAND + [(0.92, True)] * 5
    p = cal.propose("cyner", "tool", 0.70, points, target_precision=0.9, min_samples=50)
    assert p.status == "above_auto_accept"
    assert p.proposed is None
    assert p.unclamped == 0.92
