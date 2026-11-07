"""Promotion rows with a NULL source, and active promotions that stay current (#418).

A NULL `source` used to be added to the sources set: `sorted()` then raised
TypeError beside a string.  An active promotion was also part of the
gazetteer's surface forms, so it was never proposed again and its counts
never refreshed.
"""
from __future__ import annotations

from uuid import uuid4

from pipeline import overrides
from pipeline import promotion as pm
from pipeline.promotion import compute_candidates


def _d(value: str, etype: str, source: str | None, accepted: int | None, job: str):
    return (value, etype, source, accepted, job)


def _seed(db, rows) -> None:
    conn = db.get_conn()
    now = db.now_iso()
    for job in sorted({r[4] for r in rows}):
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
            (job, f"{job}.pdf", "for_review", now, now),
        )
    conn.executemany(
        "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, source, "
        "decision_origin) VALUES (?,?,?,?,?,?,?,?,?)",
        [(str(uuid4()), job, value, etype, "", 0.9, acc, source, None if acc is None else "human")
         for value, etype, source, acc, job in rows],
    )
    conn.commit()


def test_a_null_source_is_not_listed_and_does_not_break_sorting_issue_418():
    rows = [_d("Microsoft", "threat_actor", None, 0, "j1"),
            _d("Microsoft", "threat_actor", "cyner", 0, "j2"),
            _d("microsoft", "threat_actor", None, 0, "j3")]
    [c] = compute_candidates(rows)
    assert (c.action, c.rejected_count) == ("deny", 3)
    assert c.sources == ["cyner"]

    [only_null] = compute_candidates([_d("Microsoft", "threat_actor", None, 0, f"j{i}") for i in range(3)])
    assert only_null.sources == []


def test_a_null_source_row_in_the_store_is_read_and_proposed_issue_418(temp_db):
    _seed(temp_db, [_d("Microsoft", "threat_actor", None, 0, "j1"),
                    _d("Microsoft", "threat_actor", "cyner", 0, "j2"),
                    _d("Microsoft", "threat_actor", None, 0, "j3")])
    [c] = pm.propose(temp_db.get_conn())
    assert (c.action, c.rejected_count, c.sources) == ("deny", 3, ["cyner"])


def test_an_active_promotion_keeps_its_counts_current_issue_418(temp_db):
    conn = temp_db.get_conn()
    _seed(temp_db, [_d("Zorblax Crew", "malware", "cyner", 1, f"j{i}") for i in (1, 2, 3)])
    [c] = pm.propose(conn)
    assert c.action == "promote"
    pm.apply_candidates(conn, [c], temp_db.now_iso())
    [row] = pm.list_overrides(conn)
    pm.set_status(conn, row["id"], "active", temp_db.now_iso())
    overrides.reload()

    # Active, the promotion is a gazetteer surface form now, but not a known term for proposals.
    assert "zorblax crew" not in pm.gazetteer_terms()

    _seed(temp_db, [_d("ZORBLAX CREW", "malware", "gliner", 1, "j4")])
    [again] = pm.propose(conn)
    assert (again.action, again.existing_status, again.accepted_count) == ("promote", "active", 4)
    pm.apply_candidates(conn, [again], temp_db.now_iso())
    [row2] = pm.list_overrides(conn)
    assert (row2["id"], row2["status"], row2["accepted_count"], row2["job_count"]) == (row["id"], "active", 4, 4)


def test_a_term_in_the_index_and_promoted_stays_known_issue_418(temp_db):
    conn = temp_db.get_conn()
    base = "lazarus group"
    assert base in pm.gazetteer_terms()
    pm.add_manual(conn, base, "threat_actor", "promote", temp_db.now_iso())
    overrides.reload()
    assert base in pm.gazetteer_terms()
