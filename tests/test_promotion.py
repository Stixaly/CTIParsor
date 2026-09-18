"""Deny / promote candidates grown from analyst decisions (ADR-0052).

The rules are exercised on hand-built decision lists whose answer is known;
the store half (upsert that never changes a status, manual rules, activation)
runs on the isolated `temp_db` fixture on both engines.
"""
from __future__ import annotations

from uuid import uuid4

from pipeline import promotion as pm
from pipeline.promotion import compute_candidates


def _d(value: str, etype: str, source: str, accepted: int | None, job: str):
    return (value, etype, source, accepted, job)


# ── deny ─────────────────────────────────────────────────────────────────────


def test_deny_needs_rejections_across_reports_and_a_clear_majority():
    rows = ([_d("Microsoft", "threat_actor", "cyner", 0, "j1")] * 2
            + [_d("microsoft", "threat_actor", "gliner", 0, "j2")])
    [c] = compute_candidates(rows)
    assert (c.action, c.term, c.entity_type) == ("deny", "microsoft", "threat_actor")
    assert (c.rejected_count, c.accepted_count, c.job_count) == (3, 0, 2)
    assert c.sources == ["cyner", "gliner"]
    assert c.display == "microsoft"          # nothing was ever accepted, so no surface form to prefer

    # Three rejections in ONE report is one analyst's afternoon, not a rule.
    assert compute_candidates([_d("Microsoft", "threat_actor", "cyner", 0, "j1")] * 3) == []

    # Contested: 3 rejected, 2 accepted -> 60 % < 80 %.
    contested = rows + [_d("Microsoft", "threat_actor", "cyner", 1, "j3")] * 2
    assert compute_candidates(contested) == []


def test_deny_is_per_type_and_ignores_unnamed_types():
    rows = (
        [_d("Russia", "threat_actor", "cyner", 0, f"j{i}") for i in range(3)]
        + [_d("Russia", "location", "gliner", 1, f"j{i}") for i in range(3)]      # fine as a location
        + [_d("10.0.0.1", "ipv4", "ioc", 0, f"j{i}") for i in range(3)]          # never a rule
    )
    cands = compute_candidates(rows)
    assert [(c.action, c.term, c.entity_type) for c in cands] == [("deny", "russia", "threat_actor")]


def test_thresholds_are_parameters():
    rows = [_d("Team", "threat_actor", "cyner", 0, "j1"), _d("Team", "threat_actor", "cyner", 0, "j2")]
    assert compute_candidates(rows) == []
    [c] = compute_candidates(rows, min_rejections=2)
    assert c.action == "deny"


# ── promote ──────────────────────────────────────────────────────────────────


def test_promote_needs_a_gazetteer_type_accepted_across_reports_and_unknown():
    rows = [
        _d("ARGUEPATCH", "malware", "cyner", 1, "j1"),
        _d("ARGUEPATCH", "malware", "cyner", 1, "j2"),
        _d("Arguepatch", "malware", "llm", 1, "j2"),
    ]
    [c] = compute_candidates(rows)
    assert (c.action, c.term, c.entity_type, c.display) == ("promote", "arguepatch", "malware", "ARGUEPATCH")
    assert (c.accepted_count, c.rejected_count, c.job_count) == (3, 0, 2)

    # Already a gazetteer surface form -> nothing to learn.
    assert compute_candidates(rows, known_terms={"arguepatch"}) == []

    # A sector is not something the gazetteer emits.
    sectors = [_d("healthcare", "identity", "gliner", 1, f"j{i}") for i in range(3)]
    assert compute_candidates(sectors) == []


def test_hand_created_entities_count_as_accepts_even_when_never_reviewed():
    rows = [
        _d("XAKNET Team", "threat_actor", "manual", None, "j1"),
        _d("XAKNET Team", "threat_actor", "manual", None, "j2"),
        _d("Xaknet Team", "threat_actor", "cyner", 1, "j3"),
    ]
    [c] = compute_candidates(rows)
    assert (c.action, c.accepted_count, c.job_count, c.display) == ("promote", 3, 3, "XAKNET Team")

    # ...unless the analyst rejected the manual row afterwards.
    rows[0] = _d("XAKNET Team", "threat_actor", "manual", 0, "j1")
    assert compute_candidates(rows) == []


def test_promote_refuses_generic_vocabulary_and_short_terms():
    generic = [_d("the malware", "malware", "cyner", 1, f"j{i}") for i in range(3)]
    short = [_d("APT", "threat_actor", "cyner", 1, f"j{i}") for i in range(3)]
    assert compute_candidates(generic + short) == []


def test_a_contested_name_is_neither_denied_nor_promoted():
    rows = [_d("Snake", "malware", "cyner", 1, f"j{i}") for i in range(3)] \
        + [_d("Snake", "malware", "cyner", 0, f"k{i}") for i in range(3)]
    assert compute_candidates(rows) == []


def test_blank_values_are_ignored():
    assert compute_candidates([_d("   ", "malware", "cyner", 0, "j1")] * 3) == []


# ── store ────────────────────────────────────────────────────────────────────


def _seed(db, rows: list[tuple[str, str, str, int | None, str]]) -> None:
    conn = db.get_conn()
    now = db.now_iso()
    for job in sorted({r[4] for r in rows}):
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
            (job, f"{job}.pdf", "for_review", now, now),
        )
    conn.executemany(
        "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, source) "
        "VALUES (?,?,?,?,?,?,?,?)",
        [(str(uuid4()), job, value, etype, "", 0.9, acc, source) for value, etype, source, acc, job in rows],
    )
    conn.commit()


_DENY_ROWS = ([_d("Microsoft", "threat_actor", "cyner", 0, "j1")] * 2
              + [_d("Microsoft", "threat_actor", "gliner", 0, "j2")])


def test_propose_reads_the_store_and_apply_never_touches_a_status(temp_db):
    _seed(temp_db, _DENY_ROWS)
    conn = temp_db.get_conn()

    [c] = pm.propose(conn)
    assert (c.action, c.term, c.existing_status) == ("deny", "microsoft", None)
    assert pm.apply_candidates(conn, [c], temp_db.now_iso()) == 1
    [row] = pm.list_overrides(conn)
    assert (row["status"], row["origin"], row["rejected_count"]) == ("candidate", "auto", 3)

    # A human activates it; the next promotion refreshes counts, keeps the status.
    assert pm.set_status(conn, row["id"], "active", temp_db.now_iso())["status"] == "active"
    _seed(temp_db, [_d("MICROSOFT", "threat_actor", "cyner", 0, "j3")])
    [again] = pm.propose(conn)
    assert again.existing_status == "active" and again.rejected_count == 4
    pm.apply_candidates(conn, [again], temp_db.now_iso())
    [row2] = pm.list_overrides(conn)
    assert (row2["id"], row2["status"], row2["rejected_count"], row2["job_count"]) == (row["id"], "active", 4, 3)

    # And an ignored candidate stays ignored.
    pm.set_status(conn, row["id"], "ignored", temp_db.now_iso())
    pm.apply_candidates(conn, pm.propose(conn), temp_db.now_iso())
    assert pm.list_overrides(conn)[0]["status"] == "ignored"


def test_list_overrides_filters_by_status_and_action(temp_db):
    conn = temp_db.get_conn()
    now = temp_db.now_iso()
    pm.add_manual(conn, "Google", "threat_actor", "deny", now)
    pm.add_manual(conn, "ArguePatch", "malware", "promote", now, display="ARGUEPATCH")
    assert [o["term"] for o in pm.list_overrides(conn, action="deny")] == ["google"]
    assert [o["display"] for o in pm.list_overrides(conn, action="promote")] == ["ARGUEPATCH"]
    assert len(pm.list_overrides(conn, status="active")) == 2
    assert pm.list_overrides(conn, status="candidate") == []


def test_manual_rule_is_active_at_once_and_replaces_rather_than_duplicates(temp_db):
    conn = temp_db.get_conn()
    row = pm.add_manual(conn, "  Google ", "threat_actor", "deny", temp_db.now_iso(), note="vendor")
    assert (row["term"], row["status"], row["origin"], row["note"]) == ("google", "active", "manual", "vendor")

    again = pm.add_manual(conn, "GOOGLE", "threat_actor", "deny", temp_db.now_iso(), note="still a vendor")
    assert again["id"] == row["id"] and again["note"] == "still a vendor"
    assert len(pm.list_overrides(conn)) == 1

    assert pm.delete_override(conn, row["id"]) is True
    assert pm.delete_override(conn, row["id"]) is False
    assert pm.set_status(conn, row["id"], "active", temp_db.now_iso()) is None


def test_activate_all_candidates_leaves_ignored_rows_alone(temp_db):
    _seed(temp_db, _DENY_ROWS + [_d("Cloudflare", "threat_actor", "gliner", 0, f"j{i}") for i in range(1, 4)])
    conn = temp_db.get_conn()
    cands = pm.propose(conn)
    pm.apply_candidates(conn, cands, temp_db.now_iso())
    rows = pm.list_overrides(conn)
    pm.set_status(conn, rows[0]["id"], "ignored", temp_db.now_iso())
    assert pm.activate_all_candidates(conn, temp_db.now_iso()) == 1
    assert sorted(o["status"] for o in pm.list_overrides(conn)) == ["active", "ignored"]


def test_gazetteer_terms_are_the_index_surface_forms():
    terms = pm.gazetteer_terms()
    assert len(terms) > 1000
    assert all(t == t.lower() for t in terms)
