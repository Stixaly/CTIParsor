"""Decision provenance (ADR-0058): every write of `accepted` says who made it.

Against an isolated PostgreSQL schema (`temp_db`), because `decisions.record`
is one PostgreSQL statement (CTE + UPDATE ... RETURNING + INSERT ... SELECT).
"""
from uuid import uuid4

import pytest

from pipeline import calibration as cal
from pipeline import decisions, promotion


def _job(db, job_id="job-dec"):
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, report_text, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (job_id, "r.txt", "for_review", "APT29 used WellMess.", db.now_iso(), db.now_iso()),
        )
        conn.commit()
    return job_id


def _entity(db, job_id, *, value="WellMess", etype="malware", conf=0.5, accepted=None,
            origin=None, source="gliner"):
    eid = str(uuid4())
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, "
            "source, decision_origin) VALUES (?,?,?,?,?,?,?,?,?)",
            (eid, job_id, value, etype, "", conf, accepted, source, origin),
        )
        conn.commit()
    return eid


def _row(db, eid, table="entities"):
    return db.get_conn().execute(f"SELECT * FROM {table} WHERE id=?", (eid,)).fetchone()


def _journal(db, target_id):
    return db.get_conn().execute(
        "SELECT * FROM review_decisions WHERE target_id=? ORDER BY id", (target_id,),
    ).fetchall()


# ── Migration ────────────────────────────────────────────────────────────────

def test_rows_decided_before_the_column_existed_become_legacy(temp_db):
    job = _job(temp_db)
    decided = _entity(temp_db, job, accepted=1)
    pending = _entity(temp_db, job, accepted=None)

    temp_db.init_db()   # the migration runs on every start

    assert _row(temp_db, decided)["decision_origin"] == "legacy"
    assert _row(temp_db, pending)["decision_origin"] is None


# ── Entity routes ────────────────────────────────────────────────────────────

def test_patch_accepted_is_a_human_decision_and_is_journaled(temp_db, temp_db_client):
    job = _job(temp_db)
    eid = _entity(temp_db, job)

    resp = temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}", json={"accepted": True})
    assert resp.status_code == 200, resp.text
    assert resp.json()["decision_origin"] == "human"

    row = _row(temp_db, eid)
    assert row["accepted"] == 1 and row["decision_origin"] == "human" and row["decided_at"]
    [line] = _journal(temp_db, eid)
    assert (line["previous"], line["accepted"], line["origin"], line["target_kind"]) == (
        None, 1, "human", "entity")


def test_patch_can_say_bulk_but_never_claim_an_automatic_origin(temp_db, temp_db_client):
    job = _job(temp_db)
    eid = _entity(temp_db, job)

    ok = temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}",
                              json={"accepted": False, "decision_origin": "human_bulk"})
    assert ok.status_code == 200 and _row(temp_db, eid)["decision_origin"] == "human_bulk"

    for origin in ("auto_policy", "default", "legacy", "anything"):
        bad = temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}",
                                   json={"accepted": True, "decision_origin": origin})
        assert bad.status_code == 400, origin
    assert _row(temp_db, eid)["accepted"] == 0


def test_editing_the_value_alone_is_not_a_decision(temp_db, temp_db_client):
    job = _job(temp_db)
    eid = _entity(temp_db, job)
    resp = temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}", json={"value": "WellMail"})
    assert resp.status_code == 200
    row = _row(temp_db, eid)
    assert row["value"] == "WellMail" and row["decision_origin"] is None
    assert _journal(temp_db, eid) == []


def test_patch_on_a_missing_entity_is_404_and_journals_nothing(temp_db, temp_db_client):
    job = _job(temp_db)
    resp = temp_db_client.patch(f"/api/jobs/{job}/entities/nope", json={"accepted": True})
    assert resp.status_code == 404
    assert temp_db.get_conn().execute("SELECT COUNT(*) AS n FROM review_decisions").fetchone()["n"] == 0


def test_accept_pending_and_bulk_are_bulk_decisions(temp_db, temp_db_client):
    job = _job(temp_db)
    a = _entity(temp_db, job, etype="malware")
    b = _entity(temp_db, job, etype="tool")
    c = _entity(temp_db, job, etype="tool")

    resp = temp_db_client.post(f"/api/jobs/{job}/entities/bulk",
                               json={"entity_type": "tool", "action": "reject"})
    assert resp.json()["updated"] == 2
    resp = temp_db_client.post(f"/api/jobs/{job}/entities/accept-pending")
    assert resp.json()["accepted"] == 1

    assert (_row(temp_db, a)["accepted"], _row(temp_db, a)["decision_origin"]) == (1, "human_bulk")
    for eid in (b, c):
        assert (_row(temp_db, eid)["accepted"], _row(temp_db, eid)["decision_origin"]) == (0, "human_bulk")
    assert len(_journal(temp_db, a)) == len(_journal(temp_db, b)) == 1


# ── Auto-accept ──────────────────────────────────────────────────────────────

def test_auto_accept_takes_undecided_rows_at_the_level_and_records_the_policy(temp_db):
    job = _job(temp_db)
    high = _entity(temp_db, job, conf=0.95)
    exact = _entity(temp_db, job, conf=0.90)
    low = _entity(temp_db, job, conf=0.89)
    conn = temp_db.get_conn()

    counts = decisions.apply_auto_accept(conn, job, temp_db.now_iso(), rate=0.0)

    assert counts == {"accepted": 2, "control_sample": 0}
    for eid in (high, exact):
        row = _row(temp_db, eid)
        assert (row["accepted"], row["decision_origin"]) == (1, "auto_policy")
        assert row["policy_version"] == "auto-accept/1 level=0.90 control=0.00"
        [line] = _journal(temp_db, eid)
        assert line["origin"] == "auto_policy" and line["policy_version"] == row["policy_version"]
    assert _row(temp_db, low)["accepted"] is None


def test_auto_accept_never_overrides_an_analyst_reset(temp_db, temp_db_client):
    job = _job(temp_db)
    eid = _entity(temp_db, job, conf=0.99)
    temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}", json={"accepted": None})

    counts = decisions.apply_auto_accept(temp_db.get_conn(), job, temp_db.now_iso(), rate=0.0)

    assert counts["accepted"] == 0
    row = _row(temp_db, eid)
    assert row["accepted"] is None and row["decision_origin"] == "human"


def test_the_control_sample_is_left_pending_and_flagged(temp_db):
    job = _job(temp_db)
    ids = [_entity(temp_db, job, value=f"m{i}", conf=0.95) for i in range(40)]
    conn = temp_db.get_conn()

    counts = decisions.apply_auto_accept(conn, job, temp_db.now_iso(), rate=0.25)

    sampled = [e for e in ids if decisions.in_control_sample(e, 0.25)]
    assert counts == {"accepted": 40 - len(sampled), "control_sample": len(sampled)}
    for eid in ids:
        row = _row(temp_db, eid)
        if eid in sampled:
            assert (row["accepted"], row["control_sample"], row["decision_origin"]) == (None, 1, None)
        else:
            assert (row["accepted"], row["control_sample"]) == (1, 0)

    # A second run changes nothing: sampled rows stay pending, accepted stay accepted.
    assert decisions.apply_auto_accept(conn, job, temp_db.now_iso(), rate=0.25) == {
        "accepted": 0, "control_sample": 0}


def test_control_sample_draw_is_deterministic_and_respects_the_edges():
    ids = [str(uuid4()) for _ in range(2000)]
    assert [decisions.in_control_sample(i, 0.1) for i in ids] == [
        decisions.in_control_sample(i, 0.1) for i in ids]
    share = sum(decisions.in_control_sample(i, 0.1) for i in ids) / len(ids)
    assert 0.07 < share < 0.13
    assert not any(decisions.in_control_sample(i, 0.0) for i in ids)
    assert all(decisions.in_control_sample(i, 1.0) for i in ids)


def test_control_sample_rate_reads_and_clamps_the_environment(monkeypatch):
    monkeypatch.setenv("REVIEW_CONTROL_SAMPLE_RATE", "0.3")
    assert decisions.control_sample_rate() == 0.3
    monkeypatch.setenv("REVIEW_CONTROL_SAMPLE_RATE", "7")
    assert decisions.control_sample_rate() == 1.0
    monkeypatch.setenv("REVIEW_CONTROL_SAMPLE_RATE", "-1")
    assert decisions.control_sample_rate() == 0.0


def test_the_audit_measures_auto_accept_from_confirmed_control_rows(temp_db, temp_db_client):
    job = _job(temp_db)
    ids = [_entity(temp_db, job, value=f"m{i}", conf=0.95, source="cyner") for i in range(4)]
    decisions.apply_auto_accept(temp_db.get_conn(), job, temp_db.now_iso(), rate=1.0)
    temp_db_client.patch(f"/api/jobs/{job}/entities/{ids[0]}", json={"accepted": True})
    temp_db_client.patch(f"/api/jobs/{job}/entities/{ids[1]}", json={"accepted": True})
    temp_db_client.patch(f"/api/jobs/{job}/entities/{ids[2]}", json={"accepted": False})

    data = temp_db_client.get("/api/thresholds").json()

    assert data["auto_accept_audit"] == [{
        "source": "cyner", "entity_type": "malware",
        "sampled": 4, "decided": 3, "confirmed": 2, "precision": 0.6667,
    }]
    assert "control_sample_rate" in data


# ── Readers of decisions ─────────────────────────────────────────────────────

def _seed_curve(db, job, origin):
    """300 gliner/malware decisions whose accept rate rises with the score."""
    rows = []
    for i in range(300):
        conf = 0.40 + 0.5 * i / 300
        rows.append((conf, 1 if i % 10 < (i // 30) else 0))
    with db.get_conn() as conn:
        conn.executemany(
            "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, "
            "source, decision_origin) VALUES (?,?,?,?,?,?,?,?,?)",
            [(str(uuid4()), job, f"e{i}", "malware", "", c, a, "gliner", origin)
             for i, (c, a) in enumerate(rows)],
        )
        conn.commit()


def test_calibration_ignores_automatic_bulk_and_legacy_decisions(temp_db):
    job = _job(temp_db)
    _seed_curve(temp_db, job, "human")
    conn = temp_db.get_conn()
    [before] = cal.calibrate(conn, target_precision=0.9, min_samples=100)

    # The page's old behaviour: a flood of accepts above 0.9, labelled every way
    # a non-analyst accept can be.
    for origin in ("auto_policy", "human_bulk", "legacy", "default"):
        for i in range(200):
            _entity(temp_db, job, value=f"{origin}{i}", conf=0.95, accepted=1, origin=origin)
    [after] = cal.calibrate(conn, target_precision=0.9, min_samples=100)

    assert after.as_dict() == before.as_dict()
    assert cal.excluded_decisions(conn) == {
        "auto_policy": 200, "human_bulk": 200, "legacy": 200, "default": 200}

    widened = cal.calibrate(conn, target_precision=0.9, min_samples=100,
                            origins=cal.decision_origins(include_bulk=True))
    assert widened[0].sample_size == before.sample_size + 200


def test_recalibrate_route_reports_what_it_set_aside(temp_db, temp_db_client):
    job = _job(temp_db)
    _seed_curve(temp_db, job, "human")
    _entity(temp_db, job, conf=0.95, accepted=1, origin="auto_policy")

    data = temp_db_client.post("/api/thresholds/recalibrate", json={}).json()

    assert data["origins"] == ["human"]
    assert data["excluded_by_origin"] == {"auto_policy": 1}
    both = temp_db_client.post("/api/thresholds/recalibrate",
                               json={"include_bulk": True, "include_legacy": True}).json()
    assert both["origins"] == ["human", "human_bulk", "legacy"]


@pytest.mark.parametrize(("origin", "counts"), [
    ("human", True), ("human_bulk", True),
    ("auto_policy", False), ("legacy", False), ("default", False), ("propagated", False),
])
def test_only_analyst_accepts_count_toward_promotion(temp_db, origin, counts):
    for j in ("j1", "j2", "j3"):
        _job(temp_db, j)
        _entity(temp_db, j, value="Sunspotter", etype="malware", conf=0.9, accepted=1,
                origin=origin, source="llm")

    decided = promotion.load_decisions(temp_db.get_conn())

    assert (len(decided) == 3) is counts


def test_a_legacy_reject_still_counts_toward_deny(temp_db):
    for j in ("j1", "j2", "j3"):
        _job(temp_db, j)
        _entity(temp_db, j, value="Microsoft", etype="threat_actor", accepted=0, origin="legacy",
                source="cyner")
    [c] = promotion.compute_candidates(promotion.load_decisions(temp_db.get_conn()))
    assert (c.action, c.rejected_count) == ("deny", 3)


# ── Relationships and the worker's own writes ────────────────────────────────

def test_relationship_create_and_patch_are_human_decisions(temp_db, temp_db_client):
    job = _job(temp_db)
    created = temp_db_client.post(
        f"/api/jobs/{job}/relationships",
        json={"source_value": "APT29", "relationship_type": "uses", "target_value": "WellMess"},
    ).json()
    assert created["decision_origin"] == "human"
    assert [line["accepted"] for line in _journal(temp_db, created["id"])] == [1]

    resp = temp_db_client.patch(f"/api/jobs/{job}/relationships/{created['id']}",
                                json={"accepted": False})
    assert resp.status_code == 200 and resp.json()["decision_origin"] == "human"
    assert [(line["previous"], line["accepted"]) for line in _journal(temp_db, created["id"])] == [
        (None, 1), (1, 0)]
    assert temp_db_client.patch(
        f"/api/jobs/{job}/relationships/{created['id']}",
        json={"accepted": True, "decision_origin": "auto_policy"},
    ).status_code == 400


def test_pipeline_relationships_are_accepted_by_default_not_by_anyone(temp_db):
    from api import worker
    from models.schemas import EvidenceLabel
    from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted

    job = _job(temp_db)
    worker._save_entities(job, [], LLMEnrichmentResult(relationships=[RelationshipExtracted(
        source_value="APT29", relationship_type="uses", target_value="WellMess",
        confidence=0.9, evidence_text="APT29 used WellMess.", evidence_label=EvidenceLabel.OBSERVED,
    )]))

    row = temp_db.get_conn().execute(
        "SELECT accepted, decision_origin FROM relationships WHERE job_id=?", (job,)).fetchone()
    assert (row["accepted"], row["decision_origin"]) == (1, "default")


def test_worker_auto_accept_hook_never_fails_the_job(temp_db, monkeypatch):
    from api import worker

    def boom(*a, **k):
        raise RuntimeError("store down")

    monkeypatch.setattr("pipeline.decisions.apply_auto_accept", boom)
    worker._apply_auto_accept("no-such-job")   # logs, does not raise
