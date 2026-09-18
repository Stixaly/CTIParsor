"""/api/overrides (ADR-0052) — list, promote, hand-write, activate, delete.

Runs on the isolated temp database on both engines.  The contract under
test: promotion writes candidates only when asked and never activates; a
candidate does nothing until a person activates it; a hand-written rule is
active at once.
"""
from __future__ import annotations

from uuid import uuid4

import pipeline.overrides as ov


def _seed_rejections(db, value: str, etype: str, jobs: int) -> None:
    conn = db.get_conn()
    now = db.now_iso()
    for i in range(jobs):
        job = f"job-{etype}-{i}"
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
            (job, "r.pdf", "for_review", now, now),
        )
        conn.execute(
            "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, source) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (str(uuid4()), job, value, etype, "", 0.9, 0, "cyner"),
        )
    conn.commit()


def test_get_is_empty_on_a_fresh_store(temp_db, temp_db_client):
    resp = temp_db_client.get("/api/overrides")
    assert resp.status_code == 200
    assert resp.json() == {"enabled": True, "rows": []}
    assert temp_db_client.get("/api/overrides?status=nope").status_code == 400
    assert temp_db_client.get("/api/overrides?action=nope").status_code == 400


def test_promote_is_a_dry_run_unless_asked_and_never_activates(temp_db, temp_db_client):
    _seed_rejections(temp_db, "Microsoft", "threat_actor", 3)

    resp = temp_db_client.post("/api/overrides/promote", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["applied"] is False and data["written"] == 0
    [c] = data["candidates"]
    assert (c["action"], c["term"], c["entity_type"]) == ("deny", "microsoft", "threat_actor")
    assert c["existing_status"] is None
    assert temp_db_client.get("/api/overrides").json()["rows"] == []

    resp = temp_db_client.post("/api/overrides/promote", json={"apply": True})
    assert resp.json()["written"] == 1
    [row] = temp_db_client.get("/api/overrides").json()["rows"]
    assert row["status"] == "candidate"
    assert ov.is_denied("Microsoft", "threat_actor") is False      # a candidate does nothing

    resp = temp_db_client.patch(f"/api/overrides/{row['id']}", json={"status": "active"})
    assert resp.status_code == 200 and resp.json()["status"] == "active"
    assert ov.is_denied("Microsoft", "threat_actor") is True

    active = temp_db_client.get("/api/overrides?status=active&action=deny").json()["rows"]
    assert [r["status"] for r in active] == ["active"]
    assert temp_db_client.get("/api/overrides?status=candidate").json()["rows"] == []


def test_promote_validates_its_parameters(temp_db, temp_db_client):
    assert temp_db_client.post("/api/overrides/promote", json={"share": 0}).status_code == 400
    assert temp_db_client.post("/api/overrides/promote", json={"share": 1.5}).status_code == 400
    assert temp_db_client.post("/api/overrides/promote", json={"min_jobs": 0}).status_code == 400


def test_a_hand_written_rule_is_active_at_once(temp_db, temp_db_client):
    resp = temp_db_client.post("/api/overrides", json={
        "term": "ArguePatch", "entity_type": "malware", "action": "promote",
        "display": "ARGUEPATCH", "note": "Mandiant name",
    })
    assert resp.status_code == 200
    row = resp.json()
    assert (row["term"], row["display"], row["status"], row["origin"], row["note"]) == \
        ("arguepatch", "ARGUEPATCH", "active", "manual", "Mandiant name")
    assert ov.promoted_entries()[0]["canonical"] == "ARGUEPATCH"

    resp = temp_db_client.patch(f"/api/overrides/{row['id']}", json={"status": "ignored"})
    assert resp.status_code == 200
    assert ov.promoted_entries() == []

    assert temp_db_client.patch(f"/api/overrides/{row['id']}", json={"status": "nope"}).status_code == 400
    assert temp_db_client.patch("/api/overrides/missing", json={"status": "active"}).status_code == 404

    assert temp_db_client.delete(f"/api/overrides/{row['id']}").status_code == 200
    assert temp_db_client.delete(f"/api/overrides/{row['id']}").status_code == 404
    assert temp_db_client.get("/api/overrides").json()["rows"] == []


def test_create_validates_action_type_and_term(temp_db, temp_db_client):
    bad = [
        {"term": "x", "entity_type": "malware", "action": "block"},        # unknown action
        {"term": "x", "entity_type": "identity", "action": "promote"},     # the gazetteer has no identities
        {"term": "x", "entity_type": "ipv4", "action": "deny"},            # never a rule for an IoC type
        {"term": "   ", "entity_type": "malware", "action": "deny"},       # empty term
    ]
    for body in bad:
        assert temp_db_client.post("/api/overrides", json=body).status_code == 400, body
    assert temp_db_client.get("/api/overrides").json()["rows"] == []
