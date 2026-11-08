"""Response models of the entities, relationships and overrides routes (ADR-0097 item 22).

The models describe what the routes already return; they change no response.
Each operation is called on a seeded temp database and its JSON body is
compared with the full dict the route builds.  The last test reads the
published OpenAPI schema: every operation of these three route files must
declare a response, so the contract snapshot records it.
"""
from __future__ import annotations

from uuid import UUID

import pytest

from api.routes.relationships import VALID_REL_TYPES
from pipeline import decisions


@pytest.fixture()
def job(temp_db) -> str:
    ts = temp_db.now_iso()
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES ('j1', 'r.pdf', 'for_review', ?, ?)", (ts, ts))
        conn.commit()
    return "j1"


def _entity_dict(eid: str, value: str, entity_type: str, *, accepted=None, origin=None) -> dict:
    return {
        "id": eid, "job_id": "j1", "value": value, "entity_type": entity_type, "context": "",
        "confidence": 0.7, "mitre_id": None, "accepted": accepted, "source": "manual",
        "decision_origin": origin, "control_sample": False, "held_reason": None,
        "enrichment_status": None, "baseline_stix_id": None,
    }


def _rel_dict(rid: str, *, accepted=True, origin="human") -> dict:
    return {
        "id": rid, "job_id": "j1", "source_value": "APT29", "relationship_type": "uses",
        "target_value": "WellMess", "confidence": 0.9, "evidence_text": "APT29 used WellMess.",
        "evidence_label": "observed", "start_time": None, "stop_time": None, "times": [],
        "accepted": accepted, "decision_origin": origin, "held_reason": None,
        "enrichment_status": None, "baseline_stix_id": None,
    }


# ── entities ───────────────────────────────────────────────────────────────────

def test_entity_operations_return_the_rows_they_describe(temp_db_client, job):
    base = f"/api/jobs/{job}/entities"

    made = temp_db_client.post(base, json={"value": "SUNBURST", "entity_type": "malware",
                                           "context": "", "confidence": 0.7})
    assert made.status_code == 200
    eid = made.json()["id"]
    UUID(eid)
    assert made.json() == _entity_dict(eid, "SUNBURST", "malware")

    listed = temp_db_client.get(base)
    assert listed.status_code == 200
    assert listed.json() == [_entity_dict(eid, "SUNBURST", "malware")]

    patched = temp_db_client.patch(f"{base}/{eid}", json={"accepted": True})
    assert patched.status_code == 200
    assert patched.json() == _entity_dict(eid, "SUNBURST", "malware", accepted=True,
                                          origin=decisions.HUMAN)

    pending = temp_db_client.post(base, json={"value": "Cobalt Strike", "entity_type": "tool"}).json()
    accepted_pending = temp_db_client.post(f"{base}/accept-pending")
    assert accepted_pending.status_code == 200
    assert accepted_pending.json() == {"accepted": 1}
    assert pending["accepted"] is None

    bulk = temp_db_client.post(f"{base}/bulk", json={"entity_type": "malware", "action": "reject",
                                                     "scope": "all"})
    assert bulk.status_code == 200
    assert bulk.json() == {"updated": 1, "entity_type": "malware", "action": "reject", "scope": "all"}

    deleted = temp_db_client.delete(f"{base}/{eid}")
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": eid}


# ── relationships ──────────────────────────────────────────────────────────────

def test_relationship_operations_return_the_rows_they_describe(temp_db_client, job):
    base = f"/api/jobs/{job}/relationships"

    types = temp_db_client.get(f"{base}/valid-types")
    assert types.status_code == 200
    assert types.json() == VALID_REL_TYPES

    made = temp_db_client.post(base, json={
        "source_value": "APT29", "relationship_type": "uses", "target_value": "WellMess",
        "confidence": 0.9, "evidence_text": "APT29 used WellMess.", "evidence_label": "observed",
    })
    assert made.status_code == 200
    rid = made.json()["id"]
    UUID(rid)
    assert made.json() == _rel_dict(rid)

    listed = temp_db_client.get(base)
    assert listed.status_code == 200
    assert listed.json() == [_rel_dict(rid)]

    patched = temp_db_client.patch(f"{base}/{rid}", json={"accepted": False})
    assert patched.status_code == 200
    assert patched.json() == _rel_dict(rid, accepted=False)

    bulk = temp_db_client.post(f"{base}/bulk", json={"ids": [rid], "action": "reset"})
    assert bulk.status_code == 200
    assert bulk.json() == {"updated": 1, "action": "reset"}

    deleted = temp_db_client.delete(f"{base}/{rid}")
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": rid}


# ── overrides ──────────────────────────────────────────────────────────────────

def _seed_rejections(db, value: str, etype: str, jobs: int) -> None:
    from uuid import uuid4

    conn = db.get_conn()
    now = db.now_iso()
    for i in range(jobs):
        job = f"job-{etype}-{i}"
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
            (job, "r.pdf", "for_review", now, now),
        )
        conn.execute(
            "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, source, "
            "decision_origin) VALUES (?,?,?,?,?,?,?,?,?)",
            (str(uuid4()), job, value, etype, "", 0.9, 0, "cyner", "human"),
        )
    conn.commit()


def test_override_operations_return_the_rows_they_describe(temp_db, temp_db_client):
    _seed_rejections(temp_db, "Microsoft", "threat_actor", 3)

    empty = temp_db_client.get("/api/overrides")
    assert empty.status_code == 200
    assert empty.json() == {"enabled": True, "rows": []}

    promoted = temp_db_client.post("/api/overrides/promote", json={})
    assert promoted.status_code == 200
    body = promoted.json()
    assert body["applied"] is False and body["written"] == 0
    [candidate] = body["candidates"]
    assert candidate == {
        "term": "microsoft", "entity_type": "threat_actor", "action": "deny",
        "display": "microsoft", "accepted_count": 0, "rejected_count": 3, "job_count": 3,
        "existing_status": None, "sources": ["cyner"],
    }

    made = temp_db_client.post("/api/overrides", json={"term": "Foo Bar", "entity_type": "threat_actor",
                                                       "action": "deny", "note": "x"})
    assert made.status_code == 200
    row = made.json()
    oid = row["id"]
    UUID(oid)
    assert row == {
        "id": oid, "term": "foo bar", "entity_type": "threat_actor", "action": "deny",
        "status": "active", "display": "Foo Bar", "accepted_count": 0, "rejected_count": 0,
        "job_count": 0, "origin": "manual", "note": "x",
        "created_at": row["created_at"], "updated_at": row["updated_at"],
    }

    patched = temp_db_client.patch(f"/api/overrides/{oid}", json={"status": "ignored"})
    assert patched.status_code == 200
    assert patched.json() == {**row, "status": "ignored", "updated_at": patched.json()["updated_at"]}

    listed = temp_db_client.get("/api/overrides").json()
    assert listed["enabled"] is True
    assert patched.json() in listed["rows"]

    deleted = temp_db_client.delete(f"/api/overrides/{oid}")
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": oid}


# ── the published schema ───────────────────────────────────────────────────────

_PREFIXES = ("/api/jobs/{job_id}/entities", "/api/jobs/{job_id}/relationships", "/api/overrides")


def test_every_operation_of_these_routes_declares_its_response():
    from api.main import app

    paths = app.openapi()["paths"]
    operations = [
        (path, method)
        for path, item in paths.items() if path.startswith(_PREFIXES)
        for method in item
    ]
    assert len(operations) == 17

    for path, method in operations:
        responses = paths[path][method]["responses"]
        ok = responses["200"]
        assert "content" in ok and "application/json" in ok["content"], (method, path)
        assert "schema" in ok["content"]["application/json"], (method, path)
