"""/api/jobs/{job_id}/entities — list, manual create, edit, bulk and delete.

Decision bookkeeping (origin, journal) is test_decisions.py's; these tests
cover the CRUD paths and their refusals.
"""
from __future__ import annotations

import pytest


@pytest.fixture()
def job(temp_db) -> str:
    ts = temp_db.now_iso()
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES ('j1', 'r.pdf', 'for_review', ?, ?)", (ts, ts))
        conn.commit()
    return "j1"


def _url(job: str, suffix: str = "") -> str:
    return f"/api/jobs/{job}/entities{suffix}"


def _create(client, job: str, value: str, entity_type: str = "malware", **kw) -> dict:
    resp = client.post(_url(job), json={"value": value, "entity_type": entity_type, **kw})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_a_manual_entity_is_created_pending_and_listed(temp_db_client, job):
    made = _create(temp_db_client, job, "SUNBURST", context="deployed SUNBURST", confidence=0.7)

    assert made["source"] == "manual" and made["accepted"] is None and made["control_sample"] is False
    listed = temp_db_client.get(_url(job)).json()
    assert [(e["id"], e["value"], e["context"], e["confidence"]) for e in listed] == [
        (made["id"], "SUNBURST", "deployed SUNBURST", 0.7)]


def test_entities_are_listed_by_type_then_value(temp_db_client, job):
    _create(temp_db_client, job, "Zebra", "threat_actor")
    _create(temp_db_client, job, "beta", "malware")
    _create(temp_db_client, job, "Alpha", "malware")
    assert [e["value"] for e in temp_db_client.get(_url(job)).json()] == ["Alpha", "beta", "Zebra"]
    assert temp_db_client.get(_url("other-job")).json() == []


def test_create_refuses_an_unknown_type_or_job(temp_db_client, job):
    assert temp_db_client.post(_url(job), json={"value": "x", "entity_type": "rootkit"}).status_code == 400
    assert temp_db_client.post(_url("nope"), json={"value": "x", "entity_type": "malware"}).status_code == 404


def test_an_entity_can_be_retyped_renamed_and_its_mitre_id_cleared(temp_db_client, job):
    eid = _create(temp_db_client, job, "spearphish", "technique", mitre_id="T1566")["id"]

    edited = temp_db_client.patch(_url(job, f"/{eid}"), json={"value": "Spearphishing", "entity_type": "tool"}).json()
    assert (edited["value"], edited["entity_type"], edited["mitre_id"]) == ("Spearphishing", "tool", "T1566")

    cleared = temp_db_client.patch(_url(job, f"/{eid}"), json={"mitre_id": None}).json()
    assert cleared["mitre_id"] is None and cleared["accepted"] is None       # no decision was made


def test_an_empty_patch_changes_nothing(temp_db_client, job):
    made = _create(temp_db_client, job, "SUNBURST")
    assert temp_db_client.patch(_url(job, f"/{made['id']}"), json={}).json() == made


def test_patch_refuses_an_unknown_type_origin_or_entity(temp_db_client, job):
    eid = _create(temp_db_client, job, "SUNBURST")["id"]

    bad_type = temp_db_client.patch(_url(job, f"/{eid}"), json={"entity_type": "rootkit"})
    assert bad_type.status_code == 400 and "rootkit" in bad_type.json()["detail"]
    bad_origin = temp_db_client.patch(_url(job, f"/{eid}"), json={"accepted": True, "decision_origin": "auto"})
    assert bad_origin.status_code == 400 and "human, human_bulk" in bad_origin.json()["detail"]
    assert temp_db_client.patch(_url("other-job", f"/{eid}"), json={"value": "x"}).status_code == 404


@pytest.mark.parametrize("body,message", [
    ({"entity_type": "malware", "action": "delete"}, "action must be one of"),
    ({"entity_type": "malware", "action": "accept", "scope": "some"}, "scope must be one of"),
    ({"entity_type": "malware", "action": "reset"}, "is a no-op"),
    ({"entity_type": "rootkit", "action": "accept"}, "Unknown entity_type"),
])
def test_bulk_refuses_an_invalid_request(temp_db_client, job, body, message):
    resp = temp_db_client.post(_url(job, "/bulk"), json=body)
    assert resp.status_code == 400 and message in resp.json()["detail"]


def test_bulk_on_an_unknown_job_is_a_404(temp_db_client, job):
    resp = temp_db_client.post(_url("nope", "/bulk"), json={"entity_type": "malware", "action": "accept"})
    assert resp.status_code == 404


def test_bulk_reject_all_then_reset_all(temp_db_client, job):
    a = _create(temp_db_client, job, "A")["id"]
    _create(temp_db_client, job, "B")
    _create(temp_db_client, job, "APT29", "threat_actor")
    temp_db_client.patch(_url(job, f"/{a}"), json={"accepted": True})

    rejected = temp_db_client.post(_url(job, "/bulk"),
                                   json={"entity_type": "malware", "action": "reject", "scope": "all"}).json()
    assert rejected == {"updated": 2, "entity_type": "malware", "action": "reject", "scope": "all"}

    reset = temp_db_client.post(_url(job, "/bulk"),
                                json={"entity_type": "malware", "action": "reset", "scope": "all"}).json()
    assert reset["updated"] == 2
    states = {e["value"]: e["accepted"] for e in temp_db_client.get(_url(job)).json()}
    assert states == {"A": None, "B": None, "APT29": None}


def test_an_entity_can_be_deleted_once(temp_db_client, job):
    eid = _create(temp_db_client, job, "SUNBURST")["id"]
    assert temp_db_client.delete(_url(job, f"/{eid}")).json() == {"deleted": eid}
    assert temp_db_client.delete(_url(job, f"/{eid}")).status_code == 404
    assert temp_db_client.get(_url(job)).json() == []
