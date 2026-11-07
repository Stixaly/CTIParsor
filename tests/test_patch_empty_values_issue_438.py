"""PATCH refuses an empty or blank relationship_type / value (issue #438).

A key that is sent with an empty value is refused with 400 and changes nothing.
A key that is absent from the body is a partial PATCH and leaves the field alone.
"""
from __future__ import annotations

import pytest


@pytest.fixture()
def job(temp_db) -> str:
    ts = temp_db.now_iso()
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES ('j438', 'r.pdf', 'for_review', ?, ?)", (ts, ts))
        conn.commit()
    return "j438"


def _rel(client, job: str) -> dict:
    resp = client.post(f"/api/jobs/{job}/relationships",
                       json={"source_value": "APT29", "relationship_type": "uses", "target_value": "WellMess"})
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.parametrize("empty", ["", "   "])
def test_an_empty_relationship_type_is_refused_and_not_stored_issue_438(temp_db_client, job, empty):
    rid = _rel(temp_db_client, job)["id"]
    resp = temp_db_client.patch(f"/api/jobs/{job}/relationships/{rid}", json={"relationship_type": empty})
    assert resp.status_code == 400, resp.text
    assert "relationship_type" in resp.json()["detail"]
    stored = [r for r in temp_db_client.get(f"/api/jobs/{job}/relationships").json() if r["id"] == rid]
    assert stored[0]["relationship_type"] == "uses"


def test_an_absent_relationship_type_is_a_partial_patch_issue_438(temp_db_client, job):
    rid = _rel(temp_db_client, job)["id"]
    resp = temp_db_client.patch(f"/api/jobs/{job}/relationships/{rid}", json={"accepted": True})
    assert resp.status_code == 200, resp.text
    assert resp.json()["relationship_type"] == "uses"


def test_a_valid_relationship_type_is_still_accepted_issue_438(temp_db_client, job):
    rid = _rel(temp_db_client, job)["id"]
    resp = temp_db_client.patch(f"/api/jobs/{job}/relationships/{rid}", json={"relationship_type": "communicates-with"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["relationship_type"] == "communicates-with"


@pytest.mark.parametrize("empty", ["", "   "])
def test_an_empty_entity_value_is_refused_and_not_stored_issue_438(temp_db_client, job, empty):
    eid = temp_db_client.post(f"/api/jobs/{job}/entities",
                              json={"value": "SUNBURST", "entity_type": "malware"}).json()["id"]
    resp = temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}", json={"value": empty})
    assert resp.status_code == 400, resp.text
    assert "value" in resp.json()["detail"]
    stored = [e for e in temp_db_client.get(f"/api/jobs/{job}/entities").json() if e["id"] == eid]
    assert stored[0]["value"] == "SUNBURST"


def test_an_absent_entity_value_is_a_partial_patch_issue_438(temp_db_client, job):
    eid = temp_db_client.post(f"/api/jobs/{job}/entities",
                              json={"value": "SUNBURST", "entity_type": "malware"}).json()["id"]
    resp = temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}", json={"entity_type": "tool"})
    assert resp.status_code == 200, resp.text
    assert (resp.json()["value"], resp.json()["entity_type"]) == ("SUNBURST", "tool")


def test_an_empty_entity_type_is_still_refused_issue_438(temp_db_client, job):
    eid = temp_db_client.post(f"/api/jobs/{job}/entities",
                              json={"value": "SUNBURST", "entity_type": "malware"}).json()["id"]
    resp = temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}", json={"entity_type": ""})
    assert resp.status_code == 400, resp.text
