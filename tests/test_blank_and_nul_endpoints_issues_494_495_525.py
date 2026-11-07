"""Blank and unrepresentable values are refused by the entity and relationship API
(issues #494, #495, #525).

A blank value (after stripping) is a 400 and changes nothing, as the PATCH check
of #438 already answers. A NUL byte or a lone UTF-16 surrogate is a client error
(422 from pydantic, the same validator overrides.py uses), never a 500 from
PostgreSQL. A key that is absent from a PATCH body is a partial patch.
"""
from __future__ import annotations

import json

import pytest


def _raw_json(body: dict) -> dict:
    # httpx's json= encodes strictly as UTF-8, so a lone surrogate never leaves the
    # client. json.dumps escapes it as \ud800 in ASCII, and the server parses it back.
    return {"content": json.dumps(body), "headers": {"Content-Type": "application/json"}}


@pytest.fixture()
def job(temp_db) -> str:
    ts = temp_db.now_iso()
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES ('j494', 'r.pdf', 'reviewing', ?, ?)", (ts, ts))
        conn.commit()
    return "j494"


def _entity(client, job: str, value: str = "SUNBURST") -> str:
    resp = client.post(f"/api/jobs/{job}/entities", json={"value": value, "entity_type": "malware"})
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def _rel(client, job: str) -> str:
    resp = client.post(f"/api/jobs/{job}/relationships",
                       json={"source_value": "APT29", "relationship_type": "uses", "target_value": "WellMess"})
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def _stored_entity_values(client, job: str) -> list[str]:
    return [e["value"] for e in client.get(f"/api/jobs/{job}/entities").json()]


def _stored_relationships(client, job: str) -> list[dict]:
    return client.get(f"/api/jobs/{job}/relationships").json()


# ── Entity creation: blank values (#525) ──────────────────────────────────────

@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_a_blank_entity_value_on_create_is_refused_and_not_stored_issue_525(temp_db_client, job, blank):
    resp = temp_db_client.post(f"/api/jobs/{job}/entities", json={"value": blank, "entity_type": "malware"})
    assert resp.status_code == 400, resp.text
    assert "value" in resp.json()["detail"]
    assert _stored_entity_values(temp_db_client, job) == []


# ── NUL bytes and lone surrogates (#495, #525) ────────────────────────────────

@pytest.mark.parametrize("bad", ["abc\x00def", "\x00", "\ud800", "a\udfffb"])
def test_a_nul_or_lone_surrogate_entity_value_on_create_is_a_client_error_issue_495(temp_db_client, job, bad):
    resp = temp_db_client.post(f"/api/jobs/{job}/entities", **_raw_json({"value": bad, "entity_type": "malware"}))
    assert 400 <= resp.status_code < 500, resp.text
    assert _stored_entity_values(temp_db_client, job) == []


@pytest.mark.parametrize("bad", ["abc\x00def", "\ud800"])
def test_a_nul_or_lone_surrogate_entity_value_on_patch_is_a_client_error_issue_525(temp_db_client, job, bad):
    eid = _entity(temp_db_client, job)
    resp = temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}", **_raw_json({"value": bad}))
    assert 400 <= resp.status_code < 500, resp.text
    assert _stored_entity_values(temp_db_client, job) == ["SUNBURST"]


def test_a_blank_entity_value_on_patch_is_still_refused_issue_525(temp_db_client, job):
    eid = _entity(temp_db_client, job)
    resp = temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}", json={"value": "   "})
    assert resp.status_code == 400, resp.text
    assert _stored_entity_values(temp_db_client, job) == ["SUNBURST"]


def test_a_valid_entity_value_is_still_accepted_issue_525(temp_db_client, job):
    resp = temp_db_client.post(f"/api/jobs/{job}/entities", json={"value": "Emotet ünïcode", "entity_type": "malware"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["value"] == "Emotet ünïcode"


# ── Relationship endpoints: blank source or target (#494) ─────────────────────

@pytest.mark.parametrize("blank", ["", "   "])
@pytest.mark.parametrize("field", ["source_value", "target_value"])
def test_a_blank_relationship_end_on_create_is_refused_and_not_stored_issue_494(temp_db_client, job, field, blank):
    body = {"source_value": "APT29", "relationship_type": "uses", "target_value": "WellMess"}
    body[field] = blank
    resp = temp_db_client.post(f"/api/jobs/{job}/relationships", json=body)
    assert resp.status_code == 400, resp.text
    assert field in resp.json()["detail"]
    assert _stored_relationships(temp_db_client, job) == []


@pytest.mark.parametrize("blank", ["", "   "])
@pytest.mark.parametrize("field", ["source_value", "target_value"])
def test_a_blank_relationship_end_on_patch_is_refused_and_not_stored_issue_494(temp_db_client, job, field, blank):
    rid = _rel(temp_db_client, job)
    resp = temp_db_client.patch(f"/api/jobs/{job}/relationships/{rid}", json={field: blank})
    assert resp.status_code == 400, resp.text
    assert field in resp.json()["detail"]
    stored = _stored_relationships(temp_db_client, job)
    assert (stored[0]["source_value"], stored[0]["target_value"]) == ("APT29", "WellMess")


def test_an_absent_relationship_end_on_patch_is_a_partial_patch_issue_494(temp_db_client, job):
    rid = _rel(temp_db_client, job)
    resp = temp_db_client.patch(f"/api/jobs/{job}/relationships/{rid}", json={"accepted": True})
    assert resp.status_code == 200, resp.text
    assert (resp.json()["source_value"], resp.json()["target_value"]) == ("APT29", "WellMess")


def test_a_valid_relationship_end_is_still_accepted_issue_494(temp_db_client, job):
    rid = _rel(temp_db_client, job)
    resp = temp_db_client.patch(f"/api/jobs/{job}/relationships/{rid}", json={"source_value": "  APT28  "})
    assert resp.status_code == 200, resp.text
    assert resp.json()["source_value"] == "APT28"


@pytest.mark.parametrize("field", ["context", "mitre_id"])
def test_a_nul_in_another_entity_field_is_a_client_error_issue_525(temp_db_client, job, field):
    """Every text the INSERT writes is checked, not only the value (#525)."""
    body = {"value": "SUNBURST", "entity_type": "malware", field: "a\x00b"}
    resp = temp_db_client.post(f"/api/jobs/{job}/entities", **_raw_json(body))
    assert resp.status_code == 422
    assert "SUNBURST" not in _stored_entity_values(temp_db_client, job)


@pytest.mark.parametrize("field", ["source_value", "target_value", "evidence_text"])
def test_a_nul_in_a_relationship_field_is_a_client_error_issue_525(temp_db_client, job, field):
    """A NUL in a relationship text is a 422, not a 500 from PostgreSQL (#494, #525)."""
    body = {"source_value": "APT29", "relationship_type": "uses", "target_value": "SUNBURST", field: "a\x00b"}
    resp = temp_db_client.post(f"/api/jobs/{job}/relationships", **_raw_json(body))
    assert resp.status_code == 422
    rid = _rel(temp_db_client, job)
    resp = temp_db_client.patch(f"/api/jobs/{job}/relationships/{rid}", **_raw_json({field: "\ud800"}))
    assert resp.status_code == 422
