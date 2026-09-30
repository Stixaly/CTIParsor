"""GET/PUT /api/relationship-policy — what the store round-trips, and every
shape the PUT refuses before it can reach Stage 4 (test_policy_rule_validation
covers the non-object rule items)."""
from __future__ import annotations

import pytest

_URL = "/api/relationship-policy"

_FULL = {
    "version": 1,
    "global": "auto",
    "rules": [{"src": "threat-actor", "verb": "uses", "tgt": "malware", "mode": "pin", "enabled": True}],
    "max_pinned_edges": 50,
    "pin_budget_mode": "sequential",
    "pin_evidence": {"mode": "cartesian", "window": 0},
    "completion": {"transitive": False, "alias": True, "semantic_alias": False, "max_new_edges": 10},
    "temporal_export": {"mode": "day"},
}


def test_the_factory_default_is_served_until_a_policy_is_stored(temp_db_client):
    assert temp_db_client.get(_URL).json() == {"version": 1, "global": "enforce", "rules": []}


def test_a_full_policy_round_trips(temp_db_client):
    assert temp_db_client.put(_URL, json=_FULL).json() == _FULL
    assert temp_db_client.get(_URL).json() == _FULL

    replacement = {"version": 1, "global": "enforce", "rules": []}
    temp_db_client.put(_URL, json=replacement)
    assert temp_db_client.get(_URL).json() == replacement            # full replacement, not a patch


@pytest.mark.parametrize("stored", ["{}", "{not json"])
def test_an_empty_or_corrupt_stored_policy_falls_back_to_the_default(temp_db_client, temp_db, stored):
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO relationship_policy (id, policy_json) VALUES (1, ?) "
                     "ON CONFLICT (id) DO UPDATE SET policy_json = excluded.policy_json", (stored,))
        conn.commit()
    assert temp_db_client.get(_URL).json()["global"] == "enforce"


def test_a_body_that_is_not_json_is_refused(temp_db_client):
    resp = temp_db_client.put(_URL, content=b"{nope", headers={"content-type": "application/json"})
    assert resp.status_code == 400 and "valid JSON" in resp.json()["detail"]


@pytest.mark.parametrize("body,message", [
    ([], "must be a JSON object"),
    ({"rules": {"src": "a"}}, "'rules' must be an array"),
    ({"global": "strict"}, "'global' must be"),
    ({"pin_budget_mode": "greedy"}, "'pin_budget_mode' must be"),
    ({"max_pinned_edges": -1}, "'max_pinned_edges' must be"),
    ({"max_pinned_edges": "200"}, "'max_pinned_edges' must be"),
    ({"max_pinned_edges": True}, "'max_pinned_edges' must be"),
    ({"pin_evidence": "cooccurrence"}, "'pin_evidence' must be a JSON object"),
    ({"pin_evidence": {"mode": "nearby"}}, "'pin_evidence.mode' must be"),
    ({"pin_evidence": {"window": -3}}, "'pin_evidence.window' must be"),
    ({"pin_evidence": {"window": False}}, "'pin_evidence.window' must be"),
    ({"completion": ["transitive"]}, "'completion' must be a JSON object"),
    ({"completion": {"long_distance": "yes"}}, "'completion.long_distance' must be a boolean"),
    ({"completion": {"max_new_edges": 1.5}}, "'completion.max_new_edges' must be"),
    ({"completion": {"max_new_edges": True}}, "'completion.max_new_edges' must be"),
    ({"temporal_export": "day"}, "'temporal_export' must be a JSON object"),
    ({"temporal_export": {"mode": "hour"}}, "'temporal_export.mode' must be one of"),
])
def test_an_invalid_policy_is_refused_and_not_stored(temp_db_client, body, message):
    resp = temp_db_client.put(_URL, json=body)
    assert resp.status_code == 400 and message in resp.json()["detail"]
    assert temp_db_client.get(_URL).json() == {"version": 1, "global": "enforce", "rules": []}
