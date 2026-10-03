"""GET/PUT /api/relationship-policy — what the store round-trips, and every
shape the PUT refuses before it can reach Stage 4 (test_policy_rule_validation
covers the non-object rule items)."""
from __future__ import annotations

import logging

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
def test_an_empty_or_corrupt_stored_policy_falls_back_to_the_default(temp_db_client, temp_db, stored,
                                                                      caplog):
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO relationship_policy (id, policy_json) VALUES (1, ?) "
                     "ON CONFLICT (id) DO UPDATE SET policy_json = excluded.policy_json", (stored,))
        conn.commit()
    with caplog.at_level(logging.ERROR, logger="api.routes.policy"):
        assert temp_db_client.get(_URL).json()["global"] == "enforce"
    # Empty means "never saved"; corrupt is an error the operator must see.
    assert any("not valid JSON" in r.getMessage() for r in caplog.records) == (stored != "{}")


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


def _rule(src="threat-actor", verb="uses", tgt="malware", mode="pin", enabled=True):
    return {"src": src, "verb": verb, "tgt": tgt, "mode": mode, "enabled": enabled}


@pytest.mark.parametrize("rules,message", [
    ([_rule(src="actor")], "'rules[0]'.src must be a STIX 2.1 SDO or SCO type"),
    ([_rule(tgt="marking-definition")], "'rules[0]'.tgt must be a STIX 2.1 SDO or SCO type"),
    ([_rule(verb="executes")], "'rules[0]'.verb 'executes' is not a STIX 2.1 relationship type"),
    ([_rule(mode="force")], "'rules[0]'.mode must be"),
    ([_rule(enabled="yes")], "'rules[0]'.enabled must be a boolean"),
    ([_rule(), _rule(verb="related-to", mode="auto")], "'rules[1]' repeats the pair threat-actor>malware"),
    # A pinned verb Stage 4 would not ship: it used to emit related-to edges
    # labelled with a verb they did not carry.
    ([_rule(src="malware", verb="duplicate-of", tgt="tool")], "which Stage 4 would not ship as written"),
    ([_rule(src="ipv4-addr", verb="uses", tgt="attack-pattern")], "which Stage 4 would not ship as written"),
])
def test_a_rule_stage4_would_not_apply_as_written_is_refused(temp_db_client, rules, message):
    resp = temp_db_client.put(_URL, json={"version": 1, "global": "enforce", "rules": rules})
    assert resp.status_code == 400 and message in resp.json()["detail"]


@pytest.mark.parametrize("rule", [
    _rule(src="ipv4-addr", verb="indicates", tgt="malware"),          # through the IoC's Indicator
    _rule(src="malware", verb="communicates-with", tgt="domain-name"),  # listed on the observable
    _rule(src="malware", verb="duplicate-of", tgt="malware"),           # same type (§3.7)
    _rule(src="malware", verb="duplicate-of", tgt="tool", enabled=False),
    _rule(src="malware", verb="duplicate-of", tgt="tool", mode="auto"),
])
def test_a_rule_that_ships_as_written_or_is_not_pinned_is_stored(temp_db_client, rule):
    resp = temp_db_client.put(_URL, json={"version": 1, "global": "enforce", "rules": [rule]})
    assert resp.status_code == 200, resp.json()
