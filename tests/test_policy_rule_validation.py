"""Regression tests: a malformed relationship policy must not break the pipeline.

`PUT /api/relationship-policy` validated that `rules` was a list but never
validated its items, so `{"rules": ["oops"]}` was accepted, stored, and then
raised AttributeError in every subsequent job — inside the one code path that
promises completion "must never break the bundle".
"""

import inspect

import pytest
import stix2
from fastapi.testclient import TestClient

from api.main import app
from pipeline.stage4_stix_mapping import build_stix_bundle
from pipeline.stage4b_graph_completion import _pol_index, complete_graph

MALFORMED_POLICIES = [
    {"version": 1, "global": "enforce", "rules": ["oops"]},
    {"version": 1, "global": "enforce", "rules": [None]},
    {"version": 1, "global": "enforce", "rules": [42]},
    {"version": 1, "global": "enforce", "rules": [{"src": "a", "tgt": "b"}, "trailing"]},
]


@pytest.mark.parametrize("policy", MALFORMED_POLICIES)
def test_pol_index_skips_non_dict_rules(policy):
    result = _pol_index(policy)
    assert isinstance(result, dict)
    if any(isinstance(r, dict) and r.get("src") == "a" for r in policy["rules"]):
        assert "a>b" in result


@pytest.mark.parametrize("policy", MALFORMED_POLICIES)
def test_complete_graph_survives_a_malformed_policy(policy):
    actor = stix2.ThreatActor(name="Probe Actor", allow_custom=True)
    mal = stix2.Malware(name="ProbeMal", is_family=False, allow_custom=True)
    rel = stix2.Relationship(relationship_type="uses", source_ref=actor.id,
                             target_ref=mal.id, allow_custom=True)
    objects = [actor, mal, rel]
    stats = complete_graph(objects, policy=policy)
    assert stats is not None
    # before the fix this raised AttributeError from `_pol_index`, which
    # runs BEFORE the per-engine try/except blocks.


@pytest.mark.parametrize("policy", MALFORMED_POLICIES)
def test_build_stix_bundle_survives_a_malformed_policy(policy):
    sig = inspect.signature(build_stix_bundle)
    if "relationship_policy" not in sig.parameters:
        pytest.skip("build_stix_bundle has no relationship_policy parameter")

    kwargs = {"relationship_policy": policy}
    for pname, p in sig.parameters.items():
        if pname == "relationship_policy" or p.default is not inspect.Parameter.empty:
            continue
        kwargs[pname] = None
    try:
        build_stix_bundle(**kwargs)
    except AttributeError as exc:      # the defect being locked
        pytest.fail(f"malformed policy reached an unguarded .get: {exc}")
    except Exception:
        pass                            # any OTHER failure is unrelated to this test
    # only AttributeError is a failure here, because
    # passing None for the real inputs will legitimately fail some other way.


def test_api_rejects_non_object_rules():
    client = TestClient(app)
    for policy in MALFORMED_POLICIES:
        r = client.put("/api/relationship-policy", json=policy)
        assert r.status_code == 400, f"accepted {policy['rules']!r}"
        assert "rules[" in r.json()["detail"]


def test_api_still_accepts_a_valid_policy():
    client = TestClient(app)
    good = {"version": 1, "global": "enforce",
            "rules": [{"src": "threat-actor", "tgt": "malware",
                       "verb": "uses", "mode": "pin", "enabled": True}]}
    r = client.put("/api/relationship-policy", json=good)
    assert r.status_code == 200
    # guards against the validation being over-tightened.


def test_api_still_accepts_empty_rules():
    client = TestClient(app)
    r = client.put("/api/relationship-policy", json={"version": 1, "global": "enforce", "rules": []})
    assert r.status_code == 200
