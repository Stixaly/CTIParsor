"""Response models of the coverage, ATT&CK and baseline routes (ADR-0094 item 1, group 2).

The models describe what the routes return; they must not change a response.
Each successful operation is called through the API and compared with what the
route function itself returns, serialised the way JSON serialises it.
"""
import json
from pathlib import Path
from uuid import uuid4

import pytest

import api.main
from api.routes import baselines, coverage
from models.detection import DetectionRule, Severity
from pipeline.detection.store import replace_corpus_rules

JOB = "jg2"
THE_HASH = "a" * 64
DOMAIN = "evil-campaign-c2.com"


def _rule(corpus, key, techniques, *, fmt="sigma", license="proprietary", atoms=()):
    return DetectionRule(
        id=f"{corpus}:{key}", corpus=corpus, title=f"rule {key}",
        technique_ids=list(techniques), severity=Severity.HIGH, license=license,
        format=fmt, atoms=list(atoms), raw=f"title: rule {key}\nlogsource: {corpus}\n",
    )


@pytest.fixture()
def seeded(temp_db):
    """A report with two techniques and two observables, and rules that hold or
    cover them: one tagged and evidence-backed, one untagged (evidence only), one
    suricata rule under another corpus."""
    conn = temp_db.get_conn()
    now = temp_db.now_iso()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)", (JOB, "report.pdf", "reviewing", now, now),
    )
    for mid in ("T1059", "T1190"):
        conn.execute(
            "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
            "VALUES (?,?,?,?,?,?,?)", (str(uuid4()), JOB, mid, "technique", mid, 1, "llm"),
        )
    for value, entity_type in ((DOMAIN, "domain"), (THE_HASH, "sha256")):
        conn.execute(
            "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
            "VALUES (?,?,?,?,?,?,?)", (str(uuid4()), JOB, value, entity_type, None, 1, "llm"),
        )
    conn.commit()
    rconn = temp_db.get_rule_conn()
    replace_corpus_rules(rconn, "sig", [
        _rule("sig", "e1", ["T1059"], atoms=[("domain", DOMAIN)]),
        _rule("sig", "h1", ["T1190"], atoms=[("hash", THE_HASH)]),
        _rule("sig", "u1", [], atoms=[("hash", THE_HASH)]),
    ])
    replace_corpus_rules(rconn, "net", [
        _rule("net", "s1", ["T1059"], fmt="suricata", license="MIT", atoms=[("domain", DOMAIN)]),
    ])
    return temp_db


def _json(value):
    """What the response body must equal: the route's return value, as JSON."""
    return json.loads(json.dumps(value))


def test_coverage_routes_return_what_the_route_function_returns(seeded, temp_db_client):
    cases = [
        (f"/api/jobs/{JOB}/coverage", lambda: coverage.get_coverage(JOB)),
        (f"/api/jobs/{JOB}/coverage/rules", lambda: coverage.get_coverage_report_rules(JOB)),
        (f"/api/jobs/{JOB}/detections/proposals", lambda: coverage.get_detection_proposals(JOB)),
        (f"/api/jobs/{JOB}/coverage/artifacts", lambda: coverage.get_artifact_coverage(JOB)),
        (f"/api/jobs/{JOB}/coverage/T1059/rules", lambda: coverage.get_coverage_rules(JOB, "T1059")),
        (f"/api/jobs/{JOB}/detections/export/facets", lambda: coverage.export_facets(JOB)),
        ("/api/detection-corpora", lambda: coverage.get_detection_corpora()),
    ]
    for url, direct in cases:
        resp = temp_db_client.get(url)
        assert resp.status_code == 200, url
        assert resp.json() == _json(direct()), url


def test_coverage_report_has_the_rules_the_fixture_seeds(seeded, temp_db_client):
    """The comparison above is only meaningful if the fixture reaches every branch."""
    body = temp_db_client.get(f"/api/jobs/{JOB}/coverage/rules").json()
    assert body["rule_total"] == 4
    groups = {g["technique_id"]: g["rules"] for g in body["techniques"]}
    assert {r["id"] for r in groups["(untagged)"]} == {"sig:u1"}
    assert {r["id"] for r in groups["T1190"]} == {"sig:h1"}
    match = groups["T1059"][0]["matches"][0]
    assert match["kind"] == "atom"
    assert match["discriminating"] is True
    assert "also_in" in groups["T1059"][0]


def test_proposals_and_artifacts_have_their_evidence(seeded, temp_db_client):
    proposals = temp_db_client.get(f"/api/jobs/{JOB}/detections/proposals").json()
    assert proposals["observables_total"] >= 2
    assert proposals["proposals"], "the domain and the hash both reach a rule"
    assert all(p["tier"] in ("direct", "behavioural", "weak") for p in proposals["proposals"])

    artifacts = temp_db_client.get(f"/api/jobs/{JOB}/coverage/artifacts").json()
    assert artifacts["artifacts"]
    assert all("class" in a for a in artifacts["artifacts"])
    assert artifacts["phases"]["gap"]


def test_export_facets_counts_the_rules_of_the_report(seeded, temp_db_client):
    facets = temp_db_client.get(f"/api/jobs/{JOB}/detections/export/facets").json()
    assert facets["total"] == 4
    assert {f["value"] for f in facets["format"]} == {"sigma", "suricata"}


def test_rule_lookup_returns_the_bodies_asked_for(seeded, temp_db_client):
    body = {"rule_ids": ["sig:e1", "net:s1", "nope:missing"], "include_body": True}
    resp = temp_db_client.post("/api/rules/lookup", json=body)
    assert resp.status_code == 200
    direct = coverage.post_rule_lookup(coverage.RuleLookup(**body))
    assert resp.json() == _json(direct)
    assert resp.json()["requested"] == 3
    assert {r["id"] for r in resp.json()["rules"]} == {"sig:e1", "net:s1"}


def test_baseline_status_returns_what_the_route_function_returns(temp_db_client):
    resp = temp_db_client.get("/api/baselines/status")
    assert resp.status_code == 200
    assert resp.json() == _json(baselines.baselines_status())


def test_every_operation_of_these_files_declares_its_response():
    """Each operation of the three files has a documented 200 response in the spec:
    a response model, or a `responses` entry that names its media type."""
    spec = api.main.app.openapi()
    tags = {"coverage", "attack", "baselines"}
    seen = []
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            if not tags & set(op.get("tags", [])):
                continue
            seen.append((method.upper(), path))
            ok = op["responses"]["200"]
            assert "content" in ok, f"{method.upper()} {path} declares no 200 content"
    assert len(seen) == 13, seen


def test_inspect_keeps_the_empty_lists_the_intake_holds(temp_db_client):
    """`response_model_exclude_unset` must not drop a field the intake holds with its
    default (an empty list): the body equals the Intake as JSON."""
    from dataclasses import asdict

    from api.baseline_store import scrubbed
    from pipeline import baseline_stix

    raw = (Path(__file__).parent / "fixtures" / "baselines" / "opencti_report.json").read_bytes()
    resp = temp_db_client.post(
        "/api/baselines/inspect",
        files={"file": ("bundle.json", raw, "application/json")},
    )
    assert resp.status_code == 200, resp.text
    _, intake, _ = baseline_stix.intake(raw, report_id=None, preview=True, validate=False)
    assert resp.json() == _json(asdict(scrubbed(intake)))
    assert "excluded" in resp.json() and "warnings" in resp.json()


def test_an_omitted_optional_key_stays_absent_from_the_body():
    """A route that leaves an optional field out of its return value: the body has no
    key for it, not a null (`response_model_exclude_unset=True`)."""
    from fastapi import APIRouter, FastAPI
    from fastapi.testclient import TestClient
    from pydantic import Field

    from api.response_models import Response

    class WithOptional(Response):
        required: int
        note: str | None = Field(default=None)

    router = APIRouter()

    @router.get("/omit", response_model=WithOptional, response_model_exclude_unset=True)
    def omit():
        return {"required": 1}

    @router.get("/set", response_model=WithOptional, response_model_exclude_unset=True)
    def set_it():
        return {"required": 1, "note": None}

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    assert client.get("/omit").json() == {"required": 1}
    assert client.get("/set").json() == {"required": 1, "note": None}
