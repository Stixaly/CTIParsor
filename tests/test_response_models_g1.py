"""Response models of api/routes/jobs.py, progress.py, queue.py and upload.py (ADR-0094 item 1).

The models describe what the routes return; they change no response.  These tests check
the declarations (every operation of the four modules has a success body in the OpenAPI
schema) and that the responses the existing tests do not pin exactly come back as the
stored or computed data says.
"""
from __future__ import annotations

import json

import api.main
from api.routes import jobs as jobs_routes
from api.routes import progress as progress_routes
from api.routes import queue as queue_routes
from api.routes import upload as upload_routes

ROUTERS = (jobs_routes.router, progress_routes.router, queue_routes.router, upload_routes.router)

# The operations that return a model, and the component each one's 200 body refers to.
MODEL_OPERATIONS = {
    ("get", "/api/jobs"): "JobSummary",
    ("get", "/api/jobs/{job_id}"): "JobDetail",
    ("patch", "/api/jobs/{job_id}"): "StatusResult",
    ("post", "/api/jobs/{job_id}/finalize"): "FinalizeResult",
    ("delete", "/api/jobs/{job_id}"): "DeleteResult",
    ("get", "/api/jobs/{job_id}/bundle/ledger"): "BundleLedger",
    ("get", "/api/queue/status"): "QueueStatus",
    ("post", "/api/upload"): "UploadResult",
}


def _operations_of_the_four_modules() -> list[tuple[str, str]]:
    """(method, path) of every route the four modules' routers hold."""
    return sorted((method.lower(), getattr(route, "path", ""))
                  for router in ROUTERS for route in router.routes
                  for method in getattr(route, "methods", ()))


def test_every_operation_of_the_four_modules_declares_its_success_body():
    operations = _operations_of_the_four_modules()
    assert len(operations) == 13, operations          # a route added or removed changes this count

    responses = api.main.app.openapi()["paths"]
    for method, path in operations:
        success = responses[path][method]["responses"]["200"]
        assert "content" in success, (method, path)  # a model, or a documented media type


def test_the_model_operations_refer_to_their_model():
    paths = api.main.app.openapi()["paths"]
    for (method, path), model in MODEL_OPERATIONS.items():
        success = paths[path][method]["responses"]["200"]
        assert model in json.dumps(success["content"]), (method, path, model)


def test_a_full_ledger_comes_back_exactly_as_stored(temp_db_client, temp_db):
    """Every key the ledger writer produces, plus the optional ones: nothing is added or dropped."""
    ledger = {
        "version": 1,
        "objects": {
            "indicator--1": {"origin": "ioc_association", "status": "rewritten"},
            "relationship--2": {"origin": "baseline", "upsert": "baseline_relationship_upsert",
                                "changes": ["confidence"]},
        },
        "entities": [
            {"value": "APT29", "entity_type": "threat-actor", "outcome": "emitted",
             "stix_id": "intrusion-set--3", "stix_type": "intrusion-set", "stix_name": "APT29"},
            {"value": "old", "entity_type": "malware", "outcome": "dropped", "reason": "no ISO code",
             "merged_via": ["alias"]},
        ],
        "relationships": [
            {"source_value": "APT29", "relationship_type": "uses", "target_value": "SUNBURST",
             "outcome": "emitted", "changes": ["stop_time"], "stix_id": "relationship--2",
             "final_type": "uses", "source_ref": "intrusion-set--3", "target_ref": "malware--4"},
        ],
        "removed": [
            {"stix_id": "malware--9", "kind": "object", "reason": "alias_merge", "replaced_by": "malware--4",
             "name": "SUNBURST"},
        ],
        "refused": [
            {"source_ref": "intrusion-set--3", "relationship_type": "targets", "target_ref": "identity--5",
             "origin": "policy_pin", "reason": "rejected_by_analyst", "rule": "x"},
        ],
    }
    stored = json.dumps(ledger)
    with temp_db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, bundle_json, bundle_ledger_json, "
            "created_at, updated_at) VALUES ('lg1','r.txt','for_review','{}',?,?,?)",
            (stored, temp_db.now_iso(), temp_db.now_iso()),
        )
        conn.commit()

    resp = temp_db_client.get("/api/jobs/lg1/bundle/ledger")
    assert resp.status_code == 200
    assert resp.json() == ledger


def test_an_optional_key_the_route_omits_stays_absent(temp_db_client, temp_db):
    """A response model would add `null` for an optional key the route did not set; the
    routes exclude unset fields, so a key left out of the data is left out of the response."""
    with temp_db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
            "VALUES ('oa1','r.txt','for_review',?,?)", (temp_db.now_iso(), temp_db.now_iso()))
        conn.commit()
    job = temp_db_client.get("/api/jobs/oa1").json()
    assert "enrichment" not in job                    # not an enrich job: the key is absent, not null

    # A ledger with only one key comes back with only that key (no refused, no objects, ...).
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE jobs SET bundle_json='{}', bundle_ledger_json=? WHERE id='oa1'",
                     ('{"entities": []}',))
        conn.commit()
    assert temp_db_client.get("/api/jobs/oa1/bundle/ledger").json() == {"entities": []}


def test_an_empty_queue_status_is_the_one_the_route_function_computes(temp_db_client, temp_db):
    """No job and no worker: every value is fixed, so the response is the function's own return."""
    expected = queue_routes.get_queue_status()
    resp = temp_db_client.get("/api/queue/status")
    assert resp.status_code == 200
    assert resp.json() == json.loads(json.dumps(expected))


def test_the_progress_stream_is_the_frames_the_stored_events_make(temp_db_client, temp_db):
    """connected, then each stored event as an id/event/data frame, then done for a finished job."""
    with temp_db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
            "VALUES ('pg1','r.txt','for_review',?,?)",
            (temp_db.now_iso(), temp_db.now_iso()),
        )
        conn.commit()
    temp_db.emit_progress("pg1", "stage", {"stage": 1})
    with temp_db.get_conn() as conn:
        rows = conn.execute(
            "SELECT id, event_type, data FROM progress_events WHERE job_id='pg1' ORDER BY id").fetchall()

    resp = temp_db_client.get("/api/jobs/pg1/progress")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    expected = 'event: connected\ndata: {"job_id": "pg1"}\n\n'
    expected += "".join(f"id: {r['id']}\nevent: {r['event_type']}\ndata: {r['data']}\n\n" for r in rows)
    expected += 'event: done\ndata: {"status": "for_review"}\n\n'
    assert resp.text == expected


def test_a_ledger_of_any_release_comes_back_as_stored(temp_db_client, temp_db):
    """CI caught a 500 here: `changes` became a list of objects (from, to, kind,
    reason) while the model said strings.  The ledger lives inside each bundle and
    its shapes changed across ADRs, so the model accepts any value."""
    ledger = {
        "version": "2",
        "relationships": [
            {"source_value": "APT29", "relationship_type": "uses", "target_value": "X",
             "outcome": "emitted",
             "changes": [{"from": "controls", "to": "uses", "kind": "verb", "reason": "policy_pin"}]},
            {"relationship_type": "uses", "outcome": None},
        ],
        "removed": [{"kind": "object", "reason": "alias_merge"}],
        "entities": [{"value": 3}],
    }
    with temp_db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, bundle_json, bundle_ledger_json, "
            "created_at, updated_at) VALUES ('lg2','r.txt','for_review','{}',?,?,?)",
            (json.dumps(ledger), temp_db.now_iso(), temp_db.now_iso()),
        )
        conn.commit()
    resp = temp_db_client.get("/api/jobs/lg2/bundle/ledger")
    assert resp.status_code == 200
    assert resp.json() == ledger
