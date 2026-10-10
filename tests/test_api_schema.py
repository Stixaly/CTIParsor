"""The REST API against its own OpenAPI schema, with Schemathesis.

Schemathesis builds requests for every operation from the schema FastAPI
publishes: valid ones, and ones that break a declared constraint. Each
response must not be a server error, and must match the response schema
its operation declares. Generation is derandomized: every run sends the same
requests, so this stays a deterministic gate (ADR-0071), and a failure comes
back on the next run of the same command. Reproduce one with the command
that found it (in CI, the whole suite): an operation's examples depend on
what ran before it in the process, so `-k` on one operation, or this module
alone, sends other requests.

The requests go through the test client, against a disposable database
(`temp_db_client`), with one job already reviewed: an operation on
`/api/jobs/{job_id}/...` reaches its handler instead of a 404. What reaches
the network, a browser or the corpus clones is left out, each where it is
excluded below.
"""
from __future__ import annotations

import shutil

import pytest

schemathesis = pytest.importorskip("schemathesis")

from hypothesis import HealthCheck, settings  # noqa: E402
from schemathesis.checks import not_a_server_error, response_schema_conformance  # noqa: E402

import api.main  # noqa: E402

# Per operation and generation mode; 52 operations.
MAX_EXAMPLES = 20

schema = (
    schemathesis.openapi.from_dict(api.main.app.openapi())
    # Captures the page in a browser, over the network (Playwright).
    .exclude(path="/api/ingest/url")
    # Clones or downloads a corpus, then rebuilds the rule store from the clones.
    .exclude(path="/api/settings/corpora/{name}/sync")
    .exclude(path="/api/settings/corpora/rebuild")
    # Server-Sent Events: the stream stays open while the job is not finished.
    .exclude(path="/api/jobs/{job_id}/progress")
)
schema.config.generation.update(
    modes=[schemathesis.GenerationMode.POSITIVE, schemathesis.GenerationMode.NEGATIVE],
    max_examples=MAX_EXAMPLES,
    deterministic=True,
)


@pytest.fixture()
def seeded_api(temp_db, temp_db_client, monkeypatch, tmp_path):
    """The test client, and the ids of one reviewed job with two entities and a relationship."""
    import api.routes.settings as settings_routes
    import pipeline.web_capture as web_capture

    # Ten uploads a minute per address: the generated requests would meet 429s.
    monkeypatch.setattr(api.main.limiter, "enabled", False)
    # The corpus routes write the overlay next to the registry: a copy here.
    registry = tmp_path / "detection_corpora.yaml"
    shutil.copy(settings_routes._CONFIG, registry)
    monkeypatch.setattr(settings_routes, "_CONFIG", registry)
    # validate_url resolves host names; answer without DNS, with a public address.
    monkeypatch.setattr(web_capture, "_resolve_all", lambda host: ["93.184.216.34"])

    ts = temp_db.now_iso()
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES ('j1', 'r.txt', 'for_review', ?, ?)", (ts, ts))
        conn.commit()
    ids = {"job_id": "j1"}
    for value, entity_type in (("SUNBURST", "malware"), ("APT29", "threat_actor")):
        resp = temp_db_client.post("/api/jobs/j1/entities", json={"value": value, "entity_type": entity_type})
        assert resp.status_code == 200, resp.text
        ids["entity_id"] = str(resp.json()["id"])
    resp = temp_db_client.post("/api/jobs/j1/relationships", json={
        "source_value": "APT29", "relationship_type": "uses", "target_value": "SUNBURST"})
    assert resp.status_code == 200, resp.text
    ids["rel_id"] = str(resp.json()["id"])
    return temp_db_client, ids


def _as_part(value):
    """A multipart part the test client can encode: (filename, bytes or text[, ...])."""
    if isinstance(value, tuple):
        filename, content, *rest = value
        if not isinstance(content, (bytes, str)) and not hasattr(content, "read"):
            content = "" if content is None else str(content)
        return (filename, content, *rest)
    if isinstance(value, (bytes, str)) or hasattr(value, "read"):
        return value
    return "" if value is None else str(value)


@schema.parametrize()
@settings(derandomize=True, database=None, deadline=None, max_examples=MAX_EXAMPLES,
          suppress_health_check=list(HealthCheck))
def test_every_operation_answers_as_its_schema_says(case, seeded_api):
    client, ids = seeded_api
    for name, value in ids.items():
        if case.path_parameters and name in case.path_parameters:
            case.path_parameters[name] = value
    kwargs = case.as_transport_kwargs(base_url="http://testserver")
    kwargs.pop("cookies", None)
    # requests' `data` may be raw bytes; the test client takes those as `content`.
    if isinstance(kwargs.get("data"), (bytes, str)):
        kwargs["content"] = kwargs.pop("data")
    # Negative cases put numbers or None in a multipart part: requests sends
    # their text, the test client cannot encode them.
    if kwargs.get("files"):
        kwargs["files"] = [(name, _as_part(value)) for name, value in kwargs["files"]]
    response = client.request(**kwargs)
    response.request.read()  # a multipart body is a stream until read
    case.validate_response(
        response, checks=[not_a_server_error, response_schema_conformance], transport_kwargs=kwargs)
