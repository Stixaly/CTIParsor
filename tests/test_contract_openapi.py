"""The OpenAPI extractor of scripts/contract.py (ADR-0094 item 1).

How the schema is built (in a process of its own, with no .env and no
inherited variable) and how it is flattened into entries, on small made-up
schemas.  The real schema is compared with contract/openapi.json by
tests/test_contract.py.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts import contract as c

_OPTIONAL_STRING = {"anyOf": [{"type": "string"}, {"type": "null"}], "title": "Tlp Level"}

_SCHEMA = {
    "openapi": "3.1.0",
    "info": {"title": "CTI to STIX", "version": "0.2.0"},
    "paths": {
        "/api/jobs/{job_id}/notes/{note_id}": {
            "patch": {
                "operationId": "patch_note", "summary": "Patch Note", "tags": ["notes"],
                "parameters": [
                    {"in": "path", "name": "note_id", "required": True, "schema": {"type": "string"}},
                    {"in": "path", "name": "job_id", "required": True, "schema": {"type": "string"}},
                    {"in": "query", "name": "format", "required": False,
                     "schema": {"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}]}},
                    {"in": "query", "name": "limit", "required": False,
                     "schema": {"type": "integer", "default": 200, "title": "Limit"}},
                    {"in": "header", "name": "X-Trace", "required": False, "schema": {"type": "string"}},
                ],
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/NoteIn"}}}},
                "responses": {
                    "200": {"description": "OK",
                            "headers": {"ETag": {"schema": {"type": "string"}}},
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Note"}}}},
                    "304": {"description": "Not Modified"},
                },
            },
            "delete": {"deprecated": True, "responses": {"200": {"content": {"application/json": {"schema": {}}}}}},
        },
    },
    "components": {"schemas": {
        "NoteIn": {"type": "object", "required": ["text"], "properties": {
            "text": {"type": "string", "description": "The note"},
            "tlp_level": _OPTIONAL_STRING,
            "kind": {"enum": ["a", "b"], "type": "string", "default": "a"},
            "file": {"type": "string", "contentMediaType": "application/octet-stream"},
        }},
        "Note": {"type": "object", "required": ["id", "counts"], "properties": {
            "id": {"type": "string"},
            "counts": {"type": "object", "additionalProperties": {"type": "integer"}},
            "status": {"const": "ok"},
            "children": {"type": "array", "items": {"$ref": "#/components/schemas/Note"}},
            "meta": {"allOf": [{"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}},
                               {"properties": {"b": {"type": "integer"}}}]},
            "extra": {"type": "object", "additionalProperties": True},
            "anything": {},
        }},
    }},
}

_ROUTE = "PATCH /api/jobs/{}/notes/{}"


@pytest.fixture()
def entries() -> dict:
    return c.openapi_entries(copy.deepcopy(_SCHEMA))


def test_an_operation(entries):
    assert entries[_ROUTE] == {"deprecated": False}
    assert entries["DELETE /api/jobs/{}/notes/{}"] == {"deprecated": True}


def test_a_path_parameter_is_known_by_its_position_not_its_name(entries):
    assert entries[f"{_ROUTE} param:path:0"] == {"required": True, "types": ["string"]}
    assert entries[f"{_ROUTE} param:path:1"] == {"required": True, "types": ["string"]}
    renamed = json.loads(json.dumps(_SCHEMA).replace("job_id", "id_of_the_job"))
    assert c.openapi_entries(renamed) == entries


def test_query_and_header_parameters(entries):
    assert entries[f"{_ROUTE} param:query:format"] == {"required": False, "types": ["array", "null"]}
    assert entries[f"{_ROUTE} param:query:format[]"] == {"required": True, "types": ["string"]}
    assert entries[f"{_ROUTE} param:query:limit"] == {"required": False, "types": ["integer"], "default": 200}
    assert entries[f"{_ROUTE} param:header:x-trace"] == {"required": False, "types": ["string"]}


def test_the_request_body(entries):
    assert entries[f"{_ROUTE} body"] == {"required": True, "media": ["application/json"], "types": ["object"]}
    assert entries[f"{_ROUTE} body.text"] == {"required": True, "types": ["string"]}
    assert entries[f"{_ROUTE} body.tlp_level"] == {"required": False, "types": ["null", "string"]}
    assert entries[f"{_ROUTE} body.kind"] == {"required": False, "types": ["string"], "enum": ["a", "b"],
                                              "default": "a"}
    assert entries[f"{_ROUTE} body.file"] == {"required": False, "types": ["string"]}


def test_a_response_its_fields_and_headers(entries):
    ok = f"{_ROUTE} response:200"
    assert entries[ok] == {"media": ["application/json"], "types": ["object"]}
    assert entries[f"{ok}.id"] == {"required": True, "types": ["string"]}
    assert entries[f"{ok}.counts"] == {"required": True, "types": ["object"]}
    assert entries[f"{ok}.counts{{*}}"] == {"required": True, "types": ["integer"]}
    assert entries[f"{ok}.status"] == {"required": False, "types": ["any"], "enum": ["ok"]}     # const
    assert entries[f"{ok}.extra"] == {"required": False, "types": ["object"]}
    assert entries[f"{ok}.anything"] == {"required": False, "types": ["any"]}
    assert entries[f"{ok} header:etag"] == {"required": False, "types": ["string"]}
    assert entries[f"{_ROUTE} response:304"] == {"media": []}
    assert entries["DELETE /api/jobs/{}/notes/{} response:200"] == {"media": ["application/json"],
                                                                     "types": ["any"]}


def test_all_of_is_merged(entries):
    meta = f"{_ROUTE} response:200.meta"
    assert entries[meta] == {"required": False, "types": ["object"]}
    assert entries[f"{meta}.a"] == {"required": True, "types": ["string"]}
    assert entries[f"{meta}.b"] == {"required": False, "types": ["integer"]}


def test_a_cycle_is_followed_once(entries):
    children = f"{_ROUTE} response:200.children"
    assert entries[f"{children}[]"] == {"required": True, "types": ["object"]}
    assert f"{children}[].id" not in entries          # Note inside Note: not expanded again


def test_fastapi_s_validation_error_is_left_out():
    schema = copy.deepcopy(_SCHEMA)
    responses = schema["paths"]["/api/jobs/{job_id}/notes/{note_id}"]["patch"]["responses"]
    responses["422"] = {"description": "Validation Error", "content": {"application/json": {
        "schema": {"$ref": "#/components/schemas/HTTPValidationError"}}}}
    assert not [key for key in c.openapi_entries(schema) if "response:422" in key]
    responses["422"]["content"]["application/json"]["schema"] = {"type": "object"}     # a 422 of our own
    assert c.openapi_entries(schema)[f"{_ROUTE} response:422"] == {"media": ["application/json"],
                                                                   "types": ["object"]}


def test_a_response_default_is_not_recorded():
    schema = copy.deepcopy(_SCHEMA)
    schema["components"]["schemas"]["Note"]["properties"]["id"]["default"] = "x"
    assert c.openapi_entries(schema)[f"{_ROUTE} response:200.id"] == {"required": True, "types": ["string"]}


def _post(body: dict) -> dict:
    """One operation, `POST /api/a`, that takes `body`."""
    return {"paths": {"/api/a": {"post": {
        "requestBody": {"required": True, "content": {"application/json": {"schema": body}}},
        "responses": {"200": {"description": "OK"}}}}}}


def test_the_restrictions_of_a_request_are_recorded():
    body = {"type": "object", "additionalProperties": False, "properties": {
        "name": {"type": "string", "maxLength": 64, "minLength": 1, "pattern": "^[a-z]+$"},
        "id": {"type": "string", "format": "uuid"},
        "limit": {"anyOf": [{"type": "integer", "maximum": 1000, "minimum": 1}, {"type": "null"}]},
        "tags": {"type": "array", "items": {"type": "string", "maxLength": 8}, "maxItems": 10, "minItems": 1},
        "ratio": {"type": "number", "exclusiveMaximum": 1, "exclusiveMinimum": 0},
    }}
    entries = c.openapi_entries(_post(body))
    assert entries["POST /api/a body"] == {"required": True, "media": ["application/json"], "types": ["object"],
                                           "closed": True}
    assert entries["POST /api/a body.name"] == {"required": False, "types": ["string"], "maxLength": 64,
                                                "minLength": 1, "pattern": "^[a-z]+$"}
    assert entries["POST /api/a body.id"] == {"required": False, "types": ["string"], "format": "uuid"}
    assert entries["POST /api/a body.limit"] == {"required": False, "types": ["integer", "null"], "maximum": 1000,
                                                 "minimum": 1}
    assert entries["POST /api/a body.tags"] == {"required": False, "types": ["array"], "maxItems": 10,
                                                "minItems": 1}
    assert entries["POST /api/a body.tags[]"] == {"required": True, "types": ["string"], "maxLength": 8}
    assert entries["POST /api/a body.ratio"] == {"required": False, "types": ["number"], "exclusiveMaximum": 1,
                                                 "exclusiveMinimum": 0}


def test_a_closed_body_behind_a_reference_and_a_parameter_s_limit():
    schema = copy.deepcopy(_SCHEMA)
    schema["components"]["schemas"]["NoteIn"]["additionalProperties"] = False
    schema["paths"]["/api/jobs/{job_id}/notes/{note_id}"]["patch"]["parameters"][3]["schema"]["maximum"] = 1000
    entries = c.openapi_entries(schema)
    assert entries[f"{_ROUTE} body"] == {"required": True, "media": ["application/json"], "types": ["object"],
                                         "closed": True}
    assert entries[f"{_ROUTE} param:query:limit"] == {"required": False, "types": ["integer"], "default": 200,
                                                      "maximum": 1000}


def test_the_restrictions_of_a_response_are_not_recorded(entries):
    schema = copy.deepcopy(_SCHEMA)
    note = schema["components"]["schemas"]["Note"]
    note["additionalProperties"] = False
    note["properties"]["id"].update(format="uuid", maxLength=36, pattern="^[0-9a-f-]+$")
    assert c.openapi_entries(schema) == entries


def test_a_variant_that_allows_anything_makes_the_union_any():
    body = {"type": "object", "properties": {
        "x": {"anyOf": [{"type": "string"}, {}]},
        "y": {"oneOf": [{"type": "integer"}, {"description": "anything"}]},
        "z": {"allOf": [{"type": "string"}, {}]},                    # allOf: both apply, a string it stays
    }}
    entries = c.openapi_entries(_post(body))
    assert entries["POST /api/a body.x"] == {"required": False, "types": ["any"]}
    assert entries["POST /api/a body.y"] == {"required": False, "types": ["any"]}
    assert entries["POST /api/a body.z"] == {"required": False, "types": ["string"]}


def test_what_a_client_does_not_see_is_ignored(entries):
    """Titles, descriptions, summaries, tags, operation ids and examples, and
    the `info` block."""
    schema = copy.deepcopy(_SCHEMA)
    schema["info"] = {"title": "Other", "version": "9.9.9", "description": "x"}
    op = schema["paths"]["/api/jobs/{job_id}/notes/{note_id}"]["patch"]
    op.update(operationId="other", summary="Other", description="Other", tags=["other"])
    text = schema["components"]["schemas"]["NoteIn"]["properties"]["text"]
    text.update(title="T", description="D", examples=["e"])
    assert c.openapi_entries(schema) == entries


def test_an_unresolved_reference_fails():
    schema = copy.deepcopy(_SCHEMA)
    del schema["components"]["schemas"]["Note"]
    with pytest.raises(c.ExtractError, match="unresolved"):
        c.openapi_entries(schema)


def test_a_path_parameter_missing_from_the_path_fails():
    schema = copy.deepcopy(_SCHEMA)
    schema["paths"]["/api/jobs/{job_id}/notes/{note_id}"]["patch"]["parameters"][0]["name"] = "nope"
    with pytest.raises(c.ExtractError, match="not in the path"):
        c.openapi_entries(schema)


def test_two_routes_that_differ_only_by_parameter_names_fail():
    schema = {"paths": {"/api/a/{x}": {"get": {"responses": {}}}, "/api/a/{y}": {"get": {"responses": {}}}}}
    with pytest.raises(c.ExtractError, match="described twice"):
        c.openapi_entries(schema)


def test_a_schema_without_an_operation_fails(monkeypatch):
    monkeypatch.setattr(c, "openapi_schema", lambda: {"openapi": "3.1.0", "paths": {}})
    with pytest.raises(c.ExtractError, match="no operation"):
        c.extract_openapi()


# ── The schema is built away from the environment ────────────────────────────

class _Run:
    """Stands for subprocess.run: records the call, writes `schema` where the child would."""

    def __init__(self, schema: dict | None, returncode: int = 0):
        self.schema, self.returncode, self.calls = schema, returncode, []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.schema is not None:
            Path(args[3]).write_text(json.dumps(self.schema), encoding="utf-8")
        return type("Done", (), {"returncode": self.returncode, "stderr": "Traceback: boom"})()


def test_the_schema_is_built_without_the_callers_environment(monkeypatch):
    run = _Run({"openapi": "3.1.0", "paths": {}})
    monkeypatch.setattr(c.subprocess, "run", run)
    monkeypatch.setenv("DATABASE_URL", "postgresql://someone@db/prod")
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "false")
    assert c.openapi_schema() == {"openapi": "3.1.0", "paths": {}}
    ((args, kwargs),) = run.calls
    assert args[1] == "-c"                       # no script file: load_dotenv() would look beside it
    child = args[2]
    assert child.index("dotenv.load_dotenv = ") < child.index("from api.main import app")
    assert set(kwargs["env"]) == {"PATH", "HOME", "PYTHONPATH", "SKIP_HEAVY_MODELS"}
    assert kwargs["env"]["PYTHONPATH"] == str(c.ROOT)
    assert Path(kwargs["cwd"]) != c.ROOT and not (Path(kwargs["cwd"]) / ".env").exists()


def test_a_failed_build_is_an_extractor_failure(monkeypatch):
    monkeypatch.setattr(c.subprocess, "run", _Run(None, returncode=1))
    with pytest.raises(c.ExtractError, match="boom"):
        c.openapi_schema()
