"""The strings a client reads are recorded, and a change to them is seen (ADR-0094 item 1).

contract/formats.json holds the SSE event names and the layout of the detection
export ZIP; the job statuses and the `X-Bundle-Validation` values are
enumerations in contract/openapi.json; `x_ctiparsor_enrichment` is a custom
property in contract/stix.json.  These tests check that the code and the
frontend use only the recorded names, and that removing or renaming one is a
breaking change while a change to prose is not.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from api.db import EVENT_DONE, EVENT_STAGE, STORED_EVENTS
from api.routes.progress import SSE_EVENTS
from scripts import contract as c

ROOT = Path(__file__).resolve().parent.parent
USE_SSE = ROOT / "frontend" / "src" / "hooks" / "useSSE.ts"
_LISTENER = re.compile(r"addEventListener\(\s*'([^']+)'")
_EMITTED = re.compile(r"emit_progress\(\s*[\w.]+\s*,\s*\"([a-z_]+)\"")
_HOOK = re.compile(r"hooks\.progress\(\s*\"([a-z_]+)\"")


def test_the_stream_sends_the_stored_types_and_connected():
    assert SSE_EVENTS == ("connected", "queued", "stage", "partial_graph", "done")
    assert set(STORED_EVENTS) == set(SSE_EVENTS) - {"connected"}
    assert (EVENT_STAGE, EVENT_DONE) == ("stage", "done")


def test_the_frontend_listens_only_to_recorded_events():
    listened = set(_LISTENER.findall(USE_SSE.read_text(encoding="utf-8")))
    assert listened, "no addEventListener in useSSE.ts: the pattern no longer reads the hook"
    assert listened <= set(SSE_EVENTS), f"not on the stream: {sorted(listened - set(SSE_EVENTS))}"


def test_the_code_emits_only_stored_types():
    """Every literal event type passed to emit_progress, or to the pipeline's progress hook, is a stored type."""
    emitted: set[str] = set()
    for path in (ROOT / "api").rglob("*.py"):
        emitted |= set(_EMITTED.findall(path.read_text(encoding="utf-8")))
    hooked = set(_HOOK.findall((ROOT / "pipeline" / "orchestrator.py").read_text(encoding="utf-8")))
    assert hooked, "no hooks.progress call in pipeline/orchestrator.py: the pattern no longer reads it"
    assert (emitted | hooked) <= set(STORED_EVENTS), sorted((emitted | hooked) - set(STORED_EVENTS))


@pytest.fixture()
def formats() -> dict:
    recorded = c.load_reference("formats")
    assert recorded is not None
    return recorded


@pytest.mark.parametrize("key", ["sse event done", "sse event partial_graph", "export manifest",
                                 "export extension sigma", "export extension other"])
def test_a_removed_format_entry_is_breaking(formats, key):
    current = copy.deepcopy(formats)
    del current[key]
    assert [(d.severity, d.key) for d in c.diff_entries("formats", formats, current, c.RULES["formats"])] == [
        ("breaking", key)]


def test_a_renamed_sse_event_is_breaking_and_the_new_name_compatible(formats):
    current = copy.deepcopy(formats)
    current["sse event progress"] = current.pop("sse event partial_graph")
    diffs = c.diff_entries("formats", formats, current, c.RULES["formats"])
    assert sorted((d.severity, d.key, d.what) for d in diffs) == [
        ("breaking", "sse event partial_graph", "removed"),
        ("compatible", "sse event progress", "added")]


@pytest.mark.parametrize(("key", "field", "value"), [
    ("export manifest", "name", "manifest.json"),
    ("export extension sigma", "extension", "yaml"),
    ("sse event done", "stored", False),
])
def test_a_changed_format_value_is_breaking(formats, key, field, value):
    current = copy.deepcopy(formats)
    current[key][field] = value
    diffs = c.diff_entries("formats", formats, current, c.RULES["formats"])
    assert [(d.severity, d.key) for d in diffs] == [("breaking", key)]


def test_a_format_entry_added_is_compatible(formats):
    current = {**copy.deepcopy(formats), "export extension txt": {"extension": "txt"}}
    diffs = c.diff_entries("formats", formats, current, c.RULES["formats"])
    assert [(d.severity, d.key) for d in diffs] == [("compatible", "export extension txt")]


# ── Enumerations in the OpenAPI schema ───────────────────────────────────────

def _schema(enum: list[str], description: str) -> dict:
    """A one-route schema whose response is an object with a `status` enumeration."""
    return {
        "paths": {"/api/x": {"get": {"responses": {"200": {"content": {"application/json": {"schema": {
            "$ref": "#/components/schemas/Job"}}}}}}}},
        "components": {"schemas": {"Job": {"type": "object", "required": ["status"], "properties": {
            "status": {"type": "string", "enum": enum, "description": description}}}}},
    }


def test_a_prose_change_to_an_enumeration_is_no_difference():
    before = c.openapi_entries(_schema(["queued", "done"], "The status."))
    after = c.openapi_entries(_schema(["queued", "done"], "The status, reworded."))
    assert before == after
    assert c.diff_entries("openapi", before, after, c.RULES["openapi"]) == []


def test_a_value_removed_from_an_enumeration_is_breaking():
    before = c.openapi_entries(_schema(["queued", "done"], "The status."))
    after = c.openapi_entries(_schema(["queued"], "The status."))
    diffs = c.diff_entries("openapi", before, after, c.RULES["openapi"])
    assert [(d.severity, d.what) for d in diffs] == [("breaking", 'enum: lost "done"')]


def test_a_value_added_to_an_enumeration_is_compatible():
    before = c.openapi_entries(_schema(["queued"], "The status."))
    after = c.openapi_entries(_schema(["queued", "done"], "The status."))
    diffs = c.diff_entries("openapi", before, after, c.RULES["openapi"])
    assert [(d.severity, d.what) for d in diffs] == [("compatible", 'enum: gained "done"')]
