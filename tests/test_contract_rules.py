"""The semantic diff of scripts/contract.py (ADR-0094 item 1).

Each rule of docs/support-policy.md, "Breaking changes and deprecation", on
small made-up entries, in both directions; then `check` and `write` on
extractors that return what each test sets.  The extractors themselves are
tested in tests/test_contract_openapi.py, tests/test_contract_cli_config.py
and tests/test_contract_stix.py; the recorded contract/*.json in
tests/test_contract.py.
"""
from __future__ import annotations

import copy
import json

import pytest

from scripts import contract as c


def _diff(surface: str, old: dict, new: dict) -> list[tuple[str, str, str]]:
    return [(d.severity, d.key, d.what) for d in c.diff_entries(surface, old, new, c.RULES[surface])]


def _severities(surface: str, old: dict, new: dict) -> set[str]:
    return {severity for severity, _, _ in _diff(surface, old, new)}


# ── The engine ───────────────────────────────────────────────────────────────

def test_equal_entries_have_no_difference():
    entries = {"GET /api/a": {"deprecated": False}, "GET /api/a response:200": {"media": ["application/json"]}}
    assert _diff("openapi", entries, copy.deepcopy(entries)) == []


@pytest.mark.parametrize(("surface", "key", "desc"), [
    ("openapi", "GET /api/a", {"deprecated": False}),
    ("openapi", "GET /api/a response:200.status", {"required": True, "types": ["string"]}),
    ("cli", "main.py --output", {"action": "store", "nargs": None, "required": False, "choices": None,
                                 "default": "out.json", "group": None}),
    ("cli", "entrypoint worker", {}),
    ("config", "env STIX_TLP", {"set": True, "values": ["amber"]}),
    ("config", "compose volume cti-state", {}),
    ("stix", "property report x_source_published", {"types": ["object"]}),
])
def test_a_removal_is_breaking(surface, key, desc):
    assert _diff(surface, {key: desc}, {}) == [("breaking", key, "removed")]


def test_a_change_no_rule_explains_is_breaking():
    assert _diff("cli", {"entrypoint serve": {}}, {"entrypoint serve": {"x": 1}}) == [
        ("breaking", "entrypoint serve", 'changed: {} -> {"x": 1}')]


def test_differences_are_sorted_breaking_first():
    diffs = [c.Difference("compatible", "cli", "a", "added"), c.Difference("default", "config", "b", "x"),
             c.Difference("breaking", "stix", "c", "removed"), c.Difference("breaking", "cli", "d", "removed")]
    assert [d.key for d in c.sort_differences(diffs)] == ["d", "c", "b", "a"]


def test_a_difference_is_one_line():
    line = c.Difference("breaking", "openapi", "GET /api/a", "removed").line()
    assert line == "BREAKING    openapi  GET /api/a: removed"


# ── openapi ──────────────────────────────────────────────────────────────────

_ROUTE = {
    "POST /api/a": {"deprecated": False},
    "POST /api/a param:path:0": {"required": True, "types": ["string"]},
    "POST /api/a body": {"required": True, "media": ["application/json"], "types": ["object"]},
    "POST /api/a body.text": {"required": True, "types": ["string"]},
    "POST /api/a body.tlp": {"required": False, "types": ["null", "string"]},
    "POST /api/a response:200": {"media": ["application/json"], "types": ["object"]},
    "POST /api/a response:200.status": {"required": True, "types": ["string"]},
}


def _changed(key: str, **fields) -> dict:
    new = copy.deepcopy(_ROUTE)
    new[key] = {**new[key], **fields}
    return new


def test_a_new_route_is_compatible_even_with_required_parameters():
    assert _severities("openapi", {}, _ROUTE) == {"compatible"}


def test_a_required_field_in_a_new_optional_body_is_compatible():
    old = {"POST /api/a": {"deprecated": False}}
    new = {**old, "POST /api/a body": {"required": False, "media": ["application/json"], "types": ["object"]},
           "POST /api/a body.x": {"required": True, "types": ["string"]}}
    assert _severities("openapi", old, new) == {"compatible"}


@pytest.mark.parametrize(("key", "required", "severity"), [
    ("POST /api/a body.extra", True, "breaking"),            # an existing body gains a required field
    ("POST /api/a body.extra", False, "compatible"),
    ("POST /api/a param:query:limit", True, "breaking"),      # an existing route gains a required parameter
    ("POST /api/a param:query:limit", False, "compatible"),
    ("POST /api/a response:200.extra", True, "compatible"),   # a new response field
])
def test_an_added_entry_on_an_existing_route(key, required, severity):
    new = {**_ROUTE, key: {"required": required, "types": ["string"]}}
    assert _diff("openapi", _ROUTE, new) == [(severity, key, "added")]


def test_a_renamed_response_field_is_a_removal_and_an_addition():
    new = copy.deepcopy(_ROUTE)
    new["POST /api/a response:200.state"] = new.pop("POST /api/a response:200.status")
    assert _diff("openapi", _ROUTE, new) == [
        ("compatible", "POST /api/a response:200.state", "added"),
        ("breaking", "POST /api/a response:200.status", "removed")]


@pytest.mark.parametrize(("key", "types", "severity"), [
    ("POST /api/a body.text", ["integer"], "breaking"),             # a request type lost
    ("POST /api/a body.text", ["integer", "string"], "compatible"),  # a request type gained
    ("POST /api/a body.text", ["any"], "compatible"),
    ("POST /api/a response:200.status", ["null", "string"], "breaking"),  # a response field may be null
    ("POST /api/a response:200.status", ["any"], "breaking"),
    ("POST /api/a body.tlp", ["string"], "breaking"),               # null no longer accepted
])
def test_types(key, types, severity):
    assert _severities("openapi", _ROUTE, _changed(key, types=types)) == {severity}


def test_a_response_narrowed_from_any_is_compatible_and_the_reverse_breaking():
    old = {**_ROUTE, "POST /api/a response:200": {"media": ["application/json"], "types": ["any"]}}
    assert _severities("openapi", old, _ROUTE) == {"compatible"}
    assert _severities("openapi", _ROUTE, old) == {"breaking"}


@pytest.mark.parametrize(("key", "before", "after", "severity"), [
    ("POST /api/a body.text", ["integer"], ["number"], "compatible"),           # every integer still accepted
    ("POST /api/a body.text", ["integer", "null"], ["null", "number"], "compatible"),
    ("POST /api/a body.text", ["number"], ["integer"], "breaking"),            # 1.5 refused
    ("POST /api/a body.text", ["any"], ["string"], "breaking"),                # `anyOf[string, {}]` became a string
    ("POST /api/a response:200.status", ["integer"], ["number"], "breaking"),  # a client may get 1.5
    ("POST /api/a response:200.status", ["number"], ["integer"], "compatible"),
])
def test_numbers_and_any(key, before, after, severity):
    assert _severities("openapi", _changed(key, types=before), _changed(key, types=after)) == {severity}


@pytest.mark.parametrize(("key", "required", "severity"), [
    ("POST /api/a body.tlp", True, "breaking"),                   # a request field made required
    ("POST /api/a body.text", False, "compatible"),
    ("POST /api/a body", False, "compatible"),
    ("POST /api/a response:200.status", False, "breaking"),       # a response field may be absent
])
def test_required(key, required, severity):
    assert _diff("openapi", _ROUTE, _changed(key, required=required)) == [
        (severity, key, f"required: {json.dumps(not required)} -> {json.dumps(required)}")]


def test_a_body_made_required_is_breaking():
    old = _changed("POST /api/a body", required=False)
    assert _severities("openapi", old, _ROUTE) == {"breaking"}


@pytest.mark.parametrize("key", ["POST /api/a body.tlp", "POST /api/a response:200.status"])
def test_enum_values(key):
    old = _changed(key, enum=["amber", "red"])
    assert _diff("openapi", old, _changed(key, enum=["amber"])) == [("breaking", key, 'enum: lost "red"')]
    assert _diff("openapi", old, _changed(key, enum=["amber", "green", "red"])) == [
        ("compatible", key, 'enum: gained "green"')]
    assert _severities("openapi", old, _ROUTE) == {"compatible"}               # the restriction goes


def test_a_restriction_that_appears_breaks_a_request_not_a_response():
    assert _severities("openapi", _ROUTE, _changed("POST /api/a body.tlp", enum=["amber"])) == {"breaking"}
    assert _severities("openapi", _ROUTE, _changed("POST /api/a response:200.status", enum=["ok"])) == {
        "compatible"}


def test_media_types():
    key = "POST /api/a body"
    assert _diff("openapi", _ROUTE, _changed(key, media=["multipart/form-data"])) == [
        ("breaking", key, "media: lost application/json"), ("compatible", key, "media: gained multipart/form-data")]
    assert _severities("openapi", _ROUTE, _changed(key, media=["application/json", "text/plain"])) == {
        "compatible"}


def test_a_deprecation_is_compatible_both_ways():
    deprecated = _changed("POST /api/a", deprecated=True)
    assert _diff("openapi", _ROUTE, deprecated) == [("compatible", "POST /api/a", "deprecated: false -> true")]
    assert _severities("openapi", deprecated, _ROUTE) == {"compatible"}


def test_a_changed_request_default_is_a_default_change():
    old = _changed("POST /api/a body.tlp", default="amber")
    assert _diff("openapi", old, _changed("POST /api/a body.tlp", default="red")) == [
        ("default", "POST /api/a body.tlp", 'default: "amber" -> "red"')]


@pytest.mark.parametrize(("before", "after", "severity"), [
    ({}, {"maxLength": 100}, "breaking"),                   # a limit appears
    ({"maxLength": 1000}, {"maxLength": 100}, "breaking"),  # a limit changes
    ({"maxLength": 100}, {"maxLength": 1000}, "breaking"),  # even raised: every change is reviewed
    ({"maxLength": 100}, {}, "compatible"),                 # a limit goes
    ({}, {"format": "uuid"}, "breaking"),
    ({}, {"pattern": "^[a-z]+$"}, "breaking"),
    ({}, {"minimum": 1, "maximum": 10}, "breaking"),
    ({}, {"closed": True}, "breaking"),                     # unknown fields now refused
    ({"closed": True}, {}, "compatible"),                   # unknown fields accepted again
])
def test_request_restrictions(before, after, severity):
    key = "POST /api/a body.text"
    old, new = copy.deepcopy(_ROUTE), copy.deepcopy(_ROUTE)
    old[key] = {**old[key], **before}
    new[key] = {**new[key], **after}
    assert _severities("openapi", old, new) == {severity}


def test_a_restriction_names_its_keyword():
    key = "POST /api/a body.text"
    assert _diff("openapi", _ROUTE, _changed(key, maxLength=100)) == [("breaking", key, "maxLength: none -> 100")]
    assert _diff("openapi", _changed(key, closed=True), _ROUTE) == [("compatible", key, "closed: true -> none")]


def test_the_side_of_a_key():
    assert c.openapi_side("GET /api/jobs/{}") == "operation"
    assert c.openapi_side("GET /api/jobs/{} param:path:0") == "request"
    assert c.openapi_side("POST /api/upload body.file") == "request"
    assert c.openapi_side("GET /api/jobs/{} response:200.status") == "response"
    assert c.openapi_side("GET /api/attack/index response:200 header:etag") == "response"


def test_the_parent_of_a_key():
    assert c.openapi_parent("POST /api/a body.x.y[]") == "POST /api/a body.x.y"
    assert c.openapi_parent("POST /api/a body.x.y") == "POST /api/a body.x"
    assert c.openapi_parent("POST /api/a body.m{*}") == "POST /api/a body.m"
    assert c.openapi_parent("POST /api/a body") == "POST /api/a"
    assert c.openapi_parent("GET /api/a param:query:format[]") == "GET /api/a param:query:format"
    assert c.openapi_parent("GET /api/a param:query:format") == "GET /api/a"


# ── cli ──────────────────────────────────────────────────────────────────────

_ARG = {"action": "store", "nargs": None, "required": False, "choices": None, "default": "db", "type": None,
        "const": None, "group": None}
_GROUP = {"members": ["--input-dir", "file"], "required": True}


def _arg(**fields) -> dict:
    return {"main.py --policy": {**_ARG, **fields}}


def test_an_optional_argument_added_is_compatible_a_required_one_breaking():
    assert _diff("cli", {}, _arg()) == [("compatible", "main.py --policy", "added")]
    assert _diff("cli", {}, _arg(required=True)) == [("breaking", "main.py --policy", "added")]


@pytest.mark.parametrize(("fields", "severity"), [
    ({"action": "append"}, "breaking"),
    ({"nargs": "?"}, "breaking"),
    ({"required": True}, "breaking"),
    ({"choices": ["db", "none"]}, "breaking"),                 # a restriction appears
    ({"default": "none"}, "default"),
    ({"type": "int"}, "breaking"),                              # "5" now read as 5, "x" refused
    ({"const": "fast"}, "breaking"),
    ({"group": _GROUP}, "breaking"),                            # the argument joins a group
])
def test_an_argument_changed(fields, severity):
    assert _severities("cli", _arg(), _arg(**fields)) == {severity}


@pytest.mark.parametrize(("before", "after", "severity"), [
    ({"required": True}, {"required": False}, "compatible"),
    ({"choices": ["db", "none"]}, {"choices": ["db"]}, "breaking"),
    ({"choices": ["db"]}, {"choices": ["db", "none"]}, "compatible"),
    ({"choices": ["db"]}, {"choices": None}, "compatible"),
    ({"group": _GROUP}, {"group": None}, "compatible"),
    ({"group": _GROUP}, {"group": {"members": ["--input-dir", "--url", "file"], "required": True}}, "compatible"),
    ({"group": _GROUP}, {"group": {"members": ["file"], "required": True}}, "compatible"),
    ({"group": {**_GROUP, "required": False}}, {"group": _GROUP}, "breaking"),
    ({"group": _GROUP}, {"group": {**_GROUP, "required": False}}, "compatible"),
    ({"type": "int"}, {"type": None}, "breaking"),
])
def test_an_argument_changed_both_ways(before, after, severity):
    assert _severities("cli", _arg(**before), _arg(**after)) == {severity}


def test_an_argument_that_joins_a_group_breaks_a_new_member_does_not():
    """`--url` made exclusive with `file`: `main.py report.txt --url x` stops
    working.  `--url` added to the group as a new argument: nothing that
    worked is refused."""
    group = {"members": ["--input-dir", "--url", "file"], "required": True}
    joined = {"main.py --url": {**_ARG, "group": group}, "main.py file": {**_ARG, "group": group}}
    before = {"main.py --url": {**_ARG}, "main.py file": {**_ARG, "group": _GROUP}}
    assert _diff("cli", before, joined) == [
        ("breaking", "main.py --url", f"group: none -> {json.dumps(group, sort_keys=True)}"),
        ("compatible", "main.py file", "group: now exclusive with --url")]
    assert _diff("cli", {"main.py file": {**_ARG, "group": _GROUP}}, joined) == [
        ("compatible", "main.py --url", "added"),
        ("compatible", "main.py file", "group: now exclusive with --url")]


def test_stage_ids():
    stage = {"stage 2d": {"can_disable": True}}
    assert _diff("cli", stage, {}) == [("breaking", "stage 2d", "removed")]
    assert _diff("cli", {}, stage) == [("compatible", "stage 2d", "added")]       # a new stage id
    fixed = {"stage 2d": {"can_disable": False}}
    assert _diff("cli", stage, fixed) == [("breaking", "stage 2d", "can_disable: true -> false")]
    assert _diff("cli", fixed, stage) == [("compatible", "stage 2d", "can_disable: false -> true")]


@pytest.mark.parametrize("key", ["entrypoint check", "entrypoint bootstrap --strict", "make db-upgrade"])
def test_container_commands(key):
    assert _diff("cli", {key: {}}, {}) == [("breaking", key, "removed")]
    assert _diff("cli", {}, {key: {}}) == [("compatible", key, "added")]


# ── config ───────────────────────────────────────────────────────────────────

def test_variables():
    tlp = {"env STIX_TLP": {"set": True, "values": ["amber"]}}
    assert _diff("config", {}, tlp) == [("compatible", "env STIX_TLP", "added")]
    assert _diff("config", tlp, {"env STIX_TLP": {"set": True, "values": ["red"]}}) == [
        ("default", "env STIX_TLP", 'values: ["amber"] -> ["red"]')]
    assert _diff("config", tlp, {"env STIX_TLP": {"set": False, "values": ["amber"]}}) == [
        ("default", "env STIX_TLP", "set: true -> false")]
    assert _severities("config", {"env STIX_TLP": {"set": False, "values": ["amber"]}}, tlp) == {"default"}


@pytest.mark.parametrize(("before", "after", "severity"), [
    ([], ["ollama"], "breaking"),                   # no longer starts by default
    (["ollama"], [], "breaking"),                   # a profile removed
    (["ollama"], ["llm"], "breaking"),
    (["ollama"], ["llm", "ollama"], "compatible"),  # one more profile starts it
])
def test_compose_profiles(before, after, severity):
    key = "compose service ollama"
    assert _severities("config", {key: {"profiles": before}}, {key: {"profiles": after}}) == {severity}


def test_compose_services_and_volumes():
    entries = {"compose service app": {"profiles": []}, "compose volume cti-state": {}}
    assert _severities("config", entries, {}) == {"breaking"}
    assert _severities("config", {}, entries) == {"compatible"}


def test_the_project_and_volume_names():
    project = {"compose project": {"name": "ctiparsor"}}
    assert _diff("config", project, {"compose project": {"name": "cti"}}) == [
        ("breaking", "compose project", 'name: "ctiparsor" -> "cti"')]
    assert _diff("config", project, {"compose project": {"name": None}}) == [
        ("breaking", "compose project", 'name: "ctiparsor" -> null')]
    assert _diff("config", project, {}) == [("breaking", "compose project", "removed")]
    volume = {"compose volume pg-data-18": {}}
    assert _diff("config", volume, {"compose volume pg-data-18": {"name": "pg"}}) == [
        ("breaking", "compose volume pg-data-18", 'name: null -> "pg"')]


# ── stix ─────────────────────────────────────────────────────────────────────

def test_custom_properties():
    prop = {"property vulnerability x_cvss_v3_score": {"types": ["number"]}}
    assert _diff("stix", prop, {}) == [("breaking", "property vulnerability x_cvss_v3_score", "removed")]
    assert _diff("stix", {}, prop) == [("compatible", "property vulnerability x_cvss_v3_score", "added")]
    wider = {"property vulnerability x_cvss_v3_score": {"types": ["number", "string"]}}
    assert _severities("stix", prop, wider) == {"breaking"}
    assert _severities("stix", wider, prop) == {"compatible"}


def test_ids():
    key = 'id minimal malware name="SUNBURST"'
    old = {key: {"id": "malware--00000000-0000-5000-8000-000000000001"}}
    new = {key: {"id": "malware--00000000-0000-5000-8000-000000000002"}}
    assert _severities("stix", old, new) == {"breaking"}                # an identity rule changed
    assert _diff("stix", old, {}) == [("compatible", key, "removed")]   # the object is no longer built
    assert _diff("stix", {}, old) == [("compatible", key, "added")]
    random = {key: {"id": "random"}}                                    # tests/stage4_reference.py's R<n>
    assert _diff("stix", old, random) == [
        ("breaking", key, "id: malware--00000000-0000-5000-8000-000000000001 -> random (an identity rule changed)")]
    assert _severities("stix", random, old) == {"breaking"}


# ── check and write ──────────────────────────────────────────────────────────

_CURRENT = {
    "openapi": {"GET /api/a": {"deprecated": False}},
    "cli": {"entrypoint serve": {}},
    "config": {"env STIX_TLP": {"set": True, "values": ["amber"]},
               "compose service app": {"profiles": []}},
    "stix": {"property report x_source_published": {"types": ["object"]}},
}


@pytest.fixture()
def surfaces(tmp_path, monkeypatch):
    """contract/ under tmp_path, and extractors that return `current`."""
    current = copy.deepcopy(_CURRENT)
    monkeypatch.setattr(c, "CONTRACT_DIR", tmp_path / "contract")
    monkeypatch.setattr(c, "EXTRACTORS", {s: (lambda s=s: copy.deepcopy(current[s])) for s in c.SURFACES})
    return current


def _files(tmp_path) -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted((tmp_path / "contract").glob("*.json"))}


def test_write_records_every_surface_and_check_then_passes(surfaces, tmp_path, capsys):
    assert c.main(["write"]) == 0
    assert set(_files(tmp_path)) == {f"{s}.json" for s in c.SURFACES}
    assert c.main(["check"]) == 0
    assert "the code matches contract/*.json" in capsys.readouterr().out


def test_a_recorded_file_holds_the_entries_and_no_date(surfaces, tmp_path):
    assert c.main(["write"]) == 0
    text = (tmp_path / "contract" / "config.json").read_text(encoding="utf-8")
    assert text == json.dumps({"entries": _CURRENT["config"], "generator": "scripts/contract.py",
                               "surface": "config"}, indent=2, sort_keys=True) + "\n"


def test_check_without_a_reference_fails(surfaces, capsys):
    assert c.main(["check"]) == 1
    assert "contract/openapi.json does not exist" in capsys.readouterr().out


def test_check_fails_on_a_compatible_difference(surfaces, capsys):
    assert c.main(["write"]) == 0
    surfaces["config"]["env NEW_FLAG"] = {"set": False, "values": ["false"]}
    capsys.readouterr()
    assert c.main(["check"]) == 1
    out = capsys.readouterr().out
    assert "COMPATIBLE  config   env NEW_FLAG: added" in out
    assert "Run `make contract` to record it." in out


def test_check_names_a_breaking_difference_and_the_way_out(surfaces, capsys):
    assert c.main(["write"]) == 0
    del surfaces["cli"]["entrypoint serve"]
    surfaces["cli"]["entrypoint worker"] = {}
    capsys.readouterr()
    assert c.main(["check"]) == 1
    out = capsys.readouterr().out
    assert "BREAKING    cli      entrypoint serve: removed" in out
    assert out.index("BREAKING") < out.index("COMPATIBLE")
    assert "make contract ACCEPT_BREAKING=1" in out
    assert "a major version from 1.0 on, a minor one before" in out


def test_a_changed_default_names_the_changelog(surfaces, capsys):
    assert c.main(["write"]) == 0
    surfaces["config"]["env STIX_TLP"] = {"set": True, "values": ["red"]}
    capsys.readouterr()
    assert c.main(["check"]) == 1
    out = capsys.readouterr().out
    assert 'DEFAULT     config   env STIX_TLP: values: ["amber"] -> ["red"]' in out
    assert "CHANGELOG" in out


def test_write_refuses_a_breaking_change_and_writes_nothing(surfaces, tmp_path, capsys):
    assert c.main(["write"]) == 0
    before = _files(tmp_path)
    del surfaces["config"]["env STIX_TLP"]
    surfaces["stix"]["property report x_new"] = {"types": ["string"]}
    assert c.main(["write"]) == 1
    assert _files(tmp_path) == before                       # not even the compatible addition
    assert "nothing written" in capsys.readouterr().out
    assert c.main(["write", "--accept-breaking"]) == 0
    assert "STIX_TLP" not in _files(tmp_path)["config.json"]
    assert "x_new" in _files(tmp_path)["stix.json"]


def test_write_records_a_compatible_change(surfaces, tmp_path):
    assert c.main(["write"]) == 0
    surfaces["openapi"]["GET /api/b"] = {"deprecated": False}
    assert c.main(["write"]) == 0
    assert "GET /api/b" in _files(tmp_path)["openapi.json"]


@pytest.mark.parametrize("command", [["check"], ["write"], ["write", "--accept-breaking"]])
def test_an_extractor_that_finds_nothing_is_2_and_writes_nothing(surfaces, monkeypatch, tmp_path, command):
    monkeypatch.setitem(c.EXTRACTORS, "stix", lambda: {})
    assert c.main(command) == 2
    assert _files(tmp_path) == {}


def test_an_extractor_that_fails_is_2(surfaces, monkeypatch, capsys):
    def broken() -> dict:
        raise c.ExtractError("cli: docker/entrypoint.sh: no command found")

    monkeypatch.setitem(c.EXTRACTORS, "cli", broken)
    assert c.main(["check"]) == 2
    assert "no command found" in capsys.readouterr().err


@pytest.mark.parametrize("command", [["check"], ["write"]])
def test_an_extractor_that_raises_anything_is_2(surfaces, monkeypatch, tmp_path, capsys, command):
    def broken() -> dict:
        raise ValueError("compose.yaml: mapping values are not allowed here")

    monkeypatch.setitem(c.EXTRACTORS, "config", broken)
    assert c.main(command) == 2
    assert "contract: config: the extractor failed: ValueError: compose.yaml" in capsys.readouterr().err
    assert _files(tmp_path) == {}


def test_a_surface_without_an_extractor_is_2(surfaces, monkeypatch):
    monkeypatch.delitem(c.EXTRACTORS, "openapi")
    assert c.main(["check"]) == 2


@pytest.mark.parametrize("text", ["{not json", '{"surface": "cli", "entries": {}}', '{"surface": "stix"}'])
def test_an_unreadable_reference_is_2(surfaces, tmp_path, text):
    assert c.main(["write"]) == 0
    (tmp_path / "contract" / "stix.json").write_text(text, encoding="utf-8")
    assert c.main(["check"]) == 2
    assert c.main(["write"]) == 2
