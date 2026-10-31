"""The stable contract of docs/support-policy.md, recorded and checked (ADR-0094 item 1).

    python scripts/contract.py check
        compare the code's surfaces with contract/*.json and print every difference
    python scripts/contract.py write [--accept-breaking]
        record the code's surfaces in contract/*.json (`make contract`)

One reference file per surface, under contract/:

    openapi.json  every operation of the API's OpenAPI schema: its parameters,
                  request body and responses, field by field
    cli.json      main.py's arguments, the stage ids, the container commands of
                  docker/entrypoint.sh and `make db-upgrade`
    config.json   the variables of .env.example and the Compose layout
    stix.json     the custom properties of the Stage 4 reference bundles, and
                  the ids of their deterministic objects

Each difference has a severity.  `breaking` needs a major version
(docs/support-policy.md, "Breaking changes and deprecation"); `default` is a
changed default, allowed in a minor release when the CHANGELOG names it;
`compatible` is an addition or a relaxation.  `check` fails on any
difference, a compatible one included: the reference always equals the code,
so a field added and later removed is caught as a removal.

Exit codes:
    0  check: every surface equals its reference; write: the references were written
    1  check: a difference; write: a breaking change without --accept-breaking (nothing written)
    2  an extractor failed or found nothing, or a reference file is unreadable
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, NamedTuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:      # main.py and pipeline/ import from the repository root
    sys.path.insert(0, str(ROOT))

CONTRACT_DIR = ROOT / "contract"
GENERATOR = "scripts/contract.py"
SURFACES = ("openapi", "cli", "config", "stix")

BREAKING, DEFAULT, COMPATIBLE = "breaking", "default", "compatible"
_RANK = {BREAKING: 0, DEFAULT: 1, COMPATIBLE: 2}

Entries = dict[str, dict[str, Any]]
Change = tuple[str, str]           # (severity, what changed)


class ExtractError(RuntimeError):
    """An extractor failed or found nothing (exit 2): never an empty surface."""


class Difference(NamedTuple):
    severity: str
    surface: str
    key: str
    what: str

    def line(self) -> str:
        return f"{self.severity.upper():<10}  {self.surface:<7}  {self.key}: {self.what}"


class Rules(NamedTuple):
    """How one surface classifies an entry added (given the reference's
    entries), an entry removed, and an entry changed."""
    added: Callable[[str, dict[str, Any], Entries], str]
    removed: Callable[[str, dict[str, Any]], str]
    changed: Callable[[str, dict[str, Any], dict[str, Any]], list[Change]]


# ── Diff engine ──────────────────────────────────────────────────────────────

def _show(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def diff_entries(surface: str, old: Entries, new: Entries, rules: Rules) -> list[Difference]:
    """Every difference between the reference `old` and the code's `new`.  A
    changed entry no rule explains is breaking: an unknown change is not
    assumed safe."""
    found: list[Difference] = []
    for key in sorted(set(old) | set(new)):
        if key not in new:
            found.append(Difference(rules.removed(key, old[key]), surface, key, "removed"))
        elif key not in old:
            found.append(Difference(rules.added(key, new[key], old), surface, key, "added"))
        elif old[key] != new[key]:
            changes = rules.changed(key, old[key], new[key]) or [
                (BREAKING, f"changed: {_show(old[key])} -> {_show(new[key])}")]
            found += [Difference(severity, surface, key, what) for severity, what in changes]
    return found


def sort_differences(diffs: Iterable[Difference]) -> list[Difference]:
    """Breaking first, then default, then compatible; by surface, key and text."""
    return sorted(diffs, key=lambda d: (_RANK[d.severity], d.surface, d.key, d.what))


def _lost_gained(old: Iterable[Any], new: Iterable[Any],
                 fmt: Callable[[Any], str] = _show) -> tuple[list[str], list[str]]:
    a, b = {fmt(v) for v in old}, {fmt(v) for v in new}
    return sorted(a - b), sorted(b - a)


def _widened(old: list[str], new: list[str]) -> bool:
    """Whether `new` admits a type `old` did not ("any" admits every type,
    "number" every integer)."""
    if "any" in old:
        return False
    gained = set(new) - set(old)
    if "number" in old:
        gained.discard("integer")
    return "any" in new or bool(gained)


def _types_change(side: str, old: list[str], new: list[str]) -> list[Change]:
    """A request may accept more types, never fewer; a response may return
    fewer, never more (a field that becomes nullable breaks a client)."""
    if not old or not new or sorted(old) == sorted(new):
        return []
    harmful = _widened(new, old) if side == "request" else _widened(old, new)
    return [(BREAKING if harmful else COMPATIBLE, f"types: {'|'.join(old)} -> {'|'.join(new)}")]


def _required_change(side: str, old: bool, new: bool, label: str = "required") -> list[Change]:
    """Request side: optional -> required breaks.  Response side: a field
    always present that may now be absent breaks."""
    if old == new:
        return []
    harmful = new if side == "request" else old
    return [(BREAKING if harmful else COMPATIBLE, f"{label}: {_show(old)} -> {_show(new)}")]


def _values_change(side: str, old: list[Any] | None, new: list[Any] | None,
                   label: str = "enum") -> list[Change]:
    """A list of allowed values: losing one breaks, gaining one does not.  A
    restriction that appears breaks a request; one that goes is compatible."""
    if old == new:
        return []
    if old is None:
        return [(BREAKING if side == "request" else COMPATIBLE, f"{label}: none -> {_show(new)}")]
    if new is None:
        return [(COMPATIBLE, f"{label}: {_show(old)} -> none")]
    lost, gained = _lost_gained(old, new)
    changes: list[Change] = []
    if lost:
        changes.append((BREAKING, f"{label}: lost {', '.join(lost)}"))
    if gained:
        changes.append((COMPATIBLE, f"{label}: gained {', '.join(gained)}"))
    return changes


def _media_change(old: list[str], new: list[str]) -> list[Change]:
    lost, gained = _lost_gained(old, new, str)
    changes: list[Change] = []
    if lost:
        changes.append((BREAKING, f"media: lost {', '.join(lost)}"))
    if gained:
        changes.append((COMPATIBLE, f"media: gained {', '.join(gained)}"))
    return changes


def _default_change(old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
    if old.get("default") == new.get("default") and ("default" in old) == ("default" in new):
        return []
    before = _show(old["default"]) if "default" in old else "none"
    after = _show(new["default"]) if "default" in new else "none"
    return [(DEFAULT, f"default: {before} -> {after}")]


# What a request schema may restrict besides its types and values, recorded on
# the request side only (`_flatten`); `closed` is `additionalProperties: false`.
RESTRICTIONS = ("closed", "exclusiveMaximum", "exclusiveMinimum", "format", "maxItems", "maxLength", "maximum",
                "minItems", "minLength", "minimum", "pattern")


def _restrictions_change(old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
    """A restriction on what a request may send: one that appears or changes
    may refuse what a client sends today (breaking), one that goes does not."""
    changes: list[Change] = []
    for name in RESTRICTIONS:
        if (name in old, old.get(name)) == (name in new, new.get(name)):
            continue
        before = _show(old[name]) if name in old else "none"
        after = _show(new[name]) if name in new else "none"
        changes.append((BREAKING if name in new else COMPATIBLE, f"{name}: {before} -> {after}"))
    return changes


def _always_breaking(key: str, desc: dict[str, Any]) -> str:
    return BREAKING


def _always_compatible(key: str, desc: dict[str, Any], old: Entries) -> str:
    return COMPATIBLE


# ── Rules: openapi ───────────────────────────────────────────────────────────

def openapi_side(key: str) -> str:
    """"operation" (`GET /api/x`), "response" (`... response:200...`) or
    "request" (`... param:...`, `... body...`)."""
    parts = key.split(" ", 2)
    if len(parts) < 3:
        return "operation"
    return "response" if parts[2].startswith("response:") else "request"


def openapi_parent(key: str) -> str:
    """The entry `key` belongs to: `GET /a body.x[]` -> `GET /a body.x` ->
    `GET /a body` -> `GET /a`."""
    method, path, rest = key.split(" ", 2)
    base = f"{method} {path}"
    for suffix in ("[]", "{*}"):
        if rest.endswith(suffix):
            return f"{base} {rest[:-len(suffix)]}"
    if "." in rest:
        return f"{base} {rest.rsplit('.', 1)[0]}"
    return base


def _openapi_added(key: str, desc: dict[str, Any], old: Entries) -> str:
    """A required parameter or field breaks the clients of what already
    existed; on a new route, or inside a new body or field, it does not."""
    if openapi_side(key) == "request" and desc.get("required") and openapi_parent(key) in old:
        return BREAKING
    return COMPATIBLE


def _openapi_changed(key: str, old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
    side = openapi_side(key)
    if side == "operation":
        if old.get("deprecated") != new.get("deprecated"):
            return [(COMPATIBLE, f"deprecated: {_show(old.get('deprecated'))} -> {_show(new.get('deprecated'))}")]
        return []
    changes = _media_change(old.get("media", []), new.get("media", []))
    changes += _required_change(side, bool(old.get("required")), bool(new.get("required")))
    changes += _types_change(side, old.get("types", []), new.get("types", []))
    changes += _values_change(side, old.get("enum"), new.get("enum"))
    if side == "request":
        changes += _default_change(old, new)
        changes += _restrictions_change(old, new)
    return changes


# ── Rules: cli ───────────────────────────────────────────────────────────────

def _cli_added(key: str, desc: dict[str, Any], old: Entries) -> str:
    return BREAKING if desc.get("required") else COMPATIBLE


def _group_change(old: dict[str, Any] | None, new: dict[str, Any] | None) -> list[Change]:
    """A mutually exclusive group.  An argument that joins one, or whose group
    becomes required, can refuse a command line that worked: breaking.
    Members that come or go are compatible: a new member is a new argument,
    which no command line uses yet.  (An argument that moves from one group to
    another is not seen.)"""
    if old == new:
        return []
    if old is None:
        return [(BREAKING, f"group: none -> {_show(new)}")]
    if new is None:
        return [(COMPATIBLE, f"group: {_show(old)} -> none")]
    lost, gained = _lost_gained(old["members"], new["members"], str)
    changes: list[Change] = []
    if gained:
        changes.append((COMPATIBLE, f"group: now exclusive with {', '.join(gained)}"))
    if lost:
        changes.append((COMPATIBLE, f"group: no longer exclusive with {', '.join(lost)}"))
    changes += _required_change("request", bool(old["required"]), bool(new["required"]), "group required")
    return changes


def _cli_changed(key: str, old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
    if key.startswith("stage "):
        if old.get("can_disable") == new.get("can_disable"):
            return []
        harmful = bool(old.get("can_disable")) and not new.get("can_disable")
        return [(BREAKING if harmful else COMPATIBLE,
                 f"can_disable: {_show(old.get('can_disable'))} -> {_show(new.get('can_disable'))}")]
    if not key.startswith("main.py "):
        return []
    changes: list[Change] = []
    for field in ("action", "nargs", "type", "const"):
        if old.get(field) != new.get(field):
            changes.append((BREAKING, f"{field}: {_show(old.get(field))} -> {_show(new.get(field))}"))
    changes += _required_change("request", bool(old.get("required")), bool(new.get("required")))
    changes += _values_change("request", old.get("choices"), new.get("choices"), "choices")
    changes += _default_change(old, new)
    changes += _group_change(old.get("group"), new.get("group"))
    return changes


# ── Rules: config ────────────────────────────────────────────────────────────

def _config_changed(key: str, old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
    if key.startswith("env "):
        changes: list[Change] = []
        if old.get("values") != new.get("values"):
            changes.append((DEFAULT, f"values: {_show(old.get('values'))} -> {_show(new.get('values'))}"))
        if old.get("set") != new.get("set"):
            changes.append((DEFAULT, f"set: {_show(old.get('set'))} -> {_show(new.get('set'))}"))
        return changes
    if key.startswith("compose service "):
        before, after = old.get("profiles", []), new.get("profiles", [])
        if before == after:
            return []
        lost, _ = _lost_gained(before, after, str)
        # A profile removed, or a first profile: the service no longer starts as it did.
        harmful = bool(lost) or (not before and bool(after))
        return [(BREAKING if harmful else COMPATIBLE, f"profiles: {_show(before)} -> {_show(after)}")]
    if key == "compose project" or key.startswith("compose volume "):
        # The project's name prefixes each volume's, which `name:` replaces:
        # under another name, the stack starts on empty volumes.
        if old.get("name") != new.get("name"):
            return [(BREAKING, f"name: {_show(old.get('name'))} -> {_show(new.get('name'))}")]
    return []


# ── Rules: stix ──────────────────────────────────────────────────────────────

def _stix_removed(key: str, desc: dict[str, Any]) -> str:
    """Which objects a report yields varies (docs/support-policy.md): an id
    entry may go.  A custom property may not."""
    return COMPATIBLE if key.startswith("id ") else BREAKING


def _stix_changed(key: str, old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
    if key.startswith("id "):
        if old.get("id") != new.get("id"):
            return [(BREAKING, f"id: {old.get('id')} -> {new.get('id')} (an identity rule changed)")]
        return []
    return _types_change("response", old.get("types", []), new.get("types", []))


RULES: dict[str, Rules] = {
    "openapi": Rules(added=_openapi_added, removed=_always_breaking, changed=_openapi_changed),
    "cli": Rules(added=_cli_added, removed=_always_breaking, changed=_cli_changed),
    "config": Rules(added=_always_compatible, removed=_always_breaking, changed=_config_changed),
    "stix": Rules(added=_always_compatible, removed=_stix_removed, changed=_stix_changed),
}


# ── Extractor: openapi ───────────────────────────────────────────────────────

# Run by `python -c` in an empty directory.  `load_dotenv()` (api/db.py,
# pipeline/stage3_llm.py) finds the repository's .env from the calling
# module's directory whenever the main module is a file, whatever the working
# directory: the child turns it off before it imports the app.  The schema
# goes to a file, since the app's logging writes to stdout.
_OPENAPI_CHILD = """
import json, sys
import dotenv
dotenv.load_dotenv = lambda *args, **kwargs: False
from api.main import app
with open(sys.argv[1], "w", encoding="utf-8") as out:
    json.dump(app.openapi(), out)
"""
_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_PATH_PARAM = re.compile(r"\{([^}]*)\}")


def openapi_schema() -> dict[str, Any]:
    """The schema the app serves at /openapi.json, built in a process of its
    own: an environment of PATH, HOME, PYTHONPATH and SKIP_HEAVY_MODELS only,
    an empty working directory and no .env, so that neither a developer's
    settings nor CI's change it."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"),
           "PYTHONPATH": str(ROOT), "SKIP_HEAVY_MODELS": "1"}
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "openapi.json"
        done = subprocess.run([sys.executable, "-c", _OPENAPI_CHILD, str(out)], cwd=tmp, env=env,
                              capture_output=True, text=True, timeout=900)
        if done.returncode != 0 or not out.is_file():
            raise ExtractError(f"openapi: building the schema failed (exit {done.returncode}):\n"
                               f"{done.stderr[-2000:]}")
        schema: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return schema


class _Node(NamedTuple):
    """A schema as a client sees it."""
    types: set[str]
    enum: list[Any] | None
    props: dict[str, list[dict[str, Any]]]
    required: set[str]
    items: list[dict[str, Any]]
    values: list[dict[str, Any]]
    refs: frozenset[str]
    restrictions: dict[str, list[Any]]


def _collapse(schema: dict[str, Any], components: dict[str, Any], seen: frozenset[str]) -> _Node:
    """`schema` reduced to its JSON types, its allowed values (enum, const),
    its properties, which of them are required, the schemas of its array
    items and map values, and its RESTRICTIONS.  A `$ref` is followed, except
    to a schema already on the way (a cycle: an object without fields); anyOf
    and oneOf are a union (a property is required when every object variant
    requires it; a variant that allows anything, `{}`, makes the union "any");
    allOf is merged.  Titles, descriptions and examples are ignored."""
    ref = schema.get("$ref")
    if isinstance(ref, str):
        name = ref.rsplit("/", 1)[-1]
        if name in seen:
            return _Node({"object"}, None, {}, set(), [], [], seen, {})
        if name not in components:
            raise ExtractError(f"openapi: unresolved $ref {ref}")
        return _collapse(components[name], components, seen | {name})
    declared = schema.get("type")
    types: set[str] = {declared} if isinstance(declared, str) else set(declared or [])
    enum: list[Any] | None = list(schema["enum"]) if "enum" in schema else None
    if "const" in schema:
        enum = [schema["const"]]
    props: dict[str, list[dict[str, Any]]] = {
        name: [sub] for name, sub in (schema.get("properties") or {}).items()}
    required: set[str] = set(schema.get("required") or [])
    items = [schema["items"]] if isinstance(schema.get("items"), dict) else []
    extra = schema.get("additionalProperties")
    values = [extra] if isinstance(extra, dict) and extra else []
    restrictions: dict[str, list[Any]] = {name: [schema[name]] for name in RESTRICTIONS if name in schema}
    if extra is False:
        restrictions["closed"] = [True]
    refs = seen
    if props and not types:
        types.add("object")
    if items and not types:
        types.add("array")
    for keyword in ("anyOf", "oneOf", "allOf"):
        variants = [_collapse(v, components, seen) for v in schema.get(keyword) or []]
        for v in variants:
            types |= v.types
            if keyword != "allOf" and not (v.types or v.enum is not None or v.props or v.items or v.values):
                types.add("any")
            if v.enum is not None:
                enum = (enum or []) + [e for e in v.enum if e not in (enum or [])]
            for name, subs in v.props.items():
                props.setdefault(name, []).extend(subs)
            items += v.items
            values += v.values
            refs |= v.refs
            for name, found in v.restrictions.items():
                kept = restrictions.setdefault(name, [])
                kept += [x for x in found if x not in kept]
        objects = [v.required for v in variants if v.props]
        if objects:
            required |= set.union(*objects) if keyword == "allOf" else set.intersection(*objects)
    return _Node(types, enum, props, required, items, values, refs, restrictions)


def _one(schemas: list[dict[str, Any]]) -> dict[str, Any]:
    return schemas[0] if len(schemas) == 1 else {"anyOf": schemas}


def _put(out: Entries, key: str, desc: dict[str, Any]) -> None:
    if key in out:
        raise ExtractError(f"openapi: {key} is described twice")
    out[key] = desc


def _flatten(schema: dict[str, Any], key: str, required: bool, side: str, components: dict[str, Any],
             out: Entries, seen: frozenset[str] = frozenset()) -> None:
    """One entry for `schema` at `key`, then one per property (`key.name`),
    array item (`key[]`) and map value (`key{*}`), recursively."""
    node = _collapse(schema, components, seen)
    types = ["any"] if not node.types or "any" in node.types else sorted(node.types)
    desc: dict[str, Any] = {"required": required, "types": types}
    if node.enum is not None:
        desc["enum"] = sorted(node.enum, key=_show)
    if side == "request":
        if "default" in schema:
            desc["default"] = schema["default"]
        for name, found in sorted(node.restrictions.items()):
            desc[name] = found[0] if len(found) == 1 else sorted(found, key=_show)
    _put(out, key, desc)
    for name in sorted(node.props):
        _flatten(_one(node.props[name]), f"{key}.{name}", name in node.required, side, components, out,
                 node.refs)
    if node.items:
        _flatten(_one(node.items), f"{key}[]", True, side, components, out, node.refs)
    if node.values:
        _flatten(_one(node.values), f"{key}{{*}}", True, side, components, out, node.refs)


def _flatten_content(content: dict[str, Any], key: str, desc: dict[str, Any], side: str,
                     components: dict[str, Any], out: Entries) -> None:
    """A request body or a response: `desc` (its media types; for a body,
    whether it is required) and the JSON types of its schema (for a body, its
    RESTRICTIONS too), then its fields."""
    schemas = [media["schema"] for media in content.values() if media.get("schema") is not None]
    if not schemas:
        _put(out, key, desc)
        return
    _flatten(_one(schemas), key, True, side, components, out)
    flat = out[key]
    out[key] = {**desc, "types": flat["types"], **{name: flat[name] for name in RESTRICTIONS if name in flat}}


_VALIDATION_ERROR = "#/components/schemas/HTTPValidationError"


def _is_validation_error(code: str, response: dict[str, Any]) -> bool:
    """FastAPI's own 422, which it adds to every route that takes a parameter
    or a body.  Its body is FastAPI's, and the support policy does not cover
    error details: recorded, it would make more than half of the entries, and
    a route losing its last parameter would read as a breaking change.  A 422
    with a body of our own is kept."""
    content = response.get("content") or {}
    return code == "422" and bool(content) and all(
        (media.get("schema") or {}).get("$ref") == _VALIDATION_ERROR for media in content.values())


def openapi_entries(schema: dict[str, Any]) -> Entries:
    """The schema flattened into what a client depends on.  A path parameter's
    name is invisible to a client: `{job_id}` becomes `{}`, and the parameter
    is known by its position (`param:path:0`).  Keys and descriptors:

        METHOD /path                                  deprecated
        METHOD /path param:<in>:<name>[...]           required, types, enum?, default?, RESTRICTIONS?
        METHOD /path body                             required, media, types, RESTRICTIONS?
        METHOD /path body.<field>[...]                required, types, enum?, default?, RESTRICTIONS?
        METHOD /path response:<code>                  media, types (when it has a schema)
        METHOD /path response:<code>.<field>[...]     required, types, enum?
        METHOD /path response:<code> header:<name>    required, types

    where [...] continues with `.field`, `[]` (array items) and `{*}` (map values).
    FastAPI's own 422 is left out (`_is_validation_error`).
    """
    components: dict[str, Any] = (schema.get("components") or {}).get("schemas") or {}
    out: Entries = {}
    for path, item in sorted((schema.get("paths") or {}).items()):
        names = _PATH_PARAM.findall(path)
        route = _PATH_PARAM.sub("{}", path)
        for method in _HTTP_METHODS:
            op = item.get(method)
            if op is None:
                continue
            base = f"{method.upper()} {route}"
            _put(out, base, {"deprecated": bool(op.get("deprecated", False))})
            for param in [*(item.get("parameters") or []), *(op.get("parameters") or [])]:
                where, name = param.get("in"), param.get("name")
                if where == "path":
                    if name not in names:
                        raise ExtractError(f"openapi: {base}: path parameter {name!r} is not in the path")
                    pid = f"path:{names.index(name)}"
                elif where == "header":
                    pid = f"header:{str(name).lower()}"
                else:
                    pid = f"{where}:{name}"
                _flatten(param.get("schema") or {}, f"{base} param:{pid}",
                         where == "path" or bool(param.get("required")), "request", components, out)
            body = op.get("requestBody")
            if body is not None:
                content = body.get("content") or {}
                _flatten_content(content, f"{base} body",
                                 {"required": bool(body.get("required", False)), "media": sorted(content)},
                                 "request", components, out)
            for code, response in sorted((op.get("responses") or {}).items()):
                if _is_validation_error(code, response):
                    continue
                content = response.get("content") or {}
                _flatten_content(content, f"{base} response:{code}", {"media": sorted(content)},
                                 "response", components, out)
                for header, spec in sorted((response.get("headers") or {}).items()):
                    _flatten(spec.get("schema") or {}, f"{base} response:{code} header:{header.lower()}",
                             bool(spec.get("required", False)), "response", components, out)
    return out


def extract_openapi() -> Entries:
    entries = openapi_entries(openapi_schema())
    if not any(openapi_side(key) == "operation" for key in entries):
        raise ExtractError("openapi: the schema has no operation")
    return entries


# ── Extractor: cli ───────────────────────────────────────────────────────────

_DISPATCH = re.compile(r'^case "\$cmd" in\n(.*?)^esac', re.M | re.S)
_BOOTSTRAP = re.compile(r"^bootstrap\(\) \{\n(.*?)^\}", re.M | re.S)
_COMMAND_LABEL = re.compile(r"^\s*([a-z][a-z0-9-]*)\)", re.M)
_FLAG_LABEL = re.compile(r"^\s*(--[a-z][a-z0-9-]*)\)", re.M)


def _action_kind(action: argparse.Action) -> str:
    """argparse's name for an action: `_StoreTrueAction` gives "store_true"."""
    name = type(action).__name__.strip("_")
    name = name.removesuffix("Action") or name
    return re.sub(r"(?<=[a-z])(?=[A-Z])", "_", name).lower()


def _argument(action: argparse.Action) -> str:
    """How a user names an argument: its option strings, or a positional's dest."""
    return "|".join(action.option_strings) if action.option_strings else action.dest


def _type_name(convert: Any) -> str | None:
    """The name of what argparse converts a value with (`int`), or None."""
    if convert is None:
        return None
    return str(getattr(convert, "__name__", type(convert).__name__))


def parser_entries(parser: argparse.ArgumentParser, prog: str = "main.py") -> Entries:
    """One entry per argument but --help, keyed `<prog> <argument>`."""
    groups: dict[int, dict[str, Any]] = {}
    for group in parser._mutually_exclusive_groups:
        members = sorted(_argument(a) for a in group._group_actions)
        for a in group._group_actions:
            groups[id(a)] = {"members": members, "required": bool(group.required)}
    out: Entries = {}
    for action in parser._actions:
        kind = _action_kind(action)
        if kind == "help":
            continue
        out[f"{prog} {_argument(action)}"] = {
            "action": kind,
            "nargs": action.nargs,
            "required": bool(action.required),
            "choices": sorted(str(c) for c in action.choices) if action.choices is not None else None,
            "default": json.loads(json.dumps(action.default, default=repr)),
            "type": _type_name(action.type),
            "const": json.loads(json.dumps(action.const, default=repr)),
            "group": groups.get(id(action)),
        }
    return out


def stage_entries(stages: Iterable[str], mandatory: Iterable[str]) -> Entries:
    """`stage <id>`: every stage id, and whether --disable-stage accepts it."""
    fixed = set(mandatory)
    return {f"stage {s}": {"can_disable": s not in fixed} for s in stages}


def entrypoint_entries(text: str) -> Entries:
    """The commands docker/entrypoint.sh dispatches (`*)` left out) and the
    options its `bootstrap` parses.  A block not found, or without a label,
    fails: the parser no longer reads the script."""
    dispatch, bootstrap = _DISPATCH.search(text), _BOOTSTRAP.search(text)
    if dispatch is None or bootstrap is None:
        raise ExtractError("cli: docker/entrypoint.sh: no dispatch `case` block or no `bootstrap()` function")
    commands = _COMMAND_LABEL.findall(dispatch.group(1))
    flags = _FLAG_LABEL.findall(bootstrap.group(1))
    if not commands or not flags:
        raise ExtractError("cli: docker/entrypoint.sh: no command or no bootstrap option found")
    out: Entries = {f"entrypoint {c}": {} for c in commands}
    out.update({f"entrypoint bootstrap {f}": {} for f in flags})
    return out


def make_entries(text: str) -> Entries:
    """`make db-upgrade`, the one make target the policy lists."""
    return {"make db-upgrade": {}} if re.search(r"^db-upgrade:", text, re.M) else {}


def extract_cli() -> Entries:
    import main as cti_main
    from pipeline.orchestrator import MANDATORY_STAGES, STAGES

    out = parser_entries(cti_main.build_parser())
    if not out:
        raise ExtractError("cli: main.py's parser has no argument")
    out.update(stage_entries(STAGES, MANDATORY_STAGES))
    out.update(entrypoint_entries((ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")))
    out.update(make_entries((ROOT / "Makefile").read_text(encoding="utf-8")))
    return out


# ── Extractor: config ────────────────────────────────────────────────────────

# `NAME=value` sets a variable; `# NAME=value` shows the default of one left
# unset (the conventions at the top of .env.example).  The commented form
# takes exactly one space and a value without blanks, so that the prose
# lines `#   KEY=value     a setting to review`,
# `#   CTI_GIT_REV=$(git rev-parse --short HEAD) docker compose build` and
# `# TTP_MODE=select retrieval (ADR-0072; ...)` are not read as variables.
_ENV_SET = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
_ENV_SHOWN = re.compile(r"^# ([A-Z][A-Z0-9_]*)=(\S*)$")
# Not a stable surface (docs/support-policy.md, Configuration, "Not covered").
UNSTABLE_VARIABLES = frozenset({"SKIP_HEAVY_MODELS", "TTP_RETRIEVAL_EXCLUDE_CITED"})


def env_entries(text: str) -> Entries:
    """`env NAME`: whether a line sets it, and its values as written, in file order."""
    out: Entries = {}
    for line in text.splitlines():
        match, is_set = _ENV_SET.match(line), True
        if match is None:
            match, is_set = _ENV_SHOWN.match(line), False
        if match is None or match.group(1) in UNSTABLE_VARIABLES:
            continue
        entry = out.setdefault(f"env {match.group(1)}", {"set": False, "values": []})
        entry["set"] = entry["set"] or is_set
        entry["values"].append(match.group(2))
    return out


def _volume_source(volume: Any) -> str:
    if isinstance(volume, dict):
        return str(volume.get("source", ""))
    return str(volume).split(":", 1)[0]


def compose_entries(text: str) -> Entries:
    """The project name of compose.yaml, which prefixes the name of each
    volume; its services with their profiles; its named volumes, with the
    `name:` that replaces that prefix when one is set.  The `dev` profile
    (dev, frontend-dev) is not a stable surface, nor is a volume that only its
    services use."""
    import yaml

    data = yaml.safe_load(text) or {}
    out: Entries = {"compose project": {"name": data.get("name")}}
    kept: set[str] = set()
    dev: set[str] = set()
    for name, service in (data.get("services") or {}).items():
        profiles = sorted(service.get("profiles") or [])
        sources = {_volume_source(v) for v in service.get("volumes") or []}
        if "dev" in profiles:
            dev |= sources
            continue
        kept |= sources
        out[f"compose service {name}"] = {"profiles": profiles}
    for volume, spec in (data.get("volumes") or {}).items():
        if volume in kept or volume not in dev:
            named = spec.get("name") if isinstance(spec, dict) else None
            out[f"compose volume {volume}"] = {} if named is None else {"name": named}
    return out


def extract_config() -> Entries:
    env = env_entries((ROOT / ".env.example").read_text(encoding="utf-8"))
    compose = compose_entries((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    if not env or not any(key.startswith("compose service ") for key in compose):
        raise ExtractError("config: no variable in .env.example, or no service in compose.yaml")
    return {**env, **compose}


# ── Extractor: stix ──────────────────────────────────────────────────────────

# tests/stage4_reference.py writes a random (uuid4) id as `<type>--R<n>`:
# relationships, the Report, and an AttackPattern built without a standard
# id.  Every other id in its expected files is the one the code computes.  An
# object with a random id and a natural key is recorded with the id RANDOM, so
# an id that becomes random, or stops being random, is a changed id.
_RANDOM_ID = re.compile(r"^[a-z][a-z0-9-]*--R\d+$")
RANDOM = "random"
# What names an object from one release to the next, first found wins.
NATURAL_KEYS = ("name", "value", "key", "pattern", "hashes", "definition")


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int | float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def stix_entries(files: Iterable[Path]) -> tuple[Entries, int]:
    """(entries, objects not recorded).  `property <type> <x_name>`: the JSON
    types a custom property takes.  `id <scenario> <type> <field>=<value>`:
    the id of each object, or RANDOM.  An object without a natural key is not
    recorded: counted when its id is deterministic, left out when it is random
    (the relationships)."""
    out: Entries = {}
    types: dict[str, set[str]] = {}
    unkeyed = 0
    for path in files:
        for obj in json.loads(path.read_text(encoding="utf-8"))["objects"]:
            for name, value in obj.items():
                if name.startswith("x_"):
                    types.setdefault(f"property {obj['type']} {name}", set()).add(_json_type(value))
            random = _RANDOM_ID.match(obj["id"]) is not None
            field = next((f for f in NATURAL_KEYS if f in obj), None)
            if field is None:
                unkeyed += 0 if random else 1
                continue
            key = f"id {path.stem} {obj['type']} {field}={_show(obj[field])}"
            if key in out:
                raise ExtractError(f"stix: two objects of {path.name} have the key {key}")
            out[key] = {"id": RANDOM if random else obj["id"]}
    out.update({key: {"types": sorted(found)} for key, found in types.items()})
    return out, unkeyed


def extract_stix() -> Entries:
    files = sorted((ROOT / "tests" / "fixtures" / "stage4_reference" / "expected").glob("*.json"))
    entries, unkeyed = stix_entries(files)
    if not entries:
        raise ExtractError("stix: no object in tests/fixtures/stage4_reference/expected/")
    if unkeyed:
        print(f"contract: stix: {unkeyed} object(s) with a deterministic id but none of "
              f"{', '.join(NATURAL_KEYS)} are not recorded", file=sys.stderr)
    return entries


# ── Registry, files, commands ────────────────────────────────────────────────

EXTRACTORS: dict[str, Callable[[], Entries]] = {
    "openapi": extract_openapi, "cli": extract_cli, "config": extract_config, "stix": extract_stix}


def extract(surface: str) -> Entries:
    """The code's entries for `surface`, as JSON gives them back.  Whatever an
    extractor raises is an extractor failure (exit 2), never a difference."""
    extractor = EXTRACTORS.get(surface)
    if extractor is None:
        raise ExtractError(f"{surface}: no extractor")
    try:
        entries = extractor()
    except ExtractError:
        raise
    except Exception as exc:     # a file it cannot parse, an import that fails
        raise ExtractError(f"{surface}: the extractor failed: {type(exc).__name__}: {exc}") from exc
    if not entries:
        raise ExtractError(f"{surface}: the extractor found nothing")
    loaded: Entries = json.loads(json.dumps(entries, sort_keys=True))
    return loaded


def reference_path(surface: str) -> Path:
    return CONTRACT_DIR / f"{surface}.json"


def dump(surface: str, entries: Entries) -> str:
    """The text of contract/<surface>.json: sorted and indented, with no date,
    commit or version, so that it changes only when the contract does."""
    document = {"surface": surface, "generator": GENERATOR, "entries": entries}
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def load_reference(surface: str) -> Entries | None:
    """The recorded entries of `surface`, or None when its file does not exist."""
    path = reference_path(surface)
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ExtractError(f"{path.name}: unreadable: {exc}") from exc
    if not isinstance(document, dict) or document.get("surface") != surface \
            or not isinstance(document.get("entries"), dict):
        raise ExtractError(f"{path.name}: not the contract file of surface {surface!r}")
    entries: Entries = document["entries"]
    return entries


def footer(diffs: list[Difference]) -> str:
    """The counts, and what to do about them."""
    counts = {severity: sum(d.severity == severity for d in diffs) for severity in _RANK}
    text = (f"contract: {len(diffs)} difference(s): {counts[BREAKING]} breaking, "
            f"{counts[DEFAULT]} default, {counts[COMPATIBLE]} compatible.")
    if counts[BREAKING]:
        return (text + "\nA breaking change needs a major version from 1.0 on, a minor one before "
                "(docs/releasing.md); if it is intended, run `make contract ACCEPT_BREAKING=1` and "
                "announce it in the CHANGELOG.")
    if counts[DEFAULT]:
        text += ("\nA changed default goes in the CHANGELOG, with the value that restores the "
                 "previous behaviour (docs/support-policy.md).")
    return text + "\nRun `make contract` to record it."


def check() -> int:
    """0 when every surface equals its reference, 1 on any difference, 2 when
    an extractor fails or a reference file is unreadable."""
    try:
        current = {surface: extract(surface) for surface in SURFACES}
        recorded = {surface: load_reference(surface) for surface in SURFACES}
    except ExtractError as exc:
        print(f"contract: {exc}", file=sys.stderr)
        return 2
    diffs: list[Difference] = []
    missing = False
    for surface in SURFACES:
        old = recorded[surface]
        if old is None:
            print(f"MISSING     {surface:<7}  contract/{surface}.json does not exist")
            missing = True
            continue
        diffs += diff_entries(surface, old, current[surface], RULES[surface])
    diffs = sort_differences(diffs)
    for d in diffs:
        print(d.line())
    if diffs or missing:
        print(footer(diffs))
        return 1
    total = sum(len(entries) for entries in current.values())
    print(f"contract: the code matches contract/*.json ({total} entries, {len(SURFACES)} surfaces)")
    return 0


def write(accept_breaking: bool) -> int:
    """Record every surface; refuse (1, nothing written) a breaking change
    unless `accept_breaking`; 2 when an extractor fails."""
    try:
        current = {surface: extract(surface) for surface in SURFACES}
        recorded = {surface: load_reference(surface) for surface in SURFACES}
    except ExtractError as exc:
        print(f"contract: {exc}", file=sys.stderr)
        return 2
    diffs: list[Difference] = []
    for surface in SURFACES:
        old = recorded[surface]
        if old is None:          # a first recording: nothing to compare with
            print(f"NEW         {surface:<7}  contract/{surface}.json is recorded for the first time")
            continue
        diffs += diff_entries(surface, old, current[surface], RULES[surface])
    diffs = sort_differences(diffs)
    for d in diffs:
        print(d.line())
    if any(d.severity == BREAKING for d in diffs) and not accept_breaking:
        print("contract: nothing written.  A breaking change needs a major version from 1.0 on, a minor one "
              "before (docs/releasing.md); if it is intended, run `make contract ACCEPT_BREAKING=1` and "
              "announce it in the CHANGELOG.")
        return 1
    CONTRACT_DIR.mkdir(parents=True, exist_ok=True)
    for surface in SURFACES:
        reference_path(surface).write_text(dump(surface, current[surface]), encoding="utf-8", newline="\n")
    print(f"contract: wrote contract/*.json ({len(diffs)} difference(s) recorded)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts/contract.py",
                                     description="Record or check the stable contract (ADR-0094 item 1).")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="compare the code's surfaces with contract/*.json")
    write_command = commands.add_parser("write", help="record the code's surfaces in contract/*.json")
    write_command.add_argument("--accept-breaking", action="store_true",
                               help="write even when a difference is breaking")
    args = parser.parse_args(argv)
    if args.command == "check":
        return check()
    return write(args.accept_breaking)


if __name__ == "__main__":
    sys.exit(main())
