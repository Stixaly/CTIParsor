"""Check A4 of ADR-0090 (lot 7): what OpenCTI keeps of an enriched bundle.

CTIParsor's enriched bundle re-issues the analyst's Report under the same id,
with more object_refs. OpenCTI's import is an upsert, so what the Report holds
afterwards is decided by OpenCTI, not by the bundle. This script imports the
bundles into a running throwaway OpenCTI and reads back what it kept:

1. the analyst's baseline, as admin: nothing is refused;
2. the enriched bundle, as a user whose maximum confidence is 50 (below the
   Report's 85): nothing errors, and the Report keeps its 9 original
   references, since OpenCTI adds missing references on an upsert only when
   the applied confidence is at least the stored one (ADR-0090 section 6);
3. the enriched bundle, as admin: one Report with the baseline's id and name,
   its references a superset of the baseline's and the additions', every
   baseline object once (by STIX id and by type and name/value), and every
   object of the bundle present;
4. optionally the rejected bundle (WellMess removed), as admin: OpenCTI never
   removes a reference on an upsert, so WellMess must still be referenced.

Import path: the calls the OpenCTI worker makes for a bundle (pycti's
import_bundle with update=True, after OpenCTIStix2Splitter), but item by item,
so each refused object is caught and recorded. pycti's import_bundle, given no
work_id, counts a functional refusal as imported, which would hide what A4
must show.

Exit 0 when every expectation holds, 1 otherwise, and 2 when a call to OpenCTI
fails (unreachable, refused token): one line on stderr, no traceback. The admin
token is read from the env file and never printed. Run it from WSL with the
pycti venv, not with the project venv: pycti is not a project requirement, and
the script imports nothing from the CTIParsor packages.

The script creates a role, a group, a user and an API token that never expires
(UNLIMITED), and it never revokes them. It is meant for the throwaway instance
of docker/opencti-test only, never for a real OpenCTI.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
import time
from collections import Counter
from importlib import metadata
from pathlib import Path
from typing import Any, Callable, Iterator

from pycti import OpenCTIApiClient
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV = REPO_ROOT / "docker" / "opencti-test" / ".env"

WELLMESS_ID = "malware--ce12e6b1-5ad7-4fc6-a2ed-2a3ca268a445"
LOWCONF_NAME = "ctiparsor-lowconf"
LOWCONF_GROUP = "ctiparsor-lowconf-group"
LOWCONF_ROLE = "ctiparsor-lowconf-role"
LOWCONF_EMAIL = "ctiparsor-lowconf@example.invalid"
LOWCONF_MAX_CONFIDENCE = 50
# Create and update knowledge, and call the API with a token. SETTINGS_SETMARKINGS
# is needed to import the bundles' marking-definition objects: without it OpenCTI
# answers 403 FORBIDDEN_ACCESS to them, and every object that uses a marking is
# refused with MISSING_REFERENCE_ERROR.
# Artifacts with a payload need KNOWLEDGE_KNUPLOAD, and an attack pattern's kill
# chain phases SETTINGS_SETKILLCHAINPHASES: without them OpenCTI answers 403
# FORBIDDEN_ACCESS (A4 run 3).
LOWCONF_CAPABILITIES = (
    "KNOWLEDGE",
    "KNOWLEDGE_KNUPDATE",
    "KNOWLEDGE_KNUPLOAD",
    "SETTINGS_SETMARKINGS",
    "SETTINGS_SETKILLCHAINPHASES",
    "APIACCESS",
    "APIACCESS_USETOKEN",
)

# OpenCTI writes asynchronously and its reads are indexed: poll, with a timeout.
POLL_TIMEOUT = 120.0
POLL_INTERVAL = 2.0
BATCH = 100

# Bundle objects that are neither SDOs nor SCOs.
NOT_SDO_SCO = ("relationship", "marking-definition")

IMPORT_PATH = (
    "pycti OpenCTIStix2Splitter + OpenCTIStix2.import_item(item, update=True) per object "
    "(the worker's import_bundle, without its work_id-less error swallowing)"
)

CAPABILITIES_QUERY = "{ capabilities(first: 200) { edges { node { id name } } } }"
NAMED_QUERY = "query Named($search: String) { %s(search: $search, first: 50) { edges { node { id name } } } }"
USER_ADD_QUERY = "mutation UserAdd($input: UserAddInput!) { userAdd(input: $input) { id name } }"
ME_QUERY = "{ me { name user_confidence_level { max_confidence } groups { edges { node { name } } } } }"
ABOUT_QUERY = "{ about { version } }"
CORE_QUERY = (
    "query Core($filters: FilterGroup) { stixCoreObjects(first: 500, filters: $filters) "
    "{ edges { node { standard_id x_opencti_stix_ids entity_type representative { main } } } } }"
)
REL_QUERY = (
    "query Rel($filters: FilterGroup) { stixCoreRelationships(first: 500, filters: $filters) "
    "{ edges { node { standard_id x_opencti_stix_ids entity_type } } } }"
)
MARKING_QUERY = "{ markingDefinitions(first: 500) { edges { node { id standard_id } } } }"
SEARCH_QUERY = (
    "query Search($search: String) { stixCoreObjects(first: 100, search: $search) { edges { node { "
    "standard_id x_opencti_stix_ids entity_type representative { main } "
    "... on Identity { name identity_class } ... on AttackPattern { name } ... on Malware { name } "
    "... on IntrusionSet { name } ... on Indicator { name } ... on Report { name } ... on StixFile { file_name: name } "
    "... on StixCyberObservable { observable_value } } } } }"
)
REPORT_QUERY = (
    "query Report($id: String!) { report(id: $id) { standard_id name modified "
    "objects(all: true) { edges { node { ... on BasicObject { standard_id entity_type } "
    "... on StixObject { x_opencti_stix_ids } "
    "... on BasicRelationship { standard_id entity_type } "
    "... on StixCoreRelationship { x_opencti_stix_ids } } } } } }"
)


class Recorder:
    """Keeps the checks in order; the table and the JSON are both built from them."""

    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []
        self.details: dict[str, Any] = {}

    def check(self, step: str, name: str, expected: str, observed: str, passed: bool, detail: Any = None) -> None:
        self.checks.append(
            {"step": step, "check": name, "expected": expected, "observed": observed, "pass": bool(passed)}
        )
        if detail is not None:
            self.details[f"{step}: {name}"] = detail

    def table(self) -> str:
        rows = [("step", "check", "expected", "observed", "result")]
        for c in self.checks:
            rows.append((c["step"], c["check"], c["expected"], c["observed"], "PASS" if c["pass"] else "FAIL"))
        widths = [max(len(row[i]) for row in rows) for i in range(5)]
        return "\n".join("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)) for row in rows)


def make_client(url: str, token: str) -> OpenCTIApiClient:
    return OpenCTIApiClient(url, token, log_level="error", perform_health_check=False)


def read_admin_token(env_file: Path) -> str:
    """Return OPENCTI_ADMIN_TOKEN from a KEY=VALUE file. The value is never printed."""
    for line in env_file.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "OPENCTI_ADMIN_TOKEN":
            return value.strip()
    raise SystemExit(f"OPENCTI_ADMIN_TOKEN not found in {env_file}")


def load_bundle(path: str) -> dict[str, Any]:
    """Read a bundle from disk. Each import gets a fresh copy, because pycti edits the items it imports."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def single_report(bundle: dict[str, Any]) -> dict[str, Any]:
    reports = [o for o in bundle["objects"] if o["type"] == "report"]
    if len(reports) != 1:
        raise SystemExit(f"expected one report in the bundle, found {len(reports)}")
    return reports[0]


def edges(connection: dict[str, Any] | None) -> list[dict[str, Any]]:
    return [edge["node"] for edge in (connection or {}).get("edges", [])]


def gql(client: OpenCTIApiClient, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
    return client.query(query, variables or {})["data"]


def batches(items: list[str]) -> Iterator[list[str]]:
    for start in range(0, len(items), BATCH):
        yield items[start : start + BATCH]


def norm_type(stix_type: str) -> str:
    """Compare a STIX type with an OpenCTI entity_type: 'IPv4-Addr' and 'ipv4-addr' agree, 'StixFile' and 'file' too."""
    key = stix_type.replace("-", "").lower()
    return "stixfile" if key == "file" else key


def poll(read: Callable[[], Any], done: Callable[[Any], bool], timeout: float = POLL_TIMEOUT) -> Any:
    """Read until done() holds or the timeout ends; return the last reading."""
    deadline = time.monotonic() + timeout
    value = read()
    while not done(value) and time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        value = read()
    return value


def stix_ids_of(node: dict[str, Any]) -> set[str]:
    """The STIX ids a node answers to: the one OpenCTI stored from the bundle, and its own standard_id.

    OpenCTI keeps the id of an imported object in x_opencti_stix_ids and gives
    the object its own standard_id, which differs for an analyst's random (v4)
    ids. Comparing standard_id alone would miss every such object.
    """
    return {node["standard_id"], *(node.get("x_opencti_stix_ids") or [])}


def lookup(client: OpenCTIApiClient, ids: list[str]) -> list[dict[str, Any]]:
    """Return the nodes OpenCTI holds for these STIX ids (objects, relationships, markings)."""
    rel_ids = [i for i in ids if i.startswith("relationship--")]
    mark_ids = {i for i in ids if i.startswith("marking-definition--")}
    core_ids = [i for i in ids if i not in rel_ids and i not in mark_ids]
    nodes: list[dict[str, Any]] = []
    for chunk in batches(core_ids):
        filters = {"mode": "and", "filters": [{"key": "ids", "values": chunk}], "filterGroups": []}
        nodes += edges(gql(client, CORE_QUERY, {"filters": filters})["stixCoreObjects"])
    for chunk in batches(rel_ids):
        filters = {"mode": "and", "filters": [{"key": "ids", "values": chunk}], "filterGroups": []}
        nodes += edges(gql(client, REL_QUERY, {"filters": filters})["stixCoreRelationships"])
    if mark_ids:
        marks = edges(gql(client, MARKING_QUERY)["markingDefinitions"])
        nodes += [m for m in marks if m["standard_id"] in mark_ids]
    return nodes


def await_visible(client: OpenCTIApiClient, ids: list[str]) -> list[str]:
    """Poll until OpenCTI shows every id; return the ids still missing when the timeout ends."""

    def missing() -> list[str]:
        present = set().union(*(stix_ids_of(n) for n in lookup(client, ids)))
        return [i for i in ids if i not in present]

    return poll(missing, lambda m: not m)


def same_named(client: OpenCTIApiClient, obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the objects of obj's type, under obj's name or value, that OpenCTI's search shows.

    OpenCTI files an identity under its class (Organization, System, Sector ...)
    and shows an ATT&CK pattern with its technique id in front ("[T1059.001] PowerShell").
    """
    key = obj.get("name") or obj.get("value")
    matches = []
    for node in edges(gql(client, SEARCH_QUERY, {"search": key})["stixCoreObjects"]):
        if obj["type"] == "identity":
            entity_class = {"class": "sector"}.get(obj.get("identity_class", ""), obj.get("identity_class", ""))
            is_kind = norm_type(node["entity_type"]) == norm_type(entity_class)
        else:
            is_kind = norm_type(node["entity_type"]) == norm_type(obj["type"])
        shown = node.get("name") or node.get("file_name") or node.get("observable_value")
        shown = shown or (node.get("representative") or {}).get("main") or ""
        shown = re.sub(r"^\[[^\]]+\] ", "", shown)
        if is_kind and shown == key:
            matches.append(node)
    return matches


def report_state(client: OpenCTIApiClient, report_id: str) -> dict[str, Any]:
    """The Report's references: the entities it holds, and the STIX ids those entities answer to.

    An entity can carry several STIX ids (x_opencti_stix_ids accumulates the ids of
    every bundle that merged into it), so the two sets can differ.
    """
    report = gql(client, REPORT_QUERY, {"id": report_id})["report"]
    if report is None:
        return {"found": False, "entities": set(), "refs": set(), "modified": None, "name": None}
    entities: set[str] = set()
    refs: set[str] = set()
    for node in edges(report["objects"]):
        entities.add(node["standard_id"])
        refs |= set(node.get("x_opencti_stix_ids") or []) or {node["standard_id"]}
    return {
        "found": True,
        "entities": entities,
        "refs": refs,
        "modified": report.get("modified"),
        "name": report.get("name"),
    }


def settled_report(client: OpenCTIApiClient, report_id: str) -> dict[str, Any]:
    """The Report's state once two readings in a row agree.

    A reference OpenCTI adds late shows up as a change between two readings: a
    single read taken just after the import would miss it.
    """
    readings: list[dict[str, Any]] = []

    def settled(state: dict[str, Any]) -> bool:
        readings.append(state)
        return len(readings) >= 2 and readings[-1]["entities"] == readings[-2]["entities"]

    return poll(lambda: report_state(client, report_id), settled)


def find_named(client: OpenCTIApiClient, kind: str, name: str) -> dict[str, Any] | None:
    """Find a role, group or user by exact name."""
    for node in edges(gql(client, NAMED_QUERY % kind, {"search": name})[kind]):
        if node["name"] == name:
            return node
    return None


def ensure_lowconf_user(admin: OpenCTIApiClient, stamp: str, marking_ids: list[str]) -> str:
    """Create or reuse the low-confidence user, and return a new API token for it.

    The group caps the confidence at LOWCONF_MAX_CONFIDENCE and grants access to
    the markings the bundles use: OpenCTI refuses an object whose marking the
    importer cannot access. The user is created with prevent_default_groups, so
    the Default group (max confidence 100) does not lift the cap. A reused role
    or group keeps what it was created with.
    """
    caps = {n["name"]: n["id"] for n in edges(gql(admin, CAPABILITIES_QUERY)["capabilities"])}
    role = find_named(admin, "roles", LOWCONF_ROLE)
    if role is None:
        role = admin.role.create(name=LOWCONF_ROLE, description="ADR-0090 check A4: import knowledge, API token")
        for cap in LOWCONF_CAPABILITIES:
            admin.role.add_capability(id=role["id"], capability_id=caps[cap])
    group = find_named(admin, "groups", LOWCONF_GROUP)
    if group is None:
        group = admin.group.create(
            name=LOWCONF_GROUP,
            description="ADR-0090 check A4: caps the confidence below the baseline Report's 85",
            group_confidence_level={"max_confidence": LOWCONF_MAX_CONFIDENCE, "overrides": []},
        )
        admin.group.add_role(id=group["id"], role_id=role["id"])
        internal = {n["standard_id"]: n["id"] for n in edges(gql(admin, MARKING_QUERY)["markingDefinitions"])}
        for marking_id in marking_ids:
            admin.group.add_allowed_marking(id=group["id"], marking_id=internal[marking_id])
    user = find_named(admin, "users", LOWCONF_NAME)
    if user is None:
        user_input = {
            "name": LOWCONF_NAME,
            "user_email": LOWCONF_EMAIL,
            "password": secrets.token_urlsafe(32),
            "groups": [group["id"]],
            "user_confidence_level": {"max_confidence": LOWCONF_MAX_CONFIDENCE, "overrides": []},
            "prevent_default_groups": True,
        }
        user = gql(admin, USER_ADD_QUERY, {"input": user_input})["userAdd"]
    token = admin.user.create_token(
        user_id=user["id"], token_name=f"a4-import-check-{stamp}", token_duration="UNLIMITED"
    )
    return token["plaintext_token"]


def import_per_object(client: OpenCTIApiClient, bundle: dict[str, Any]) -> dict[str, Any]:
    """Import a bundle the way the worker does, and record every refused object.

    The splitter orders the bundle the same way pycti's import_bundle does. Each
    item then goes through import_item with update=True. An item that raises is
    refused, and its error text is kept exactly as OpenCTI returned it.
    """
    splitter = OpenCTIStix2Splitter()
    event_version = bundle.get("x_opencti_event_version")
    _, incompatible, parts = splitter.split_bundle_with_expectations(bundle, False, event_version)
    refused: list[dict[str, Any]] = [
        {"id": item.get("id"), "type": item.get("type"), "error": "incompatible: dropped by the splitter"}
        for item in incompatible
    ]
    imported: list[str] = []
    for part in parts:
        for item in part["objects"]:
            try:
                client.stix2.import_item(item, True, None, None, part["id"])
            except Exception as ex:  # any refusal is recorded, whatever OpenCTI raised
                refused.append({"id": item.get("id"), "type": item.get("type"), "error": str(ex)})
            else:
                imported.append(item["id"])
    return {"objects": len(bundle["objects"]), "imported": imported, "refused": refused}


def run(args: argparse.Namespace, rec: Recorder) -> None:
    admin = make_client(args.url, read_admin_token(Path(args.env_file)))
    about = gql(admin, ABOUT_QUERY)["about"]
    rec.details["versions"] = {"opencti": about["version"], "pycti": metadata.version("pycti")}
    rec.details["import_path"] = IMPORT_PATH

    baseline = load_bundle(args.baseline)
    enriched = load_bundle(args.enriched)
    base_report = single_report(baseline)
    enr_report = single_report(enriched)
    report_id = base_report["id"]
    base_refs = set(base_report["object_refs"])
    expected_refs = base_refs | set(enr_report["object_refs"])
    stamp = time.strftime("%Y%m%d%H%M%S")

    # 1. The analyst's baseline, as admin.
    first = import_per_object(admin, load_bundle(args.baseline))
    rec.details["import: baseline (admin)"] = first
    rec.check(
        "1",
        "nothing refused: baseline as admin",
        "0 refused",
        f"{len(first['refused'])} refused of {first['objects']}",
        not first["refused"],
        first["refused"],
    )

    # 2. The enriched bundle, as the low-confidence user.
    baseline_entities = {n["standard_id"] for n in lookup(admin, sorted(base_refs))}
    markings =[o for o in baseline["objects"] + enriched["objects"] if o["type"] == "marking-definition"]
    token = ensure_lowconf_user(admin, stamp, sorted({o["id"] for o in markings}))
    lowconf = make_client(args.url, token)
    me = gql(lowconf, ME_QUERY)["me"]
    max_conf = me["user_confidence_level"]["max_confidence"]
    rec.check(
        "2",
        "lowconf user's max confidence",
        str(LOWCONF_MAX_CONFIDENCE),
        str(max_conf),
        max_conf == LOWCONF_MAX_CONFIDENCE,
        me,
    )
    low = import_per_object(lowconf, load_bundle(args.enriched))
    rec.details["import: enriched (lowconf)"] = low
    rec.check(
        "2",
        "nothing errored: enriched as lowconf",
        "0 refused",
        f"{len(low['refused'])} refused of {low['objects']}",
        not low["refused"],
        low["refused"],
    )
    await_visible(admin, low["imported"])
    state = settled_report(admin, report_id)
    rec.check(
        "2",
        "Report keeps its original refs (additions not made)",
        f"{len(base_refs)} baseline refs, {len(baseline_entities)} entities",
        f"{len(state['entities'])} entities",
        state["entities"] == baseline_entities,
        {
            "entities_added": sorted(state["entities"] - baseline_entities),
            "entities_missing": sorted(baseline_entities - state["entities"]),
            "stix_ids": sorted(state["refs"]),
        },
    )

    # 3. The enriched bundle, as admin.
    full = import_per_object(admin, load_bundle(args.enriched))
    rec.details["import: enriched (admin)"] = full
    rec.check(
        "3",
        "nothing refused: enriched as admin",
        "0 refused",
        f"{len(full['refused'])} refused of {full['objects']}",
        not full["refused"],
        full["refused"],
    )
    state = poll(lambda: report_state(admin, report_id), lambda s: expected_refs <= s["refs"])
    missing_refs = sorted(expected_refs - state["refs"])
    rec.check(
        "3",
        "Report refs contain the baseline's and the additions",
        f"{len(expected_refs)} STIX ids",
        f"{len(expected_refs) - len(missing_refs)} of {len(expected_refs)} present",
        not missing_refs,
        {"missing": missing_refs, "extra": sorted(state["refs"] - expected_refs)},
    )
    await_visible(admin, full["imported"])
    by_id = [n for n in lookup(admin, [report_id]) if report_id in stix_ids_of(n)]
    by_name = same_named(admin, base_report)
    rec.check(
        "3",
        "one Report: the baseline id, no second with its name",
        "1 by id, 1 by name",
        f"{len(by_id)} by id, {len(by_name)} by name",
        len(by_id) == 1 and len(by_name) == 1 and report_id in stix_ids_of(by_name[0]),
        {"by_name": by_name},
    )

    sdo_sco = [o for o in baseline["objects"] if o["type"] not in NOT_SDO_SCO]
    counts = Counter(i for n in lookup(admin, [o["id"] for o in sdo_sco]) for i in stix_ids_of(n))
    not_once = [o["id"] for o in sdo_sco if counts[o["id"]] != 1]
    rec.check(
        "3",
        "each baseline SDO/SCO present once, by STIX id",
        f"{len(sdo_sco)} once",
        f"{len(sdo_sco) - len(not_once)} once",
        not not_once,
        not_once,
    )

    # An object with neither name nor value (a hash-only file, an unnamed
    # Indicator) has nothing to search for: the check above covers it by id.
    named = [o for o in sdo_sco if o.get("name") or o.get("value")]
    duplicates: dict[str, Any] = {}
    for o in named:
        matches = same_named(admin, o)
        if not (len(matches) == 1 and o["id"] in stix_ids_of(matches[0])):
            duplicates[o["id"]] = [(m["entity_type"], m["standard_id"]) for m in matches]
    rec.check(
        "3",
        "no second baseline object with the same type and name/value",
        f"{len(named)} with 1 match each",
        f"{len(named) - len(duplicates)} with 1 match",
        not duplicates,
        duplicates,
    )

    enriched_ids = [o["id"] for o in enriched["objects"]]
    present = set().union(*(stix_ids_of(n) for n in lookup(admin, enriched_ids)))
    absent = [i for i in enriched_ids if i not in present]
    rec.check(
        "3",
        "every object of the enriched bundle present",
        f"{len(enriched_ids)} present",
        f"{len(enriched_ids) - len(absent)} present",
        not absent,
        absent,
    )

    # 4. The enriched bundle after the rejection of WellMess, as admin.
    if args.rejected:
        rejected = load_bundle(args.rejected)
        rej = import_per_object(admin, rejected)
        rec.details["import: rejected (admin)"] = rej
        rec.check(
            "4",
            "nothing refused: rejected as admin",
            "0 refused",
            f"{len(rej['refused'])} refused of {rej['objects']}",
            not rej["refused"],
            rej["refused"],
        )
        state = poll(lambda: report_state(admin, report_id), lambda s: WELLMESS_ID in s["refs"])
        rec.check(
            "4",
            "WellMess still referenced by the Report",
            "referenced",
            "referenced" if WELLMESS_ID in state["refs"] else "not referenced",
            WELLMESS_ID in state["refs"],
            {"refs": sorted(state["refs"]), "refs_after_rejected_import": len(state["refs"])},
        )


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ADR-0090 check A4: import bundles into a throwaway OpenCTI.")
    parser.add_argument("--url", default="http://127.0.0.1:4000", help="OpenCTI platform URL, without /graphql")
    parser.add_argument("--env-file", default=str(DEFAULT_ENV), help="env file holding OPENCTI_ADMIN_TOKEN")
    parser.add_argument("--baseline", required=True, help="the analyst's bundle")
    parser.add_argument("--enriched", required=True, help="CTIParsor's enriched bundle")
    parser.add_argument("--rejected", help="the enriched bundle after a rejection (optional)")
    parser.add_argument("--out", help="write the JSON results to this path")
    return parser.parse_args(argv)


def jsonable(value: Any) -> Any:
    """Turn the sets of STIX ids into sorted lists; anything else unknown becomes its text."""
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    return str(value)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    rec = Recorder()
    try:
        run(args, rec)
    except Exception as exc:  # noqa: BLE001 — OpenCTI unreachable or token refused: one line, not a traceback
        first = next(iter(str(exc).splitlines()), "")
        print(f"the check stopped at {args.url}: {type(exc).__name__}: {first}", file=sys.stderr)
        return 2
    passed = all(c["pass"] for c in rec.checks)
    print(rec.table())
    print("RESULT: " + ("every expectation holds" if passed else "at least one expectation FAILS"))
    if args.out:
        payload = {
            "passed": passed,
            "versions": rec.details.get("versions"),
            "import_path": IMPORT_PATH,
            "checks": rec.checks,
            "details": rec.details,
        }
        Path(args.out).write_text(json.dumps(payload, indent=2, ensure_ascii=True, default=jsonable), encoding="utf-8")
        print(f"JSON written to {args.out}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
