"""Import one bundle into a throwaway OpenCTI, then check what it kept (ADR-0094 item 10, #708).

    python scripts/opencti_import_bundle.py BUNDLE.json [--url URL] [--token-file FILE]
                                            [--out-dir DIR] [--timeout SECONDS]
                                            [--image-digest sha256:HEX]

The run, in order:

1. The inventory of the bundle, taken before anything is sent: every object
   (id, type, name or value, whether it has a description), every
   relationship (type and ends), and each Report (its object_refs, its
   description, the names of its attached files, x_opencti_files).
2. The import, as the token's user, the way the OpenCTI worker imports a bundle
   (scripts/opencti_import_check.py, import_per_object).
3. The read-back of the whole platform, repeated until two readings in a row
   agree, within --timeout seconds.
4. The expectations of scripts/opencti_expectations.py on that reading: each
   object once, no second object under its name, value or alias, each
   relationship on an object of its own joining the objects it names, the
   authors and markings the bundles set, the descriptions, and each Report: one
   in the bundle, its references, its description, its files, its confidence.
5. A second import of the same bundle and a second read-back: nothing refused,
   nothing added, no attribute changed, and the checks of step 4 again.

Each check is pass, fail or not_checked. A required check that did not run is
not_checked, and a not_checked check is never a pass: the run fails on it. The
required checks are listed in REQUIRED.

The report goes to DIR (default output/opencti-import/<UTC time>/): report.md
for people, report.json for the record (the inventory, the checks, the counts
per type, the missing and refused objects, the transformations OpenCTI made,
the bundle's sha256, the OpenCTI and pycti versions, and the image digest when
--image-digest gives one). It is written whatever the result.

Exit codes: 0 when every check passed; 1 when a check failed or was not run
(the report names it); 2 when the run cannot start or OpenCTI fails a call (one
line on stderr, no traceback).

The token comes from --token-file: a file holding the API token alone, or a
KEY=VALUE file with OPENCTI_ADMIN_TOKEN. Without --token-file, the token is read
from docker/opencti-test/.env. It is never printed. The script does not
compare the bundle with CTIParsor's own expectations (its baseline and enriched
bundles): scripts/opencti_import_check.py does that, for its own fixtures.

Run it with the pycti venv of TESTING.md (*OpenCTI import (A4)*), not with the
project venv: pycti is not a project requirement. Use it on the throwaway
instance of docker/opencti-test only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from importlib import metadata
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:   # run as a script: the repository root is not on the path
    sys.path.insert(0, str(REPO_ROOT))

from scripts import opencti_expectations as expect  # standard library only
from scripts import opencti_import_check as check  # pycti is imported lazily there, so --help works without it (#622)

DEFAULT_URL = "http://127.0.0.1:4000"
OUTPUT_ROOT = REPO_ROOT / "output" / "opencti-import"
TOKEN_KEY = "OPENCTI_ADMIN_TOKEN"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

# A check that is not in the checks of a run is not_checked, and fails the run.
# Each name must appear, as a substring, in the check names of the run.
REQUIRED = (
    "nothing refused on import",
    "one Report in the bundle",
    "every object in OpenCTI, once",
    "no second object of the same type and name",
    "each relationship on an OpenCTI relationship of its own",
    "each relationship joins the objects the bundle names",
    "each object's author (created_by_ref) attached",
    "each object's markings (TLP, PAP) as the bundles set them",
    "no description emptied",
    "the Report holds the bundle's references",
    "every reading of the platform settled",
    "nothing refused on a second import",
    "a second import adds nothing",
    "no attribute changed by a second import",
)


class CannotRun(Exception):
    """The run cannot start: an unreadable bundle or token, or a bad option. The message never holds the token."""


def read_token(path: Path) -> str:
    """The API token from a file: the token alone, or the OPENCTI_ADMIN_TOKEN line of a KEY=VALUE file."""
    try:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError as exc:
        raise CannotRun(f"cannot read the token file {path}: {exc.strerror}") from exc
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and key.strip() == TOKEN_KEY:
            if not value.strip():
                raise CannotRun(f"{TOKEN_KEY} is empty in {path}")
            return value.strip()
    if len(lines) == 1 and "=" not in lines[0]:
        return lines[0]
    raise CannotRun(f"no API token in {path}: one line with the token, or {TOKEN_KEY}=...")


def read_bundle(path: Path) -> dict[str, Any]:
    """The bundle, checked for what the import and the checks need: objects with an id and a type,
    and relationships with their ends."""
    try:
        bundle = check.load_bundle(str(path))
    except (OSError, ValueError) as exc:
        raise CannotRun(f"cannot read the bundle {path}: {exc}") from exc
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list) or not objects:
        raise CannotRun(f"no objects in the bundle {path}")
    for obj in objects:
        if not isinstance(obj, dict) or not obj.get("id") or not obj.get("type"):
            raise CannotRun(f"cannot read the bundle {path}: an object has no id or no type")
        if obj["type"] == "relationship":
            ends = [obj.get("relationship_type"), obj.get("source_ref"), obj.get("target_ref")]
            if not all(isinstance(v, str) and v for v in ends):
                raise CannotRun(f"cannot read the bundle {path}: relationship {obj['id']} has no type or no ends")
    return bundle


def inventory(bundle: dict[str, Any]) -> dict[str, Any]:
    """What the bundle holds, as it is before the import: the objects, the relationships' ends and each Report."""
    objects = bundle["objects"]
    return {
        "objects": [{"id": o["id"], "type": o["type"], "name": o.get("name") or o.get("value"),
                     "description": bool(o.get("description"))} for o in objects],
        "relationships": [{"id": o["id"], "relationship_type": o["relationship_type"],
                           "source_ref": o["source_ref"], "target_ref": o["target_ref"]}
                          for o in objects if o["type"] == "relationship"],
        "reports": [{"id": o["id"], "name": o.get("name"), "object_refs": list(o.get("object_refs") or []),
                     "description": bool(o.get("description")),
                     "files": [f.get("name") for f in o.get("x_opencti_files") or []]}
                    for o in objects if o["type"] == "report"],
    }


def add(checks: list[dict[str, Any]], step: str, name: str, expected: str, observed: str,
        passed: bool, detail: Any = None) -> None:
    checks.append({"step": step, "check": name, "expected": expected, "observed": observed,
                   "status": "pass" if passed else "fail", "detail": detail})


def extend(checks: list[dict[str, Any]], results: list[dict[str, Any]]) -> None:
    """Record the checks scripts/opencti_expectations.py returned, in order."""
    for c in results:
        add(checks, c["step"], c["check"], c["expected"], c["observed"], c["pass"], c.get("detail"))


def settled_platform(client: Any, timeout: float) -> tuple[expect.Platform, bool]:
    """The platform as OpenCTI shows it, and whether two readings in a row agreed before the timeout."""
    reading, settled = expect.settle(lambda: check.read_platform(client), timeout, check.POLL_INTERVAL)
    return expect.Platform(reading["objects"], reading["relationships"], reading["markings"]), settled


def pycti_version() -> str:
    try:
        return metadata.version("pycti")
    except metadata.PackageNotFoundError:
        return "not installed"


def run(args: argparse.Namespace, stamp: str) -> dict[str, Any]:
    bundle_path = Path(args.bundle)
    bundle = read_bundle(bundle_path)
    objects = bundle["objects"]
    if args.image_digest is not None and not DIGEST.match(args.image_digest):
        raise CannotRun("--image-digest must be sha256: followed by 64 lowercase hex digits")
    token = read_token(Path(args.token_file)) if args.token_file else read_token(check.DEFAULT_ENV)
    client = check.make_client(args.url, token)
    about = check.gql(client, check.ABOUT_QUERY)["about"]
    inv = inventory(bundle)
    sha = check.file_sha256(str(bundle_path))
    checks: list[dict[str, Any]] = []

    # First import and read-back. The import works on its own copy: pycti edits the items it imports.
    first_import = check.import_per_object(client, read_bundle(bundle_path))
    first, first_settled = settled_platform(client, args.timeout)
    refused = first_import["refused"]
    refused_ids = {e["id"] for e in refused}
    add(checks, "import", "nothing refused on import", "0 refused",
        f"{len(refused)} refused of {first_import['objects']}", not refused, refused)
    reports = [o["id"] for o in objects if o["type"] == "report"]
    add(checks, "inventory", "one Report in the bundle", "1 Report", f"{len(reports)} in the bundle",
        len(reports) == 1, reports)
    extend(checks, expect.bundle_checks("readback", "the bundle", bundle, [bundle], first))
    first_changes = expect.transformations(bundle, first)

    # Second import of the same bundle, and a second read-back.
    second_import = check.import_per_object(client, read_bundle(bundle_path))
    after, after_settled = settled_platform(client, args.timeout)
    extend(checks, expect.reimport_checks("reimport", "the bundle", second_import, first.counts(), after.counts()))
    extend(checks, expect.bundle_checks("reimport", "the bundle", bundle, [bundle, bundle], after))
    changed = expect.later_changes(first_changes, expect.transformations(bundle, after))
    add(checks, "reimport", "no attribute changed by a second import", "no change",
        f"{len(changed)} changed", not changed, changed)
    extend(checks, expect.reading_checks("readback", [
        {"label": "after the import", "settled": first_settled},
        {"label": "after the second import", "settled": after_settled},
    ]))

    names = [c["check"] for c in checks]
    not_checked = [name for name in REQUIRED if not any(name in n for n in names)]
    for name in not_checked:
        checks.append({"step": "required", "check": name, "expected": "checked", "observed": "not checked",
                       "status": "not_checked", "detail": None})

    # Per type, what the first read-back holds: by STIX id, or by name or alias when OpenCTI renamed it.
    sent = Counter(obj["type"] for obj in objects)
    types: dict[str, dict[str, int]] = {}
    for stix_type in sorted(sent):
        of_type = [obj for obj in objects if obj["type"] == stix_type]
        found = [o["id"] for o in of_type if first.resolve(o)[0] is not None]
        types[stix_type] = {
            "sent": sent[stix_type],
            "found": len(found),
            "missing": len(of_type) - len(found),
            "refused": sum(1 for o in of_type if o["id"] in refused_ids),
        }
    totals = {key: sum(row[key] for row in types.values()) for key in ("sent", "found", "missing", "refused")}
    missing = list({o["id"]: {"id": o["id"], "type": o["type"]} for o in objects
                    if first.resolve(o)[0] is None}.values())
    refused_rows = [{"id": e.get("id"), "type": e.get("type"), "error": e.get("error")} for e in refused]

    return {
        "passed": bool(checks) and all(c["status"] == "pass" for c in checks) and not missing and not refused,
        "started_utc": stamp,
        "bundle": {
            "path": str(bundle_path),
            "id": bundle.get("id"),
            "sha256": sha,
            "objects": len(objects),
        },
        "opencti": {"url": args.url, "version": about["version"]},
        "pycti": pycti_version(),
        "image_digest": args.image_digest,
        "import_path": check.IMPORT_PATH,
        "inventory": inv,
        "types": types,
        "totals": totals,
        "missing": missing,
        "refused": refused_rows,
        "readings": {"after_import_settled": first_settled, "after_second_import_settled": after_settled},
        "checks": checks,
        "not_checked": not_checked,
        "transformations": expect.summarize(first_changes),
    }


def table(result: dict[str, Any]) -> str:
    rows = [("type", "sent", "found", "missing", "refused")]
    for stix_type, row in result["types"].items():
        rows.append((stix_type, str(row["sent"]), str(row["found"]), str(row["missing"]), str(row["refused"])))
    t = result["totals"]
    rows.append(("total", str(t["sent"]), str(t["found"]), str(t["missing"]), str(t["refused"])))
    widths = [max(len(r[i]) for r in rows) for i in range(5)]
    return "\n".join("  ".join(cell.ljust(widths[i]) if i == 0 else cell.rjust(widths[i])
                              for i, cell in enumerate(row)) for row in rows)


def _cell(text: Any) -> str:
    return str(text if text is not None else "").replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def markdown(result: dict[str, Any]) -> str:
    b, o = result["bundle"], result["opencti"]
    verdict = "PASS, every check passed" if result["passed"] else "FAIL, see the checks"
    out = [
        f"# OpenCTI import of {Path(b['path']).name}",
        "",
        f"- Result: {verdict}",
        f"- Bundle: `{b['path']}`, {b['objects']} objects, sha256 `{b['sha256']}`",
        f"- OpenCTI {o['version']} at {o['url']}; pycti {result['pycti']}",
        f"- Image digest: {result['image_digest'] or 'not given'}",
        f"- Started (UTC): {result['started_utc']}",
        "",
        "| type | sent | found | missing | refused |",
        "|---|---:|---:|---:|---:|",
    ]
    for stix_type, row in result["types"].items():
        out.append(f"| {_cell(stix_type)} | {row['sent']} | {row['found']} | {row['missing']} | {row['refused']} |")
    t = result["totals"]
    out.append(f"| **total** | {t['sent']} | {t['found']} | {t['missing']} | {t['refused']} |")
    out += ["", "## Checks", "", "| step | check | expected | observed | status |", "|---|---|---|---|---|"]
    for c in result["checks"]:
        out.append(f"| {_cell(c['step'])} | {_cell(c['check'])} | {_cell(c['expected'])} | "
                   f"{_cell(c['observed'])} | {c['status']} |")
    out += ["", "## Missing", ""]
    out += [f"- `{m['id']}` ({_cell(m['type'])})" for m in result["missing"]] or ["None."]
    out += ["", "## Refused", ""]
    out += [f"- `{_cell(r['id'])}` ({_cell(r['type'])}): {_cell(r['error'])}" for r in result["refused"]] or ["None."]
    out += ["", "## Not checked", ""]
    out += [f"- {_cell(name)}" for name in result["not_checked"]] or ["None."]
    out += ["", "## Transformations (what OpenCTI holds differently, after the first import)", ""]
    out += [f"- {_cell(t['type'])} `{_cell(t['field'])}`: {_cell(t['change'])} on {t['objects']} object(s)"
            for t in result["transformations"]] or ["None."]
    out.append("")
    return "\n".join(out)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import one bundle into OpenCTI, check what it kept, report.")
    parser.add_argument("bundle", help="the bundle to import (JSON)")
    parser.add_argument("--url", default=DEFAULT_URL, help="OpenCTI platform URL, without /graphql")
    parser.add_argument("--token-file", help="file with the API token, or with OPENCTI_ADMIN_TOKEN=... "
                                             "(default: docker/opencti-test/.env)")
    parser.add_argument("--out-dir", help="where report.md and report.json go "
                                          "(default: output/opencti-import/<UTC time>/)")
    parser.add_argument("--timeout", type=float, default=check.POLL_TIMEOUT,
                        help="seconds to wait for two readings of OpenCTI to agree (default: %(default)s)")
    parser.add_argument("--image-digest", help="the digest of the image under test, sha256:<64 hex>, "
                                              "recorded in the report")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out_dir = Path(args.out_dir) if args.out_dir else OUTPUT_ROOT / stamp
    try:
        result = run(args, stamp)
    except CannotRun as exc:
        print(f"the import cannot run: {exc}", file=sys.stderr)
        return 2
    # OpenCTI unreachable or token refused: one line on stderr, not a traceback.
    except Exception as exc:  # noqa: BLE001
        first = next(iter(str(exc).splitlines()), "")
        print(f"the import stopped at {args.url}: {type(exc).__name__}: {first}", file=sys.stderr)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(result, indent=2, ensure_ascii=True, default=str),
                                         encoding="utf-8")
    (out_dir / "report.md").write_text(markdown(result), encoding="utf-8")
    print(table(result))
    for m in result["missing"]:
        print(f"MISSING  {m['id']} ({m['type']})")
    for r in result["refused"]:
        print(f"REFUSED  {r['id']} ({r['type']}): {r['error']}")
    for c in result["checks"]:
        if c["status"] != "pass":
            print(f"{c['status'].upper()}  {c['step']}: {c['check']} "
                  f"(expected {c['expected']}, observed {c['observed']})")
    print("RESULT: " + ("every check passed" if result["passed"] else "some checks failed or were not checked"))
    print(f"Report written to {out_dir}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
