"""Import one bundle into a throwaway OpenCTI, then read back every object of it (ADR-0094 item 10).

    python scripts/opencti_import_bundle.py BUNDLE.json [--url URL] [--token-file FILE]
                                            [--out-dir DIR] [--timeout SECONDS]

The bundle is imported as the token's user, the way the OpenCTI worker imports
a bundle (scripts/opencti_import_check.py, import_per_object). The script then
waits until OpenCTI shows the objects it accepted, and reads back every object
of the bundle by STIX id: an object counts as found when OpenCTI holds it under
that id (its own standard id, or the id it stored from the bundle).

Per type, the report gives: sent (objects of the bundle), found (read back),
missing (not read back) and refused (the import's errors, as OpenCTI returned
them). The run passes only when nothing is missing and nothing is refused.

The report goes to DIR (default output/opencti-import/<UTC time>/): report.md
for people, report.json for the record. It is written whatever the result.

Exit codes: 0 when nothing is missing or refused; 1 when something is missing
or refused (the report names it); 2 when the run cannot start or OpenCTI fails
a call (one line on stderr, no traceback).

The token comes from --token-file: a file holding the API token alone, or a
KEY=VALUE file with OPENCTI_ADMIN_TOKEN. Without --token-file, the token is read
from docker/opencti-test/.env. It is never printed. The script does not check
the bundle against the expectations of scripts/opencti_expectations.py (its
duplicates and merges): scripts/opencti_import_check.py does that, for its own
fixtures.

Run it with the pycti venv of TESTING.md (*OpenCTI import (A4)*), not with the
project venv: pycti is not a project requirement. Use it on the throwaway
instance of docker/opencti-test only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from importlib import metadata
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:   # run as a script: the repository root is not on the path
    sys.path.insert(0, str(REPO_ROOT))

from scripts import opencti_import_check as check  # pycti: the venv of TESTING.md, see the docstring

DEFAULT_URL = "http://127.0.0.1:4000"
OUTPUT_ROOT = REPO_ROOT / "output" / "opencti-import"
TOKEN_KEY = "OPENCTI_ADMIN_TOKEN"


class CannotRun(Exception):
    """The run cannot start: an unreadable bundle or token. The message names the file, never the token."""


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
    """The bundle, checked for the one thing the import needs: a list of objects, each with an id and a type."""
    try:
        bundle = check.load_bundle(str(path))
    except (OSError, ValueError) as exc:
        raise CannotRun(f"cannot read the bundle {path}: {exc}") from exc
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list) or not objects:
        raise CannotRun(f"no objects in the bundle {path}")
    for obj in objects:
        if not isinstance(obj, dict) or not obj.get("id") or not obj.get("type"):
            raise CannotRun(f"an object of {path} has no id or no type")
    return bundle


def present_ids(client: Any, ids: list[str]) -> set[str]:
    """The ids of this list that OpenCTI holds, under the STIX id or its standard id."""
    nodes = check.lookup(client, ids)
    return set().union(*(check.stix_ids_of(n) for n in nodes)) & set(ids)


def read_back(client: Any, ids: list[str], timeout: float) -> set[str]:
    """Read the ids back until OpenCTI shows them all, or the timeout ends; return the last reading.

    OpenCTI writes asynchronously and its reads are indexed, so the first
    reading can miss objects that arrive a moment later.
    """
    return check.poll(lambda: present_ids(client, ids), lambda found: set(ids) <= found, timeout)


def pycti_version() -> str:
    try:
        return metadata.version("pycti")
    except metadata.PackageNotFoundError:
        return "not installed"


def run(args: argparse.Namespace, stamp: str) -> dict[str, Any]:
    bundle_path = Path(args.bundle)
    bundle = read_bundle(bundle_path)
    objects = bundle["objects"]
    token = read_token(Path(args.token_file)) if args.token_file else read_token(check.DEFAULT_ENV)
    client = check.make_client(args.url, token)
    about = check.gql(client, check.ABOUT_QUERY)["about"]

    # The import works on its own copy: pycti edits the items it imports.
    imported = check.import_per_object(client, read_bundle(bundle_path))
    ids = list(dict.fromkeys(obj["id"] for obj in objects))
    found = read_back(client, ids, args.timeout)

    refused_ids = {entry["id"] for entry in imported["refused"]}
    sent = Counter(obj["type"] for obj in objects)
    types: dict[str, dict[str, int]] = {}
    for stix_type in sorted(sent):
        of_type = [obj["id"] for obj in objects if obj["type"] == stix_type]
        types[stix_type] = {
            "sent": sent[stix_type],
            "found": sum(1 for i in of_type if i in found),
            "missing": sum(1 for i in of_type if i not in found),
            "refused": sum(1 for i in of_type if i in refused_ids),
        }
    totals = {key: sum(row[key] for row in types.values()) for key in ("sent", "found", "missing", "refused")}
    missing = [{"id": obj["id"], "type": obj["type"]} for obj in objects if obj["id"] not in found]
    missing = list({m["id"]: m for m in missing}.values())
    refused = [{"id": e.get("id"), "type": e.get("type"), "error": e.get("error")} for e in imported["refused"]]

    return {
        "passed": not missing and not refused,
        "started_utc": stamp,
        "bundle": {
            "path": str(bundle_path),
            "id": bundle.get("id"),
            "sha256": check.file_sha256(str(bundle_path)),
            "objects": len(objects),
        },
        "opencti": {"url": args.url, "version": about["version"]},
        "pycti": pycti_version(),
        "import_path": check.IMPORT_PATH,
        "types": types,
        "totals": totals,
        "missing": missing,
        "refused": refused,
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
    out = [
        f"# OpenCTI import of {Path(b['path']).name}",
        "",
        f"- Result: {'PASS, nothing missing or refused' if result['passed'] else 'FAIL'}",
        f"- Bundle: `{b['path']}`, {b['objects']} objects, sha256 `{b['sha256']}`",
        f"- OpenCTI {o['version']} at {o['url']}; pycti {result['pycti']}",
        f"- Started (UTC): {result['started_utc']}",
        "",
        "| type | sent | found | missing | refused |",
        "|---|---:|---:|---:|---:|",
    ]
    for stix_type, row in result["types"].items():
        out.append(f"| {_cell(stix_type)} | {row['sent']} | {row['found']} | {row['missing']} | {row['refused']} |")
    t = result["totals"]
    out.append(f"| **total** | {t['sent']} | {t['found']} | {t['missing']} | {t['refused']} |")
    out += ["", "## Missing", ""]
    out += [f"- `{m['id']}` ({_cell(m['type'])})" for m in result["missing"]] or ["None."]
    out += ["", "## Refused", ""]
    out += [f"- `{_cell(r['id'])}` ({_cell(r['type'])}): {_cell(r['error'])}" for r in result["refused"]] or ["None."]
    out.append("")
    return "\n".join(out)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import one bundle into OpenCTI and read every object back.")
    parser.add_argument("bundle", help="the bundle to import (JSON)")
    parser.add_argument("--url", default=DEFAULT_URL, help="OpenCTI platform URL, without /graphql")
    parser.add_argument("--token-file", help="file with the API token, or with OPENCTI_ADMIN_TOKEN=... "
                                             "(default: docker/opencti-test/.env)")
    parser.add_argument("--out-dir", help="where report.md and report.json go "
                                          "(default: output/opencti-import/<UTC time>/)")
    parser.add_argument("--timeout", type=float, default=check.POLL_TIMEOUT,
                        help="seconds to wait for OpenCTI to show every object (default: %(default)s)")
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
    (out_dir / "report.json").write_text(json.dumps(result, indent=2, ensure_ascii=True), encoding="utf-8")
    (out_dir / "report.md").write_text(markdown(result), encoding="utf-8")
    print(table(result))
    for m in result["missing"]:
        print(f"MISSING  {m['id']} ({m['type']})")
    for r in result["refused"]:
        print(f"REFUSED  {r['id']} ({r['type']}): {r['error']}")
    print("RESULT: " + ("nothing missing or refused" if result["passed"] else "something is missing or refused"))
    print(f"Report written to {out_dir}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
