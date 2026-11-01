"""The documented commands and the API journey of the clean-install check (ADR-0094 item 9).

scripts/check_clean_install.sh runs the commands of the public documentation
as a newcomer would; this file gives it what is easier in Python, with the
standard library only, so the host's python3 runs it:

* ``blocks``: the command blocks the check runs, read from the documentation
  (README.md, docs/docker.md, docs/upgrading.md), each under its marker
  comment; ``block NAME`` prints one;
* ``report``: a first report through the API, as the interface makes it:
  tests/fixtures/sample_report.txt uploaded, one decision taken, the review
  completed (POST /finalize) and the bundle downloaded with its
  ``X-Bundle-Validation``;
* ``upload`` and ``follow``: a report started, then followed through a
  restart, each change of its status timed;
* ``bundle``: a report read back after a restart, an upgrade or a restore,
  its status and its bundle's sha256 compared with those first recorded;
* ``summary``: report.json and report.md from what the check recorded.

Exit 0 on success, 1 when a check fails, 2 when a step cannot run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.opencti_candidate_bundles import Refused, call, decide, request, upload, wait_for_review  # noqa: E402

SAMPLE = ROOT / "tests" / "fixtures" / "sample_report.txt"

#: The blocks the check runs: name -> the file that holds it.
BLOCKS = {
    "INSTALL_FILES": "README.md",
    "INSTALL_START": "README.md",
    "RESTART_COMMANDS": "docs/docker.md",
    "STOP_START_COMMANDS": "docs/docker.md",
    "BACKUP_COMMANDS": "docs/docker.md",
    "CHECK_COMMANDS": "docs/docker.md",
    "RESTORE_COMMANDS": "docs/docker.md",
    "UPGRADE_COMMANDS": "docs/upgrading.md",
}
_MARKER = re.compile(r"^<!-- scripts/(?:check_clean_install|check_backup_restore_docker)\.sh: (\w+) -->\n"
                     r"```bash\n(.*?)\n```$", re.MULTILINE | re.DOTALL)
#: The first line of the blocks that name a release, which the check replaces with its own.
VALUES = {
    "INSTALL_FILES": re.compile(r"^version=\S+ digest=sha256:[0-9a-f]{64}$"),
    "UPGRADE_COMMANDS": re.compile(r"^old=\S+ new=\S+ digest=sha256:[0-9a-f]{64}$"),
}
REVIEWABLE = ("for_review", "reviewing", "completed")


def read_blocks(root: Path = ROOT) -> dict[str, list[str]]:
    """Every block of BLOCKS, its lines as written; Refused when one is missing,
    written twice, or its values line is not the expected one."""
    found: dict[str, list[str]] = {}
    for name, rel in BLOCKS.items():
        text = (root / rel).read_text(encoding="utf-8")
        matches = [m for m in _MARKER.finditer(text) if m.group(1) == name]
        if len(matches) != 1:
            raise Refused(f"{rel}: {len(matches)} block(s) marked {name}, expected 1")
        lines = matches[0].group(2).split("\n")
        if name in VALUES and not VALUES[name].match(lines[0]):
            raise Refused(f"{rel}, {name}: the first line {lines[0]!r} is not its values line")
        found[name] = lines
    return found


def _write(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def bundle_of(api: str, job_id: str) -> dict[str, Any]:
    """The job's status and its stored bundle, as GET /api/jobs/{id}/bundle serves it."""
    job = call(api, "GET", f"/api/jobs/{job_id}")
    status, headers, data = request(api, "GET", f"/api/jobs/{job_id}/bundle")
    out: dict[str, Any] = {"job_id": job_id, "status": job["status"], "bundle_http": status}
    if status == 200:
        out.update(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                   objects=len(json.loads(data).get("objects", [])),
                   validation=headers.get("x-bundle-validation", "absent"))
    return out


def first_report(api: str, out: Path, name: str, accept: list[str], timeout: float) -> dict[str, Any]:
    """Upload, wait, decide, complete the review, download: the bundle in out/<name>.json."""
    t0 = time.monotonic()
    job_id = upload(api, SAMPLE)
    job = wait_for_review(api, job_id, timeout)
    waited = round(time.monotonic() - t0, 1)
    decisions = []
    for item in accept:
        value, _, entity_type = item.rpartition(":")
        decisions.append(decide(api, job_id, value, entity_type, True))
    call(api, "POST", f"/api/jobs/{job_id}/finalize")
    status, headers, data = request(api, "GET", f"/api/jobs/{job_id}/bundle")
    if status != 200:
        raise Refused(f"GET /api/jobs/{job_id}/bundle: HTTP {status}: {data[:300].decode('utf-8', 'replace')}")
    (out / f"{name}.json").write_bytes(data)
    result = {**bundle_of(api, job_id), "name": name, "source": "tests/fixtures/sample_report.txt",
              "status_before_review": job["status"], "seconds_to_review": waited, "decisions": decisions,
              "seconds": round(time.monotonic() - t0, 1)}
    if result.get("sha256") != hashlib.sha256(data).hexdigest():
        raise Refused(f"{name}: the bundle served twice differs")
    return result


def follow(api: str, job_id: str, timeout: float, poll: float = 1.0) -> dict[str, Any]:
    """Each change of the job's status, and each time the API stopped or started
    answering, with the seconds since the start; until a reviewable or failed status."""
    t0 = time.monotonic()
    seen: list[dict[str, Any]] = []
    last = None
    while True:
        try:
            now = call(api, "GET", f"/api/jobs/{job_id}")["status"]
        except (urllib.error.URLError, OSError, ValueError, Refused):
            now = "(API not answering)"
        if now != last:
            seen.append({"at_s": round(time.monotonic() - t0, 1), "status": now})
            last = now
        if now in REVIEWABLE or now == "failed":
            break
        if time.monotonic() - t0 > timeout:
            seen.append({"at_s": round(time.monotonic() - t0, 1), "status": f"(still {now}: timeout)"})
            break
        time.sleep(poll)
    return {"job_id": job_id, "final": last, "timeline": seen, "seconds": round(time.monotonic() - t0, 1)}


# ── The summary ───────────────────────────────────────────────────────────────

def _steps(out: Path) -> list[dict[str, Any]]:
    rows = []
    for line in (out / "steps.tsv").read_text(encoding="utf-8").splitlines():
        name, status, seconds, detail = (line.split("\t") + ["", "", ""])[:4]
        rows.append({"step": name, "status": status, "seconds": int(seconds or 0), "detail": detail})
    return rows


def _lines(out: Path) -> list[dict[str, Any]]:
    """The documented commands as they ran: block, line, exit status, seconds."""
    rows = []
    for path in sorted((out / "logs").glob("*.times")):
        for line in path.read_text(encoding="utf-8").splitlines():
            code, seconds, command = line.split("\t", 2)
            rows.append({"block": path.stem.split("-", 1)[-1], "exit": int(code), "seconds": float(seconds),
                         "command": command})
    return rows


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def summary(out: Path) -> dict[str, Any]:
    run = _load(out / "run.json") or {}
    steps = _steps(out)
    report = {
        **run,
        "result": "FAIL" if any(s["status"] == "FAIL" for s in steps) else "PASS",
        "steps": steps,
        "commands": _lines(out),
        "reports": {name: _load(out / f"{name}.meta.json") for name in ("A", "B", "C", "A-after-restart",
                                                                         "A-after-upgrade", "A-restored")},
    }
    _write(out / "report.json", report)
    md = [f"# Clean install: {report['result']}", ""]
    if run.get("mode") == "quick":
        md += ["**`--quick`: no model or corpus was downloaded and the model stages were off. "
               "This run is not the release gate.**", ""]
    for key in ("date", "mode", "previous", "candidate", "checkout", "host"):
        if key in run:
            md.append(f"- {key}: `{json.dumps(run[key])}`")
    md += ["", "| Step | Result | Seconds | Detail |", "|---|---|---|---|"]
    md += [f"| {s['step']} | {s['status']} | {s['seconds']} | {s['detail']} |" for s in steps]
    md += ["", "## The documented commands as they ran", "",
           "| Block | Exit | Seconds | Command |", "|---|---|---|---|"]
    md += [f"| {c['block']} | {c['exit']} | {c['seconds']:.1f} | `{c['command'][:110]}` |" for c in report["commands"]]
    for key in ("sizes_mb", "memory_mb", "durations_s"):
        if key in run:
            md += ["", f"## {key}", "", "```json", json.dumps(run[key], indent=2), "```"]
    (out / "report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("blocks", help="every block the check runs, as --print-blocks shows them")
    p.add_argument("--root", type=Path, default=ROOT)
    p = sub.add_parser("block", help="one block's lines")
    p.add_argument("name", choices=sorted(BLOCKS))
    p.add_argument("--root", type=Path, default=ROOT)
    for name in ("report", "upload", "follow", "bundle"):
        p = sub.add_parser(name)
        p.add_argument("--api", required=True)
        p.add_argument("--out", type=Path, required=True,
                       help="the file (follow, bundle) or directory (report, upload)")
        p.add_argument("--timeout", type=float, default=900.0)
        if name in ("report", "upload"):
            p.add_argument("--name", required=True)
        if name == "report":
            p.add_argument("--accept", action="append", default=[], metavar="VALUE:TYPE")
        if name in ("follow", "bundle"):
            p.add_argument("--job", required=True)
        if name == "bundle":
            p.add_argument("--expect-sha256", default="")
            p.add_argument("--expect-status", default="")
    p = sub.add_parser("summary")
    p.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in ("blocks", "block"):
            blocks = read_blocks(args.root)
            if args.command == "block":
                print("\n".join(blocks[args.name]))
            else:
                for name, lines in blocks.items():
                    print(f"== {name} ({BLOCKS[name]})")
                    print("\n".join(lines))
            return 0
        if args.command == "summary":
            return 0 if summary(args.out)["result"] == "PASS" else 1
        api = args.api.rstrip("/")
        if args.command == "report":
            args.out.mkdir(parents=True, exist_ok=True)
            result = first_report(api, args.out, args.name, args.accept, args.timeout)
            _write(args.out / f"{args.name}.meta.json", result)
            print(json.dumps(result))
            return 0
        if args.command == "upload":
            job_id = upload(api, SAMPLE)
            _write(args.out / f"{args.name}.upload.json", {"job_id": job_id, "name": args.name})
            print(job_id)
            return 0
        if args.command == "follow":
            result = follow(api, args.job, args.timeout)
            _write(args.out, result)
            print(json.dumps(result))
            return 0 if result["final"] in REVIEWABLE else 1
        result = bundle_of(api, args.job)
        _write(args.out, result)
        print(json.dumps(result))
        same = ((not args.expect_sha256 or result.get("sha256") == args.expect_sha256)
                and (not args.expect_status or result.get("status") == args.expect_status))
        return 0 if same else 1
    except (Refused, urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        print(f"clean_install_journey: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
