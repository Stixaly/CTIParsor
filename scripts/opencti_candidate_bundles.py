"""Produce the bundles of the OpenCTI check through a candidate's API (ADR-0094 item 8).

Run by scripts/check_opencti_candidate.sh against the candidate image, started
in a Compose project of its own with the offline profile; Python's standard
library only, so the host's python3 runs it.  Three bundles, each through the
routes the interface uses (POST /api/upload, PATCH .../entities/{id},
POST /finalize, GET /bundle):

* ``full``: tests/fixtures/sample_report.txt, extracted from scratch; APT29
  (a threat actor the run leaves pending) accepted and update-service.net
  (a domain the run accepts) rejected, as the browser journey does;
* ``enriched``: tests/fixtures/baselines/opencti_report.txt with
  opencti_report.json as its baseline (ADR-0090), finalized as it comes;
* ``rejected``: the same job after the analyst rejects WellMess, a malware of
  the baseline the text never names, exported again (A4's re-export).

Each bundle is written to ``--out`` with its ``X-Bundle-Validation``, its sha256
and its job in ``manifest.json``.  Every report is marked TLP:AMBER and
PAP:GREEN: the baseline's TLP, so an object two bundles share carries the same
markings in each, whatever order OpenCTI receives them in.

Exit 0 when the three bundles are written, 2 when the API refuses a step, a run
fails or times out, or a row the profile always extracts is missing (one line
on stderr).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
FULL_REPORT = ROOT / "tests" / "fixtures" / "sample_report.txt"
ENRICH_REPORT = ROOT / "tests" / "fixtures" / "baselines" / "opencti_report.txt"
BASELINE = ROOT / "tests" / "fixtures" / "baselines" / "opencti_report.json"

TLP = "AMBER"
PAP = "GREEN"
#: (value, entity_type, accepted): the full report's decisions, the browser journey's.
FULL_DECISIONS = (("APT29", "threat_actor", True), ("update-service.net", "domain", False))
#: The baseline's malware the enrichment text never names; rejecting it makes the third bundle.
REJECTED = ("WellMess", "malware")
POLL_S = 2.0


class Refused(Exception):
    """A step the check cannot go on without."""


def request(api: str, method: str, path: str, body: bytes | None = None,
            headers: dict[str, str] | None = None, timeout: float = 120.0) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(api + path, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def call(api: str, method: str, path: str, payload: Any = None) -> Any:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if body is not None else {}
    status, _, data = request(api, method, path, body, headers)
    if status >= 300:
        raise Refused(f"{method} {path}: HTTP {status}: {data[:300].decode('utf-8', 'replace')}")
    return json.loads(data) if data else None


def multipart(fields: dict[str, str], files: dict[str, tuple[str, bytes, str]]) -> tuple[bytes, str]:
    """A multipart/form-data body: the form the interface posts to /api/upload."""
    boundary = uuid.uuid4().hex
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    for name, (filename, data, mime) in files.items():
        head = (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                f"Content-Type: {mime}\r\n\r\n")
        parts.append(head.encode() + data + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def upload(api: str, report: Path, baseline: Path | None = None) -> str:
    files = {"file": (report.name, report.read_bytes(), "text/plain")}
    if baseline is not None:
        files["baseline_stix"] = (baseline.name, baseline.read_bytes(), "application/json")
    body, ctype = multipart({"tlp_level": TLP, "pap_level": PAP}, files)
    status, _, data = request(api, "POST", "/api/upload", body, {"Content-Type": ctype})
    if status >= 300:
        raise Refused(f"POST /api/upload {report.name}: HTTP {status}: {data[:300].decode('utf-8', 'replace')}")
    return json.loads(data)["job_id"]


def wait_for_review(api: str, job_id: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        job = call(api, "GET", f"/api/jobs/{job_id}")
        if job["status"] in ("for_review", "reviewing", "completed"):
            return job
        if job["status"] == "failed":
            raise Refused(f"job {job_id} ({job['original_filename']}) failed")
        if time.monotonic() > deadline:
            raise Refused(f"job {job_id} still {job['status']} after {timeout:.0f} s")
        time.sleep(POLL_S)


def decide(api: str, job_id: str, value: str, entity_type: str, accepted: bool) -> dict[str, Any]:
    rows = [r for r in call(api, "GET", f"/api/jobs/{job_id}/entities")
            if r["value"] == value and r["entity_type"] == entity_type]
    if not rows:
        raise Refused(f"job {job_id}: no {entity_type} row {value!r}: the profile or the fixture changed")
    for row in rows:
        call(api, "PATCH", f"/api/jobs/{job_id}/entities/{row['id']}", {"accepted": accepted})
    return {"value": value, "entity_type": entity_type, "accepted": accepted,
            "rows": len(rows), "before": sorted({str(r["accepted"]) for r in rows})}


def export(api: str, job_id: str, out: Path, name: str) -> dict[str, Any]:
    """Finalize the job (the Complete Review click), then download its bundle as the interface does."""
    call(api, "POST", f"/api/jobs/{job_id}/finalize")
    status, headers, data = request(api, "GET", f"/api/jobs/{job_id}/bundle")
    if status != 200:
        raise Refused(f"GET /api/jobs/{job_id}/bundle: HTTP {status}: {data[:300].decode('utf-8', 'replace')}")
    path = out / f"{name}.json"
    path.write_bytes(data)
    bundle = json.loads(data)
    return {
        "file": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "objects": len(bundle.get("objects", [])),
        "validation": headers.get("x-bundle-validation", "absent"),
        "job_id": job_id,
        "job_status": call(api, "GET", f"/api/jobs/{job_id}")["status"],
    }


def produce(api: str, out: Path, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    bundles: dict[str, Any] = {}

    full_job = upload(api, FULL_REPORT)
    wait_for_review(api, full_job, timeout)
    decisions = [decide(api, full_job, *d) for d in FULL_DECISIONS]
    bundles["full"] = {**export(api, full_job, out, "full"), "source": "tests/fixtures/sample_report.txt",
                       "baseline": None, "decisions": decisions}

    enrich_job = upload(api, ENRICH_REPORT, BASELINE)
    wait_for_review(api, enrich_job, timeout)
    bundles["enriched"] = {**export(api, enrich_job, out, "enriched"),
                           "source": "tests/fixtures/baselines/opencti_report.txt",
                           "baseline": "tests/fixtures/baselines/opencti_report.json", "decisions": []}
    rejected = decide(api, enrich_job, *REJECTED, False)
    bundles["rejected"] = {**export(api, enrich_job, out, "rejected"),
                           "source": "tests/fixtures/baselines/opencti_report.txt",
                           "baseline": "tests/fixtures/baselines/opencti_report.json", "decisions": [rejected]}
    return {"api": api, "tlp": TLP, "pap": PAP, "bundles": bundles,
            "seconds": round(time.monotonic() - started, 1)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Produce the OpenCTI check's bundles through a candidate's API.")
    parser.add_argument("--api", required=True, help="the candidate's API, e.g. http://127.0.0.1:8790")
    parser.add_argument("--out", required=True, help="directory for the bundles and manifest.json")
    parser.add_argument("--timeout", type=float, default=600.0, help="seconds a report may take (default 600)")
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    try:
        manifest = produce(args.api.rstrip("/"), out, args.timeout)
    except (Refused, urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        print(f"opencti_candidate_bundles: {exc}", file=sys.stderr)
        return 2
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    for name, b in manifest["bundles"].items():
        print(f"{name}: {b['objects']} objects, {b['validation']}, sha256 {b['sha256']}, job {b['job_id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
