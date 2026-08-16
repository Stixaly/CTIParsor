"""Read-only API edge-case conformance harness.

This module issues only GET requests (plus the explicitly listed PUT probe,
though none are present in the current probe table) and never touches a
mutating endpoint. It reports which endpoints return 500 (unhandled
exception) instead of a proper 4xx for malformed arguments.
"""

import argparse
import sys
import traceback
from collections import Counter
from pathlib import Path
from typing import Any

# Ensure the project root is on sys.path so `api.main` is importable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from api.main import app

# ---------------------------------------------------------------------------
# Probe table
# ---------------------------------------------------------------------------

_PROBES: list[tuple[str, str, str]] = [
    # --- nonexistent / malformed job ids ---
    ("GET", "/api/jobs/does-not-exist/coverage", "unknown job"),
    ("GET", "/api/jobs/does-not-exist/coverage/rules", "unknown job"),
    ("GET", "/api/jobs/does-not-exist/detections/proposals", "unknown job"),
    ("GET", "/api/jobs/does-not-exist/detections/export/facets", "unknown job"),
    ("GET", "/api/jobs/../../etc/passwd/coverage", "path traversal in job id"),
    ("GET", "/api/jobs/%00/coverage", "null byte in job id"),
    ("GET", "/api/jobs/' OR 1=1--/coverage", "sql metacharacters in job id"),
    # --- limit / pagination bounds ---
    ("GET", "/api/jobs/{job}/detections/proposals?limit=0", "limit zero"),
    ("GET", "/api/jobs/{job}/detections/proposals?limit=-5", "negative limit"),
    ("GET", "/api/jobs/{job}/detections/proposals?limit=999999999", "huge limit"),
    ("GET", "/api/jobs/{job}/detections/proposals?limit=abc", "non-numeric limit"),
    ("GET", "/api/jobs/{job}/detections/proposals?limit=1.5", "float limit"),
    # --- technique id shapes ---
    ("GET", "/api/jobs/{job}/coverage/T1059/rules", "valid technique"),
    ("GET", "/api/jobs/{job}/coverage/not-a-technique/rules", "bad technique"),
    ("GET", "/api/jobs/{job}/coverage//rules", "empty technique"),
    ("GET", "/api/jobs/{job}/coverage/%20/rules", "whitespace technique"),
    ("GET", "/api/jobs/{job}/coverage/" + "T" * 500 + "/rules", "overlong technique"),
    # --- export filter axes ---
    ("GET", "/api/jobs/{job}/detections/export?format=nope", "unknown format"),
    ("GET", "/api/jobs/{job}/detections/export?severity=", "empty severity"),
    ("GET", "/api/jobs/{job}/detections/export?format=sigma&severity=critical&corpus=nope",
     "combination matching nothing"),
    ("GET", "/api/jobs/{job}/detections/export?format=sigma&format=yara", "repeated axis"),
    # --- entities / relationships ---
    ("GET", "/api/jobs/does-not-exist/entities", "unknown job entities"),
    ("GET", "/api/jobs/does-not-exist/relationships", "unknown job relationships"),
    # --- settings + policy reads ---
    ("GET", "/api/settings/corpora", "list corpora"),
    ("GET", "/api/settings/formats", "list formats"),
    ("GET", "/api/detection-corpora", "corpus counts"),
    ("GET", "/api/relationship-policy", "read policy"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _real_job_id(client: TestClient) -> str | None:
    """Return a job id that actually exists, so 404-vs-500 is meaningful."""
    r = client.get("/api/jobs")
    if r.status_code != 200:
        return None
    body = r.json()
    items = body if isinstance(body, list) else body.get("jobs") or []
    for it in items:
        if isinstance(it, dict) and it.get("id"):
            return it["id"]
    return None


def run_probe(client: TestClient, method: str, url: str, description: str) -> dict:
    """Send a single probe request and return a result dict."""
    try:
        r = client.request(method, url)
        result: dict[str, Any] = {
            "url": url,
            "desc": description,
            "status": r.status_code,
            "error": "",
        }
        if r.status_code >= 500:
            result["body"] = r.text[:300]
        return result
    except Exception as e:
        return {
            "url": url,
            "desc": description,
            "status": None,
            "error": "".join(traceback.format_exception_only(type(e), e)).strip(),
        }


def classify(result: dict) -> str:
    """Classify a probe result into CRASH, SERVER, OK, CLIENT, or OTHER."""
    status = result.get("status")
    if status is None:
        return "CRASH"
    if status >= 500:
        return "SERVER"
    if 200 <= status < 300:
        return "OK"
    if 400 <= status < 500:
        return "CLIENT"
    return "OTHER"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    """Run all probes, print the table and summary, and return 0."""
    parser = argparse.ArgumentParser(description="Read-only API edge-case conformance harness.")
    parser.add_argument("--show", type=int, default=400,
                        help="Max characters of a body to print (default: 400).")
    args = parser.parse_args()

    client = TestClient(app, raise_server_exceptions=False)

    job_id = _real_job_id(client)
    print(f"Real job id: {job_id}")
    print()

    results: list[dict] = []
    for method, url_template, description in _PROBES:
        if "{job}" in url_template and job_id is None:
            print(f"  SKIPPED (no job id): {description}  {url_template}")
            continue
        url = url_template.replace("{job}", job_id) if job_id else url_template
        result = run_probe(client, method, url, description)
        results.append(result)

    # Print the table
    for result in results:
        verdict = classify(result)
        status_str = str(result["status"]) if result["status"] is not None else "raised"
        print(f"{verdict:7s} {status_str:>6s}  {result['desc']:38s} {result['url']}")

    # Summary
    counts = Counter(classify(r) for r in results)
    print()
    print("=== summary ===")
    print(f"probes run : {len(results)}")
    print(f"OK         : {counts.get('OK', 0)}")
    print(f"CLIENT 4xx : {counts.get('CLIENT', 0)}")
    print(f"SERVER 5xx : {counts.get('SERVER', 0)}     <-- defects")
    print(f"CRASH      : {counts.get('CRASH', 0)}     <-- defects")

    # Detail blocks for SERVER and CRASH
    defects = [r for r in results if classify(r) in ("SERVER", "CRASH")]
    if defects:
        print()
        for r in defects:
            print(f"--- {r['desc']} ---")
            print(r["url"])
            detail = r.get("error") or r.get("body", "")
            if detail:
                print(detail[:args.show])
            else:
                print("(no detail)")
    else:
        print()
        print("  (none)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
