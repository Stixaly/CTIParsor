"""The end-to-end journey with the real models on a running stack (ADR-0097 item 24).

    python scripts/check_model_journey.py --pdf PATH --url URL \\
        [--base-url http://127.0.0.1:8000] [--report-dir output/model-journey/<UTC time>] \\
        [--wait-s 2400] [--required-stages "2c 2e 3"]

Two journeys run one after the other, on the stack as it is configured (its
models, its LLM):

- pdf: the report is uploaded (POST /api/upload);
- url: the page is captured and ingested (POST /api/ingest/url).

Each job is waited for until it leaves uploaded, queued and processing (or
--wait-s passes). Then its checks read the job's record, its entities and its
bundle; the url journey also reads the captured source. Every check has a
name, a status (pass, fail or not_checked) and a detail:

- 0 job created: the POST answered 200, 201 or 202 with a job id;
- 1 job ended: the status is completed or for_review, not failed;
- 2 required stages ran: each stage of --required-stages is in the stage report
  as `ran`; Stage 3 also needs an egress record that allows the report and at
  least one provider call;
- 3 models ran: stages 2c and 2e are in the report and ran (a skip for any
  reason, the heavy models off included, fails);
- 4 document text: Stage 1 recorded a number of characters above zero;
- 5 extraction: the job has at least one entity, and at least one IoC or
  technique (entity types ipv4, ipv6, domain, url, email, md5, sha1, sha256,
  and ttp);
- 6 bundle exports: GET /api/jobs/{id}/bundle answers 200 with a STIX 2.1
  bundle that holds a report, and every relationship refers to objects in it;
- 7 captured source recorded (url only): the POST answered the final URL, and
  GET /api/jobs/{id}/source answers 200 with the archive.

Standard library only. The base URL must be on loopback, as the failure
recipe's is. A bearer token, when the stack has authentication, is read from
CTIPARSOR_TOKEN: it is sent and never written down. The reports (report.md,
report.json) hold no token and no URL query.

Exit 0 when every check of both journeys passed, 1 when one did not, 2 for a
usage error before any request (a bad URL, a missing or non-PDF file, a base
URL that is not on loopback, bad --required-stages), and 2 too when the stack
does not answer /api/health with 200 (nothing has been submitted then).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_REQUIRED = "2c 2e 3"
TOKEN_ENV = "CTIPARSOR_TOKEN"  # noqa: S105 - the name of the variable, not a secret
MODEL_STAGES = ("2c", "2e")
PENDING = frozenset({"uploaded", "queued", "processing"})
ENDED_OK = frozenset({"completed", "for_review"})
IOC_TYPES = frozenset({"ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256"})
TECHNIQUE_TYPE = "ttp"
JOB_ID = re.compile(r"[0-9a-f-]{36}")
STAGE_ID = re.compile(r"[0-9][0-9a-z]*")
NOT_REPORTED = "not reported"
PASS, FAIL, NOT_CHECKED = "pass", "fail", "not_checked"
CHECK_SUBMITTED = "0 job created"
CHECKS_AFTER_SUBMIT = ("1 job ended", "2 required stages ran", "3 models ran", "4 document text",
                       "5 extraction", "6 bundle exports")
CHECK_SOURCE = "7 captured source recorded"
SNIPPET = 200


class ApiError(Exception):
    """A request that got no answer (refused, timed out). The journey it belongs to fails."""


@dataclass
class Check:
    name: str
    status: str  # pass, fail or not_checked
    detail: str = ""


@dataclass
class Journey:
    name: str
    source: dict[str, Any]
    job_id: str | None = None
    checks: list[Check] = field(default_factory=list)
    stages: list[dict[str, Any]] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    marks: dict[str, float] = field(default_factory=dict)  # monotonic seconds
    times: dict[str, str] = field(default_factory=dict)    # UTC, as observed or as the server wrote them

    def mark(self, name: str, at: float) -> None:
        self.marks[name] = at
        self.times[name] = utc_now()

    @property
    def status(self) -> str:
        if any(c.status == FAIL for c in self.checks):
            return "failed"
        if self.checks and all(c.status == PASS for c in self.checks):
            return "passed"
        return "not_checked"

    def durations(self) -> dict[str, float | None]:
        posted, started, ended = self.marks.get("posted"), self.marks.get("started"), self.marks.get("ended")
        out: dict[str, float | None] = {"queued_observed_s": None, "run_observed_s": None,
                                        "total_observed_s": None}
        if posted is not None and started is not None:
            out["queued_observed_s"] = round(started - posted, 1)
        if started is not None and ended is not None:
            out["run_observed_s"] = round(ended - started, 1)
        if posted is not None and ended is not None:
            out["total_observed_s"] = round(ended - posted, 1)
        return out


class Api:
    """The HTTP side: one request function, the only place the token is put on the wire."""

    def __init__(self, base_url: str, token: str | None, *, timeout_s: float = 60.0,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_s = timeout_s
        self.clock = clock
        self.sleep = sleep

    def request(self, method: str, path: str, *, body: bytes | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
        sent = dict(headers or {})
        if self.token:
            sent["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.base_url + path, data=body, method=method, headers=sent)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:  # noqa: S310 - loopback only
                return response.status, response.read(), dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers.items())
        except (urllib.error.URLError, OSError) as exc:
            raise ApiError(f"{method} {path}: {exc}") from exc

    def json(self, method: str, path: str, *, body: bytes | None = None,
             headers: dict[str, str] | None = None) -> tuple[int, Any]:
        status, raw, _ = self.request(method, path, body=body, headers=headers)
        try:
            return status, (json.loads(raw) if raw else None)
        except ValueError:
            return status, None


# ── Small helpers ────────────────────────────────────────────────────────────


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def snippet(raw: bytes, limit: int = SNIPPET) -> str:
    return " ".join(raw.decode("utf-8", "replace").split())[:limit]


def header(headers: dict[str, str], name: str) -> str | None:
    return next((v for k, v in headers.items() if k.lower() == name.lower()), None)


def counts_of(record: dict[str, Any] | None) -> dict[str, Any]:
    value = (record or {}).get("counts")
    return value if isinstance(value, dict) else {}


def find_stage(stages: list[dict[str, Any]], stage_id: str) -> dict[str, Any] | None:
    return next((s for s in stages if str(s.get("stage")) == stage_id), None)


def reason_of(record: dict[str, Any]) -> str:
    return " ".join(str(record.get("reason") or "").split())


def redact_url(url: str) -> str:
    """Scheme, host, port and path. Credentials and the query are left out."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    shown = f"{parts.scheme}://{netloc}{parts.path}"
    return shown + (" (query omitted)" if parts.query else "")


def multipart(filename: str, data: bytes) -> tuple[bytes, str]:
    boundary = uuid4().hex
    safe = re.sub(r'["\r\n]', "_", filename)
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{safe}"\r\n'
            "Content-Type: application/pdf\r\n\r\n").encode("utf-8")
    return head + data + f"\r\n--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


def base_url_error(value: str) -> str | None:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return f"--base-url must be an http(s) URL, not {value!r}"
    if parts.hostname not in LOOPBACK_HOSTS:
        return f"--base-url must be on loopback, not {parts.hostname!r}"
    return None


def url_error(value: str) -> str | None:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return f"--url must be an http or https URL with a host, not {value!r}"
    if any(ch.isspace() for ch in value):
        return "--url must not contain spaces"
    return None


def pdf_error(path: Path) -> str | None:
    if not path.is_file():
        return f"no such file: {path}"
    head = path.read_bytes()[:5]
    if not head:
        return f"empty file: {path}"
    if head != b"%PDF-":
        return f"not a PDF (no %PDF- header): {path}"
    return None


# ── Server facts ─────────────────────────────────────────────────────────────


def server_facts(api: Api) -> dict[str, str]:
    """What the API reports about itself. A value no route gives is "not reported"."""
    facts = {"version": NOT_REPORTED, "commit": NOT_REPORTED, "llm_provider": NOT_REPORTED,
             "llm_host": NOT_REPORTED, "llm_model": NOT_REPORTED}
    status, spec = api.json("GET", "/openapi.json")
    if status == 200 and isinstance(spec, dict):
        version = (spec.get("info") or {}).get("version")
        if isinstance(version, str) and version:
            facts["version"] = version
    status, egress = api.json("GET", "/api/llm/egress?tlp=AMBER")
    if status == 200 and isinstance(egress, dict):
        found = egress.get("text")
        text: dict[str, Any] = found if isinstance(found, dict) else {}
        if text.get("provider"):
            facts["llm_provider"] = str(text["provider"])
        if text.get("host"):
            facts["llm_host"] = str(text["host"])
    return facts


# ── A journey ────────────────────────────────────────────────────────────────


def wait_for_job(api: Api, journey: Journey, job_id: str, wait_s: float) -> dict[str, Any] | None:
    """Poll the job with back-off until it leaves uploaded, queued and processing, or wait_s passes."""
    deadline = api.clock() + wait_s
    delay = 1.0
    last: dict[str, Any] | None = None
    while True:
        status, data = api.json("GET", f"/api/jobs/{job_id}")
        if status != 200 or not isinstance(data, dict):
            journey.facts["wait_error"] = f"GET /api/jobs/{job_id} answered {status}"
            return last
        last = data
        state = data.get("status")
        if state == "processing" and "started" not in journey.marks:
            journey.mark("started", api.clock())
        if state not in PENDING:
            journey.mark("ended", api.clock())
            return data
        now = api.clock()
        if now >= deadline:
            return last
        api.sleep(min(delay, deadline - now))
        delay = min(delay * 2, 30.0)


def run_journey(api: Api, journey: Journey, submit: Callable[[], tuple[int, Any, bytes]], *,
                wait_s: float, required: tuple[str, ...], url: bool) -> Journey:
    names = CHECKS_AFTER_SUBMIT + ((CHECK_SOURCE,) if url else ())
    journey.mark("posted", api.clock())
    try:
        status, data, raw = submit()
    except ApiError as exc:
        journey.checks.append(Check(CHECK_SUBMITTED, FAIL, str(exc)))
        journey.checks += [Check(n, NOT_CHECKED, "the job was not created") for n in names]
        return journey
    job_id = data.get("job_id") if isinstance(data, dict) else None
    if status not in (200, 201, 202) or not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
        journey.checks.append(Check(CHECK_SUBMITTED, FAIL, f"POST answered {status}: {snippet(raw)}"))
        journey.checks += [Check(n, NOT_CHECKED, "the job was not created") for n in names]
        return journey
    journey.job_id = job_id
    journey.facts["submitted"] = {k: data[k] for k in (
        "filename", "status", "source_url", "blocked_requests", "rendered_chars") if k in data}
    if isinstance(journey.facts["submitted"].get("source_url"), str):
        # The capture's final URL, as the report keeps it: no credentials, no query.
        journey.facts["submitted"]["source_url"] = redact_url(journey.facts["submitted"]["source_url"])
    journey.checks.append(Check(CHECK_SUBMITTED, PASS, f"job {job_id}, POST status {status}"))

    detail = wait_for_job(api, journey, job_id, wait_s)
    if detail is None or detail.get("status") in PENDING:
        state = None if detail is None else detail.get("status")
        why = (journey.facts.get("wait_error") or f"the job did not end within {wait_s:g} s (status {state})")
        journey.checks.append(Check(names[0], FAIL, str(why)))
        journey.checks += [Check(n, NOT_CHECKED, "the job did not end") for n in names[1:]]
        return journey

    journey.stages = [s for s in detail.get("stages") or [] if isinstance(s, dict)]
    journey.facts["job"] = {k: detail.get(k) for k in ("original_filename", "created_at", "updated_at",
                                                        "pipeline_mode", "tlp_level", "pap_level")}
    journey.checks.append(check_ended(detail))
    journey.checks.append(check_required(journey.stages, required))
    journey.checks.append(check_models(journey.stages))
    journey.checks.append(check_text(journey.stages))
    journey.checks.append(check_extraction(api, job_id))
    journey.checks.append(check_bundle(api, job_id, journey))
    if url:
        journey.checks.append(check_source(api, job_id, journey))
    return journey


def check_ended(detail: dict[str, Any]) -> Check:
    state = detail.get("status")
    if state in ENDED_OK:
        return Check(CHECKS_AFTER_SUBMIT[0], PASS, f"status {state}")
    return Check(CHECKS_AFTER_SUBMIT[0], FAIL, f"status {state}")


def check_required(stages: list[dict[str, Any]], required: tuple[str, ...]) -> Check:
    name = CHECKS_AFTER_SUBMIT[1]
    problems: list[str] = []
    seen: list[str] = []
    for stage_id in required:
        record = find_stage(stages, stage_id)
        if record is None:
            problems.append(f"stage {stage_id} is missing from the stage report")
            continue
        state = record.get("status")
        if state != "ran":
            reason = reason_of(record)
            problems.append(f"stage {stage_id} {state}" + (f": {reason}" if reason else ""))
            continue
        if stage_id == "3":
            egress = record.get("egress")
            if not isinstance(egress, dict):
                problems.append("stage 3 has no egress record")
            elif egress.get("allowed") is not True:
                problems.append(f"stage 3 refused by egress: {egress.get('reason') or 'no reason'}")
            calls = counts_of(record).get("provider_calls", 0)
            if not calls:
                problems.append("stage 3 ran but made no provider call")
            seen.append(f"3 ran with {calls} provider calls")
        else:
            seen.append(f"{stage_id} ran")
    if problems:
        return Check(name, FAIL, "; ".join(problems))
    return Check(name, PASS, "; ".join(seen) or "no stage required")


def check_models(stages: list[dict[str, Any]]) -> Check:
    name = CHECKS_AFTER_SUBMIT[2]
    problems: list[str] = []
    seen: list[str] = []
    for stage_id in MODEL_STAGES:
        record = find_stage(stages, stage_id)
        if record is None:
            problems.append(f"stage {stage_id} is missing from the stage report")
            continue
        state = record.get("status")
        if state != "ran":
            problems.append(f"stage {stage_id} {state}: {reason_of(record) or 'no reason recorded'}")
            continue
        counts = counts_of(record)
        found = counts.get("entities", counts.get("candidates"))
        seen.append(f"{stage_id} ran ({found if found is not None else 'no'} rows)")
    if problems:
        return Check(name, FAIL, "; ".join(problems))
    return Check(name, PASS, "; ".join(seen))


def check_text(stages: list[dict[str, Any]]) -> Check:
    name = CHECKS_AFTER_SUBMIT[3]
    record = find_stage(stages, "1")
    chars = counts_of(record).get("chars")
    if isinstance(chars, int) and chars > 0:
        chunks = counts_of(record).get("chunks")
        return Check(name, PASS, f"{chars} characters, {chunks} chunks (pages are not recorded)")
    return Check(name, FAIL, f"stage 1 records {chars!r} characters")


def check_extraction(api: Api, job_id: str) -> Check:
    name = CHECKS_AFTER_SUBMIT[4]
    status, rows = api.json("GET", f"/api/jobs/{job_id}/entities")
    if status != 200 or not isinstance(rows, list):
        return Check(name, FAIL, f"entities answered {status}")
    types = Counter(str(r.get("entity_type")) for r in rows if isinstance(r, dict))
    iocs = sum(types[t] for t in IOC_TYPES)
    techniques = types[TECHNIQUE_TYPE]
    detail = f"{len(rows)} entities, {iocs} IoC, {techniques} technique"
    if not rows:
        return Check(name, FAIL, detail + " (no entity at all)")
    if iocs + techniques == 0:
        return Check(name, FAIL, detail + " (no IoC and no technique)")
    return Check(name, PASS, detail)


def check_bundle(api: Api, job_id: str, journey: Journey) -> Check:
    name = CHECKS_AFTER_SUBMIT[5]
    status, raw, headers = api.request("GET", f"/api/jobs/{job_id}/bundle")
    if status != 200:
        return Check(name, FAIL, f"bundle answered {status}: {snippet(raw)}")
    try:
        bundle = json.loads(raw)
    except ValueError:
        return Check(name, FAIL, "the bundle is not JSON")
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        return Check(name, FAIL, "the body is not a STIX bundle (type is not bundle)")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        return Check(name, FAIL, "the bundle has no objects")
    dicts = [o for o in objects if isinstance(o, dict)]
    by_type = Counter(str(o.get("type")) for o in dicts)
    ids = {o["id"] for o in dicts if isinstance(o.get("id"), str)}
    relationships = [o for o in dicts if o.get("type") == "relationship"]
    dangling = [f"{rel.get('id')} {key}={rel.get(key)}" for rel in relationships for key in ("source_ref", "target_ref")
                if rel.get(key) not in ids]
    sha = hashlib.sha256(raw).hexdigest()
    journey.facts["bundle"] = {"sha256": sha, "bytes": len(raw), "objects": sorted_counts(by_type),
                               "relationships": len(relationships),
                               "validation": header(headers, "X-Bundle-Validation") or "not reported"}
    problems = []
    if by_type["report"] < 1:
        problems.append("the bundle has no report object")
    if dangling:
        problems.append(f"{len(dangling)} relationship(s) refer to objects not in the bundle, "
                        f"first {dangling[0]}")
    if problems:
        return Check(name, FAIL, "; ".join(problems))
    return Check(name, PASS, f"{len(objects)} objects, {len(relationships)} relationships, sha256 {sha[:16]}...")


def sorted_counts(counter: Counter) -> dict[str, int]:
    return {k: counter[k] for k in sorted(counter)}


def check_source(api: Api, job_id: str, journey: Journey) -> Check:
    name = CHECK_SOURCE
    submitted = journey.facts.get("submitted", {})
    final = submitted.get("source_url")
    if not isinstance(final, str) or not final:
        return Check(name, FAIL, "the POST answered no source_url")
    status, raw, headers = api.request("GET", f"/api/jobs/{job_id}/source")
    title = (journey.facts.get("job") or {}).get("original_filename")
    blocked = submitted.get("blocked_requests")
    rendered = submitted.get("rendered_chars")
    detail = (f"captured {final}; title or filename {title!r}; blocked_requests {blocked}, "
              f"rendered_chars {rendered}; archive answered {status}, {len(raw)} bytes")
    if status != 200:
        return Check(name, FAIL, detail)
    return Check(name, PASS, detail)


# ── Reports ──────────────────────────────────────────────────────────────────


def _cell(text: Any) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def redact(text: str, token: str | None) -> str:
    return text.replace(token, "[redacted]") if token else text


def journey_payload(journey: Journey) -> dict[str, Any]:
    return {
        "name": journey.name,
        "status": journey.status,
        "source": journey.source,
        "job_id": journey.job_id,
        "times": journey.times,
        "durations": journey.durations(),
        "stages": [{"stage": s.get("stage"), "status": s.get("status"), "seconds": s.get("seconds"),
                    "reason": reason_of(s)} for s in journey.stages],
        "checks": [{"name": c.name, "status": c.status, "detail": c.detail} for c in journey.checks],
        "facts": journey.facts,
    }


def render_markdown(meta: dict[str, Any], journeys: list[Journey]) -> str:
    server = meta["server"]
    lines = [
        f"# Model journey, run {meta['started_at']}",
        "",
        f"Base URL: `{meta['base_url']}`. Result: **{'passed' if meta['exit_code'] == 0 else 'not passed'}** "
        f"(exit {meta['exit_code']}). Required stages: {', '.join(meta['required_stages'])}.",
        "",
        "## Server",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| API version | {_cell(server['version'])} |",
        f"| Commit | {_cell(server['commit'])} |",
        f"| LLM provider | {_cell(server['llm_provider'])} |",
        f"| LLM host | {_cell(server['llm_host'])} |",
        f"| LLM model | {_cell(server['llm_model'])} |",
    ]
    for journey in journeys:
        shown_input = ", ".join(f"{k} {v}" for k, v in journey.source.items())
        lines += ["", f"## {journey.name}: {journey.status}", "", f"Input: {_cell(shown_input)}.", ""]
        lines += [f"Job: `{journey.job_id}`." if journey.job_id else "Job: none was created.", ""]
        lines += ["| Check | Status | Detail |", "|---|---|---|"]
        lines += [f"| {_cell(c.name)} | {c.status} | {_cell(c.detail)} |" for c in journey.checks]
        durations = journey.durations()
        lines += ["", "Times (UTC; observed by this script at its polls, or written by the server):", "",
                  "| Mark | Time |", "|---|---|"]
        lines += [f"| {_cell(k)} | {_cell(v)} |" for k, v in journey.times.items()]
        lines += ["", "Durations (s): " + ", ".join(
            f"{k} {v if v is not None else 'not observed'}" for k, v in durations.items()), ""]
        lines += ["| Stage | Status | Seconds |", "|---|---|---|"]
        lines += [f"| {_cell(s.get('stage'))} | {_cell(s.get('status'))} | {_cell(s.get('seconds', 'not recorded'))} |"
                  for s in journey.stages]
        bundle = journey.facts.get("bundle")
        if bundle:
            lines += ["", f"Bundle: sha256 `{bundle['sha256']}`, {bundle['bytes']} bytes, validation "
                          f"{_cell(bundle['validation'])}. Objects by type: "
                          + ", ".join(f"{k} {v}" for k, v in bundle["objects"].items()) + "."]
    lines.append("")
    return "\n".join(lines)


def write_reports(out_dir: Path, meta: dict[str, Any], journeys: list[Journey], token: str | None) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {**meta, "journeys": [journey_payload(j) for j in journeys]}
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    json_path.write_text(redact(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", token), encoding="utf-8")
    md_path.write_text(redact(render_markdown(meta, journeys), token), encoding="utf-8")
    return md_path, json_path


# ── Command line ─────────────────────────────────────────────────────────────


def _positive(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be above zero")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python scripts/check_model_journey.py",
                                     description="The end-to-end journey with the real models (ADR-0097 item 24).")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL,
                        help="the API of the running stack, on loopback (default: %(default)s)")
    parser.add_argument("--pdf", type=Path, required=True, help="the report to upload as a PDF")
    parser.add_argument("--url", required=True, help="the page to capture and ingest")
    parser.add_argument("--report-dir", type=Path, default=None,
                        help="where report.md and report.json go (default: output/model-journey/<UTC time>)")
    parser.add_argument("--wait-s", type=_positive, default=2400.0,
                        help="how long each job may take to end (default: %(default)s)")
    parser.add_argument("--required-stages", default=DEFAULT_REQUIRED,
                        help='stages that must have run, space-separated (default: "%(default)s")')
    return parser


def _usage(message: str) -> int:
    print(f"check_model_journey: {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    # Arguments are checked before any request is sent: the URLs, the stage ids and a
    # non-empty PDF. A bad argument returns the usage code without contacting the server.
    parser = build_parser()
    args = parser.parse_args(argv)
    error = base_url_error(args.base_url) or url_error(args.url) or pdf_error(args.pdf)
    if error:
        return _usage(error)
    required = tuple(args.required_stages.split())
    if not required or not all(STAGE_ID.fullmatch(s) for s in required):
        return _usage(f"--required-stages must be stage ids such as \"2c 2e 3\", not {args.required_stages!r}")
    pdf_bytes = args.pdf.read_bytes()
    if not pdf_bytes:
        return _usage(f"empty file: {args.pdf}")

    # The server must answer /api/health with 200 before the journeys start. Exit code 2
    # covers an unreachable server or a non-200 answer; the server facts are read after.
    token = os.environ.get(TOKEN_ENV) or None  # sent as a bearer, never printed or written
    api = Api(args.base_url, token)
    started = datetime.now(timezone.utc)
    try:
        status, _ = api.json("GET", "/api/health")
    except ApiError as exc:
        print(f"check_model_journey: {exc}", file=sys.stderr)
        return 2
    if status != 200:
        print(f"check_model_journey: {args.base_url}/api/health answers {status}, not 200; start the stack first",
              file=sys.stderr)
        return 2
    server = server_facts(api)

    # Two journeys run in turn: a PDF upload and a URL ingest. Each submit closure sends one
    # request. A request error is recorded as a failed check on its journey, not raised, so
    # the other journey still runs.
    journeys: list[Journey] = []
    pdf_journey = Journey("pdf", {"file": args.pdf.name, "sha256": hashlib.sha256(pdf_bytes).hexdigest(),
                                  "bytes": len(pdf_bytes)})
    body, content_type = multipart(args.pdf.name, pdf_bytes)

    def submit_pdf() -> tuple[int, Any, bytes]:
        status, raw, _ = api.request("POST", "/api/upload", body=body, headers={"Content-Type": content_type})
        try:
            data: Any = json.loads(raw)
        except ValueError:
            data = None
        return status, data, raw

    url_journey = Journey("url", {"url": redact_url(args.url)})
    url_body = json.dumps({"url": args.url}).encode("utf-8")

    def submit_url() -> tuple[int, Any, bytes]:
        status, raw, _ = api.request("POST", "/api/ingest/url", body=url_body,
                                     headers={"Content-Type": "application/json"})
        try:
            data: Any = json.loads(raw)
        except ValueError:
            data = None
        return status, data, raw

    for journey, submit, url in ((pdf_journey, submit_pdf, False), (url_journey, submit_url, True)):
        try:
            journeys.append(run_journey(api, journey, submit, wait_s=args.wait_s, required=required, url=url))
        except ApiError as exc:
            journey.checks.append(Check("request failed", FAIL, str(exc)))
            journeys.append(journey)

    # Exit 0 only when every journey passed (and at least one ran). The report goes to
    # --report-dir, or to a timestamped directory under output/model-journey.
    exit_code = 0 if journeys and all(j.status == "passed" for j in journeys) else 1
    out_dir = args.report_dir or ROOT / "output" / "model-journey" / started.strftime("%Y%m%dT%H%M%SZ")
    meta = {
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": utc_now(),
        "base_url": args.base_url,
        "server": server,
        "required_stages": list(required),
        "wait_s": args.wait_s,
        "exit_code": exit_code,
    }
    md_path, json_path = write_reports(out_dir, meta, journeys, token)
    print(f"report: {md_path}\n        {json_path}")
    failed = [j.name for j in journeys if j.status != "passed"]
    print("PASSED" if exit_code == 0 else f"NOT PASSED: {', '.join(failed) or 'no journey ran'}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
