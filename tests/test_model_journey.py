"""scripts/check_model_journey.py: the end-to-end journey with the real models (ADR-0097 item 24).

No Docker, no network beyond loopback: the stack is a fake HTTP server on
127.0.0.1 (http.server in a thread). Its answers have the shapes of the real
routes: POST /api/upload and /api/ingest/url (api/routes/upload.py,
ingest.py), GET /api/jobs/{id} (api/routes/jobs.py: `stages` from the stage
report), /entities (api/routes/entities.py), /bundle and /source, and
GET /api/llm/egress (api/routes/llm.py).
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from scripts import check_model_journey as cmj

JSON = "application/json"
PDF_JOB = "11111111-1111-1111-1111-111111111111"
URL_JOB = "22222222-2222-2222-2222-222222222222"
URL = "https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/"
FINAL_URL = "https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/?utm=1"
TOKEN = "ctp_TESTTOKEN_0123456789abcdef"


class FakeStack:
    """Canned answers by (method, path); job details by id, one per poll (the last repeats)."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], tuple[int, Any, str]] = {}
        self.job_states: dict[str, list[dict[str, Any]]] = {}
        self.seen: list[tuple[str, str, str | None]] = []
        self.base_url = ""

    def answer(self, method: str, path: str) -> tuple[int, bytes, str]:
        if method == "GET" and path.startswith("/api/jobs/") and path.count("/") == 3:
            states = self.job_states.get(path.rsplit("/", 1)[1])
            if states:
                detail = states.pop(0) if len(states) > 1 else states[0]
                return 200, json.dumps(detail).encode(), JSON
        route = self.routes.get((method, path))
        if route is None:
            return 404, b'{"detail":"Not Found"}', JSON
        status, payload, ctype = route
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        return status, body, ctype


class _Handler(BaseHTTPRequestHandler):
    server: Any

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - the base class's name
        return

    def _serve(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        stack: FakeStack = self.server.stack
        stack.seen.append((method, self.path, self.headers.get("Authorization")))
        status, body, ctype = stack.answer(method, urlsplit(self.path).path)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - the base class's name
        self._serve("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._serve("POST")


@pytest.fixture
def stack():
    fake = FakeStack()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.stack = fake  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fake.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()


# ── The canned stack: a run that passes ─────────────────────────────────────


def good_stages() -> list[dict[str, Any]]:
    return [
        {"stage": "1", "status": "ran", "reason": "", "seconds": 0.4, "counts": {"chars": 12345, "chunks": 6}},
        {"stage": "2", "status": "ran", "reason": "", "seconds": 0.1, "counts": {"entities": 30}},
        {"stage": "2c", "status": "ran", "reason": "", "seconds": 3.2, "counts": {"candidates": 12}},
        {"stage": "2d", "status": "ran", "reason": "", "seconds": 5.0, "counts": {"entities": 9}},
        {"stage": "2e", "status": "ran", "reason": "", "seconds": 4.1, "counts": {"entities": 4}},
        {"stage": "3", "status": "ran", "reason": "", "seconds": 120.0,
         "counts": {"provider_calls": 14, "extraction_ok": 14},
         "egress": {"tlp": "AMBER", "provider": "vllm", "host": "192.168.0.29:8000", "local": False,
                    "allowed": True}},
        {"stage": "4", "status": "ran", "reason": "", "seconds": 1.0, "counts": {"objects": 40, "iocs": 10}},
        {"stage": "5", "status": "ran", "reason": "", "seconds": 0.2, "counts": {"valid": 1}},
    ]


def replace_stage(stages: list[dict[str, Any]], stage_id: str, **fields: Any) -> list[dict[str, Any]]:
    out = []
    for record in stages:
        if record["stage"] == stage_id:
            record = {**record, **fields}
        out.append(record)
    return out


def job_detail(job_id: str, status: str = "for_review", stages: list[dict[str, Any]] | None = None) -> dict:
    return {
        "id": job_id, "original_filename": "industroyer2.pdf", "status": status, "report_text": None,
        "tlp_level": "AMBER", "pap_level": None, "created_at": "2026-11-09T10:00:00+00:00",
        "updated_at": "2026-11-09T10:04:00+00:00", "pipeline_mode": "full", "entity_count": 3,
        "relationship_count": 1, "stages": good_stages() if stages is None else stages,
    }


ENTITIES = [
    {"id": "e1", "job_id": PDF_JOB, "entity_type": "ipv4", "value": "203.0.113.7"},
    {"id": "e2", "job_id": PDF_JOB, "entity_type": "ttp", "value": "T1059"},
    {"id": "e3", "job_id": PDF_JOB, "entity_type": "malware", "value": "Industroyer2"},
]
BUNDLE = {"type": "bundle", "id": "bundle--aaa", "objects": [
    {"type": "report", "spec_version": "2.1", "id": "report--1"},
    {"type": "malware", "spec_version": "2.1", "id": "malware--1"},
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--1"},
    {"type": "relationship", "spec_version": "2.1", "id": "relationship--1",
     "source_ref": "malware--1", "target_ref": "indicator--1"},
]}
EGRESS = {"tlp": "AMBER", "figures": None, "text": {
    "tlp": "AMBER", "provider": "vllm", "host": "192.168.0.29:8000", "local": False, "allowed": True, "reason": ""}}


def wire_happy(stack: FakeStack) -> None:
    stack.routes[("GET", "/api/health")] = (200, {"status": "ok"}, JSON)
    stack.routes[("GET", "/openapi.json")] = (200, {"info": {"version": "0.6.0"}}, JSON)
    stack.routes[("GET", "/api/llm/egress")] = (200, EGRESS, JSON)
    stack.routes[("POST", "/api/upload")] = (200, {"job_id": PDF_JOB, "filename": "industroyer2.pdf",
                                                   "status": "queued"}, JSON)
    stack.routes[("POST", "/api/ingest/url")] = (200, {
        "job_id": URL_JOB, "filename": "industroyer2.pdf", "status": "processing", "source_url": FINAL_URL,
        "blocked_requests": 2, "rendered_chars": 8000}, JSON)
    for job in (PDF_JOB, URL_JOB):
        stack.job_states[job] = [job_detail(job)]
        stack.routes[("GET", f"/api/jobs/{job}/entities")] = (200, ENTITIES, JSON)
        stack.routes[("GET", f"/api/jobs/{job}/bundle")] = (200, BUNDLE, JSON)
    stack.routes[("GET", f"/api/jobs/{URL_JOB}/source")] = (200, b"%PDF-1.4 archive", "application/pdf")


@pytest.fixture
def sample_pdf(tmp_path: Path) -> Path:
    path = tmp_path / "industroyer2.pdf"
    path.write_bytes(b"%PDF-1.4\n% a fixture, not a real report\n%%EOF\n")
    return path


def run(stack: FakeStack, pdf: Path, tmp_path: Path, *extra: str, base_url: str | None = None,
        url: str = URL) -> tuple[int, Path]:
    report_dir = tmp_path / "report"
    args = ["--base-url", base_url or stack.base_url, "--pdf", str(pdf), "--url", url,
            "--report-dir", str(report_dir), "--wait-s", "5", *extra]
    return cmj.main(args), report_dir


def load(report_dir: Path) -> dict[str, Any]:
    return json.loads((report_dir / "report.json").read_text(encoding="utf-8"))


def checks_of(report: dict[str, Any], journey: str) -> dict[str, dict[str, str]]:
    found = next(j for j in report["journeys"] if j["name"] == journey)
    return {c["name"]: c for c in found["checks"]}


# ── Passing and failing runs ────────────────────────────────────────────────


def test_all_checks_of_both_journeys_pass_and_the_exit_is_zero(stack, sample_pdf, tmp_path, monkeypatch):
    wire_happy(stack)
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 0
    report = load(report_dir)
    assert report["exit_code"] == 0
    assert [j["status"] for j in report["journeys"]] == ["passed", "passed"]
    for journey in ("pdf", "url"):
        assert all(c["status"] == "pass" for c in checks_of(report, journey).values())
    assert "7 captured source recorded" in checks_of(report, "url")
    assert "7 captured source recorded" not in checks_of(report, "pdf")
    bundle = next(j for j in report["journeys"] if j["name"] == "pdf")["facts"]["bundle"]
    assert bundle["objects"] == {"indicator": 1, "malware": 1, "relationship": 1, "report": 1}
    assert len(bundle["sha256"]) == 64


def test_the_server_facts_are_recorded_and_missing_ones_say_not_reported(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    _, report_dir = run(stack, sample_pdf, tmp_path)
    server = load(report_dir)["server"]
    assert server["version"] == "0.6.0"
    assert server["llm_provider"] == "vllm"
    assert server["llm_host"] == "192.168.0.29:8000"
    assert server["commit"] == cmj.NOT_REPORTED
    assert server["llm_model"] == cmj.NOT_REPORTED


def test_a_failed_job_fails_check_one(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    stack.job_states[PDF_JOB] = [job_detail(PDF_JOB, status="failed")]
    stack.routes[("GET", f"/api/jobs/{PDF_JOB}/bundle")] = (404, {"detail": "Bundle not yet available"}, JSON)
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 1
    pdf = checks_of(load(report_dir), "pdf")
    assert pdf["1 job ended"]["status"] == "fail"
    assert "failed" in pdf["1 job ended"]["detail"]
    assert pdf["6 bundle exports"]["status"] == "fail"


def test_a_job_that_never_ends_fails_check_one_and_leaves_the_rest_not_checked(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    stack.job_states[PDF_JOB] = [job_detail(PDF_JOB, status="queued")]
    code, report_dir = run(stack, sample_pdf, tmp_path, "--wait-s", "0.3")
    assert code == 1
    pdf = checks_of(load(report_dir), "pdf")
    assert pdf["1 job ended"]["status"] == "fail"
    assert "did not end" in pdf["1 job ended"]["detail"]
    assert pdf["2 required stages ran"]["status"] == "not_checked"
    assert checks_of(load(report_dir), "url")["1 job ended"]["status"] == "pass"


@pytest.mark.parametrize("skipped, reason", [
    ({"status": "skipped", "reason": "LLM provider not ready (vllm)"}, "LLM provider not ready"),
    ({"status": "skipped", "reason": "text may not go to vllm at tlp RED"}, "text may not go"),
])
def test_stage_three_skipped_or_refused_by_egress_fails_check_two(stack, sample_pdf, tmp_path, skipped, reason):
    wire_happy(stack)
    stages = replace_stage(good_stages(), "3", **skipped)
    stack.job_states[PDF_JOB] = [job_detail(PDF_JOB, stages=stages)]
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 1
    check = checks_of(load(report_dir), "pdf")["2 required stages ran"]
    assert check["status"] == "fail"
    assert "stage 3 skipped" in check["detail"] and reason in check["detail"]


def test_stage_three_allowed_by_egress_but_without_a_provider_call_fails(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    stages = replace_stage(good_stages(), "3", counts={"provider_calls": 0})
    stack.job_states[URL_JOB] = [job_detail(URL_JOB, stages=stages)]
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 1
    assert "made no provider call" in checks_of(load(report_dir), "url")["2 required stages ran"]["detail"]


def test_a_model_skipped_for_heavy_models_fails_check_three(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    stages = replace_stage(good_stages(), "2e", status="skipped", reason="model or index unavailable")
    stack.job_states[PDF_JOB] = [job_detail(PDF_JOB, stages=stages)]
    code, report_dir = run(stack, sample_pdf, tmp_path, "--required-stages", "3")
    assert code == 1
    check = checks_of(load(report_dir), "pdf")["3 models ran"]
    assert check["status"] == "fail"
    assert "stage 2e skipped: model or index unavailable" in check["detail"]
    assert checks_of(load(report_dir), "pdf")["2 required stages ran"]["status"] == "pass"


def test_a_relationship_to_a_missing_object_fails_check_six(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    broken = json.loads(json.dumps(BUNDLE))
    broken["objects"][3]["target_ref"] = "indicator--404"
    stack.routes[("GET", f"/api/jobs/{PDF_JOB}/bundle")] = (200, broken, JSON)
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 1
    check = checks_of(load(report_dir), "pdf")["6 bundle exports"]
    assert check["status"] == "fail"
    assert "relationship--1 target_ref=indicator--404" in check["detail"]


def test_a_bundle_that_is_not_stix_fails_check_six(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    stack.routes[("GET", f"/api/jobs/{URL_JOB}/bundle")] = (200, {"type": "report", "objects": []}, JSON)
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 1
    assert checks_of(load(report_dir), "url")["6 bundle exports"]["status"] == "fail"


def test_an_empty_text_fails_check_four(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    stages = replace_stage(good_stages(), "1", counts={"chars": 0, "chunks": 0})
    stack.job_states[PDF_JOB] = [job_detail(PDF_JOB, stages=stages)]
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 1
    assert checks_of(load(report_dir), "pdf")["4 document text"]["status"] == "fail"


def test_no_entity_fails_check_five(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    stack.routes[("GET", f"/api/jobs/{PDF_JOB}/entities")] = (200, [], JSON)
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 1
    assert "no entity at all" in checks_of(load(report_dir), "pdf")["5 extraction"]["detail"]


def test_a_missing_captured_archive_fails_check_seven(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    stack.routes.pop(("GET", f"/api/jobs/{URL_JOB}/source"))
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 1
    detail = checks_of(load(report_dir), "url")[cmj.CHECK_SOURCE]
    assert detail["status"] == "fail"
    assert "archive answered 404" in detail["detail"]


def test_a_refused_upload_fails_the_submission_and_nothing_else_runs(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    stack.routes[("POST", "/api/upload")] = (413, {"detail": "File too large"}, JSON)
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 1
    pdf = checks_of(load(report_dir), "pdf")
    assert pdf["0 job created"]["status"] == "fail"
    assert pdf["1 job ended"]["status"] == "not_checked"
    assert not any(method == "GET" and path.startswith(f"/api/jobs/{PDF_JOB}") for method, path, _ in stack.seen)


# ── Usage errors: exit 2 before any request ─────────────────────────────────


def test_a_base_url_off_loopback_exits_two_before_any_request(sample_pdf, tmp_path, monkeypatch):
    def no_request(*args, **kwargs):
        raise AssertionError("a request was made")

    monkeypatch.setattr(cmj.urllib.request, "urlopen", no_request)
    code = cmj.main(["--base-url", "http://192.168.0.5:8000", "--pdf", str(sample_pdf), "--url", URL,
                     "--report-dir", str(tmp_path / "r")])
    assert code == 2
    assert not (tmp_path / "r").exists()


@pytest.mark.parametrize("bad_url", ["ftp://www.example.org/report", "not a url", "https://"])
def test_a_bad_url_exits_two_before_any_request(stack, sample_pdf, tmp_path, bad_url):
    wire_happy(stack)
    code, _ = run(stack, sample_pdf, tmp_path, url=bad_url)
    assert code == 2
    assert stack.seen == []


def test_a_missing_pdf_and_a_non_pdf_exit_two_before_any_request(stack, tmp_path):
    wire_happy(stack)
    assert run(stack, tmp_path / "absent.pdf", tmp_path)[0] == 2
    text = tmp_path / "report.pdf"
    text.write_text("plain text, not a PDF", encoding="utf-8")
    assert run(stack, text, tmp_path)[0] == 2
    assert stack.seen == []


def test_a_stack_that_does_not_answer_health_exits_two(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    stack.routes[("GET", "/api/health")] = (503, {"status": "degraded"}, JSON)
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 2
    assert not report_dir.exists()
    assert ("POST", "/api/upload", None) not in stack.seen


# ── The token ────────────────────────────────────────────────────────────────


def test_the_token_is_sent_as_a_bearer_and_never_written(stack, sample_pdf, tmp_path, monkeypatch):
    wire_happy(stack)
    monkeypatch.setenv(cmj.TOKEN_ENV, TOKEN)
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 0
    assert stack.seen and all(auth == f"Bearer {TOKEN}" for _, _, auth in stack.seen)
    for name in ("report.md", "report.json"):
        assert TOKEN not in (report_dir / name).read_text(encoding="utf-8")


def test_a_token_echoed_by_the_server_is_redacted_in_the_report(stack, sample_pdf, tmp_path, monkeypatch):
    wire_happy(stack)
    monkeypatch.setenv(cmj.TOKEN_ENV, TOKEN)
    stack.routes[("POST", "/api/upload")] = (500, {"detail": f"rejected token {TOKEN}"}, JSON)
    code, report_dir = run(stack, sample_pdf, tmp_path)
    assert code == 1
    for name in ("report.md", "report.json"):
        text = (report_dir / name).read_text(encoding="utf-8")
        assert TOKEN not in text
        assert "[redacted]" in text


def test_the_url_query_is_left_out_of_the_report(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    url = "https://user:secret@www.example.org/report?session=abc123"
    _, report_dir = run(stack, sample_pdf, tmp_path, url=url)
    text = (report_dir / "report.json").read_text(encoding="utf-8")
    assert "session=abc123" not in text
    assert "utm=1" not in text  # the capture's final URL, from the fake, has a query too
    assert "secret" not in text
    assert "https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/ (query omitted)" in text


# ── The reports ──────────────────────────────────────────────────────────────


def test_the_reports_hold_the_table_per_journey_and_the_stage_durations(stack, sample_pdf, tmp_path):
    wire_happy(stack)
    _, report_dir = run(stack, sample_pdf, tmp_path)
    markdown = (report_dir / "report.md").read_text(encoding="utf-8")
    assert "## pdf: passed" in markdown and "## url: passed" in markdown
    assert "| Check | Status | Detail |" in markdown
    assert "| 3 | ran | 120.0 |" in markdown
    journey = next(j for j in load(report_dir)["journeys"] if j["name"] == "pdf")
    assert {s["stage"]: s["seconds"] for s in journey["stages"]}["3"] == 120.0
    assert journey["times"]["posted"]
