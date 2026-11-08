"""scripts/check_failure_recipe.py: the load and failure recipe (ADR-0097 item 23).

No Docker, no network: the stack is a fake. Its commands and its HTTP answers
come from `World`, a small model of the parts the cases read (jobs, the
database, /metrics, the upload gate). The rules come from the real rules
file, and the command blocks are compared with those of docs/docker.md.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from pathlib import Path
from typing import Any

import pytest

from scripts import check_failure_recipe as cfr

ROOT = Path(__file__).resolve().parent.parent
GIB = 1024 ** 3
MIB = 1024 ** 2
ALL_ALERTS = {
    "CtiparsorNoLiveWorker", "CtiparsorQueueWaitTooLong", "CtiparsorFailedJobsRising", "CtiparsorDatabaseDown",
    "CtiparsorDiskNearlyFull", "CtiparsorBackupTooOld", "CtiparsorBackupLastAttemptFailed",
}


def _rule(name: str) -> cfr.Rule:
    return next(r for r in cfr.load_rules() if r.name == name)


def _evaluate(name: str, series: cfr.Series, now: float = 1_000_000.0) -> str:
    return cfr.evaluate_rule(_rule(name), series, now).state


# ── The rules file ───────────────────────────────────────────────────────────


def test_the_real_rules_file_has_its_seven_alerts_with_their_for_durations():
    rules = {r.name: r for r in cfr.load_rules()}
    assert set(rules) == ALL_ALERTS
    assert rules["CtiparsorDatabaseDown"].for_seconds == 60
    assert rules["CtiparsorDiskNearlyFull"].for_seconds == 600
    assert rules["CtiparsorBackupTooOld"].for_seconds is None
    assert rules["CtiparsorDatabaseDown"].expr == "ctiparsor_database_up == 0"


def test_every_runbook_anchor_names_a_heading_of_the_operations_doc():
    text = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
    slugs = {re.sub(r"[^a-z0-9 -]", "", h.lower()).strip().replace(" ", "-")
             for h in re.findall(r"^#{2,3} (.+)$", text, re.MULTILINE)}
    for rule in cfr.load_rules():
        assert rule.runbook.split("#", 1)[1] in slugs, rule.name


def test_a_rule_without_an_expression_or_with_a_bad_for_is_an_error(tmp_path):
    no_expr = tmp_path / "a.yml"
    no_expr.write_text("groups:\n  - name: g\n    rules:\n      - alert: X\n        for: 5m\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no expr"):
        cfr.load_rules(no_expr)
    bad_for = tmp_path / "b.yml"
    bad_for.write_text("groups:\n  - name: g\n    rules:\n      - alert: X\n        expr: up == 0\n"
                       "        for: five\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unreadable for"):
        cfr.load_rules(bad_for)


# ── The evaluator, on each form of the real rules ────────────────────────────


@pytest.mark.parametrize("series, expected", [
    ({"ctiparsor_database_up": [({}, 0.0)]}, "true"),
    ({"ctiparsor_database_up": [({}, 1.0)]}, "false"),
    ({}, "false"),
])
def test_database_down_is_a_metric_compared_with_a_number(series, expected):
    assert _evaluate("CtiparsorDatabaseDown", series) == expected


@pytest.mark.parametrize("workers, expected", [
    ([({"state": "busy"}, 0), ({"state": "idle"}, 0), ({"state": "stale"}, 2)], "true"),
    ([({"state": "idle"}, 1)], "false"),
    ([({"state": "busy"}, 1)], "false"),
    ([], "false"),
])
def test_no_live_worker_sums_a_label_selector(workers, expected):
    assert _evaluate("CtiparsorNoLiveWorker", {"ctiparsor_workers": workers}) == expected


@pytest.mark.parametrize("age, expected", [(1800.0, "false"), (1801.0, "true")])
def test_queue_wait_is_a_plain_comparison(age, expected):
    assert _evaluate("CtiparsorQueueWaitTooLong", {"ctiparsor_oldest_queued_job_age_seconds": [({}, age)]}) == expected


def test_failed_jobs_rising_is_not_checked_because_it_needs_a_range():
    reading = cfr.evaluate_rule(_rule("CtiparsorFailedJobsRising"), {"ctiparsor_failed_jobs": [({}, 9.0)]}, 0.0)
    assert reading.state == "not_checked"
    assert "range" in reading.detail


@pytest.mark.parametrize("free, total, expected", [
    (1 * GIB, 500 * GIB, "true"),    # under 2 GiB, though 0.2 %
    (5 * GIB, 40 * GIB, "false"),    # 12.5 %, and more than 2 GiB
    (3 * GIB, 20 * GIB, "false"),    # 15 %
    (9 * GIB, 100 * GIB, "true"),    # 9 %, under 10 %
])
def test_disk_nearly_full_is_a_division_or_an_absolute_threshold(free, total, expected):
    series: cfr.Series = {"ctiparsor_state_dir_free_bytes": [({}, float(free))],
              "ctiparsor_state_dir_total_bytes": [({}, float(total))]}
    assert _evaluate("CtiparsorDiskNearlyFull", series) == expected


def test_disk_nearly_full_without_its_metrics_is_false_not_passed():
    assert _evaluate("CtiparsorDiskNearlyFull", {}) == "false"


def test_backup_too_old_is_a_time_difference_or_an_absent_metric():
    now = 1_000_000.0
    assert _evaluate("CtiparsorBackupTooOld", {}, now) == "true"
    old: cfr.Series = {"ctiparsor_backup_last_success_timestamp_seconds": [({}, now - 93601)]}
    assert _evaluate("CtiparsorBackupTooOld", old, now) == "true"
    edge: cfr.Series = {"ctiparsor_backup_last_success_timestamp_seconds": [({}, now - 93600)]}
    assert _evaluate("CtiparsorBackupTooOld", edge, now) == "false"
    fresh: cfr.Series = {"ctiparsor_backup_last_success_timestamp_seconds": [({}, now - 1000)]}
    assert _evaluate("CtiparsorBackupTooOld", fresh, now) == "false"


@pytest.mark.parametrize("value, expected", [(0.0, "true"), (1.0, "false")])
def test_backup_last_attempt_failed_is_a_comparison(value, expected):
    series: cfr.Series = {"ctiparsor_backup_last_attempt_ok": [({}, value)]}
    assert _evaluate("CtiparsorBackupLastAttemptFailed", series) == expected


@pytest.mark.parametrize("expr", ["foo(x) > 1", "up >", "rate(up[5m]) > 0", "up{job=~\"x\"} > 1 ~"])
def test_a_form_the_evaluator_does_not_read_is_not_checked(expr):
    rule = cfr.Rule("X", expr, None, "warning", "")
    assert cfr.evaluate_rule(rule, {"up": [({}, 1.0)]}, 0.0).state == "not_checked"


def test_the_metrics_text_is_read_with_its_escapes_and_special_values():
    text = (
        "# HELP x help\n# TYPE x gauge\n"
        'x{path="a\\"b",note="c\\\\d"} +Inf\n'
        "y NaN\n"
        "z 3\n"
    )
    series = cfr.parse_metrics(text)
    assert series["x"] == [({"path": 'a"b', "note": "c\\d"}, float("inf"))]
    assert series["y"][0][0] == {}
    assert series["z"] == [({}, 3.0)]


# ── Reports, outcomes and the override file ─────────────────────────────────


def test_a_case_settles_to_error_failed_not_checked_or_passed():
    report = cfr.CaseReport("c")
    report.settle()
    assert report.status == "error"
    report = cfr.CaseReport("c", checks=[cfr.Check("a", "pass")])
    report.settle()
    assert report.status == "passed"
    report = cfr.CaseReport("c", checks=[cfr.Check("a", "pass"), cfr.Check("b", "not_checked")])
    report.settle()
    assert report.status == "not_checked"
    report = cfr.CaseReport("c", checks=[cfr.Check("a", "fail"), cfr.Check("b", "not_checked")])
    report.settle()
    assert report.status == "failed"


def test_the_reports_are_written_as_markdown_and_json_with_every_alert(tmp_path):
    report = cfr.CaseReport("database-down", checks=[cfr.Check("health 503", "pass", "503")], seconds=12.5)
    report.alerts.append("CtiparsorDatabaseDown")
    report.commands.append("docker compose stop postgres")
    report.settle()
    meta = {"started_at": "t0", "finished_at": "t1", "base_url": "http://127.0.0.1:8000",
            "compose_file": "compose.yaml", "cases_run": ["database-down"], "exit_code": 0}
    md_path, json_path = cfr.write_reports(tmp_path, meta, [report], cfr.load_rules())
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["cases"][0]["status"] == "passed"
    assert {a["name"] for a in payload["alerts"]} == ALL_ALERTS
    db = next(a for a in payload["alerts"] if a["name"] == "CtiparsorDatabaseDown")
    assert db["exercised_by"] == ["database-down"]
    markdown = md_path.read_text(encoding="utf-8")
    assert "| CtiparsorDatabaseDown | critical | 60 s | database-down |" in markdown
    assert "docker compose stop postgres" in markdown
    assert "not exercised by these cases" in markdown


def test_the_override_file_sets_one_service_and_refuses_a_bad_name(tmp_path):
    path = cfr.write_override(tmp_path / "o.yaml", "worker", {"LLM_PROVIDER": "vllm", "VLLM_BASE_URL": "http://127.0.0.1:9"})
    assert path.read_text(encoding="utf-8").splitlines() == [
        "services:", "  worker:", "    environment:",
        '      LLM_PROVIDER: "vllm"', '      VLLM_BASE_URL: "http://127.0.0.1:9"',
    ]
    with pytest.raises(ValueError):
        cfr.write_override(tmp_path / "bad.yaml", "app", {"lower": "x"})


# ── The command blocks are the documented ones ──────────────────────────────


def _docs_block(name: str) -> list[str]:
    text = (ROOT / "docs" / "docker.md").read_text(encoding="utf-8")
    found = re.findall(r"<!-- scripts/check_backup_restore_docker\.sh: (\w+) -->\n```bash\n(.*?)\n```", text, re.DOTALL)
    return dict((n, b.split("\n")) for n, b in found)[name]


def test_the_backup_commands_are_the_documented_ones():
    assert cfr.BACKUP_COMMANDS == _docs_block("BACKUP_COMMANDS")


def test_the_check_commands_are_the_documented_ones():
    assert cfr.CHECK_COMMANDS == _docs_block("CHECK_COMMANDS")


def test_the_restore_line_is_the_documented_one_with_only_the_database_named():
    documented = _docs_block("RESTORE_COMMANDS")[1]
    assert cfr.RESTORE_PG_LINE.format(user="ctiparsor", database="ctiparsor") == documented


# ── A fake stack ──────────────────────────────────────────────────────────────


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


class World:
    """The parts of the stack the cases read. Defaults are the healthy stack."""

    def __init__(self) -> None:
        self.clock = FakeClock()
        self.jobs: dict[str, dict[str, Any]] = {}
        self.worker_up = True
        self.db_up = True
        self.free = 50 * GIB
        self.total = 100 * GIB
        self.threshold_mb: int | None = None
        self.llm_override = False
        self.new_job_status = "processing"
        self.new_job_stage: list[dict[str, Any]] = []
        self.rerun_result: str | None = "completed"
        self.drop_jobs_on_db_start = False
        self.drill_mismatch = False
        self.live_bundle = b"bundle-bytes"
        self.uploaded = 0
        self.commands: list[list[str]] = []

    # commands

    def run(self, argv: list[str], stdin_text: str | None, cwd: Path | None) -> tuple[int, str, str]:
        self.commands.append(argv)
        if argv[0] == "bash":
            return self._bash(argv[-1], cwd)
        args = argv[2:]
        overrides = []
        while args[:1] == ["-f"]:
            overrides.append(Path(args[1]))
            args = args[2:]
        verb = args[0]
        if verb == "exec":
            service, command = args[2], args[3:]
            if service == "postgres":
                if not self.db_up:
                    return 1, "", "connection refused"
                return 0, self._psql(stdin_text or "", command[-1]), ""
            if command[0] == "sh":
                return 0, f"{self.uploaded}\n", ""
            data = self.live_bundle if command[1].endswith("bundle.json") else b"upload"
            return 0, f"{hashlib.sha256(data).hexdigest()}  {command[1]}\n", ""
        if verb == "kill":
            self.worker_up = False
        elif verb == "stop" and "postgres" in args:
            self.db_up = False
        elif verb == "start":
            if "postgres" in args:
                self.db_up = True
                if self.drop_jobs_on_db_start:
                    self.jobs.clear()
            if "worker" in args:
                self._worker_started()
        elif verb == "up":
            self._up(args, overrides)
        elif verb == "ps":
            return 0, ("cid\n" if self.worker_up else ""), ""
        return 0, "", ""

    def _worker_started(self) -> None:
        self.worker_up = True
        for job in self.jobs.values():
            if job["status"] == "processing" and self.rerun_result:
                job.update(status=self.rerun_result, attempts=job["attempts"] + 1)

    def _up(self, args: list[str], overrides: list[Path]) -> None:
        if "app" in args:
            self.threshold_mb = None
            for path in overrides:
                found = re.search(r'UPLOAD_MIN_FREE_MB: "(\d+)"', path.read_text(encoding="utf-8"))
                if found:
                    self.threshold_mb = int(found.group(1))
        if "worker" in args:
            self.worker_up = True
            self.llm_override = any("VLLM_BASE_URL" in p.read_text(encoding="utf-8") for p in overrides)

    def _bash(self, block: str, cwd: Path | None) -> tuple[int, str, str]:
        assert cwd is not None
        if "pg_dump" in block:
            stamp = "2026-11-08-120000"
            (cwd / f"ctiparsor-{stamp}.dump").write_bytes(b"DUMP")
            with tarfile.open(cwd / f"cti-state-{stamp}.tgz", "w:gz") as tar:
                # The archive holds the bundle as the backup took it, whatever the live file is now.
                for name, data in (("./output/bundle.json", b"bundle-bytes"), ("./uploads/a.txt", b"upload")):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            return 0, "", ""
        if "pg_restore -l" in block:
            return 0, "4\n", ""
        if "tar tzf" in block:
            return 0, "2\n", ""
        return 0, "", ""

    # the database

    def _probe(self, database_is_drill: bool) -> str:
        rows = sorted(self.jobs.items())
        if database_is_drill and self.drill_mismatch:
            return "99|changed"
        digest = hashlib.md5(",".join(f"{k}|{v['status']}|{v['name']}" for k, v in rows).encode()).hexdigest()
        return f"{len(rows)}|{digest}"

    def _psql(self, sql: str, inner: str) -> str:
        found = re.search(r"'([0-9a-f-]{36})'", sql)
        job = self.jobs.get(found.group(1)) if found else None
        if "pg_tables" in sql:
            return "5"
        if "CREATE DATABASE" in sql or "DROP DATABASE" in sql:
            return ""
        if "SELECT status, attempts" in sql:
            return f"{job['status']}|{job['attempts']}|{job['worker']}" if job else ""
        if "progress_events" in sql:
            return json.dumps({"error": job.get("error", "")} if job else {})
        if "run_config_json" in sql:
            return json.dumps({"stage_report": job["stage"] if job else []})
        if "WHERE original_filename" in sql:
            name = re.search(r"original_filename='([^']+)'", sql)
            return str(sum(1 for j in self.jobs.values() if name and j["name"] == name.group(1)))
        if "string_agg(id || '|'" in sql:
            return self._probe(database_is_drill="$POSTGRES_DB" not in inner)
        if "string_agg(id, ','" in sql:
            ids = ",".join(sorted(self.jobs))
            return f"{len(self.jobs)}|{hashlib.md5(ids.encode()).hexdigest()}"
        raise AssertionError(f"unexpected SQL: {sql}")

    # HTTP

    def request(self, method: str, path: str, body: bytes | None) -> tuple[int, bytes]:
        if path == "/api/health":
            return (200, b'{"status":"ok"}') if self.db_up else (503, b'{"status":"degraded"}')
        if path == "/metrics":
            return 200, self._metrics().encode()
        if path == "/api/queue/status":
            counts: dict[str, int] = {}
            for job in self.jobs.values():
                counts[job["status"]] = counts.get(job["status"], 0) + 1
            return 200, json.dumps({"counts": counts}).encode()
        if path.startswith("/api/jobs/"):
            found_job = self.jobs.get(path.rsplit("/", 1)[1])
            if found_job is None:
                return 404, b"{}"
            return 200, json.dumps({"status": found_job["status"]}).encode()
        if path == "/api/upload":
            return self._upload(body or b"")
        raise AssertionError(f"unexpected request {method} {path}")

    def _metrics(self) -> str:
        if not self.db_up:
            return "ctiparsor_database_up 0\n"
        processing = sum(1 for j in self.jobs.values() if j["status"] == "processing")
        busy = 1 if self.worker_up else 0
        return "\n".join([
            "ctiparsor_database_up 1",
            f'ctiparsor_jobs{{status="processing"}} {processing}',
            f'ctiparsor_workers{{state="busy"}} {busy}',
            'ctiparsor_workers{state="idle"} 0',
            f"ctiparsor_state_dir_free_bytes {self.free}",
            f"ctiparsor_state_dir_total_bytes {self.total}",
            "ctiparsor_backup_last_attempt_ok 1",
        ]) + "\n"

    def _upload(self, body: bytes) -> tuple[int, bytes]:
        if self.threshold_mb is not None and self.free // MIB < self.threshold_mb:
            return 507, b"Insufficient Storage: refused"
        found_name = re.search(rb'filename="([^"]+)"', body)
        assert found_name is not None
        name = found_name.group(1).decode()
        job_id = f"{len(self.jobs) + 1:08x}-0000-4000-8000-{'0' * 12}"
        status = self.new_job_status
        self.jobs[job_id] = {"name": name, "status": status, "attempts": 1 if status == "processing" else 0,
                             "worker": "w1" if status == "processing" else "", "stage": list(self.new_job_stage),
                             "error": ""}
        self.uploaded += 1
        return 200, json.dumps({"job_id": job_id, "filename": name, "status": status}).encode()


class FakeStack(cfr.Stack):
    def __init__(self, world: World, token: str | None = None) -> None:
        super().__init__("http://127.0.0.1:8000", ROOT / "compose.yaml", token,
                         clock=world.clock, sleep=world.clock.sleep)
        self.world = world

    def _run(self, argv, *, timeout, stdin_text=None, env=None, cwd=None):  # type: ignore[override]
        if self.current is not None:
            self.current.commands.append(" ".join(argv))
        return self.world.run(list(argv), stdin_text, cwd)

    def _request(self, method, path, *, body=None, headers=None, timeout=20.0):  # type: ignore[override]
        return self.world.request(method, path, body)


def _run_case(name: str, world: World, tmp_path: Path, wait_s: float = 600.0) -> cfr.CaseReport:
    stack = FakeStack(world)
    report = cfr.CaseReport(name)
    run = cfr.Run(stack, report, cfr.Options(wait_s=wait_s, poll_s=5.0), tmp_path, cfr.load_rules())
    stack.current = report
    try:
        cfr.CASES[name](run)
    finally:
        stack.current = None
        report.settle()
    return report


def _checks(report: cfr.CaseReport) -> dict[str, str]:
    return {c.name: c.status for c in report.checks}


# ── worker-killed ────────────────────────────────────────────────────────────


def test_worker_killed_passes_when_the_job_is_run_again_and_ends(tmp_path):
    world = World()
    report = _run_case("worker-killed", world, tmp_path)
    assert report.status == "passed", report.checks
    assert ["docker", "compose", "-f", str(cfr.ROOT / "compose.yaml"), "kill", "worker"] in world.commands


def test_worker_killed_fails_when_the_job_stays_processing(tmp_path):
    world = World()
    world.rerun_result = None
    report = _run_case("worker-killed", world, tmp_path, wait_s=30.0)
    assert report.status == "failed"
    assert _checks(report)["the job ends in a terminal status, never processing"] == "fail"


# ── llm-down ─────────────────────────────────────────────────────────────────


def test_llm_down_passes_with_stage_three_failed_and_the_reason_kept(tmp_path):
    world = World()
    world.new_job_status = "completed"
    world.new_job_stage = [{"stage": "3", "status": "failed", "reason": "connection refused"}]
    report = _run_case("llm-down", world, tmp_path)
    assert report.status == "passed", report.checks
    assert world.llm_override


def test_llm_down_fails_when_stage_three_has_no_reason(tmp_path):
    world = World()
    world.new_job_status = "completed"
    world.new_job_stage = [{"stage": "3", "status": "skipped", "reason": ""}]
    report = _run_case("llm-down", world, tmp_path)
    assert report.status == "failed"
    assert _checks(report)["Stage 3 is recorded as failed or skipped, with a reason"] == "fail"


# ── database-down ────────────────────────────────────────────────────────────


def test_database_down_passes_when_the_alert_holds_and_the_jobs_are_back(tmp_path):
    world = World()
    world.jobs["00000001-0000-4000-8000-000000000000"] = {
        "name": "a.txt", "status": "completed", "attempts": 1, "worker": "w1", "stage": [], "error": ""}
    report = _run_case("database-down", world, tmp_path)
    assert report.status == "passed", report.checks
    assert report.alerts == ["CtiparsorDatabaseDown"]
    assert world.clock.t >= 60  # the for: duration was waited for


def test_database_down_fails_when_a_job_is_lost(tmp_path):
    world = World()
    world.jobs["00000001-0000-4000-8000-000000000000"] = {
        "name": "a.txt", "status": "completed", "attempts": 1, "worker": "w1", "stage": [], "error": ""}
    world.drop_jobs_on_db_start = True
    report = _run_case("database-down", world, tmp_path)
    assert report.status == "failed"
    assert _checks(report)["the jobs table holds the same job ids as before"] == "fail"


def test_an_alert_whose_condition_is_false_at_the_first_scrape_fails(tmp_path):
    world = World()
    report = cfr.CaseReport("database-down")
    run = cfr.Run(FakeStack(world), report, cfr.Options(), tmp_path, cfr.load_rules())
    run.hold_alert("CtiparsorDatabaseDown")
    assert _checks(report) == {"alert CtiparsorDatabaseDown (severity critical, for 60 s)": "fail"}


# ── disk-nearly-full ─────────────────────────────────────────────────────────


def test_disk_nearly_full_passes_when_the_upload_is_refused_and_the_alert_holds(tmp_path):
    world = World()
    world.free = 1 * GIB
    world.total = 500 * GIB
    report = _run_case("disk-nearly-full", world, tmp_path)
    assert report.status == "passed", report.checks
    assert world.uploaded == 0
    assert world.threshold_mb == 1025  # one MB above the 1024 MB free: the override was applied


def test_disk_nearly_full_on_a_roomy_disk_checks_the_gate_and_not_the_alert(tmp_path):
    world = World()
    report = _run_case("disk-nearly-full", world, tmp_path)
    assert report.status == "not_checked", report.checks
    checks = _checks(report)
    assert checks["alert CtiparsorDiskNearlyFull"] == "not_checked"
    assert checks["the upload is refused with 507"] == "pass"


def test_the_threshold_constants_match_the_rules_file():
    rule = next(r for r in cfr.load_rules() if r.name == "CtiparsorDiskNearlyFull")
    assert str(cfr.DISK_ALERT_MIN_FREE) in rule.expr
    assert f"< {cfr.DISK_ALERT_RATIO:.2f}" in rule.expr


def test_a_multi_line_expr_is_refused(tmp_path):
    rules = tmp_path / "rules.yml"
    lines = ["groups:", "  - name: g", "    rules:", "      - alert: A", "        expr: |", "          up == 0", ""]
    rules.write_text("\n".join(lines), encoding="utf-8")
    with pytest.raises(ValueError, match="multi-line"):
        cfr.load_rules(rules)


# ── restore-drill ────────────────────────────────────────────────────────────


def test_restore_drill_passes_when_the_restored_jobs_and_files_match(tmp_path):
    world = World()
    report = _run_case("restore-drill", world, tmp_path)
    assert report.status == "passed", report.checks
    assert report.extra["check_counts"] == [4, 2]
    assert "restore_seconds" in report.extra
    assert not list(tmp_path.glob("restore-drill/ctiparsor-*.dump"))  # the backup is removed


def test_restore_drill_fails_when_the_restored_database_differs(tmp_path):
    world = World()
    world.drill_mismatch = True
    report = _run_case("restore-drill", world, tmp_path)
    assert report.status == "failed"
    assert _checks(report)["the restored jobs equal the source's, row by row"] == "fail"


def test_restore_drill_fails_when_a_live_file_differs_from_the_archive(tmp_path):
    world = World()
    world.live_bundle = b"changed"
    report = _run_case("restore-drill", world, tmp_path)
    assert report.status == "failed"
    assert _checks(report)["the archive's bundles and uploads match the live files"] == "fail"


# ── the command line and the whole run ──────────────────────────────────────


def test_the_run_refuses_without_the_flag_and_touches_nothing(monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise AssertionError("no command may run without the flag")

    monkeypatch.setattr(cfr.Stack, "_run", boom)
    monkeypatch.setattr(cfr.Stack, "_request", boom)
    with pytest.raises(SystemExit) as exc:
        cfr.main(["--base-url", "http://127.0.0.1:8000"])
    assert exc.value.code == 2
    assert "--i-know-this-stops-services" in capsys.readouterr().err


def test_the_run_refuses_a_base_url_that_is_not_on_loopback(monkeypatch):
    monkeypatch.setattr(cfr.Stack, "_request", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no call")))
    with pytest.raises(SystemExit) as exc:
        cfr.main(["--base-url", "http://192.168.0.5:8000", "--i-know-this-stops-services"])
    assert exc.value.code == 2


def test_case_selection_takes_the_named_cases_only_and_refuses_others():
    parser = cfr.build_parser()
    args = parser.parse_args(["--case", "restore-drill", "--case", "llm-down", "--i-know-this-stops-services"])
    assert args.cases == ["restore-drill", "llm-down"]
    assert parser.parse_args(["--i-know-this-stops-services"]).cases is None
    with pytest.raises(SystemExit):
        parser.parse_args(["--case", "not-a-case", "--i-know-this-stops-services"])


def test_a_whole_run_writes_the_reports_and_exits_by_the_outcome(monkeypatch, tmp_path):
    world = World()
    monkeypatch.setattr(cfr, "Stack", lambda base, compose, token: FakeStack(world, token))
    code = cfr.main(["--case", "disk-nearly-full", "--i-know-this-stops-services",
                     "--report-dir", str(tmp_path / "run")])
    assert code == 1  # the disk has room: the alert is not checked, so not a pass
    payload = json.loads((tmp_path / "run" / "report.json").read_text(encoding="utf-8"))
    assert payload["exit_code"] == 1
    assert payload["cases"][0]["name"] == "disk-nearly-full"
    assert (tmp_path / "run" / "report.md").is_file()


def test_the_metrics_token_is_sent_as_a_bearer_and_a_403_says_why(tmp_path):
    seen: list[dict[str, str]] = []

    class Forbidden(FakeStack):
        def _request(self, method, path, *, body=None, headers=None, timeout=20.0):  # type: ignore[override]
            seen.append(headers or {})
            return 403, b"{}"

    stack = Forbidden(World(), token="secret-value")
    with pytest.raises(cfr.StepError, match="METRICS_TOKEN"):
        stack.scrape()
    assert seen == [{"Authorization": "Bearer secret-value"}]


def test_the_report_holds_no_token_value(tmp_path, monkeypatch):
    monkeypatch.setenv(cfr.TOKEN_ENV, "top-secret-token-value")
    world = World()
    monkeypatch.setattr(cfr, "Stack", lambda base, compose, token: FakeStack(world, token))
    cfr.main(["--case", "database-down", "--i-know-this-stops-services", "--report-dir", str(tmp_path / "r")])
    written = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "r").iterdir())
    assert "top-secret-token-value" not in written


def test_the_multipart_body_carries_the_file_under_the_file_field():
    body, content_type = cfr._multipart("a.txt", b"hello")
    assert content_type.startswith("multipart/form-data; boundary=")
    assert b'name="file"; filename="a.txt"' in body and b"hello" in body


def test_the_archive_comparison_names_the_files_whose_live_bytes_differ(tmp_path):
    archive = tmp_path / "a.tgz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, data in (("./output/bundle.json", b"abc"), ("./uploads/a.txt", b"upload")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    world = World()
    world.live_bundle = b"abc"  # the bundle matches
    wanted, mismatches = cfr._compare_archive_files(FakeStack(world), archive)
    assert wanted == 2
    assert mismatches == []
    world.live_bundle = b"abd"
    _, mismatches = cfr._compare_archive_files(FakeStack(world), archive)
    assert mismatches == ["output/bundle.json"]
