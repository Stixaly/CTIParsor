"""The queue load profile of a running stack (issue #710).

    python scripts/measure_queue_load.py --base-url http://127.0.0.1:8000 --reports 10 --arrival burst \
        --worker-max-concurrent 1 --report-dir output/load-profile/<name> [--interval-s 7] \
        [--timeout-s 3600] [--poll-s 2]

It submits N copies of tests/fixtures/sample_report.txt, each with a line of its own, so that each
upload is a new job, and follows them until every job holds a terminal status (completed, for_review
or failed) or the timeout passes. It samples /api/queue/status, /api/jobs/<id> and /metrics on every
poll, and evaluates the alert rules of docs/monitoring/ctiparsor.rules.yml on each scrape.

Arrival: `burst` submits all the reports at once; `interval` submits one every `--interval-s` seconds.
The upload route allows 10 uploads per minute per client address (api/routes/upload.py), so a burst
is at most 10 reports, and an interval is at least 6 s. The profile is refused before it starts when a
setting would be refused by that limit.

Measures, from the server's own timestamps (created_at, and updated_at at the claim, the first poll
that sees `processing`):
- queue wait: claim minus created_at. Its resolution is the poll interval, and it is not measured for
  a job whose claim the poll did not see.
- run time: the terminal updated_at minus the claim.
- throughput: completed-or-for_review jobs per minute, from the first submission to the last end.
- the deepest queue and the most live workers seen on /api/queue/status; the failed jobs; the rejected
  uploads; the job names found twice in /api/jobs.
- for each alert: whether its condition was true, the longest run of true scrapes, and whether that run
  held for the rule's `for:` duration (`fired`). A rule whose expression the evaluator cannot read is
  reported as not checked.

Memory, disk and the attempts of each job are not sampled here: docs/releases/1.0-failure-recipe.md
gives the commands that read them (`docker stats`, the `jobs` table). Standard library only; the
client sends no secret except METRICS_TOKEN as a bearer, read from the environment and never written.

Exit 0 when every job ended in a terminal status, 1 otherwise, 2 on a usage error.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

try:
    from scripts import check_failure_recipe as cfr
except ImportError:  # run as a script: scripts/ is on sys.path
    import check_failure_recipe as cfr  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "sample_report.txt"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
TERMINAL = ("completed", "for_review", "failed")
DONE = ("completed", "for_review")
#: api/routes/upload.py: @limiter.limit("10/minute").
UPLOADS_PER_MINUTE = 10
#: The clock and the sleep of the profile (replaced by the tests).
CLOCK: Callable[[], float] = time.monotonic
SLEEP: Callable[[float], None] = time.sleep
TOKEN_ENV = "METRICS_TOKEN"


class Client:
    """HTTP on the API. `request` returns (status, body bytes); a connection error raises OSError."""

    def __init__(self, base_url: str, token: str | None) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, bytes]:
        request = urllib.request.Request(self.base_url + path, data=body, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def metrics(self) -> cfr.Series:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        status, body = self.request("GET", "/metrics", headers=headers)
        if status != 200:
            raise RuntimeError(f"/metrics answered {status}")
        return cfr.parse_metrics(body.decode("utf-8", "replace"))


@dataclass
class Job:
    name: str
    job_id: str | None = None
    submitted: float | None = None  # seconds from the start of the profile
    rejected: int | None = None  # the status an upload was refused with
    created: str | None = None  # server created_at
    claimed: str | None = None  # server updated_at at the first poll that saw `processing`
    ended: str | None = None  # server updated_at at the terminal status
    status: str = "submitted"


@dataclass
class RuleTrack:
    """What one alert did over the scrapes: whether its condition was ever true, the longest run of true
    scrapes (seconds), and whether that run covers the rule's `for:` duration."""

    name: str
    for_seconds: int
    checked: bool = False
    any_true: bool = False
    longest_run_s: float = 0.0
    run_start: float | None = None
    last_true: float | None = None
    detail: str = ""

    def observe(self, t: float, reading: cfr.Reading) -> None:
        if reading.state == "not_checked":
            self.detail = reading.detail
            return
        self.checked = True
        if reading.state != "true":
            self.run_start = None
            self.last_true = None
            return
        self.any_true = True
        self.detail = reading.detail
        if self.run_start is None:
            self.run_start = t
        self.last_true = t
        self.longest_run_s = max(self.longest_run_s, t - self.run_start)

    @property
    def fired(self) -> bool:
        return self.any_true and self.longest_run_s >= self.for_seconds


@dataclass
class Profile:
    reports: int
    arrival: str  # "burst" or "interval"
    interval_s: float = 0.0
    worker_max_concurrent: int = 1


@dataclass
class Outcome:
    profile: Profile
    jobs: list[Job] = field(default_factory=list)
    rules: dict[str, RuleTrack] = field(default_factory=dict)
    samples: list[dict[str, Any]] = field(default_factory=list)
    elapsed_s: float = 0.0
    timed_out: bool = False
    max_queue_depth: int = 0
    max_live_workers: int = 0
    scrape_errors: int = 0
    name_counts: dict[str, int] = field(default_factory=dict)


def check_profile(profile: Profile) -> str | None:
    """Why the profile would be refused by the upload limit or is malformed, or None."""
    if profile.reports < 1:
        return "--reports must be at least 1"
    if profile.arrival not in ("burst", "interval"):
        return "--arrival is burst or interval"
    if profile.arrival == "burst" and profile.reports > UPLOADS_PER_MINUTE:
        return (
            f"a burst of {profile.reports} uploads is refused by the upload limit of "
            f"{UPLOADS_PER_MINUTE} per minute per address; use --arrival interval"
        )
    if profile.arrival == "interval" and profile.interval_s < 60.0 / UPLOADS_PER_MINUTE:
        return f"--interval-s must be at least {60.0 / UPLOADS_PER_MINUTE:g} (the upload limit)"
    if profile.worker_max_concurrent < 1:
        return "--worker-max-concurrent must be at least 1"
    return None


def arrival_offsets(profile: Profile) -> list[float]:
    """When each report is submitted, in seconds from the start."""
    if profile.arrival == "burst":
        return [0.0] * profile.reports
    return [i * profile.interval_s for i in range(profile.reports)]


def build_reports(fixture: bytes, count: int, tag: str) -> list[tuple[str, bytes]]:
    """`count` reports, each the fixture with a line of its own, so that none is a duplicate of another."""
    reports = []
    for i in range(count):
        name = f"load-{tag}-{i:03d}.txt"
        body = fixture + f"\n# load profile {tag} report {i:03d} {uuid4().hex}\n".encode()
        reports.append((name, body))
    return reports


def percentile(values: list[float], p: float) -> float | None:
    """The nearest-rank percentile of `values` (p in 0..100), None for no value."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(p / 100.0 * len(ordered)))
    return ordered[rank - 1]


def parse_ts(text: str) -> datetime:
    value = datetime.fromisoformat(text.replace(" ", "T"))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def seconds_between(start: str | None, end: str | None) -> float | None:
    if not start or not end:
        return None
    return (parse_ts(end) - parse_ts(start)).total_seconds()


def submit(client: Client, job: Job, name: str, data: bytes, now: float) -> None:
    body, content_type = cfr._multipart(name, data)
    job.submitted = now
    try:
        status, raw = client.request("POST", "/api/upload", body, {"Content-Type": content_type})
    except OSError as exc:
        job.rejected = 0
        job.status = f"not sent: {exc}"
        return
    if status in (200, 201, 202):
        job.job_id = str(json.loads(raw)["job_id"])
        job.status = "queued"
    else:
        job.rejected = status
        job.status = f"rejected {status}"


def refresh(client: Client, job: Job, now_s: float) -> None:
    """Read the job; take its claim time the first time it is seen `processing`; note its end."""
    if job.job_id is None or job.status in TERMINAL:
        return
    status, raw = client.request("GET", f"/api/jobs/{job.job_id}")
    if status != 200:
        return
    detail = json.loads(raw)
    job.created = detail["created_at"]
    job.status = detail["status"]
    if job.status == "processing" and job.claimed is None:
        job.claimed = detail["updated_at"]
    if job.status in TERMINAL:
        job.ended = detail["updated_at"]


def run_profile(
    client: Client,
    profile: Profile,
    reports: list[tuple[str, bytes]],
    *,
    clock: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
    poll_s: float = 2.0,
    timeout_s: float = 3600.0,
    rules: list[cfr.Rule] | None = None,
) -> Outcome:
    clock = clock or CLOCK
    sleep = sleep or SLEEP
    rules = cfr.load_rules() if rules is None else rules
    outcome = Outcome(profile)
    outcome.jobs = [Job(name) for name, _ in reports]
    outcome.rules = {r.name: RuleTrack(r.name, r.for_seconds or 0) for r in rules}
    offsets = arrival_offsets(profile)
    start = clock()
    next_index = 0
    while True:
        now = clock() - start
        while next_index < len(reports) and offsets[next_index] <= now:
            name, data = reports[next_index]
            submit(client, outcome.jobs[next_index], name, data, now)
            next_index += 1
        for job in outcome.jobs:
            try:
                refresh(client, job, now)
            except (OSError, ValueError, KeyError):
                pass  # one unreadable job does not stop the profile; the next poll reads it again
        _sample(client, outcome, rules, now)
        pending = [j for j in outcome.jobs if j.job_id is not None and j.status not in TERMINAL]
        if next_index == len(reports) and not pending:
            break
        if clock() - start >= timeout_s:
            outcome.timed_out = True
            break
        sleep(poll_s)
    outcome.elapsed_s = clock() - start
    outcome.name_counts = job_name_counts(client, [name for name, _ in reports])
    return outcome


def job_name_counts(client: Client, names: list[str]) -> dict[str, int]:
    """How many jobs of the API hold each of the profile's report names (one job each is expected)."""
    status, raw = client.request("GET", "/api/jobs")
    if status != 200:
        raise RuntimeError(f"/api/jobs answered {status}")
    counts = {name: 0 for name in names}
    for row in json.loads(raw):
        found = row.get("original_filename")
        if found in counts:
            counts[found] += 1
    return counts


def _sample(client: Client, outcome: Outcome, rules: list[cfr.Rule], now: float) -> None:
    try:
        series = client.metrics()
    except (OSError, RuntimeError):
        outcome.scrape_errors += 1
        return
    wall = time.time()
    for rule in rules:
        outcome.rules[rule.name].observe(now, cfr.evaluate_rule(rule, series, wall))
    try:
        status, raw = client.request("GET", "/api/queue/status")
    except OSError:
        return
    if status != 200:
        return
    queue = json.loads(raw)
    depth = int(queue["queue"]["depth"])
    live = sum(1 for w in queue.get("workers", []) if w.get("state") in ("busy", "idle"))
    outcome.max_queue_depth = max(outcome.max_queue_depth, depth)
    outcome.max_live_workers = max(outcome.max_live_workers, live)
    outcome.samples.append(
        {
            "t_s": round(now, 1),
            "queued": depth,
            "live_workers": live,
            "oldest_queued_s": queue["queue"].get("oldest_queued_seconds"),
            "counts": queue.get("counts", {}),
        }
    )


def summarize(outcome: Outcome) -> dict[str, Any]:
    jobs = outcome.jobs
    waits = [w for w in (seconds_between(j.created, j.claimed) for j in jobs) if w is not None]
    runs = [r for r in (seconds_between(j.claimed, j.ended) for j in jobs) if r is not None]
    ends = [parse_ts(j.ended) for j in jobs if j.status in DONE and j.ended]
    starts = [parse_ts(j.created) for j in jobs if j.created]
    throughput = None
    if ends and starts:
        span = (max(ends) - min(starts)).total_seconds()
        if span > 0:
            throughput = len(ends) / (span / 60.0)
    duplicates = sorted(name for name, count in outcome.name_counts.items() if count > 1)
    return {
        "reports": len(jobs),
        "arrival": outcome.profile.arrival,
        "interval_s": outcome.profile.interval_s,
        "worker_max_concurrent": outcome.profile.worker_max_concurrent,
        "terminal": sum(1 for j in jobs if j.status in TERMINAL),
        "statuses": _count([j.status for j in jobs]),
        "rejected_uploads": sum(1 for j in jobs if j.rejected is not None),
        "queue_wait_s": {"p50": percentile(waits, 50), "p95": percentile(waits, 95), "n": len(waits)},
        "run_time_s": {"p50": percentile(runs, 50), "p95": percentile(runs, 95), "n": len(runs)},
        "throughput_per_min": throughput,
        "max_queue_depth": outcome.max_queue_depth,
        "max_live_workers": outcome.max_live_workers,
        "failed": sum(1 for j in jobs if j.status == "failed"),
        "duplicate_names": duplicates,
        "elapsed_s": round(outcome.elapsed_s, 1),
        "timed_out": outcome.timed_out,
        "scrape_errors": outcome.scrape_errors,
        "alerts": {
            name: {
                "checked": t.checked,
                "any_true": t.any_true,
                "longest_true_s": round(t.longest_run_s, 1),
                "for_s": t.for_seconds,
                "fired": t.fired,
                "detail": t.detail,
            }
            for name, t in outcome.rules.items()
        },
        "host": host_facts(),
    }


def _count(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def host_facts() -> dict[str, Any]:
    """The machine the profile ran on: CPUs and memory as the kernel reports them."""
    mem_total_kib = None
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                mem_total_kib = int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return {
        "cpus": os.cpu_count(),
        "mem_total_mib": mem_total_kib // 1024 if mem_total_kib else None,
        "platform": platform.platform(),
    }


def render_markdown(summary: dict[str, Any]) -> str:
    def val(x: Any) -> str:
        return "n/a" if x is None else (f"{x:.1f}" if isinstance(x, float) else str(x))

    lines = [
        "# Queue load profile",
        "",
        f"Reports: {summary['reports']}; arrival: {summary['arrival']}"
        + (f" every {summary['interval_s']:g} s" if summary["arrival"] == "interval" else " (all at once)")
        + f"; WORKER_MAX_CONCURRENT: {summary['worker_max_concurrent']}.",
        (
            f"Terminal: {summary['terminal']} of {summary['reports']}; timed out: {summary['timed_out']}; "
            f"elapsed {val(summary['elapsed_s'])} s; rejected uploads: {summary['rejected_uploads']}; "
            f"failed: {summary['failed']}; duplicate names: {len(summary['duplicate_names'])}."
        ),
        "",
        "| Measure | p50 (s) | p95 (s) | n |",
        "|---|---|---|---|",
        (
            f"| queue wait | {val(summary['queue_wait_s']['p50'])} | {val(summary['queue_wait_s']['p95'])} "
            f"| {summary['queue_wait_s']['n']} |"
        ),
        (
            f"| run time | {val(summary['run_time_s']['p50'])} | {val(summary['run_time_s']['p95'])} "
            f"| {summary['run_time_s']['n']} |"
        ),
        "",
        (
            f"Throughput: {val(summary['throughput_per_min'])} reports per minute; deepest queue "
            f"{summary['max_queue_depth']}; most live workers {summary['max_live_workers']}."
        ),
        "",
        "| Alert | checked | condition true | longest true run (s) | for (s) | fired |",
        "|---|---|---|---|---|---|",
    ]
    for name, alert in summary["alerts"].items():
        lines.append(
            f"| {name} | {'yes' if alert['checked'] else 'no'} | {'yes' if alert['any_true'] else 'no'} "
            f"| {alert['longest_true_s']:g} | {alert['for_s']} | {'yes' if alert['fired'] else 'no'} |"
        )
    lines += [
        "",
        (
            f"Host: {summary['host']['cpus']} CPUs, {summary['host']['mem_total_mib']} MiB memory "
            f"({summary['host']['platform']})."
        ),
    ]
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python scripts/measure_queue_load.py",
        description="The queue load profile of a running stack (issue #710).",
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--reports", type=int, required=True)
    parser.add_argument("--arrival", choices=("burst", "interval"), required=True)
    parser.add_argument("--interval-s", type=float, default=0.0)
    parser.add_argument(
        "--worker-max-concurrent",
        type=int,
        default=1,
        help="the WORKER_MAX_CONCURRENT the stack runs with (recorded, not set here)",
    )
    parser.add_argument("--timeout-s", type=float, default=3600.0)
    parser.add_argument("--poll-s", type=float, default=2.0)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--tag", default=None, help="a name for this run's report names (default: a short id)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    host = urlsplit(args.base_url).hostname or ""
    if host not in LOOPBACK_HOSTS:
        parser.error(f"--base-url must be on loopback, not {host!r}")
    profile = Profile(args.reports, args.arrival, args.interval_s, args.worker_max_concurrent)
    refusal = check_profile(profile)
    if refusal:
        print(f"measure_queue_load: {refusal}", file=sys.stderr)
        return 2
    if not FIXTURE.is_file():
        print(f"measure_queue_load: no fixture at {FIXTURE}", file=sys.stderr)
        return 2
    token = os.environ.get(TOKEN_ENV) or None  # never printed, never written
    client = Client(args.base_url, token)
    reports = build_reports(FIXTURE.read_bytes(), args.reports, args.tag or uuid4().hex[:6])
    outcome = run_profile(client, profile, reports, poll_s=args.poll_s, timeout_s=args.timeout_s)
    summary = summarize(outcome)
    args.report_dir.mkdir(parents=True, exist_ok=True)
    (args.report_dir / "load.json").write_text(
        json.dumps(
            {"summary": summary, "jobs": [vars(j) for j in outcome.jobs], "samples": outcome.samples},
            indent=2,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )
    (args.report_dir / "load.md").write_text(render_markdown(summary), encoding="utf-8")
    print(render_markdown(summary))
    ok = summary["terminal"] == summary["reports"] and not summary["timed_out"]
    print("ENDED" if ok else "NOT ENDED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
