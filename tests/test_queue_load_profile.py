"""scripts/measure_queue_load.py: the load profile, against a fake API (issue #710).

No Docker and no network. The fake answers the three routes the profile reads (upload, jobs,
queue status) and /metrics. A job is queued until `claim_s` after its upload, processing until
`claim_s + service_s`, then completed: so the queue wait and the run time are known exactly and the
profile's numbers can be checked against them.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts import check_failure_recipe as cfr
from scripts import measure_queue_load as mql

BASE = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)


def stamp(seconds: float) -> str:
    return (BASE + timedelta(seconds=seconds)).isoformat()


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


class FakeApi:
    """The routes the profile reads. Job state is a function of the time since its upload."""

    def __init__(
        self,
        clock: FakeClock,
        *,
        claim_s: float = 5.0,
        service_s: float = 10.0,
        oldest_queued_s: float = 0.0,
        reject_status: int | None = None,
        metrics_status: int = 200,
        duplicate_row: bool = False,
    ) -> None:
        self.clock = clock
        self.claim_s = claim_s
        self.service_s = service_s
        self.oldest_queued_s = oldest_queued_s
        self.reject_status = reject_status
        self.metrics_status = metrics_status
        self.duplicate_row = duplicate_row
        self.jobs: dict[str, dict] = {}
        self.uploads = 0

    def _state(self, job: dict, now: float) -> tuple[str, str]:
        age = now - job["created_s"]
        if age < self.claim_s:
            return "queued", stamp(job["created_s"])
        if age < self.claim_s + self.service_s:
            return "processing", stamp(job["created_s"] + self.claim_s)
        return "completed", stamp(job["created_s"] + self.claim_s + self.service_s)

    def metrics(self):
        status, body = self.request("GET", "/metrics")
        if status != 200:
            raise RuntimeError(f"/metrics answered {status}")
        return cfr.parse_metrics(body.decode())

    def request(self, method, path, body=None, headers=None, timeout=30.0):
        now = self.clock()
        if method == "POST" and path == "/api/upload":
            if self.reject_status is not None:
                return self.reject_status, b'{"detail":"refused"}'
            name = re.search(rb'filename="([^"]+)"', body).group(1).decode()
            job_id = f"job-{self.uploads:03d}"
            self.uploads += 1
            self.jobs[job_id] = {"name": name, "created_s": now}
            return 200, json.dumps({"job_id": job_id}).encode()
        if method == "GET" and path.startswith("/api/jobs/"):
            job = self.jobs[path.rsplit("/", 1)[1]]
            status, updated = self._state(job, now)
            detail = {"status": status, "created_at": stamp(job["created_s"]), "updated_at": updated}
            return 200, json.dumps(detail).encode()
        if method == "GET" and path == "/api/jobs":
            rows = [{"original_filename": j["name"]} for j in self.jobs.values()]
            if self.duplicate_row and rows:
                rows.append(dict(rows[0]))
            return 200, json.dumps(rows).encode()
        if method == "GET" and path == "/api/queue/status":
            queued = sum(1 for j in self.jobs.values() if self._state(j, now)[0] == "queued")
            body_json = {
                "role": "api",
                "backend": "postgres",
                "counts": {"queued": queued},
                "queue": {
                    "depth": queued,
                    "max_depth": 100,
                    "oldest_queued_job_id": None,
                    "oldest_queued_seconds": self.oldest_queued_s,
                },
                "workers": [{"worker_id": "w1", "state": "busy"}],
            }
            return 200, json.dumps(body_json).encode()
        if method == "GET" and path == "/metrics":
            if self.metrics_status != 200:
                return self.metrics_status, b"{}"
            text = (
                "\n".join(
                    [
                        "ctiparsor_database_up 1",
                        f"ctiparsor_oldest_queued_job_age_seconds {self.oldest_queued_s}",
                        'ctiparsor_workers{state="busy"} 1',
                        'ctiparsor_workers{state="idle"} 0',
                        "ctiparsor_state_dir_free_bytes 50000000000",
                        "ctiparsor_state_dir_total_bytes 100000000000",
                    ]
                )
                + "\n"
            )
            return 200, text.encode()
        raise AssertionError(f"unexpected request {method} {path}")


def _profile(reports: int = 3, arrival: str = "burst", interval_s: float = 0.0) -> mql.Profile:
    return mql.Profile(reports, arrival, interval_s, 1)


def _run(api: FakeApi, clock: FakeClock, profile: mql.Profile, timeout_s: float = 3600.0) -> mql.Outcome:
    reports = mql.build_reports(b"fixture\n", profile.reports, "t")
    return mql.run_profile(
        api, profile, reports, clock=clock, sleep=clock.sleep, poll_s=2.0, timeout_s=timeout_s, rules=cfr.load_rules()
    )


# ── the profile ──────────────────────────────────────────────────────────────


def test_a_burst_above_the_upload_limit_is_refused_before_it_starts():
    assert mql.check_profile(_profile(10, "burst")) is None
    assert "refused by the upload limit" in mql.check_profile(_profile(11, "burst"))


def test_an_interval_below_the_upload_limit_is_refused():
    assert mql.check_profile(_profile(20, "interval", 6.0)) is None
    assert "at least 6" in mql.check_profile(_profile(20, "interval", 5.0))


def test_the_arrival_offsets_are_all_zero_or_one_per_interval():
    assert mql.arrival_offsets(_profile(3, "burst")) == [0.0, 0.0, 0.0]
    assert mql.arrival_offsets(_profile(3, "interval", 7.0)) == [0.0, 7.0, 14.0]


def test_the_reports_are_each_the_fixture_with_a_line_of_their_own():
    reports = mql.build_reports(b"fixture\n", 3, "tag")
    names = [name for name, _ in reports]
    bodies = [body for _, body in reports]
    assert len(set(names)) == 3 and len(set(bodies)) == 3
    assert all(body.startswith(b"fixture\n") for body in bodies)


def test_the_percentiles_are_nearest_rank_and_none_for_no_value():
    values = [float(v) for v in range(1, 11)]
    assert mql.percentile(values, 50) == 5.0
    assert mql.percentile(values, 95) == 10.0
    assert mql.percentile([], 50) is None


def test_the_queue_wait_and_the_run_time_are_the_server_stamps_of_each_job():
    clock = FakeClock()
    api = FakeApi(clock, claim_s=5.0, service_s=10.0)
    outcome = _run(api, clock, _profile(3, "burst"))
    summary = mql.summarize(outcome)
    assert summary["terminal"] == 3
    assert summary["statuses"] == {"completed": 3}
    assert summary["queue_wait_s"]["p50"] == pytest.approx(5.0)
    assert summary["run_time_s"]["p50"] == pytest.approx(10.0)
    assert summary["run_time_s"]["n"] == 3
    assert summary["failed"] == 0
    assert summary["duplicate_names"] == []
    assert not summary["timed_out"]


def test_an_interval_profile_submits_one_report_per_interval():
    clock = FakeClock()
    api = FakeApi(clock, claim_s=1.0, service_s=1.0)
    outcome = _run(api, clock, _profile(3, "interval", 7.0))
    submitted = [j.submitted for j in outcome.jobs]
    # Each report is sent at the first poll at or after its time: the poll is every 2 s here.
    for offset, sent in zip([0.0, 7.0, 14.0], submitted, strict=True):
        assert offset <= sent < offset + 2.0


def test_a_refused_upload_is_counted_and_is_not_a_terminal_job():
    clock = FakeClock()
    api = FakeApi(clock, reject_status=429)
    outcome = _run(api, clock, _profile(2, "burst"))
    summary = mql.summarize(outcome)
    assert summary["rejected_uploads"] == 2
    assert summary["statuses"] == {"rejected 429": 2}
    assert summary["terminal"] == 0


def test_a_job_that_never_ends_times_out_and_is_not_an_end():
    clock = FakeClock()
    api = FakeApi(clock, claim_s=10_000.0)
    outcome = _run(api, clock, _profile(1, "burst"), timeout_s=60.0)
    assert outcome.timed_out
    assert mql.summarize(outcome)["terminal"] == 0


def test_a_duplicated_job_name_is_reported():
    clock = FakeClock()
    api = FakeApi(clock, duplicate_row=True)
    summary = mql.summarize(_run(api, clock, _profile(2, "burst")))
    assert len(summary["duplicate_names"]) == 1


def test_queue_depth_and_live_workers_are_the_most_seen():
    clock = FakeClock()
    api = FakeApi(clock, claim_s=20.0, service_s=5.0)
    outcome = _run(api, clock, _profile(3, "burst"))
    assert outcome.max_queue_depth == 3
    assert outcome.max_live_workers == 1


# ── the alerts ───────────────────────────────────────────────────────────────


def test_an_alert_whose_condition_holds_for_its_for_duration_is_fired():
    clock = FakeClock()
    # The oldest queued job is 2000 s old on every scrape, and the run lasts over 300 s.
    api = FakeApi(clock, claim_s=400.0, service_s=5.0, oldest_queued_s=2000.0)
    outcome = _run(api, clock, _profile(1, "burst"))
    track = outcome.rules["CtiparsorQueueWaitTooLong"]
    assert track.checked
    assert track.fired
    assert track.longest_run_s >= 300


def test_an_alert_true_for_less_than_its_for_duration_is_not_fired():
    clock = FakeClock()
    api = FakeApi(clock, claim_s=60.0, service_s=5.0, oldest_queued_s=2000.0)
    outcome = _run(api, clock, _profile(1, "burst"))
    track = outcome.rules["CtiparsorQueueWaitTooLong"]
    assert track.any_true
    assert not track.fired


def test_an_alert_the_evaluator_cannot_read_is_not_checked():
    clock = FakeClock()
    api = FakeApi(clock, claim_s=2.0, service_s=2.0)
    outcome = _run(api, clock, _profile(1, "burst"))
    track = outcome.rules["CtiparsorFailedJobsRising"]
    assert not track.checked
    assert not track.fired


def test_an_unreadable_metrics_route_is_counted_and_the_profile_goes_on():
    clock = FakeClock()
    api = FakeApi(clock, metrics_status=500)
    outcome = _run(api, clock, _profile(1, "burst"))
    assert outcome.scrape_errors > 0
    assert mql.summarize(outcome)["terminal"] == 1


# ── the command ──────────────────────────────────────────────────────────────


def test_the_command_refuses_a_base_url_that_is_not_on_loopback():
    with pytest.raises(SystemExit) as exc:
        mql.main(["--base-url", "http://10.0.0.5:8000", "--reports", "1", "--arrival", "burst", "--report-dir", "x"])
    assert exc.value.code == 2


def test_the_command_writes_the_json_and_the_markdown_and_exits_by_the_outcome(tmp_path, monkeypatch):
    clock = FakeClock()
    api = FakeApi(clock)
    monkeypatch.setattr(mql, "Client", lambda base_url, token: api)
    monkeypatch.setattr(mql, "SLEEP", clock.sleep)
    monkeypatch.setattr(mql, "CLOCK", clock)
    code = mql.main(
        ["--reports", "2", "--arrival", "burst", "--report-dir", str(tmp_path / "run"), "--tag", "t1", "--poll-s", "2"]
    )
    assert code == 0
    data = json.loads((tmp_path / "run" / "load.json").read_text(encoding="utf-8"))
    assert data["summary"]["terminal"] == 2
    assert "# Queue load profile" in (tmp_path / "run" / "load.md").read_text(encoding="utf-8")


def test_the_run_summary_holds_no_token_value(tmp_path, monkeypatch):
    clock = FakeClock()
    api = FakeApi(clock)
    monkeypatch.setattr(mql, "Client", lambda base_url, token: api)
    monkeypatch.setenv("METRICS_TOKEN", "s3cret-token-value")
    monkeypatch.setattr(mql, "SLEEP", clock.sleep)
    monkeypatch.setattr(mql, "CLOCK", clock)
    mql.main(["--reports", "1", "--arrival", "burst", "--report-dir", str(tmp_path / "r"), "--tag", "t2"])
    text = (tmp_path / "r" / "load.json").read_text(encoding="utf-8") + (tmp_path / "r" / "load.md").read_text(
        encoding="utf-8"
    )
    assert "s3cret-token-value" not in text
    assert Path(mql.FIXTURE).is_file()
