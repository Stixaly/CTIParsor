"""api/cgroup_memory.py (issue #675): the container's memory limit from cgroup v2 or v1,
and the worker's warning when WORKER_MAX_CONCURRENT x 4.4 GB exceeds it (ADR-0037).

The cgroup root is a tmp_path, so the tests read fixture files, never the host's
/sys/fs/cgroup.  The warning is advisory: no test expects a value to change."""
from __future__ import annotations

import logging

import pytest

import api.queue_loop as queue_loop
from api.cgroup_memory import memory_limit_bytes, warn_if_memory_short

GIB = 1024**3


def _v2(root, content: str | bytes) -> None:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "memory.max"
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def _v1(root, content: str) -> None:
    d = root / "memory"
    d.mkdir(parents=True, exist_ok=True)
    (d / "memory.limit_in_bytes").write_text(content, encoding="utf-8")


def test_cgroup_v2_reads_the_limit_in_bytes(tmp_path):
    _v2(tmp_path, f"{6 * GIB}\n")
    assert memory_limit_bytes(tmp_path) == 6 * GIB


def test_cgroup_v2_max_is_unlimited(tmp_path):
    _v2(tmp_path, "max\n")
    assert memory_limit_bytes(tmp_path) is None


def test_cgroup_v2_wins_over_v1(tmp_path):
    _v2(tmp_path, f"{6 * GIB}\n")
    _v1(tmp_path, f"{2 * GIB}\n")
    assert memory_limit_bytes(tmp_path) == 6 * GIB


def test_cgroup_v1_reads_the_limit(tmp_path):
    _v1(tmp_path, f"{4 * GIB}\n")
    assert memory_limit_bytes(tmp_path) == 4 * GIB


def test_cgroup_v1_huge_value_is_unlimited(tmp_path):
    # What the kernel writes when there is no limit (page-aligned, near 2**63).
    _v1(tmp_path, "9223372036854771712\n")
    assert memory_limit_bytes(tmp_path) is None


def test_no_cgroup_file_is_no_limit(tmp_path):
    assert memory_limit_bytes(tmp_path) is None


@pytest.mark.parametrize("content", [b"\xff\xfe\x00", b"abc", b"", b"0\n", b"-5\n", b"4G\n"])
def test_unreadable_or_strange_values_are_no_limit(tmp_path, content):
    _v2(tmp_path, content)
    assert memory_limit_bytes(tmp_path) is None


def test_a_directory_where_the_file_should_be_is_no_limit(tmp_path):
    (tmp_path / "memory.max").mkdir()
    assert memory_limit_bytes(tmp_path) is None


def test_fractional_cpu_is_not_a_memory_limit(tmp_path):
    # A CPU quota (cpu.max, "150000 100000" = 1.5 CPUs) sits beside the memory file and is ignored.
    (tmp_path / "cpu.max").write_text("150000 100000\n", encoding="utf-8")
    assert memory_limit_bytes(tmp_path) is None
    _v2(tmp_path, f"{6 * GIB}\n")
    assert memory_limit_bytes(tmp_path) == 6 * GIB


def test_warns_when_one_report_does_not_fit(tmp_path, caplog):
    _v2(tmp_path, f"{4 * GIB}\n")
    with caplog.at_level(logging.WARNING, logger="api.cgroup_memory"):
        warn_if_memory_short(1, root=tmp_path)
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.WARNING
    assert "WORKER_MAX_CONCURRENT=1 needs about 4.4 GB" in caplog.text
    assert "ADR-0037" in caplog.text


def test_warns_when_two_reports_do_not_fit_in_six_gib(tmp_path, caplog):
    _v1(tmp_path, f"{6 * GIB}\n")
    with caplog.at_level(logging.WARNING, logger="api.cgroup_memory"):
        warn_if_memory_short(2, root=tmp_path)
    assert "WORKER_MAX_CONCURRENT=2 needs about 8.8 GB" in caplog.text


def test_no_warning_when_the_limit_is_large_enough(tmp_path, caplog):
    _v2(tmp_path, f"{5 * GIB}\n")
    with caplog.at_level(logging.WARNING, logger="api.cgroup_memory"):
        warn_if_memory_short(1, root=tmp_path)
    assert caplog.records == []


def test_no_warning_when_unlimited(tmp_path, caplog):
    _v2(tmp_path, "max\n")
    with caplog.at_level(logging.WARNING, logger="api.cgroup_memory"):
        warn_if_memory_short(10, root=tmp_path)
    assert caplog.records == []


def test_no_warning_without_any_cgroup_file(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="api.cgroup_memory"):
        warn_if_memory_short(10, root=tmp_path)
    assert caplog.records == []


def test_unreadable_limit_logs_one_debug_line_and_no_warning(tmp_path, caplog):
    with caplog.at_level(logging.DEBUG, logger="api.cgroup_memory"):
        warn_if_memory_short(10, root=tmp_path)
    assert [r.levelno for r in caplog.records] == [logging.DEBUG]


def test_worker_start_checks_the_concurrency_it_runs_with(monkeypatch):
    """The check sees the value the loop starts with: the default, or an explicit --max-concurrent
    (the operator's value, which the check reads and never changes)."""
    from api.worker import _MAX_CONCURRENT_JOBS
    seen = []
    monkeypatch.setattr(queue_loop, "setup_logging", lambda: None)
    monkeypatch.setattr(queue_loop, "WorkerLoop", _FakeLoop)
    monkeypatch.setattr(queue_loop, "warn_if_memory_short", lambda n: seen.append(n))
    monkeypatch.setattr("api.db.init_db", lambda: None)
    monkeypatch.setattr("api.routes.jobs.retry_pending_cleanups", lambda: None)
    assert queue_loop.main(["--once"]) == 0
    assert queue_loop.main(["--once", "--max-concurrent", "3"]) == 0
    assert seen == [_MAX_CONCURRENT_JOBS, 3]


class _FakeLoop:
    def __init__(self, max_concurrent: int) -> None:
        self.max_concurrent = max_concurrent

    def run_once(self) -> int:
        return 0

    def forget(self) -> None:
        pass
