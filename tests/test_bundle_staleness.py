# tests/test_bundle_staleness.py
import sqlite3

import pytest

from pipeline.bundle_revisions import BUNDLE_AFFECTING, audit_staleness, git_rev_of, is_ancestor, stale_entries


def test_git_rev_of_none():
    assert git_rev_of(None) is None


def test_git_rev_of_empty_string():
    assert git_rev_of("") is None


def test_git_rev_of_invalid_json():
    assert git_rev_of("{pas du json") is None


def test_git_rev_of_list_json():
    assert git_rev_of('["une", "liste"]') is None


def test_git_rev_of_valid():
    assert git_rev_of('{"git_rev": "abc123"}') == "abc123"


def test_git_rev_of_whitespace_only():
    assert git_rev_of('{"git_rev": "   "}') is None


def test_git_rev_of_missing_key():
    assert git_rev_of('{"autre": 1}') is None


def test_stale_entries_none():
    assert stale_entries(None) == []


def test_stale_entries_true(monkeypatch):
    monkeypatch.setattr("pipeline.bundle_revisions.is_ancestor", lambda *args, **kwargs: True)
    result = stale_entries("deadbeef")
    assert len(result) == len(BUNDLE_AFFECTING)


def test_stale_entries_false(monkeypatch):
    monkeypatch.setattr("pipeline.bundle_revisions.is_ancestor", lambda *args, **kwargs: False)
    assert stale_entries("deadbeef") == []


def test_stale_entries_none_verdict(monkeypatch):
    monkeypatch.setattr("pipeline.bundle_revisions.is_ancestor", lambda *args, **kwargs: None)
    assert stale_entries("deadbeef") == []


def test_is_ancestor_file_not_found(monkeypatch):
    def raise_error(*args, **kwargs):
        raise FileNotFoundError("git not found")
    monkeypatch.setattr("pipeline.bundle_revisions.subprocess.run", raise_error)
    assert is_ancestor("rev", "desc") is None


def test_is_ancestor_code_128(monkeypatch):
    class MockResult:
        returncode = 128
    monkeypatch.setattr("pipeline.bundle_revisions.subprocess.run", lambda *args, **kwargs: MockResult())
    assert is_ancestor("rev", "desc") is None


def test_is_ancestor_code_0_and_1(monkeypatch):
    class MockResult0:
        returncode = 0
    class MockResult1:
        returncode = 1

    monkeypatch.setattr("pipeline.bundle_revisions.subprocess.run", lambda *args, **kwargs: MockResult0())
    assert is_ancestor("rev", "desc") is True

    monkeypatch.setattr("pipeline.bundle_revisions.subprocess.run", lambda *args, **kwargs: MockResult1())
    assert is_ancestor("rev", "desc") is False


def test_audit_staleness():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY, run_config_json TEXT)")
    conn.execute("INSERT INTO jobs (id, run_config_json) VALUES ('job1', '{\"git_rev\": \"abc123\"}')")
    conn.execute("INSERT INTO jobs (id, run_config_json) VALUES ('job2', NULL)")
    conn.execute("INSERT INTO jobs (id, run_config_json) VALUES ('job3', 'invalid json')")
    conn.commit()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("pipeline.bundle_revisions.is_ancestor", lambda *args, **kwargs: False)

    results = audit_staleness(conn)
    assert len(results) == 3

    expected_keys = {"job_id", "git_rev", "stale", "unknown"}

    for r in results:
        assert set(r.keys()) == expected_keys

    job1 = next(r for r in results if r["job_id"] == "job1")
    assert job1["git_rev"] == "abc123"
    assert job1["unknown"] is False
    assert job1["stale"] == []

    job2 = next(r for r in results if r["job_id"] == "job2")
    assert job2["git_rev"] is None
    assert job2["unknown"] is True
    assert job2["stale"] == []

    job3 = next(r for r in results if r["job_id"] == "job3")
    assert job3["git_rev"] is None
    assert job3["unknown"] is True
    assert job3["stale"] == []

    conn.close()
