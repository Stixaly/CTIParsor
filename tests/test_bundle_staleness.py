# tests/test_bundle_staleness.py
import sqlite3
import subprocess

import pytest

from pipeline.bundle_revisions import (
    BUNDLE_AFFECTING,
    audit_staleness,
    git_rev_of,
    is_ancestor,
    resolve_commit,
    stale_entries,
)


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
    assert is_ancestor("deadbeef", "cafe1234") is None


def test_is_ancestor_code_128(monkeypatch):
    class MockResult:
        returncode = 128
    monkeypatch.setattr("pipeline.bundle_revisions.subprocess.run", lambda *args, **kwargs: MockResult())
    assert is_ancestor("deadbeef", "cafe1234") is None


def test_is_ancestor_never_passes_git_anything_but_commit_ids(monkeypatch):
    """A stored revision is data: one shaped like an option must not reach git."""
    calls = []
    monkeypatch.setattr("pipeline.bundle_revisions.subprocess.run", lambda *a, **k: calls.append(a))
    for rev in ("--output=/tmp/x", "-h", "HEAD", "abc123-dirty", "", "deadbeef;rm"):
        assert is_ancestor(rev, "cafe1234") is None
        assert is_ancestor("cafe1234", rev) is None
    assert calls == []


def test_is_ancestor_code_0_and_1(monkeypatch):
    class MockResult0:
        returncode = 0
    class MockResult1:
        returncode = 1

    monkeypatch.setattr("pipeline.bundle_revisions.subprocess.run", lambda *args, **kwargs: MockResult0())
    assert is_ancestor("deadbeef", "cafe1234") is True

    monkeypatch.setattr("pipeline.bundle_revisions.subprocess.run", lambda *args, **kwargs: MockResult1())
    assert is_ancestor("deadbeef", "cafe1234") is False


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture()
def history(tmp_path):
    """A -> B -> C in a throwaway repository: a shallow CI clone does not have
    the real history, so nothing here depends on it."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    shas = []
    for message in "ABC":
        _git(tmp_path, "commit", "-q", "--no-verify", "--allow-empty", "-m", message)
        shas.append(_git(tmp_path, "rev-parse", "HEAD"))
    return tmp_path, *shas


@pytest.mark.parametrize("entry_is_short", [False, True])
def test_a_bundle_built_at_the_fix_is_not_stale(history, monkeypatch, entry_is_short):
    """`merge-base --is-ancestor X X` succeeds: the commit that carries the fix
    must not be judged stale for lacking it."""
    repo, a, b, c = history
    entry = b[:7] if entry_is_short else b
    monkeypatch.setattr("pipeline.bundle_revisions.BUNDLE_AFFECTING", ((entry, "2026-01-01", "x", "mapping"),))

    assert [e[0] for e in stale_entries(a, repo)] == [entry]     # before the fix
    assert stale_entries(b, repo) == []                          # at it, long id
    assert stale_entries(b[:7], repo) == []                      # at it, short id
    assert stale_entries(c, repo) == []                          # after it


def test_resolve_commit(history):
    repo, a, b, _ = history
    assert resolve_commit(b[:7], repo) == resolve_commit(b, repo) == b
    assert resolve_commit(a, repo) != resolve_commit(b, repo)
    assert resolve_commit("deadbeef", repo) is None              # no such commit
    for bad in ("--output=/tmp/x", "HEAD", "", "deadbeef;rm"):
        assert resolve_commit(bad, repo) is None


def test_resolve_commit_git_missing(monkeypatch):
    def raise_error(*args, **kwargs):
        raise FileNotFoundError("git not found")
    monkeypatch.setattr("pipeline.bundle_revisions.subprocess.run", raise_error)
    assert resolve_commit("deadbeef") is None


def test_the_known_fixes_name_their_scope():
    assert {e[3] for e in BUNDLE_AFFECTING} <= {"mapping", "extraction"}
    assert [e[3] for e in BUNDLE_AFFECTING if e[0] == "eaee534"] == ["mapping"]
    assert [e[3] for e in BUNDLE_AFFECTING if e[0] == "3a25f45"] == ["extraction"]


def test_a_mapping_fix_is_judged_on_the_build_that_made_the_bundle(history, monkeypatch):
    """A finalize at a revision that has the fix rebuilds the bundle with it,
    whatever revision the run had; the reverse is not true."""
    repo, a, b, c = history
    monkeypatch.setattr("pipeline.bundle_revisions.BUNDLE_AFFECTING", ((b, "2026-01-01", "x", "mapping"),))

    assert stale_entries(a, repo, build_rev=c) == []                   # the run predates it, the rebuild has it
    assert stale_entries(a, repo, build_rev=b) == []
    assert [e[0] for e in stale_entries(c, repo, build_rev=a)] == [b]  # rebuilt by older code
    assert [e[0] for e in stale_entries(a, repo)] == [b]               # no build record: the run's
    assert stale_entries(a, repo, build_rev=None) == stale_entries(a, repo)


def test_an_extraction_fix_stays_stale_after_a_rebuild(history, monkeypatch):
    """A finalize rereads what the run extracted: only a new run clears it."""
    repo, a, b, c = history
    monkeypatch.setattr("pipeline.bundle_revisions.BUNDLE_AFFECTING", ((b, "2026-01-01", "x", "extraction"),))

    assert [e[0] for e in stale_entries(a, repo, build_rev=c)] == [b]  # rebuilt at a revision that has it
    assert [e[0] for e in stale_entries(c, repo, build_rev=a)] == [b]  # either revision predating it counts
    assert stale_entries(c, repo, build_rev=c) == []                   # a new run at a revision that has it
    assert stale_entries(c, repo) == []


def test_a_missing_revision_judges_nothing(history, monkeypatch):
    repo, a, b, _ = history
    monkeypatch.setattr("pipeline.bundle_revisions.BUNDLE_AFFECTING",
                        ((b, "2026-01-01", "x", "mapping"), (b, "2026-01-01", "y", "extraction")))
    assert stale_entries(None, repo) == [] and stale_entries(None, repo, build_rev=None) == []
    assert [e[2] for e in stale_entries(None, repo, build_rev=a)] == ["x", "y"]   # the build alone speaks
    assert [e[2] for e in stale_entries(a, repo, build_rev=b)] == ["y"]


def test_audit_staleness_reads_the_build_record(history, monkeypatch):
    repo, a, b, c = history
    monkeypatch.setattr("pipeline.bundle_revisions.BUNDLE_AFFECTING", ((b, "2026-01-01", "x", "mapping"),))
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY, run_config_json TEXT, bundle_build_json TEXT)")
    rows = [("rebuilt", f'{{"git_rev": "{a}"}}', f'{{"kind": "finalize", "git_rev": "{c}"}}'),
            ("not rebuilt", f'{{"git_rev": "{a}"}}', None),
            ("build only", None, f'{{"kind": "finalize", "git_rev": "{a}"}}'),
            ("nothing", None, None)]
    conn.executemany("INSERT INTO jobs VALUES (?, ?, ?)", rows)

    by_id = {r["job_id"]: r for r in audit_staleness(conn, repo)}

    assert (by_id["rebuilt"]["git_rev"], by_id["rebuilt"]["build_rev"]) == (a, c)
    assert by_id["rebuilt"]["stale"] == [] and by_id["rebuilt"]["unknown"] is False
    assert (by_id["not rebuilt"]["build_rev"], [e[0] for e in by_id["not rebuilt"]["stale"]]) == (None, [b])
    assert by_id["build only"]["unknown"] is False and [e[0] for e in by_id["build only"]["stale"]] == [b]
    assert (by_id["nothing"]["unknown"], by_id["nothing"]["stale"]) == (True, [])
    conn.close()


def test_audit_staleness(monkeypatch):
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY, run_config_json TEXT, bundle_build_json TEXT)")
    conn.execute("INSERT INTO jobs (id, run_config_json) VALUES ('job1', '{\"git_rev\": \"abc123\"}')")
    conn.execute("INSERT INTO jobs (id, run_config_json) VALUES ('job2', NULL)")
    conn.execute("INSERT INTO jobs (id, run_config_json) VALUES ('job3', 'invalid json')")
    conn.commit()

    monkeypatch.setattr("pipeline.bundle_revisions.is_ancestor", lambda *args, **kwargs: False)

    results = audit_staleness(conn)
    assert len(results) == 3

    expected_keys = {"job_id", "git_rev", "build_rev", "stale", "unknown"}

    for r in results:
        assert set(r.keys()) == expected_keys
        assert r["build_rev"] is None                    # no build record stored: the run's revision stands

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


def test_the_audit_names_both_revisions_when_they_differ(monkeypatch, capsys):
    """An "extraction" fix can be missing from the run while a finalize has it:
    saying only where the bundle was built would blame the wrong revision."""
    from scripts.audit_bundle_invariants import _report_staleness

    fix = ("3a25f45", "2026-09-29", "x", "extraction")
    mapping = ("eaee534", "2026-08-28", "y", "mapping")
    rows = [
        {"job_id": "aaaaaaaa-1", "git_rev": "a" * 40, "build_rev": "c" * 40, "stale": [fix], "unknown": False},
        {"job_id": "bbbbbbbb-2", "git_rev": "a" * 40, "build_rev": None, "stale": [mapping], "unknown": False},
        {"job_id": "cccccccc-3", "git_rev": "a" * 40, "build_rev": "a" * 40, "stale": [fix], "unknown": False},
        {"job_id": "dddddddd-4", "git_rev": None, "build_rev": "c" * 40, "stale": [mapping], "unknown": False},
    ]
    monkeypatch.setattr("pipeline.bundle_revisions.audit_staleness", lambda conn: rows)

    _report_staleness(None)

    out = capsys.readouterr().out
    assert "  aaaaaaaa  run aaaaaaaaa, built ccccccccc  predates 3a25f45" in out
    assert "  bbbbbbbb  built at aaaaaaaaa  predates eaee534" in out          # no build record
    assert "  cccccccc  built at aaaaaaaaa  predates 3a25f45" in out          # the same revision
    assert "  dddddddd  built at ccccccccc  predates eaee534" in out          # no run revision
    assert "only a new run" in out and "rebuild with POST" in out
