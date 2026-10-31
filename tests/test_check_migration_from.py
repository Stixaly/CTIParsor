"""scripts/check_migration_from.py: which refs it checks, its exit codes, the
throwaway database it always drops, and how it judges the state directory's
files (ADR-0094 item 2).  The migration itself runs in CI, from a git archive
(fast-tests, "Migrate databases written by the last release and the base
commit"); tests/test_migration_*.py cover its steps without one."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import check_migration_from as cmf
from scripts import migration_compare as mc
from scripts import migration_seed as ms

_URL = "postgresql://nobody@127.0.0.1:1/nothing"
_DB = "postgresql://u@h/ctiparsor_migcheck_0"


def test_the_last_release_is_the_highest_version_tag_reachable_from_head(monkeypatch):
    calls = []

    def git(*args: str) -> str:
        calls.append(args)
        return "v1.0.0-rc1\nv0.10.0\nv0.9.1\nvnext\nv0.2.0"         # as git sorts them, highest first

    monkeypatch.setattr(cmf, "git", git)
    assert cmf.last_release() == "v0.10.0"                           # a pre-release is not a release
    assert calls == [("tag", "--merged", "HEAD", "--list", "v*", "--sort=-v:refname")]
    monkeypatch.setattr(cmf, "git", lambda *args: "")
    with pytest.raises(cmf.Unusable, match="no tag vX.Y.Z is reachable from HEAD"):
        cmf.last_release()


def test_refs_resolve_to_commits_and_one_commit_is_checked_once(capsys):
    head = cmf.git("rev-parse", "HEAD")
    assert cmf.resolve(["HEAD", head]) == [("HEAD", head)]
    assert f"{head}: the same commit as HEAD, checked once" in capsys.readouterr().out
    with pytest.raises(cmf.Unusable, match="unknown ref: no-such-ref"):
        cmf.resolve(["HEAD", "no-such-ref"])


def test_usage_and_environment_errors_exit_2(monkeypatch, capsys):
    with pytest.raises(SystemExit) as caught:
        cmf.main([])
    assert caught.value.code == 2
    monkeypatch.delenv("CTIPARSOR_TEST_DATABASE_URL", raising=False)
    assert cmf.main(["HEAD"]) == 2
    assert "CTIPARSOR_TEST_DATABASE_URL is required" in capsys.readouterr().err
    monkeypatch.setenv("CTIPARSOR_TEST_DATABASE_URL", _URL)
    assert cmf.main(["no-such-ref"]) == 2
    assert "unknown ref: no-such-ref" in capsys.readouterr().err


def test_a_server_it_cannot_create_a_database_on_exits_2_in_one_line(monkeypatch, capsys):
    monkeypatch.setenv("CTIPARSOR_TEST_DATABASE_URL", _URL)               # nothing listens on port 1
    assert cmf.main(["HEAD"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("check_migration_from: cannot create a database on 127.0.0.1:1: ")
    assert err.count(chr(10)) == 1 and "Traceback" not in err


def test_every_ref_is_checked_and_any_failure_exits_1(monkeypatch):
    monkeypatch.setenv("CTIPARSOR_TEST_DATABASE_URL", _URL)
    monkeypatch.setattr(cmf, "last_release", lambda: "v0.2.0")
    monkeypatch.setattr(cmf, "resolve", lambda refs: [(ref, f"commit-{ref}") for ref in refs])
    seen: list[str] = []

    def check(ref: str, commit: str, url: str) -> bool:
        seen.append(ref)
        return ref != "bad"

    monkeypatch.setattr(cmf, "check", check)
    assert cmf.main(["--last-release", "base"]) == 0
    assert seen == ["v0.2.0", "base"]
    assert cmf.main(["bad", "good"]) == 1
    assert seen[-2:] == ["bad", "good"]                              # a failure does not stop the next ref


def _migcheck_databases() -> set[str]:
    import psycopg

    with psycopg.connect(os.environ["CTIPARSOR_TEST_DATABASE_URL"], autocommit=True) as admin:
        rows = admin.execute("SELECT datname FROM pg_database WHERE datname LIKE 'ctiparsor_migcheck_%'").fetchall()
    return {r[0] for r in rows}


@pytest.mark.parametrize("outcome", ["passes", "differs", "fails", "breaks", "unusable"])
def test_the_throwaway_database_is_dropped_whatever_happens(monkeypatch, capsys, outcome):
    if not os.getenv("CTIPARSOR_TEST_DATABASE_URL"):
        pytest.fail("CTIPARSOR_TEST_DATABASE_URL is required (ADR-0053)")
    used: list[str] = []

    def step(commit, url, tmp, version, connect):
        used.append(url.rsplit("/", 1)[1])
        assert used[0] in _migcheck_databases() and tmp.is_dir()
        if outcome == "fails":
            raise cmf.Failed("python -m api.migrate exited 1")
        if outcome == "breaks":
            raise RuntimeError("the seed met a column of another type")
        if outcome == "unusable":
            raise cmf.Unusable("git archive ce59cfb: fatal")
        return [] if outcome == "passes" else ["jobs [id='a'] status: 'failed' -> 'error'"]

    monkeypatch.setattr(cmf, "_check", step)
    url = os.environ["CTIPARSOR_TEST_DATABASE_URL"]
    if outcome == "unusable":                                        # exit 2 for the whole run
        with pytest.raises(cmf.Unusable):
            cmf.check("v0.2.0", "ce59cfb7025daf46fcb661b71c1ac7cd23f3f16b", url)
    else:
        assert cmf.check("v0.2.0", "ce59cfb7025daf46fcb661b71c1ac7cd23f3f16b", url) is (outcome == "passes")
    assert len(used) == 1 and used[0] not in _migcheck_databases()
    out = capsys.readouterr().out
    assert out.startswith("== v0.2.0 (ce59cfb)\n")
    if outcome == "breaks":
        assert "  RuntimeError: the seed met a column of another type\n" in out
    if outcome != "unusable":
        assert ("ok   v0.2.0 (ce59cfb): " if outcome == "passes" else "FAIL v0.2.0 (ce59cfb): ") in out


def test_the_state_directory_s_files_are_kept_and_db_identity_keeps_its_meaning(tmp_path):
    address = "127.0.0.1:5432/ctiparsor_migcheck_0/public"

    def record(sid: str, version: int) -> None:
        entry = {"system_identifier": sid, "schema_version": version, "recorded_at": "2026-10-31T10:00:00+00:00"}
        (tmp_path / "db-identity.json").write_text(json.dumps({address: entry}), encoding="utf-8")

    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / "a.txt").write_bytes(b"source")
    (tmp_path / "output").mkdir()
    (tmp_path / "output" / "a_bundle.json").write_bytes(b"{}")
    record("7301", 11)
    before, recorded = cmf.state_files(tmp_path), cmf.identity(tmp_path)
    assert sorted(before) == ["db-identity.json", "output/a_bundle.json", "uploads/a.txt"]

    record("7301", 13)                    # this code's start rewrote it: same cluster, its own version
    assert cmf.file_differences(tmp_path, before, recorded, 13) == []

    (tmp_path / "uploads" / "a.txt").write_bytes(b"rewritten")
    (tmp_path / "output" / "a_bundle.json").unlink()
    record("8802", 12)
    assert cmf.file_differences(tmp_path, before, recorded, 13) == [
        "output/a_bundle.json: deleted",
        "uploads/a.txt: changed",
        f"db-identity.json: {address} moved to cluster 8802",
        f"db-identity.json: {address} records schema version 12, not 13",
    ]
    (tmp_path / "db-identity.json").write_text("{}", encoding="utf-8")
    assert cmf.file_differences(tmp_path, before, recorded, 13)[-1] == \
        f"db-identity.json: the entry for {address} is gone"


def test_both_trees_run_against_the_throwaway_database_and_state_directory(tmp_path):
    env = cmf.environment("postgresql://u@h/db", tmp_path)
    assert env["DATABASE_URL"] == "postgresql://u@h/db" and env["CTIPARSOR_ROLE"] == "api"
    assert (env["CTIPARSOR_STATE_DIR"], env["CTIPARSOR_UPLOADS_DIR"], env["CTIPARSOR_OUTPUT_DIR"]) == (
        str(tmp_path), str(tmp_path / "uploads"), str(tmp_path / "output"))
    assert env["PYTHON_DOTENV_DISABLED"] == "1"


def test_no_dotenv_reaches_the_processes_of_either_tree(tmp_path):
    """api/db.py and Stage 3 call load_dotenv(), which finds the checkout's
    .env: the pinned python-dotenv skips it under PYTHON_DOTENV_DISABLED."""
    (tmp_path / ".env").write_text("CTIPARSOR_MIGCHECK_PROBE=from-dotenv" + chr(10), encoding="utf-8")
    probe = "import os; from dotenv import load_dotenv; load_dotenv(); print(os.getenv('CTIPARSOR_MIGCHECK_PROBE'))"
    env = {k: v for k, v in cmf.environment(_DB, tmp_path).items() if k != "CTIPARSOR_MIGCHECK_PROBE"}
    without = {k: v for k, v in env.items() if k != "PYTHON_DOTENV_DISABLED"}
    for environ, seen in ((without, "from-dotenv"), (env, "None")):          # the control, then the check
        done = subprocess.run([sys.executable, "-c", probe], cwd=tmp_path, env=environ, capture_output=True,
                              text=True, check=True)
        assert done.stdout.strip() == seen


def test_a_step_that_fails_shows_the_end_of_its_stderr(tmp_path):
    script = "import sys; print(chr(10).join(f'line {i}' for i in range(100)), file=sys.stderr); sys.exit(3)"
    with pytest.raises(cmf.Failed) as caught:
        cmf.run([sys.executable, "-c", script], tmp_path, dict(os.environ))
    lines = str(caught.value).splitlines()
    assert " exited 3:" in lines[0] and lines[-40:] == [f"line {i}" for i in range(60, 100)]
    assert "line 59" not in lines


# ── _check, its steps stubbed ────────────────────────────────────────────────

class _Conn:
    def close(self) -> None:
        pass


def _snapshot(status: str, status_type: str = "text") -> mc.Snapshot:
    return {"schema_migrations": mc.Table({"version": "integer"}, ("version",), {(13,): {"version": 13}}),
            "jobs": mc.Table({"id": "text", "status": status_type}, ("id",), {("a",): {"id": "a", "status": status}})}


_READ = {"passed": 3, "mismatches": [], "skipped": []}


def _stub(monkeypatch, reads, readback=_READ, stderr="", release_builds=False) -> dict:
    """`_check` with git, both trees' processes, the seed and the database
    stubbed: `reads` are what the three reads of every table return (steps 3, 5
    and 7), `readback` what the read-back writes (None: it writes nothing)."""
    snapshots, seen = iter(reads), {}

    def extract(commit, dest):
        dest.mkdir(parents=True)
        if release_builds:
            shutil.copytree(ms.STAGE4, dest / "tests" / "fixtures" / "stage4_reference")

    def seed(conn, state, stage4=None):
        seen["stage4"] = stage4
        (state / "uploads").mkdir(parents=True)
        (state / "uploads" / "a.txt").write_bytes(b"source")
        return ms.Seeded(rows={"jobs": [{"id": "a", "status": "failed"}]}, files={"uploads/a.txt": "-"})

    def run(cmd, cwd, env, ok=(0,)):
        if cmd[1].endswith("migration_readback.py"):
            if readback is not None:
                Path(cmd[3]).write_text(json.dumps(readback), encoding="utf-8")
            failed = readback is None or bool(readback["mismatches"])
            return subprocess.CompletedProcess(cmd, int(failed), "", stderr)
        return subprocess.CompletedProcess(cmd, 0, "[db] schema version 13 -> 13; applied -, recognised -", "")

    monkeypatch.setattr(cmf, "extract", extract)
    monkeypatch.setattr(cmf, "run", run)
    monkeypatch.setattr(ms, "seed", seed)
    monkeypatch.setattr(ms, "coverage_errors", lambda conn, seeded: [])
    monkeypatch.setattr(mc, "snapshot", lambda conn: next(snapshots))
    monkeypatch.setattr(mc, "sequence_differences", lambda conn, tables: (1, []))
    return seen


def _run_check(tmp_path) -> list[str]:
    return cmf._check("c0ffee", _DB, tmp_path, 13, lambda url: _Conn())


def test_check_finds_nothing_when_nothing_changed(monkeypatch, tmp_path, capsys):
    seen = _stub(monkeypatch, [_snapshot("failed")] * 3)
    assert _run_check(tmp_path) == []
    out = capsys.readouterr().out
    assert seen["stage4"] is None and "payloads: current fixtures, the release has none" in out
    assert "content: 2 tables, 2 rows, 3 values compared; every one kept" in out
    assert "sequences: 1 identity column(s); each one's next value above the highest stored" in out
    assert "after the read-back: 2 tables, 2 rows, 3 values compared; every one kept" in out
    assert "files: 1 in the state directory; every one unchanged (no db-identity.json" in out


def test_check_seeds_the_release_s_own_builds_when_its_tree_has_them(monkeypatch, tmp_path, capsys):
    seen = _stub(monkeypatch, [_snapshot("failed")] * 3, release_builds=True)
    assert _run_check(tmp_path) == []
    assert seen["stage4"] == tmp_path / "old" / "tests" / "fixtures" / "stage4_reference"
    assert "payloads: the release's own Stage 4 reference builds" in capsys.readouterr().out


@pytest.mark.parametrize(("reads", "readback", "problems"), [
    # the migration rewrote a value
    ([_snapshot("failed"), _snapshot("error"), _snapshot("error")], _READ,
     ["jobs [id='a'] status: 'failed' -> 'error'"]),
    # the app's first start, or a read route, did (step 7)
    ([_snapshot("failed"), _snapshot("failed"), _snapshot("error")], _READ,
     ["jobs [id='a'] status: 'failed' -> 'error'"]),
    # the migration retyped a column
    ([_snapshot("failed"), _snapshot("failed", "character varying"), _snapshot("failed", "character varying")],
     _READ, ["jobs.status: retyped text -> character varying"]),
    # a route no longer returns what was stored
    ([_snapshot("failed")] * 3, {"passed": 2, "mismatches": ["GET /api/jobs [a] status: expected 'failed'"],
                                 "skipped": []}, ["GET /api/jobs [a] status: expected 'failed'"]),
])
def test_check_returns_every_difference(monkeypatch, tmp_path, reads, readback, problems):
    _stub(monkeypatch, reads, readback)
    assert _run_check(tmp_path) == problems


def test_check_returns_a_sequence_left_behind(monkeypatch, tmp_path):
    _stub(monkeypatch, [_snapshot("failed")] * 3)
    behind = mc.Difference("review_decisions", "", "id", 6, "its sequence gives 1 next")
    monkeypatch.setattr(mc, "sequence_differences", lambda conn, tables: (1, [behind]))
    assert _run_check(tmp_path) == ["review_decisions.id: its sequence gives 1 next"] * 2     # steps 5 and 7


def test_a_read_back_that_breaks_fails_the_ref_with_its_stderr(monkeypatch, tmp_path):
    frames = "".join("  a frame" + chr(10) for _ in range(60))
    stderr = "Traceback (most recent call last):" + chr(10) + frames + "ValueError: STIX_TLP 'bogus'"
    _stub(monkeypatch, [_snapshot("failed")] * 3, readback=None, stderr=stderr)
    with pytest.raises(cmf.Failed) as caught:
        _run_check(tmp_path)
    lines = str(caught.value).splitlines()
    assert lines[0] == "the read-back exited 1 without a result:"
    assert lines[-1] == "ValueError: STIX_TLP 'bogus'" and len(lines) == 41
