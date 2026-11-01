"""scripts/check_backup_restore.py and scripts/check_backup_restore_docker.sh:
the backup and restore of docs/docker.md, checked (ADR-0094 item 3).

The real pg_dump and pg_restore run in CI (fast-tests, "Back up a used install
and restore it into an empty one", in the PostgreSQL service's container) and
the documented commands themselves in the container-image job
(scripts/docker_smoke.sh --backup-restore).  Here pg_dump and pg_restore are
replaced by a copy of the source database (CREATE DATABASE ... TEMPLATE), so
that every other step runs for real: the commands and their flags, the strict
comparison, the files, db-identity.json."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
import pytest

from api import migrate
from api import migrations as history
from api.db_backend import PgConnection
from scripts import check_backup_restore as cbr
from scripts import migration_seed as ms

ROOT = Path(__file__).resolve().parent.parent
_URL = "postgresql://ctiparsor:s%40cret@127.0.0.1:1/ctiparsor"


def _admin() -> str:
    url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    if not url:
        pytest.fail("CTIPARSOR_TEST_DATABASE_URL is required (ADR-0053)")
    return url


# ── The documented commands ──────────────────────────────────────────────────

def _docs_blocks() -> dict[str, list[str]]:
    """The fenced blocks of docs/docker.md marked for the script, by name."""
    text = (ROOT / "docs" / "docker.md").read_text(encoding="utf-8")
    found = re.findall(r"<!-- scripts/check_backup_restore_docker\.sh: (\w+) -->\n```bash\n(.*?)\n```", text, re.DOTALL)
    return {name: block.split("\n") for name, block in found}


def _script_blocks() -> dict[str, list[str]]:
    text = (ROOT / "scripts" / "check_backup_restore_docker.sh").read_text(encoding="utf-8")
    found = re.findall(r"read -r -d '' (\w+) <<'COMMANDS'\n(.*?)\nCOMMANDS\n", text, re.DOTALL)
    return {name: block.split("\n") for name, block in found}


def test_the_smoke_runs_the_commands_of_the_docs_as_written():
    docs, script = _docs_blocks(), _script_blocks()
    assert sorted(docs) == ["BACKUP_COMMANDS", "CHECK_COMMANDS", "RESTORE_COMMANDS"]
    assert docs == script
    assert docs["BACKUP_COMMANDS"][:2] == [
        "day=$(date +%F)",                    # one date for both files
        "docker compose stop app worker"]     # one moment for both
    # The files hold every report: readable by their owner only.  The umask is
    # set in a subshell of each command that writes one, so that it does not
    # stay in the operator's shell (ADR-0094 item 9: a release unpacked there
    # next came out unreadable by the containers).
    writers = [line for line in docs["BACKUP_COMMANDS"] if " > " in line]
    assert len(writers) == 2
    assert all(line.startswith("(umask 077; docker compose ") and line.endswith(")") for line in writers)
    assert docs["RESTORE_COMMANDS"][0] == "docker compose up -d --wait postgres"    # the database first


def _documented(block: str, program: str) -> list[str]:
    """`program` and its arguments in a documented command, up to its
    redirection (`--entrypoint tar app czf ...`: the service name left out)."""
    for line in _docs_blocks()[block]:
        words = shlex.split(line)
        if program in words:
            at = words.index(program)
            rest = words[at + 2:] if words[at - 1] == "--entrypoint" else words[at + 1:]
            return [program, *rest[:next((i for i, w in enumerate(rest) if w in ("<", ">", "|")), len(rest))]]
    raise AssertionError(f"no {program} in {block}")


def _named(words: list[str], values: dict[str, str]) -> list[str]:
    """The words, each flag of `values` given that value instead."""
    out = list(words)
    for flag, value in values.items():
        out[out.index(flag) + 1] = value
    return out


# ── Where pg_dump and pg_restore run ─────────────────────────────────────────

def _versions(monkeypatch, stdout: str | dict[str, str] = "pg_dump (PostgreSQL) 18.1\n", returncode: int = 0,
              stderr: str = "") -> list[tuple[list[str], dict]]:
    """`--version` answered with `stdout`, or with stdout[program]."""
    calls: list[tuple[list[str], dict]] = []

    def run(cmd, env=None, **kwargs):
        calls.append((list(cmd), dict(env or {})))
        out = stdout[cmd[-2]] if isinstance(stdout, dict) else stdout
        return subprocess.CompletedProcess(cmd, returncode, out, stderr)

    monkeypatch.setattr(cbr.subprocess, "run", run)
    return calls


def test_the_tools_run_in_the_server_s_container_the_password_in_the_environment(monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "not-this-one")
    calls = _versions(monkeypatch)
    pg = cbr.tools(_URL, "5f2c0d9e", 18)
    assert pg.prefix == ("docker", "exec", "-i", "-e", "PGPASSWORD", "5f2c0d9e")
    assert pg.command("pg_dump", "-Fc") == ["docker", "exec", "-i", "-e", "PGPASSWORD", "5f2c0d9e", "pg_dump", "-Fc"]
    assert pg.env["PGPASSWORD"] == "s@cret" and "PGHOST" not in pg.env
    assert pg.version == "pg_dump (PostgreSQL) 18.1, in container 5f2c0d9e"
    assert calls == [(["docker", "exec", "-i", "-e", "PGPASSWORD", "5f2c0d9e", program, "--version"], pg.env)
                     for program in ("pg_dump", "pg_restore")]
    assert not any("s@cret" in word for cmd, _ in calls for word in cmd)


def test_without_a_container_this_host_s_pg_dump_must_be_as_new_as_the_server(monkeypatch):
    monkeypatch.setattr(cbr.shutil, "which", lambda name: None)
    with pytest.raises(cbr.Unusable, match="no pg_dump on this host: name the PostgreSQL server's container"):
        cbr.tools(_URL, None, 18)
    monkeypatch.setattr(cbr.shutil, "which", lambda name: "/usr/bin/pg_dump")
    _versions(monkeypatch, "pg_dump (PostgreSQL) 16.4 (Ubuntu 16.4-0ubuntu0.24.04.2)\n")
    with pytest.raises(cbr.Unusable, match=r"older than the server \(PostgreSQL 18\), which it cannot dump"):
        cbr.tools(_URL, None, 18)
    _versions(monkeypatch, {"pg_dump": "pg_dump (PostgreSQL) 18.1\n",
                            "pg_restore": "pg_restore (PostgreSQL) 16.4\n"})
    with pytest.raises(cbr.Unusable, match=r"^pg_restore on this host is 'pg_restore \(PostgreSQL\) 16.4', older"):
        cbr.tools(_URL, None, 18)
    _versions(monkeypatch, "pg_dump (PostgreSQL) 18.1\n")
    pg = cbr.tools(_URL, None, 17)
    assert pg.prefix == ()
    assert (pg.env["PGHOST"], pg.env["PGPORT"], pg.env["PGPASSWORD"]) == ("127.0.0.1", "1", "s@cret")


def test_a_container_docker_cannot_reach_is_unusable(monkeypatch):
    _versions(monkeypatch, "", 1, "Error response from daemon: No such container: nosuch\n")
    with pytest.raises(cbr.Unusable, match="exited 1: Error response from daemon: No such container: nosuch$"):
        cbr.tools(_URL, "nosuch", 18)

    def missing(cmd, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "docker")

    monkeypatch.setattr(cbr.subprocess, "run", missing)
    with pytest.raises(cbr.Unusable, match="docker exec -i -e PGPASSWORD nosuch pg_dump --version: "):
        cbr.tools(_URL, "nosuch", 18)


def test_the_major_version_is_read_from_pg_dump_s_banner():
    assert cbr.major("pg_dump (PostgreSQL) 17.11") == 17
    assert cbr.major("pg_dump (PostgreSQL) 18.1 (Debian 18.1-1.pgdg13+2)") == 18
    assert cbr.major("garbage") is None


# ── Running a command ────────────────────────────────────────────────────────

def test_a_command_reads_and_writes_files_as_the_docs_redirect_them(tmp_path):
    source, copy = tmp_path / "in.bin", tmp_path / "out.bin"
    source.write_bytes(b"\x00\x01dump")
    cat = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"]
    assert cbr.tool(cat, None, stdin=source, stdout=copy) == ""
    assert copy.read_bytes() == b"\x00\x01dump"
    assert stat.S_IMODE(copy.stat().st_mode) == 0o600                         # the docs' umask 077
    assert cbr.tool(cat, None, stdin=source) == "\x00\x01dump"


def test_a_command_that_fails_or_complains_fails_the_check(tmp_path):
    loud = "import sys; print('pg_restore: error: could not execute query', file=sys.stderr); sys.exit({})"
    with pytest.raises(cbr.Failed) as caught:
        cbr.tool([sys.executable, "-c", loud.format(1)], None)
    assert " exited 1:" in str(caught.value) and str(caught.value).endswith("could not execute query")
    with pytest.raises(cbr.Failed, match="exited 0 but printed:\npg_restore: error: could not execute query"):
        cbr.tool([sys.executable, "-c", loud.format(0)], None, silent=True)
    assert cbr.tool([sys.executable, "-c", loud.format(0)], None) == ""         # pg_restore -l, pg_dump: stderr allowed
    with pytest.raises(cbr.Failed) as caught:
        cbr.tool([sys.executable, "-c", loud.format(2)], None, shown=1)
    assert str(caught.value).startswith("-c import sys")                       # the leading words left out


def test_the_state_directory_is_read_file_by_file(tmp_path):
    (tmp_path / "uploads" / "meta").mkdir(parents=True)
    (tmp_path / "uploads" / "a.txt").write_bytes(b"source")
    (tmp_path / "backups").mkdir()
    (tmp_path / "link").symlink_to("uploads/a.txt")
    assert cbr.state_tree(tmp_path) == {
        "directory backups": "", "link link": "uploads/a.txt", "directory uploads": "",
        "file uploads/a.txt": "sha256 " + hashlib.sha256(b"source").hexdigest(),
        "directory uploads/meta": ""}


def test_db_identity_keeps_the_source_s_entry_and_gains_the_target_s(tmp_path):
    source = "127.0.0.1:5432/ctiparsor_restorecheck_a/public"
    target = "127.0.0.1:5432/ctiparsor_restorecheck_b/public"
    entry = {"system_identifier": "7301", "schema_version": 13, "recorded_at": "2026-10-31T10:00:00+00:00"}

    def now(entries: dict) -> list[str]:
        (tmp_path / "db-identity.json").write_text(json.dumps(entries), encoding="utf-8")
        return cbr.identity_differences(tmp_path, {source: entry}, "ctiparsor_restorecheck_b", 13)

    later = {**entry, "recorded_at": "2026-10-31T10:01:00+00:00"}
    assert now({source: entry, target: later}) == []
    assert now({source: later, target: later}) == [
        f"db-identity.json: the entry for {source} changed: {entry!r} -> {later!r}"]
    assert now({source: entry, target: {**later, "system_identifier": "8802"}}) == [
        f"db-identity.json: {target} is not on the source's cluster: {dict(later, system_identifier='8802')!r}"]
    assert now({source: entry, target: {**later, "schema_version": 12}}) == [
        f"db-identity.json: {target} records schema version 12, not 13"]
    assert now({source: entry}) == ["db-identity.json: one entry added, for ctiparsor_restorecheck_b, expected; "
                                    "got none"]


# ── _check, pg_dump and pg_restore replaced by a template copy ────────────────

def _url(name: str) -> str:
    return urlsplit(_admin())._replace(path=f"/{name}").geturl()


def _databases() -> set[str]:
    with psycopg.connect(_admin(), autocommit=True) as admin:
        rows = admin.execute("SELECT datname FROM pg_database WHERE datname LIKE 'ctiparsor_restorecheck_%'").fetchall()
    return {r[0] for r in rows}


def _start(url: str, env: dict) -> None:
    """This code's start, in this process: the schema, db-identity.json."""
    with pytest.MonkeyPatch.context() as m:
        m.setenv("CTIPARSOR_STATE_DIR", env["CTIPARSOR_STATE_DIR"])
        conn = PgConnection(url)
        try:
            migrate.upgrade(conn)
        finally:
            conn.close()


def _fakes(monkeypatch, tamper: str = "") -> tuple[list[list[str]], list[bool]]:
    """The commands `_check` runs, and for each whether it must print nothing,
    recorded; pg_dump and pg_restore replaced by a copy of the source database,
    init_db and the read-back by this code's start in this process.  `tamper`:
    what goes wrong in the restore."""
    commands: list[list[str]] = []
    silent: list[bool] = []
    real_tool = cbr.tool
    names: dict[str, str] = {}

    def tool(cmd, env, **kwargs):
        commands.append(list(cmd))
        silent.append(bool(kwargs.get("silent")))
        words = cmd[next(i for i, w in enumerate(cmd) if w in ("pg_dump", "pg_restore", "tar")):]
        if words[0] == "pg_dump":
            names["source"] = words[words.index("-d") + 1]
            kwargs["stdout"].write_bytes(b"PGDMP")
            return ""
        if words == ["pg_restore", "-l"]:
            conn = PgConnection(_url(names["source"]))
            tables = [r["table_name"] for r in conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'").fetchall()]
            conn.close()
            return "".join(f"{3600 + i}; 0 {16000 + i} TABLE DATA public {t} ctiparsor\n" for i, t in enumerate(tables))
        if words[0] == "pg_restore":
            target = words[words.index("-d") + 1]
            with psycopg.connect(_admin(), autocommit=True) as admin:
                admin.execute(f'DROP DATABASE "{target}"')
                admin.execute(f'CREATE DATABASE "{target}" TEMPLATE "{names["source"]}"')
            sql = {"row": "DELETE FROM review_decisions WHERE id = (SELECT max(id) FROM review_decisions)",
                   # a text key, no sequence: only the strict comparison sees it
                   "extra-row": "INSERT INTO jobs SELECT (jsonb_populate_record(NULL::jobs, to_jsonb(j) "
                                "|| '{\"id\": \"restore-extra\"}')).* FROM jobs j LIMIT 1",
                   "trigger": "DROP TRIGGER entities_review_revision ON entities",
                   "sequence": "ALTER TABLE progress_events ALTER COLUMN id RESTART WITH 1"}.get(tamper)
            if sql:
                with psycopg.connect(_url(target), autocommit=True) as restored:
                    restored.execute(sql)
            return ""
        out = real_tool(cmd, env, **kwargs)
        if tamper == "file" and words[:2] == ["tar", "xzf"]:
            (Path(words[-1]) / "uploads" / f"{ms.JOB_D}.docx").write_bytes(b"not the upload")
        if tamper == "added-file" and words[:2] == ["tar", "xzf"]:
            (Path(words[-1]) / "uploads" / "restore-extra.txt").write_bytes(b"not in the backup")
        return out

    def run(cmd, cwd, env, ok=(0,)):
        url = env["DATABASE_URL"]
        _start(url, env)
        if cmd[1].endswith("migration_readback.py"):
            Path(cmd[3]).write_text(json.dumps({"passed": 7, "mismatches": [], "skipped": []}), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(cbr, "tool", tool)
    monkeypatch.setattr(cbr, "run", run)
    return commands, silent


def _run(tmp_path, capsys=None) -> tuple[list[str], str, str, cbr.Tools]:
    source, target = f"{cbr.PREFIX}t{os.getpid()}a", f"{cbr.PREFIX}t{os.getpid()}b"
    pg = cbr.Tools(("docker", "exec", "-i", "-e", "PGPASSWORD", "pg"), {}, "pg_dump (PostgreSQL) 18.1, in container pg")
    with psycopg.connect(_admin(), autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{source}"')
    try:
        user = urlsplit(_admin()).username or ""
        problems = cbr._check(_admin(), user, source, target, tmp_path, pg, history.latest_version(), PgConnection)
    finally:
        with psycopg.connect(_admin(), autocommit=True) as admin:
            for name in (source, target):
                admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    return problems, source, target, pg


def test_check_runs_the_documented_commands_and_finds_everything_back(monkeypatch, tmp_path, capsys):
    commands, silent = _fakes(monkeypatch)
    problems, source, target, pg = _run(tmp_path)
    assert problems == []
    user = urlsplit(_admin()).username or ""
    prefix = list(pg.prefix)
    # The docs' commands, their flags in their order: only the names and the paths differ.
    assert commands == [
        prefix + _named(_documented("BACKUP_COMMANDS", "pg_dump"), {"-U": user, "-d": source}),
        prefix + _documented("CHECK_COMMANDS", "pg_restore"),
        _named(_documented("BACKUP_COMMANDS", "tar"), {"-C": str(tmp_path / "state")}),
        prefix + _named(_documented("RESTORE_COMMANDS", "pg_restore"), {"-U": user, "-d": target}),
        _named(_documented("RESTORE_COMMANDS", "tar"), {"-C": str(tmp_path / "restored")}),
    ]
    assert commands[0][len(prefix):] == ["pg_dump", "-U", user, "-d", source, "-Fc"]
    assert commands[3][len(prefix):] == ["pg_restore", "-U", user, "-d", target, "--single-transaction"]
    assert commands[4] == ["tar", "xzf", "-", "--keep-old-files", "-C", str(tmp_path / "restored")]
    assert silent == [False, False, False, True, False]                       # pg_restore must print nothing
    out = capsys.readouterr().out
    for pattern in (r"restored: \d+ tables, \d+ rows, \d+ values compared; every one kept",
                    r"restored, sequences: 2; each one where the source's stood",
                    r"restored, schema: \d+ objects .*; each one defined as in the source",
                    r"restored, files: 12 files and directories; each one as in the source, byte for byte",
                    r"read-back: 7 values read back through the routes; every one as seeded",
                    r"after the app's start: \d+ tables, \d+ rows, \d+ values compared; every one kept",
                    r"after the app's start, files: each one unchanged but db-identity.json: the source's entry "
                    r"as backed up, the target's added on the same cluster"):
        assert re.search(pattern, out), (pattern, out)


@pytest.mark.parametrize(("tamper", "expected"), [
    ("row", ["review_decisions [id=6]: row missing"] * 2),
    ("extra-row", ["jobs [id='restore-extra']: row added"] * 2),
    ("trigger", ["trigger entities.entities_review_revision: missing"] * 2),
    ("sequence", ["sequence progress_events_id_seq state: 'last_value 7, is_called True' -> "
                  "'last_value 1, is_called False'"] * 2),
    ("file", [f"file uploads/{ms.JOB_D}.docx: 'sha256 "]),
    ("added-file", ["file uploads/restore-extra.txt: added"] * 2),
])
def test_check_reports_what_the_restore_lost(monkeypatch, tmp_path, tamper, expected):
    _fakes(monkeypatch, tamper)
    problems, *_ = _run(tmp_path)
    if tamper == "file":         # once restored, once after the app's start
        assert len(problems) == 2 and all(p.startswith(expected[0]) for p in problems)
    else:
        assert problems == expected


# ── The run: databases, exit codes ───────────────────────────────────────────

@pytest.mark.parametrize("outcome", ["passes", "differs", "fails", "breaks"])
def test_the_databases_and_the_directory_are_removed_whatever_happens(monkeypatch, capsys, outcome):
    seen: dict = {}
    monkeypatch.setattr(cbr, "tools", lambda url, container, server: cbr.Tools((), {}, "pg_dump 18"))

    def step(admin_url, user, source, target, tmp, pg, version, connect):
        seen.update(source=source, target=target, tmp=tmp)
        assert source in _databases() and tmp.is_dir()
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(f'CREATE DATABASE "{target}"')
        if outcome == "fails":
            raise cbr.Failed("pg_restore -U ctiparsor -d x --single-transaction exited 1:\nerror")
        if outcome == "breaks":
            raise RuntimeError("a step broke")
        return [] if outcome == "passes" else ["jobs [id='a']: row missing"]

    monkeypatch.setattr(cbr, "_check", step)
    assert cbr.check(_admin(), None) is (outcome == "passes")
    assert not {seen["source"], seen["target"]} & _databases() and not seen["tmp"].exists()
    out = capsys.readouterr().out
    assert out.startswith("== backup and restore, PostgreSQL ")
    assert ("ok   backup and restore: " if outcome == "passes" else "FAIL backup and restore: ") in out
    if outcome == "breaks":
        assert "  RuntimeError: a step broke\n" in out


def test_usage_and_environment_errors_exit_2(monkeypatch, capsys):
    monkeypatch.delenv("CTIPARSOR_TEST_DATABASE_URL", raising=False)
    assert cbr.main([]) == 2
    assert "CTIPARSOR_TEST_DATABASE_URL is required" in capsys.readouterr().err
    monkeypatch.setenv("CTIPARSOR_TEST_DATABASE_URL", "postgresql://127.0.0.1:1/ctiparsor")
    assert cbr.main([]) == 2
    assert "names no user" in capsys.readouterr().err
    monkeypatch.setenv("CTIPARSOR_TEST_DATABASE_URL", _URL)                    # nothing listens on port 1
    assert cbr.main([]) == 2
    err = capsys.readouterr().err
    assert err.startswith("check_backup_restore: cannot reach 127.0.0.1:1: ") and err.count(chr(10)) == 1


def test_the_container_comes_from_the_option_or_the_environment_and_the_result_is_the_exit_code(monkeypatch):
    seen: list = []

    def check(url: str, container: str | None) -> bool:
        seen.append(container)
        return container != "bad"

    monkeypatch.setenv("CTIPARSOR_TEST_DATABASE_URL", _URL)
    monkeypatch.setattr(cbr, "check", check)
    monkeypatch.delenv(cbr.CONTAINER_VARIABLE, raising=False)
    assert cbr.main([]) == 0 and seen[-1] is None
    monkeypatch.setenv(cbr.CONTAINER_VARIABLE, "from-env")
    assert cbr.main([]) == 0 and seen[-1] == "from-env"
    assert cbr.main(["--pg-container", "bad"]) == 1 and seen[-1] == "bad"
