"""The scheduled backup (ADR-0097 item 19): docker/backup/run.sh and its compose service.

run.sh runs under sh with BACKUP_RUN_NOW=1 in a temporary directory, on a fake
pg_dump and pg_restore placed first on PATH. tar is the real one, so the archive
is read back. No Docker, no database.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
RUN_SH = REPO / "docker" / "backup" / "run.sh"
COMPOSE = REPO / "compose.yaml"

pytestmark = pytest.mark.skipif(
    not shutil.which("sh") or not shutil.which("tar"),
    reason="run.sh is POSIX sh and needs tar",
)

STAMP = r"\d{4}-\d{2}-\d{2}-\d{6}"
DUMP_RE = re.compile(rf"^ctiparsor-({STAMP})\.dump$")

FAKE_PG_DUMP = """#!/bin/sh
echo "$*" >> "$FAKE_LOG"
echo "PGPASSWORD=$PGPASSWORD" >> "$FAKE_LOG"
if [ -n "${FAKE_DUMP_FAILS:-}" ]; then
    echo "pg_dump: error: could not write to output" >&2
    exit 1
fi
echo PGDMP
"""

FAKE_PG_RESTORE = """#!/bin/sh
if [ -n "${FAKE_RESTORE_FAILS:-}" ]; then
    echo "pg_restore: error: unexpected end of file" >&2
    exit 1
fi
echo "3600; 0 16000 TABLE DATA public jobs ctiparsor"
echo "3601; 0 16001 TABLE DATA public entities ctiparsor"
"""


@pytest.fixture
def env_dirs(tmp_path: Path) -> dict[str, Path]:
    """A fake PATH, a cti-state with one upload, a backup target, a status directory and a password file."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("pg_dump", FAKE_PG_DUMP), ("pg_restore", FAKE_PG_RESTORE)):
        fake = bin_dir / name
        fake.write_text(body, encoding="utf-8")
        fake.chmod(0o755)
    state = tmp_path / "state"
    (state / "uploads").mkdir(parents=True)
    (state / "uploads" / "report.txt").write_text("a report", encoding="utf-8")
    backups = tmp_path / "backups"
    backups.mkdir()
    status_dir = tmp_path / "status"
    status_dir.mkdir()
    password = tmp_path / "db_password"
    password.write_text("s3cret-test-value", encoding="utf-8")
    return {
        "bin": bin_dir, "state": state, "backups": backups, "status_dir": status_dir,
        "status": status_dir / "status.json", "password": password, "log": tmp_path / "pg.log",
    }


def _run(dirs: dict[str, Path], **extra: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": f"{dirs['bin']}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(dirs["bin"].parent),
        "BACKUP_RUN_NOW": "1",
        "BACKUP_DIR": str(dirs["backups"]),
        "BACKUP_STATUS_FILE": str(dirs["status"]),
        "STATE_DIR": str(dirs["state"]),
        "DB_PASSWORD_FILE": str(dirs["password"]),
        "FAKE_LOG": str(dirs["log"]),
    }
    env.update(extra)
    return subprocess.run(
        ["sh", str(RUN_SH)], env=env, capture_output=True, text=True, timeout=120, check=False,
    )


def _pairs(backups: Path) -> list[str]:
    return sorted(p.name for p in backups.iterdir() if DUMP_RE.match(p.name))


def _seed_old_pairs(backups: Path, count: int) -> list[str]:
    """Old backup pairs (2020) with the documented names; returns their dump names, oldest first."""
    names = []
    for i in range(1, count + 1):
        stamp = f"2020-01-01-{i:06d}"
        (backups / f"ctiparsor-{stamp}.dump").write_bytes(b"PGDMP old")
        (backups / f"cti-state-{stamp}.tgz").write_bytes(b"old archive")
        names.append(f"ctiparsor-{stamp}.dump")
    return names


def test_run_now_writes_named_pair_and_status(env_dirs: dict[str, Path]) -> None:
    result = _run(env_dirs)
    assert result.returncode == 0, result.stderr

    pairs = _pairs(env_dirs["backups"])
    assert len(pairs) == 1
    stamp = DUMP_RE.match(pairs[0]).group(1)
    archive = env_dirs["backups"] / f"cti-state-{stamp}.tgz"
    assert archive.is_file()
    with tarfile.open(archive) as tar:
        assert "./uploads/report.txt" in tar.getnames()

    # No temporary names left behind.
    assert not [p for p in env_dirs["backups"].iterdir() if p.name.startswith(".")]

    # pg_dump got the documented flags, and the password from the secret.
    log = env_dirs["log"].read_text(encoding="utf-8").splitlines()
    assert "-h postgres -p 5432 -U ctiparsor -d ctiparsor -Fc" in log[0]
    assert log[1] == "PGPASSWORD=s3cret-test-value"

    status = json.loads(env_dirs["status"].read_text(encoding="utf-8"))
    assert set(status) == {"last_attempt", "last_success", "ok", "error", "file"}
    assert status["ok"] is True
    assert status["error"] is None
    assert status["file"] == pairs[0]
    assert status["last_success"] == status["last_attempt"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", status["last_attempt"])
    # The app runs as another uid and reads the status file.
    assert env_dirs["status"].stat().st_mode & 0o044 == 0o044


def test_retention_keeps_seven_of_nine(env_dirs: dict[str, Path]) -> None:
    old = _seed_old_pairs(env_dirs["backups"], 8)
    result = _run(env_dirs)
    assert result.returncode == 0, result.stderr

    pairs = _pairs(env_dirs["backups"])
    archives = sorted(p.name for p in env_dirs["backups"].iterdir() if p.name.startswith("cti-state-"))
    assert len(pairs) == 7
    assert len(archives) == 7
    # The new backup and the six newest old ones stay; the two oldest go, with their archives.
    assert old[0] not in pairs and old[1] not in pairs
    assert old[2] in pairs and old[7] in pairs
    assert not (env_dirs["backups"] / "cti-state-2020-01-01-000001.tgz").exists()
    assert not (env_dirs["backups"] / "cti-state-2020-01-01-000002.tgz").exists()


def test_failing_pg_dump_keeps_older_backups(env_dirs: dict[str, Path]) -> None:
    old = _seed_old_pairs(env_dirs["backups"], 2)
    previous = "2026-01-01T02:30:00Z"
    env_dirs["status"].write_text(
        json.dumps({"last_attempt": previous, "last_success": previous, "ok": True,
                    "error": None, "file": old[-1]}), encoding="utf-8")

    result = _run(env_dirs, FAKE_DUMP_FAILS="1")
    assert result.returncode == 1

    # Nothing deleted, nothing new, no temporary file left.
    assert _pairs(env_dirs["backups"]) == old
    assert len(list(env_dirs["backups"].glob("cti-state-*.tgz"))) == 2
    assert not [p for p in env_dirs["backups"].iterdir() if p.name.startswith(".")]

    status = json.loads(env_dirs["status"].read_text(encoding="utf-8"))
    assert status["ok"] is False
    assert status["file"] is None
    assert "pg_dump failed" in status["error"]
    assert "could not write" in status["error"]
    assert status["last_success"] == previous
    assert status["last_attempt"] != previous


def test_failing_dump_check_writes_nothing_new(env_dirs: dict[str, Path]) -> None:
    old = _seed_old_pairs(env_dirs["backups"], 1)
    result = _run(env_dirs, FAKE_RESTORE_FAILS="1")
    assert result.returncode == 1

    assert _pairs(env_dirs["backups"]) == old
    assert len(list(env_dirs["backups"].glob("cti-state-*.tgz"))) == 1
    status = json.loads(env_dirs["status"].read_text(encoding="utf-8"))
    assert status["ok"] is False
    assert status["error"].startswith("checking the dump failed")
    assert status["last_success"] is None


def test_missing_password_file_is_a_failure(env_dirs: dict[str, Path]) -> None:
    env_dirs["password"].unlink()
    result = _run(env_dirs)
    assert result.returncode == 1
    status = json.loads(env_dirs["status"].read_text(encoding="utf-8"))
    assert status["ok"] is False
    assert status["error"].startswith("reading the database password failed")


@pytest.mark.parametrize("time", ["25:00", "2:30", "02:60", "noon"])
def test_bad_backup_time_is_refused(env_dirs: dict[str, Path], time: str) -> None:
    result = _run(env_dirs, BACKUP_TIME=time)
    assert result.returncode == 2
    assert "BACKUP_TIME" in result.stderr
    assert not env_dirs["status"].exists()


@pytest.mark.parametrize("keep", ["0", "-1", "seven"])
def test_bad_backup_keep_is_refused(env_dirs: dict[str, Path], keep: str) -> None:
    result = _run(env_dirs, BACKUP_KEEP=keep)
    assert result.returncode == 2
    assert "BACKUP_KEEP" in result.stderr


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_compose_backup_service_is_opt_in_and_read_only() -> None:
    services = _compose()["services"]
    backup = services["backup"]

    assert backup["profiles"] == ["backup"]
    # The same PostgreSQL image as the postgres service: pg_dump, tar and sh are in it.
    assert backup["image"] == services["postgres"]["image"]
    assert backup["entrypoint"] == ["/bin/sh", "/backup/run.sh"]
    assert backup["read_only"] is True
    assert "env_file" not in backup  # no .env: the password comes from the secret only
    assert backup["networks"] == ["backend"]

    volumes = backup["volumes"]
    assert "cti-state:/app/state:ro" in volumes
    assert "${BACKUP_TARGET:?set BACKUP_TARGET}:/backups" in volumes
    assert "cti-backup-status:/backup-status" in volumes
    assert "./docker/backup:/backup:ro" in volumes
    assert "./.secrets/db_password:/run/secrets/db_password:ro" in volumes


def test_compose_app_reads_backup_status_read_only() -> None:
    services = _compose()["services"]
    assert "cti-backup-status:/app/backup-status:ro" in services["app"]["volumes"]
    assert "cti-state:/app/state" in services["app"]["volumes"]
    assert "cti-backup-status" in _compose()["volumes"]
