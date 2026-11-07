"""docs/docker.md, "Data and backups": the backup's two files and their check (#485, #487).

The documented blocks run as written, in a directory of their own, on a fake
`docker`: `compose exec ... sh -c` (pg_dump) prints a dump or fails, `compose run`
(tar) writes a real archive of a state directory, `pg_restore -l` reads the dump.
The check's lines run with `set -e`, as scripts/check_backup_restore_docker.sh
runs them: the first line that fails stops it.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DOCS = REPO / "docs" / "docker.md"
CHECK_SCRIPT = REPO / "scripts" / "check_backup_restore_docker.sh"

pytestmark = pytest.mark.skipif(not shutil.which("bash") or not shutil.which("tar"),
                                reason="the documented commands are bash, tar and gzip")

STAMP = re.compile(r"\d{4}-\d{2}-\d{2}-\d{6}")

FAKE_DOCKER = """#!/usr/bin/env bash
case "$*" in
    "compose exec -T postgres sh -c "*)            # pg_dump, through the container's shell
        if [ -n "${FAKE_DUMP_FAILS:-}" ]; then echo "pg_dump: error: could not write" >&2; exit 1; fi
        echo PGDMP ;;
    "compose run "*) tar czf - -C "$FAKE_STATE" . ;;
    "compose exec -T postgres pg_restore -l")
        cat > /dev/null
        echo "3600; 0 16000 TABLE DATA public jobs ctiparsor"
        if [ -n "${FAKE_RESTORE_FAILS:-}" ]; then
            echo "pg_restore: error: unexpected end of file" >&2
            exit 1
        fi
        echo "3601; 0 16001 TABLE DATA public entities ctiparsor"
        echo "3602; 0 16002 TABLE DATA public relationships ctiparsor" ;;
esac
exit 0
"""


def _block(name: str) -> str:
    """The fenced block of docs/docker.md marked for the script, as the check reads it."""
    text = DOCS.read_text(encoding="utf-8")
    found = re.findall(r"<!-- scripts/check_backup_restore_docker\.sh: (\w+) -->\n```bash\n(.*?)\n```", text, re.DOTALL)
    return dict(found)[name]


def _sandbox(tmp_path: Path) -> dict[str, str]:
    """A fake docker on PATH and a state directory with one upload; returns the environment."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "docker"
    fake.write_text(FAKE_DOCKER, encoding="utf-8")
    fake.chmod(0o755)
    state = tmp_path / "state"
    (state / "uploads").mkdir(parents=True)
    (state / "uploads" / "report.txt").write_text("sample", encoding="utf-8")
    (tmp_path / "work").mkdir()
    return {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp_path),
            "FAKE_STATE": str(state)}


def _run(tmp_path: Path, text: str, env: dict[str, str], *, errexit: bool) -> subprocess.CompletedProcess:
    """The lines in a shell of their own, in tmp_path/work; `errexit` stops at the first failure."""
    script = tmp_path / "block.sh"
    script.write_text(("set -e\n" if errexit else "") + text + "\n", encoding="utf-8")
    return subprocess.run(["bash", str(script)], cwd=tmp_path / "work", env={**env},
                          capture_output=True, text=True, timeout=120)


def _backup(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    return _run(tmp_path, _block("BACKUP_COMMANDS"), env, errexit=False)


def _check(tmp_path: Path, env: dict[str, str], stamp: str) -> subprocess.CompletedProcess:
    text = re.sub(r"YYYY-MM-DD(-HHMMSS)?", stamp, _block("CHECK_COMMANDS"))
    return _run(tmp_path, text, env, errexit=True)


def _files(tmp_path: Path, pattern: str) -> list[Path]:
    return sorted((tmp_path / "work").glob(pattern))


@pytest.fixture
def sandbox(tmp_path):
    return tmp_path, _sandbox(tmp_path)


# ── #485: two backups on one day ─────────────────────────────────────────────

def test_a_failed_second_backup_leaves_the_first_one_whole(sandbox):
    """(#485) The same day, pg_dump fails the second time: the first dump is not truncated."""
    tmp_path, env = sandbox
    _backup(tmp_path, env)
    first = _files(tmp_path, "ctiparsor-*.dump")
    assert len(first) == 1 and first[0].read_bytes() == b"PGDMP\n"
    time.sleep(1.1)                                   # the next backup has another stamp
    _run(tmp_path, _block("BACKUP_COMMANDS"), {**env, "FAKE_DUMP_FAILS": "1"}, errexit=False)
    assert first[0].read_bytes() == b"PGDMP\n", "the second backup truncated the first dump"


def test_each_backup_writes_its_own_pair_of_files_named_to_the_second(sandbox):
    """(#485) Two backups on one day: two dumps and two archives, each pair under one stamp."""
    tmp_path, env = sandbox
    _backup(tmp_path, env)
    time.sleep(1.1)
    _backup(tmp_path, env)
    dumps = _files(tmp_path, "ctiparsor-*.dump")
    archives = _files(tmp_path, "cti-state-*.tgz")
    assert len(dumps) == 2 and len(archives) == 2
    stamps = [path.name[len("ctiparsor-"):-len(".dump")] for path in dumps]
    assert all(STAMP.fullmatch(stamp) for stamp in stamps), stamps
    assert [path.name for path in archives] == [f"cti-state-{stamp}.tgz" for stamp in stamps]


# ── #487: the check must fail on a truncated archive ─────────────────────────

def test_the_check_passes_on_an_intact_backup_and_counts_its_uploads(sandbox):
    """(#487) Intact files: both counts are printed and the check exits 0."""
    tmp_path, env = sandbox
    _backup(tmp_path, env)
    stamp = _files(tmp_path, "ctiparsor-*.dump")[0].name[len("ctiparsor-"):-len(".dump")]
    done = _check(tmp_path, env, stamp)
    assert done.returncode == 0, done.stderr
    assert done.stdout.split() == ["3", "1"]


def test_a_truncated_archive_fails_the_check(sandbox):
    """(#487) tar reads a few entries, then reports the end of the file: the check must fail."""
    tmp_path, env = sandbox
    _backup(tmp_path, env)
    archive = _files(tmp_path, "cti-state-*.tgz")[0]
    data = archive.read_bytes()
    archive.write_bytes(data[:-6])                    # the gzip trailer is cut: tar exits non-zero
    stamp = _files(tmp_path, "ctiparsor-*.dump")[0].name[len("ctiparsor-"):-len(".dump")]
    done = _check(tmp_path, env, stamp)
    assert done.returncode != 0, ("the check passed on a truncated archive", done.stdout)


def test_a_dump_that_pg_restore_cannot_read_fails_the_check(sandbox):
    """(#487) pg_restore -l prints a part of the table list, then fails: the check must fail."""
    tmp_path, env = sandbox
    _backup(tmp_path, env)
    stamp = _files(tmp_path, "ctiparsor-*.dump")[0].name[len("ctiparsor-"):-len(".dump")]
    done = _check(tmp_path, {**env, "FAKE_RESTORE_FAILS": "1"}, stamp)
    assert done.returncode != 0, ("the check passed on an unreadable dump", done.stdout)


# ── The docs and the script that runs them ───────────────────────────────────

def test_the_docs_use_the_stamp_and_the_script_substitutes_it():
    """(#485, #487) No YYYY-MM-DD left in the docs: every file name carries the time to the second,
    and the script replaces the placeholder the docs use."""
    text = DOCS.read_text(encoding="utf-8")
    assert "YYYY-MM-DD" not in text.replace("YYYY-MM-DD-HHMMSS", "")
    assert "${line//YYYY-MM-DD-HHMMSS/$2}" in CHECK_SCRIPT.read_text(encoding="utf-8")
