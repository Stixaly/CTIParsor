"""scripts/db_upgrade.sh and scripts/upgrade_postgres_17_to_18.sh, run on a fake
`docker` (#539).  A volume that holds PostgreSQL 18 only, or nothing, is "nothing to
do" (exit 0): under `set -euo pipefail` a `grep -v` with no line left to print
killed the script before it said so.  A real failure stays fatal.

The script runs from a copy of the repository layout (scripts/, compose.yaml,
.secrets/db_password), from another directory, so its `cd` to the root is tested too.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="the upgrade scripts are bash")

COMPOSE = ("services:\n  postgres:\n    image: postgres:18-alpine@sha256:"
           "77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873\n")

# Answers the calls the script makes: `volume inspect` by FAKE_VOLUMES, the
# PG_MAJOR of the image is 18, the majors of the volume (FAKE_MAJORS, printf %b),
# the legacy volume's PG_VERSION (FAKE_LEGACY).  Every other call succeeds silently.
FAKE_DOCKER = """#!/usr/bin/env bash
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$*" in
    "volume inspect "*)
        case " $FAKE_VOLUMES " in *" $3 "*) exit 0 ;; esac
        exit 1 ;;
    "run "*"PG_MAJOR"*) echo 18 ;;
    "run "*"/docker/PG_VERSION"*)
        [ -n "${FAKE_MAJORS_FAILS:-}" ] && exit 125
        printf '%b' "${FAKE_MAJORS:-}" ;;
    "run "*"PG_VERSION"*) printf '%b' "${FAKE_LEGACY:-}" ;;
esac
exit 0
"""


def _run(tmp_path: Path, script: str, *, volumes: str = "", majors: str = "", legacy: str = "",
         majors_fail: bool = False) -> subprocess.CompletedProcess:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / ".secrets").mkdir()
    (repo / ".secrets" / "db_password").write_text("secret\n", encoding="utf-8")
    (repo / "compose.yaml").write_text(COMPOSE, encoding="utf-8")
    for name in ("db_upgrade.sh", "upgrade_postgres_17_to_18.sh"):    # the wrapper execs db_upgrade.sh
        shutil.copy(REPO / "scripts" / name, repo / "scripts" / name)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "docker"
    fake.write_text(FAKE_DOCKER, encoding="utf-8")
    fake.chmod(0o755)
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp_path),
           "FAKE_DOCKER_LOG": str(tmp_path / "docker.log"), "FAKE_VOLUMES": volumes,
           "FAKE_MAJORS": majors, "FAKE_LEGACY": legacy}
    if majors_fail:
        env["FAKE_MAJORS_FAILS"] = "1"
    return subprocess.run(["bash", str(repo / "scripts" / script)], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("script", ["db_upgrade.sh", "upgrade_postgres_17_to_18.sh"])
def test_a_volume_that_holds_only_the_target_major_is_nothing_to_do(tmp_path, script):
    """(#539) PostgreSQL 18 alone in pg-data-18: exit 0 with the message, not a crash."""
    done = _run(tmp_path, script, volumes="ctiparsor_pg-data-18", majors="18\n")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "already holds PostgreSQL 18's cluster and no other major" in done.stdout
    assert "no cluster of another PostgreSQL major to move: nothing to do" in done.stdout


@pytest.mark.parametrize("script", ["db_upgrade.sh", "upgrade_postgres_17_to_18.sh"])
def test_an_empty_volume_is_nothing_to_do_too(tmp_path, script):
    """(#539) A volume with no PG_VERSION at all: nothing to do, exit 0."""
    done = _run(tmp_path, script, volumes="ctiparsor_pg-data-18", majors="")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "nothing to do" in done.stdout


@pytest.mark.parametrize("script", ["db_upgrade.sh", "upgrade_postgres_17_to_18.sh"])
def test_two_other_majors_in_the_volume_stay_a_refusal(tmp_path, script):
    """(#539) The fix must not turn the refusal into a pass: two other majors still die."""
    done = _run(tmp_path, script, volumes="ctiparsor_pg-data-18", majors="16\n17\n18\n")
    assert done.returncode == 1
    assert "holds clusters of PostgreSQL 16 17 besides 18: move one by hand" in done.stderr


@pytest.mark.parametrize("script", ["db_upgrade.sh", "upgrade_postgres_17_to_18.sh"])
def test_a_failed_read_of_the_volume_stays_fatal(tmp_path, script):
    """(#539) `docker run` on the volume fails: the script stops, it does not say 'nothing to do'."""
    done = _run(tmp_path, script, volumes="ctiparsor_pg-data-18", majors="18\n", majors_fail=True)
    assert done.returncode != 0
    assert "nothing to do" not in done.stdout
