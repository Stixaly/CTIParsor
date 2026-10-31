"""docker_smoke.sh and check_backup_restore_docker.sh never touch a Compose
project that is not the smoke's own, unless the caller allows it on purpose.

A fake `docker` (DOCKER_BIN) records the project of every call and fails it,
so both scripts run their course in seconds, without Docker.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SMOKE = REPO / "scripts" / "docker_smoke.sh"
CHECK = REPO / "scripts" / "check_backup_restore_docker.sh"

pytestmark = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("bash", "curl", "python3")),
    reason="needs bash, curl and python3, as the scripts do")

# Listing a project's containers or volumes succeeds, empty, as Docker does for
# a project that does not exist; FAKE_DOCKER_BUSY names a project with a
# container, FAKE_DOCKER_LIST_FAILS makes the listing fail.  Every other call fails.
FAKE_DOCKER = """#!/usr/bin/env bash
echo "${COMPOSE_PROJECT_NAME:-<unset>} $*" >> "$FAKE_DOCKER_LOG"
case "$*" in
    "compose ps -aq")
        [ -n "${FAKE_DOCKER_LIST_FAILS:-}" ] && exit 1
        if [ -n "${FAKE_DOCKER_BUSY:-}" ] && [ "${COMPOSE_PROJECT_NAME:-}" = "$FAKE_DOCKER_BUSY" ]; then
            echo 0123abcd
        fi
        exit 0 ;;
    "volume ls "*) exit 0 ;;
esac
exit 1
"""


def _run(script: Path, tmp_path: Path, *args: str, shell_project: str | None = None,
         allow: str | None = None, dotenv: str = "", busy: str | None = None,
         list_fails: bool = False) -> tuple[int, str, list[str]]:
    log = tmp_path / "docker.log"
    fake = tmp_path / "fake-docker"
    fake.write_text(FAKE_DOCKER)
    fake.chmod(0o755)
    (tmp_path / ".env").write_text("CTI_DB_PASSWORD=not-a-secret\n" + dotenv)
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "DOCKER_BIN": str(fake),
           "FAKE_DOCKER_LOG": str(log), "SMOKE_HEALTH_TIMEOUT": "1"}
    for name, value in (("COMPOSE_PROJECT_NAME", shell_project), ("SMOKE_ALLOW_PROJECT", allow),
                        ("FAKE_DOCKER_BUSY", busy), ("FAKE_DOCKER_LIST_FAILS", "1" if list_fails else None)):
        if value:
            env[name] = value
    done = subprocess.run(["bash", str(script), *args], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=120)
    calls = log.read_text().splitlines() if log.exists() else []
    return done.returncode, done.stdout + done.stderr, calls


def test_the_smoke_ignores_a_project_named_in_dotenv(tmp_path):
    code, _, calls = _run(SMOKE, tmp_path, "--no-build", "--clean",
                          dotenv="COMPOSE_PROJECT_NAME=ctiparsor\n")
    assert code == 1                                        # the fake docker fails every check
    assert calls and all(call.startswith("ctiparsor-smoke ") for call in calls)
    assert "ctiparsor-smoke compose down -v" in calls


def test_dotenv_cannot_rewrite_the_guard(tmp_path):
    _, _, calls = _run(SMOKE, tmp_path, "--no-build", "--clean",
                       dotenv="SMOKE_PROJECT=ctiparsor\nSMOKE_OWN_PROJECT=ctiparsor\n")
    assert all(call.startswith("ctiparsor-smoke ") for call in calls)


@pytest.mark.parametrize("options", [(), ("--job",), ("--keep",)])
@pytest.mark.parametrize("project", ["ctiparsor", "ctiparsor-restored"])
def test_the_smoke_refuses_a_project_from_the_shell_it_was_not_allowed(tmp_path, project, options):
    code, output, calls = _run(SMOKE, tmp_path, "--no-build", *options, shell_project=project)
    assert code == 2
    assert calls == []
    assert f"COMPOSE_PROJECT_NAME is {project}," in output


def test_allowing_one_project_does_not_allow_another(tmp_path):
    code, _, calls = _run(SMOKE, tmp_path, "--no-build", shell_project="ctiparsor-restored",
                          allow="ctiparsor")
    assert code == 2
    assert calls == []


@pytest.mark.parametrize("option", ["--clean", "--backup-restore"])
def test_an_allowed_project_still_refuses_clean_and_backup_restore(tmp_path, option):
    code, output, calls = _run(SMOKE, tmp_path, "--no-build", option, shell_project="ctiparsor",
                               allow="ctiparsor")
    assert code == 2
    assert calls == []
    assert "COMPOSE_PROJECT_NAME is ctiparsor." in output


def test_the_smoke_checks_an_allowed_project_as_the_offline_check_does(tmp_path):
    """scripts/check_offline_bundle_docker.sh: ctiparsor allowed, --no-build --keep."""
    code, _, calls = _run(SMOKE, tmp_path, "--no-build", "--keep", shell_project="ctiparsor",
                          allow="ctiparsor")
    assert code == 1
    assert calls and all(call.startswith("ctiparsor ") for call in calls)
    assert not [call for call in calls if " down" in call]


def test_the_backup_restore_check_refuses_another_project(tmp_path):
    code, output, calls = _run(CHECK, tmp_path, shell_project="ctiparsor")
    assert code == 2
    assert calls == []
    assert "COMPOSE_PROJECT_NAME is ctiparsor." in output


def test_the_backup_restore_check_leaves_a_project_it_did_not_create(tmp_path):
    code, output, calls = _run(CHECK, tmp_path, busy="ctiparsor-smoke-restored")
    assert code == 1
    assert "ctiparsor-smoke-restored compose ps -aq" in calls
    assert not [call for call in calls if " exec " in call or " down" in call]
    assert "ctiparsor-smoke-restored is not empty" in output


def test_the_backup_restore_check_stops_when_it_cannot_list_the_target(tmp_path):
    code, output, calls = _run(CHECK, tmp_path, list_fails=True)
    assert code == 1
    assert not [call for call in calls if " exec " in call or " down" in call]
    assert "cannot list" in output


def test_the_backup_restore_check_looks_at_the_target_before_it_writes(tmp_path):
    code, _, calls = _run(CHECK, tmp_path)
    assert code == 1                                        # the fake docker fails the first write
    target_checked = calls.index("ctiparsor-smoke-restored compose ps -aq")
    first_write = next(i for i, call in enumerate(calls) if " exec " in call)
    assert target_checked < first_write
    assert calls[-1] == "ctiparsor-smoke-restored compose down -v --remove-orphans"
