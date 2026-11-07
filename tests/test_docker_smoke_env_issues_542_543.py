"""scripts/docker_smoke.sh reads .env and writes .secrets/ in the repository root,
whatever the directory it is started from (#542), and reads .env as data, not as
shell code: a CRLF .env gives no carriage return in .secrets/db_password (#543).

A fake `docker` fails every call, so the script stops after the password file;
a fake `curl` records the URL the smoke polls.  The script runs from a copy of the
repository layout, so the files it writes land there, not in the repository.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="the smoke is bash")

FAKE_DOCKER = """#!/usr/bin/env bash
exit 1
"""

# The app container is found and reported healthy, so the smoke goes on to poll the API.
FAKE_DOCKER_HEALTHY = """#!/usr/bin/env bash
case "$*" in
    *" ps -q app") echo 0123abcd ;;
    *inspect*) echo healthy ;;
esac
exit 0
"""

# Records the URL it was asked for, then refuses the connection.
FAKE_CURL = """#!/usr/bin/env bash
echo "$*" >> "$FAKE_CURL_LOG"
exit 7
"""


def _run(tmp_path: Path, dotenv: bytes, *, start_in: str = "repo", shell: dict[str, str] | None = None,
         healthy: bool = False):
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    for name in ("docker_smoke.sh", "offline_lib_docker.sh"):
        shutil.copy(REPO / "scripts" / name, repo / "scripts" / name)
    (repo / ".env").write_bytes(dotenv)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("docker", FAKE_DOCKER_HEALTHY if healthy else FAKE_DOCKER), ("curl", FAKE_CURL)):
        (bin_dir / name).write_text(body, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    cwd = repo if start_in == "repo" else tmp_path / start_in
    cwd.mkdir(exist_ok=True)
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp_path),
           "DOCKER_BIN": str(bin_dir / "docker"), "FAKE_CURL_LOG": str(tmp_path / "curl.log"),
           "SMOKE_HEALTH_TIMEOUT": "1"}
    env.update(shell or {})
    done = subprocess.run(["bash", str(repo / "scripts" / "docker_smoke.sh"), "--no-build"],
                          cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    return done, repo, cwd


def test_the_secrets_are_written_beside_the_checkout_whatever_the_directory(tmp_path):
    """(#542) Started from another directory, the password file goes to the repository's .secrets/."""
    done, repo, cwd = _run(tmp_path, b"CTI_DB_PASSWORD=pw-in-root\n", start_in="elsewhere")
    assert (repo / ".secrets" / "db_password").read_text(encoding="utf-8") == "pw-in-root", done.stderr
    assert not (cwd / ".secrets").exists()


def test_a_crlf_dotenv_gives_the_password_without_a_carriage_return(tmp_path):
    """(#543) A .env saved with Windows line endings: the secret file holds the value, and nothing else."""
    done, repo, _ = _run(tmp_path, b"CTI_PORT=8000\r\nCTI_DB_PASSWORD=pw-crlf\r\n")
    assert (repo / ".secrets" / "db_password").read_bytes() == b"pw-crlf", done.stderr


def test_the_shell_password_wins_over_dotenv_as_it_does_for_compose(tmp_path):
    """(#543) compose reads CTI_DB_PASSWORD from the shell before .env: so does the smoke now."""
    _, repo, _ = _run(tmp_path, b"CTI_DB_PASSWORD=pw-dotenv\n", shell={"CTI_DB_PASSWORD": "pw-shell"})
    assert (repo / ".secrets" / "db_password").read_text(encoding="utf-8") == "pw-shell"


def test_the_bind_and_port_are_still_read_from_dotenv(tmp_path):
    """The smoke's API address comes from .env, as docs/docker.md states, once .env is no longer sourced."""
    done, repo, _ = _run(tmp_path, b"CTI_DB_PASSWORD=pw\nCTI_BIND=127.0.0.2\r\nCTI_PORT=8123\r\n", healthy=True)
    polled = (tmp_path / "curl.log").read_text(encoding="utf-8").split("\n")
    assert any("http://127.0.0.2:8123/api/health" in line for line in polled), (polled, done.stdout)
