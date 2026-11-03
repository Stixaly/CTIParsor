"""setup.sh --offline refuses a host with only the standalone docker-compose binary.

The restore (scripts/offline_lib_docker.sh) runs `docker compose` itself, as
every bundle script requires.  With only `docker-compose`, setup.sh started
postgres with it, then waited 90 s for a health status the plugin-less
`docker compose ps` could never give, and blamed postgres.

A fake `docker` (no compose plugin) and a fake `docker-compose` that logs its
calls stand in for Docker; setup.sh runs in an empty directory.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SETUP = Path(__file__).resolve().parents[1] / "setup.sh"

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="setup.sh is a bash script")

FAKE_DOCKER = """#!/usr/bin/env bash
case "$1" in
    --version) echo "Docker version 27.0.0, build fake" ;;
    info) ;;
    compose) echo "docker: 'compose' is not a docker command." >&2; exit 1 ;;
    *) exit 1 ;;
esac
"""

FAKE_DOCKER_COMPOSE = """#!/usr/bin/env bash
echo "$*" >> "$FAKE_COMPOSE_LOG"
"""


def _setup(tmp_path: Path, *args: str) -> tuple[int, str, list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("docker", FAKE_DOCKER), ("docker-compose", FAKE_DOCKER_COMPOSE)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()
    log = tmp_path / "compose.log"
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp_path),
           "FAKE_COMPOSE_LOG": str(log)}
    done = subprocess.run(["bash", str(SETUP), *args], cwd=work, env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=60)
    calls = log.read_text().splitlines() if log.exists() else []
    return done.returncode, done.stdout + done.stderr, calls


def test_offline_without_the_compose_plugin_stops_before_touching_anything(tmp_path):
    status, out, calls = _setup(tmp_path, f"--offline={tmp_path / 'offline'}")

    assert status == 1
    assert "--offline needs the 'docker compose' plugin" in out
    assert calls == []                                   # postgres is never started
    assert sorted(p.name for p in (tmp_path / "work").iterdir()) == []   # no .env, no .secrets


def test_without_offline_the_standalone_binary_is_still_accepted(tmp_path):
    status, out, calls = _setup(tmp_path)

    assert status == 0
    assert "Using the standalone docker-compose binary" in out
    assert calls == []                                   # setup.sh starts nothing
    assert (tmp_path / "work" / ".secrets" / "db_password").is_file()
