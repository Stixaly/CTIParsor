"""scripts/offline_lib_docker.sh: the offline restore reaches the role and the
database compose created, whether their names come from the shell or from .env
(#306).  The real function runs; `offline_pg_exec` is replaced by a recorder."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

LIB = Path(__file__).resolve().parents[1] / "scripts" / "offline_lib_docker.sh"

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="the offline scripts are bash")


def _restore_args(tmp_path: Path, env_file: str | None, shell_env: dict[str, str]) -> str:
    if env_file is not None:
        (tmp_path / ".env").write_text(env_file, encoding="utf-8")
    (tmp_path / "bundle").mkdir()
    (tmp_path / "bundle" / "ctiparsor.dump").write_bytes(b"")
    script = f"""
set -e
source "{LIB}"
offline_pg_exec() {{ echo "$*" >> calls.log; cat >/dev/null || true; }}
offline_docker_restore_pg_dump bundle >/dev/null 2>&1 || true
head -n 1 calls.log
"""
    env = {"PATH": "/usr/bin:/bin", **shell_env}
    out = subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True, check=True)
    return out.stdout.strip()


@pytest.mark.parametrize("env_file, shell_env, expected", [
    (None, {}, "-U ctiparsor -d ctiparsor"),
    ("CTI_DB_USER=custom_user\nCTI_DB_NAME='custom_db'  \n", {}, "-U custom_user -d custom_db"),
    ("CTI_DB_USER=custom_user\nCTI_DB_NAME=custom_db\n", {"CTI_DB_USER": "shell_user"},
     "-U shell_user -d custom_db"),
    ("CTI_DB_USER=\n", {}, "-U ctiparsor -d ctiparsor"),
])
def test_the_restore_uses_the_names_compose_uses(tmp_path, env_file, shell_env, expected):
    assert expected in _restore_args(tmp_path, env_file, shell_env)
