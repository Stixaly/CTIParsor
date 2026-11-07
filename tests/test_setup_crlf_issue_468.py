"""setup.sh reads .env values without the \\r of a CRLF file (issue #468).

On Windows an editor can save .env with CRLF line endings. `grep | cut` keeps
the \\r, so an empty `CTI_DB_PASSWORD=\\r` looked set: setup.sh skipped the
generation and wrote a lone \\r into .secrets/db_password. The values are read
through `env_value`, which is extracted from setup.sh here, not copied, and run
in a bash subprocess on a temporary .env. setup.sh itself is never run: it
installs and starts things.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SETUP = Path(__file__).resolve().parents[1] / "setup.sh"

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="setup.sh is a bash script")


def _env_value_function() -> str:
    """The `env_value() { ... }` definition, copied from setup.sh as written."""
    match = re.search(r"^env_value\(\) \{\n.*?^\}\n", SETUP.read_text(encoding="utf-8"), re.S | re.M)
    assert match, "setup.sh has no env_value() helper"
    return match.group(0)


def _read(tmp_path: Path, env_bytes: bytes, script: str) -> subprocess.CompletedProcess:
    (tmp_path / ".env").write_bytes(env_bytes)
    return subprocess.run(["bash", "-c", _env_value_function() + script], cwd=tmp_path,
                          capture_output=True, text=True, timeout=60)


def test_crlf_empty_value_reads_as_empty_issue_468(tmp_path):
    done = _read(tmp_path, b"LLM_PROVIDER=vllm\r\nCTI_DB_PASSWORD=\r\n",
                 'printf "[%s]" "$(env_value CTI_DB_PASSWORD)"')

    assert done.returncode == 0, done.stderr
    assert done.stdout == "[]"           # not "[\r]": the -n test must see an empty value


def test_crlf_value_loses_its_trailing_cr_issue_468(tmp_path):
    done = _read(tmp_path, b"LLM_PROVIDER=vllm\r\nCTI_DB_PASSWORD=abc123\r\n",
                 'printf "[%s]" "$(env_value CTI_DB_PASSWORD)"')

    assert done.returncode == 0, done.stderr
    assert done.stdout == "[abc123]"


def test_lf_value_is_unchanged_control_issue_468(tmp_path):
    done = _read(tmp_path, b"LLM_PROVIDER=vllm\nCTI_DB_PASSWORD=abc123\n",
                 'printf "[%s]" "$(env_value LLM_PROVIDER)|$(env_value CTI_DB_PASSWORD)"')

    assert done.returncode == 0, done.stderr
    assert done.stdout == "[vllm|abc123]"


def test_missing_key_does_not_abort_under_set_e_issue_468(tmp_path):
    # setup.sh runs with `set -e`: a missing key must give an empty value, not stop the script.
    done = _read(tmp_path, b"LLM_PROVIDER=vllm\r\n",
                 'set -e\nv=$(env_value ANTHROPIC_API_KEY)\nprintf "[%s]" "$v"')

    assert done.returncode == 0, done.stderr
    assert done.stdout == "[]"


def test_setup_reads_env_only_through_env_value_issue_468():
    # Every `KEY=` read of .env goes through the helper: a raw `cut` on a .env read would keep the \r again.
    text = SETUP.read_text(encoding="utf-8")
    raw_reads = [line for line in text.splitlines() if "cut -d'=' -f2-" in line and "tr -d" not in line]

    assert raw_reads == []
