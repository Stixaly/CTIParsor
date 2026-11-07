"""docker/entrypoint.sh writes ~/.pgpass with backslashes and colons escaped (issue 469).

The function is extracted from the script and run by `sh`, the POSIX shell the
container's /bin/sh provides, rather than by bash.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"


def _escape(password: str) -> str:
    text = ENTRYPOINT.read_text(encoding="utf-8")
    found = re.search(r"^pgpass_escape\(\) \{\n.*?^\}\n", text, re.DOTALL | re.MULTILINE)
    assert found, "pgpass_escape is not defined in docker/entrypoint.sh"
    script = found.group(0) + 'printf "%s" "$(pgpass_escape "$1")"'
    done = subprocess.run(["sh", "-c", script, "sh", password], capture_output=True, text=True, check=True)
    return done.stdout


@pytest.mark.parametrize("password, field", [
    ("a:b\\c", "a\\:b\\\\c"),          # the case of the issue: `\` doubled, `:` escaped
    ("p@ss:w0rd", "p@ss\\:w0rd"),     # a colon alone
    ("trail\\", "trail\\\\"),         # a backslash alone, at the end
    ("s3cret", "s3cret"),             # control: nothing to escape
])
def test_the_password_field_escapes_backslash_then_colon_issue_469(password, field):
    assert _escape(password) == field


def test_the_entrypoint_is_valid_sh_issue_469():
    done = subprocess.run(["sh", "-n", str(ENTRYPOINT)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
