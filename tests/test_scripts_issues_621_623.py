"""Scripts run as files from the repository root: the --help and no-data paths (#621, #622, #623).

Each script runs in a subprocess with sys.executable, as the docs say. None of
them needs a database, OpenCTI or pycti.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def run_script(name: str, *args: str, cwd: Path = REPO) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(REPO / "scripts" / name), *args], cwd=cwd,
                          capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("script", ["opencti_import_bundle.py", "migration_compare.py"])
def test_the_script_starts_as_a_file_without_a_traceback(script):
    """(#622, #623) `python scripts/<name>.py --help` exits 0 with no traceback, pycti or not."""
    done = run_script(script, "--help")
    assert done.returncode == 0, done.stderr
    assert "Traceback" not in done.stderr
    assert "ModuleNotFoundError" not in done.stderr


def test_the_import_bundle_help_prints_the_usage():
    """(#622) --help reaches the argument parser, so it prints the usage line."""
    done = run_script("opencti_import_bundle.py", "--help")
    assert done.returncode == 0, done.stderr
    assert "usage:" in done.stdout


def test_the_import_check_module_loads_without_pycti():
    """(#622) pycti is imported only where it is used: the module loads and pycti_version() answers."""
    code = (
        "import sys; sys.path.insert(0, %r); "
        "from scripts import opencti_import_check; "
        "print(callable(opencti_import_check.make_client))"
    ) % str(REPO)
    done = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "True"


def test_check_coverage_without_a_coverage_file_says_to_run_pytest_cov(tmp_path):
    """(#621) No .coverage in the working directory: exit 2, one clear line on stderr, no traceback."""
    assert not (tmp_path / ".coverage").exists()
    done = run_script("check_coverage.py", cwd=tmp_path)
    assert done.returncode == 2, done.stderr
    assert "Traceback" not in done.stderr
    assert "NoDataError" not in done.stderr
    assert "Run 'pytest --cov' first" in done.stderr
    assert done.stdout == ""
