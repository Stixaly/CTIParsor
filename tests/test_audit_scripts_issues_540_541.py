"""scripts/audit_edge_provenance.py and scripts/audit_coverage_formats.py run as
`python scripts/<name>.py` from the repository root, as the docs say (#540, #541).

Run as a file, the script's own directory is first on sys.path, not the root,
so `api` is not found.  `--help` answers before any database is opened.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("script", ["audit_edge_provenance.py", "audit_coverage_formats.py"])
def test_the_audit_runs_as_a_file_from_the_repository_root(script):
    """(#540, #541) `python scripts/<name>.py --help` imports `api` and prints the usage."""
    done = subprocess.run([sys.executable, f"scripts/{script}", "--help"], cwd=REPO,
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    assert "usage:" in done.stdout
