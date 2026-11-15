"""The route modules import without `api.main` having been imported first (issue #863).

The route modules took `limiter` from `api.main`, and `api.main` imports the route modules
and reads their attributes while it loads.  Imported first, a route module met a
half-initialised `api.main` and the import died.  The limiter now lives in
`api/rate_limit.py`, so the route modules no longer import `api.main`.  The whole suite
hid the defect, because an earlier test had already imported `api.main`.

Importing every route module in a fresh interpreter took about 40 s each on a Windows mount,
so the rule is checked on the source (no route module imports `api.main` at module level), and
one fresh interpreter proves the order that failed.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ROUTE_FILES = sorted(p for p in (REPO / "api" / "routes").glob("*.py") if p.stem != "__init__")


def _module_level_imports_of_api_main(path: Path) -> list[int]:
    """Line numbers of the statements of the module body that import `api.main`."""
    lines = []
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.ImportFrom) and node.module == "api.main":
            lines.append(node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.module == "api" \
                and any(a.name == "main" for a in node.names):
            lines.append(node.lineno)
        elif isinstance(node, ast.Import) and any(a.name == "api.main" for a in node.names):
            lines.append(node.lineno)
    return lines


@pytest.mark.parametrize("path", ROUTE_FILES, ids=lambda p: p.stem)
def test_route_module_does_not_import_api_main_at_module_level(path):
    assert _module_level_imports_of_api_main(path) == [], (
        f"{path.name} imports api.main at module level: imported first, it meets a "
        "half-initialised api.main (issue #863); import what it needs from a neutral module")


def test_ingest_imports_before_api_main():
    """The order of the issue: `api.routes.ingest` first, in a fresh interpreter."""
    done = subprocess.run([sys.executable, "-c", "import api.routes.ingest"], cwd=REPO,
                          capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stderr[-2000:]
