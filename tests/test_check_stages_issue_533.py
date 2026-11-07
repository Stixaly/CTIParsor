"""scripts/check_stages.py (issue #533): the Ingest row is decided by chk_browser(), which
launches Chromium, and not by importing the playwright package (ADR-0029).

The script runs its checks at import time and exits, so it is run with runpy. The
`playwright` package and the detection store are stubbed: only the browser launch
differs between the two tests."""
from __future__ import annotations

import runpy
import sys
import types
from pathlib import Path

import pytest

import api.db

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_stages.py"
INGEST = "Ingest    — URL capture (Playwright)"


class _Browser:
    def close(self):
        pass


class _Chromium:
    def __init__(self, error):
        self._error = error

    def launch(self, **kwargs):
        if self._error is not None:
            raise self._error
        return _Browser()


class _Playwright:
    def __init__(self, error):
        self.chromium = _Chromium(error)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _stub_playwright(monkeypatch, error=None):
    """A `playwright` package whose Chromium launch raises `error` (or succeeds)."""
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = lambda: _Playwright(error)
    package = types.ModuleType("playwright")
    package.sync_api = sync_api
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(api.db, "get_rule_conn", _no_store)


def _no_store():
    """The detection store is not reachable: the coverage rows are not the point here."""
    raise RuntimeError("no store")


def _ingest_line(capsys) -> str:
    with pytest.raises(SystemExit):
        runpy.run_path(str(SCRIPT), run_name="check_stages_under_test")
    return next(line for line in capsys.readouterr().out.splitlines() if INGEST in line)


def test_an_installed_package_without_a_launchable_chromium_is_not_ticked(monkeypatch, capsys):  # (#533)
    """The package imports, but Chromium cannot start: the row is open and names the fix."""
    _stub_playwright(monkeypatch, error=RuntimeError("error while loading shared libraries: libasound.so.2"))

    line = _ingest_line(capsys)

    assert "✔" not in line
    assert line.endswith("make install-capture")


def test_a_chromium_that_launches_ticks_the_ingest_row(monkeypatch, capsys):  # (#533)
    """With a browser that starts, the same row is ticked: only the launch decides it."""
    _stub_playwright(monkeypatch, error=None)

    line = _ingest_line(capsys)

    assert "✔" in line
