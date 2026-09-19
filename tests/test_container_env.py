"""Tests for container environment variable overrides.

These tests lock down CTIPARSOR_GIT_REV resolution: git revision resolution
prefers the local repository over the environment variable when available,
falling back to it otherwise. `api.db._path_from_env`/`BACKUP_DIR`, and the
`CTIPARSOR_DB_PATH` variable it used to also serve, were removed with SQLite
(ADR-0053) — `CTIPARSOR_DB_BACKUP_DIR` no longer has anything to configure
now that `backup_db()` just logs a `pg_dump` reminder rather than copying a
local file.
"""
from __future__ import annotations

import types

import api.run_config as run_config


def test_git_rev_prefers_git_when_available(monkeypatch):
    """Git rev-parse succeeds -> use git output, ignore env var."""
    # Mock subprocess.run to return success
    def fake_run(*args, **kwargs):
        return types.SimpleNamespace(returncode=0, stdout="deadbeef\n")

    monkeypatch.setattr(run_config.subprocess, "run", fake_run)
    monkeypatch.setenv("CTIPARSOR_GIT_REV", "ffff")

    result = run_config._resolve_git_rev()
    assert result == "deadbeef"


def test_git_rev_falls_back_to_env_when_git_is_missing(monkeypatch):
    """Git rev-parse fails -> use env var."""
    # Mock subprocess.run to raise FileNotFoundError
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(run_config.subprocess, "run", fake_run)
    monkeypatch.setenv("CTIPARSOR_GIT_REV", "  abc123  ")

    result = run_config._resolve_git_rev()
    assert result == "abc123"


def test_git_rev_is_none_without_git_and_without_env(monkeypatch):
    """Git rev-parse fails and env var unset/blank -> None."""
    # Mock subprocess.run to raise FileNotFoundError
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(run_config.subprocess, "run", fake_run)

    # Test unset
    monkeypatch.delenv("CTIPARSOR_GIT_REV", raising=False)
    result = run_config._resolve_git_rev()
    assert result is None

    # Test blank
    monkeypatch.setenv("CTIPARSOR_GIT_REV", "   ")
    result = run_config._resolve_git_rev()
    assert result is None


def test_git_rev_ignores_failed_git_and_uses_env(monkeypatch):
    """Git rev-parse returns non-zero -> use env var."""
    # Mock subprocess.run to return failure
    def fake_run(*args, **kwargs):
        return types.SimpleNamespace(returncode=128, stdout="")

    monkeypatch.setattr(run_config.subprocess, "run", fake_run)
    monkeypatch.setenv("CTIPARSOR_GIT_REV", "cafe")

    result = run_config._resolve_git_rev()
    assert result == "cafe"
