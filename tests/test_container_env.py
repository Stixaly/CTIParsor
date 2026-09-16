"""Tests for container environment variable overrides.

These tests lock down the behavior of the CTIPARSOR_DB_PATH,
CTIPARSOR_DB_BACKUP_DIR, and CTIPARSOR_GIT_REV environment variables,
ensuring that the application correctly falls back to defaults when
variables are unset or blank, and that git revision resolution prefers
the local repository over environment variables when available.
"""
from __future__ import annotations

import types
from pathlib import Path

import api.db as db
import api.run_config as run_config


def test_path_from_env_unset_returns_default(monkeypatch, tmp_path):
    """CTIPARSOR_DB_PATH unset -> default path."""
    monkeypatch.delenv("CTIPARSOR_DB_PATH", raising=False)
    default = Path("default.db")
    result = db._path_from_env("CTIPARSOR_DB_PATH", default)
    assert result == default


def test_path_from_env_blank_returns_default(monkeypatch, tmp_path):
    """CTIPARSOR_DB_PATH empty or whitespace -> default path."""
    default = Path("default.db")

    monkeypatch.setenv("CTIPARSOR_DB_PATH", "")
    result = db._path_from_env("CTIPARSOR_DB_PATH", default)
    assert result == default

    monkeypatch.setenv("CTIPARSOR_DB_PATH", "   ")
    result = db._path_from_env("CTIPARSOR_DB_PATH", default)
    assert result == default


def test_path_from_env_value_is_stripped_and_expanded(monkeypatch, tmp_path):
    """CTIPARSOR_DB_PATH value is stripped and ~ is expanded."""
    # Test stripping
    monkeypatch.setenv("CTIPARSOR_DB_PATH", "  /some/where/x.db  ")
    result = db._path_from_env("CTIPARSOR_DB_PATH", Path("default.db"))
    assert result == Path("/some/where/x.db")

    # Test expansion
    monkeypatch.setenv("CTIPARSOR_DB_PATH", "~/x.db")
    result = db._path_from_env("CTIPARSOR_DB_PATH", Path("default.db"))
    assert result == Path("~/x.db").expanduser()


def test_get_conn_creates_missing_parent_directory(monkeypatch, tmp_path):
    """get_conn() creates the parent directory if it doesn't exist."""
    # Set up a nested path that doesn't exist
    target_dir = tmp_path / "state" / "nested"
    target_db = target_dir / "t.db"

    # Monkeypatch DB_PATH
    monkeypatch.setattr(db, "DB_PATH", target_db)

    # Drop the thread-local connection before
    conn = getattr(db._local, "conn", None)
    if conn:
        conn.close()
        db._local.conn = None

    # Call get_conn
    conn = db.get_conn()

    # Verify directory was created
    assert target_dir.is_dir()

    # Drop the thread-local connection after
    if conn:
        conn.close()
        db._local.conn = None


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
