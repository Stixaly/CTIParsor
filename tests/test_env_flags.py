"""env_int / env_float, and .env loading order in the batch CLI.

A malformed number used to raise ValueError at import time and stop the whole
process; it now falls back to the default with a warning.  main.py used to rely
on stage3_llm's load_dotenv(), which ran after api.logging_config had already
read the LOG_* settings.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from pipeline.env_flags import env_float, env_int

REPO = Path(__file__).resolve().parent.parent


def _result_line(proc: subprocess.CompletedProcess) -> list[str]:
    """The `RESULT ...` line a subprocess printed, whatever logging wrote around it."""
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT ")), "")
    return line.split()[1:]


@pytest.mark.parametrize("raw, expected", [("42", 42), (" 7 ", 7), ("-3", -3), ("0", 0)])
def test_env_int_parses(monkeypatch, raw, expected):
    monkeypatch.setenv("CTI_TEST_INT", raw)
    assert env_int("CTI_TEST_INT", default=5) == expected


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_env_int_unset_or_blank_is_the_default_without_a_warning(monkeypatch, caplog, raw):
    if raw is None:
        monkeypatch.delenv("CTI_TEST_INT", raising=False)
    else:
        monkeypatch.setenv("CTI_TEST_INT", raw)
    with caplog.at_level("WARNING"):
        assert env_int("CTI_TEST_INT", default=5) == 5
    assert caplog.text == ""


@pytest.mark.parametrize("raw", ["abc", "5.0", "10 jobs", "1e3"])
def test_env_int_malformed_falls_back_with_a_warning(monkeypatch, caplog, raw):
    monkeypatch.setenv("CTI_TEST_INT", raw)
    with caplog.at_level("WARNING"):
        assert env_int("CTI_TEST_INT", default=5) == 5
    assert "CTI_TEST_INT" in caplog.text
    assert "default 5" in caplog.text


def test_env_float_parses_and_falls_back(monkeypatch, caplog):
    monkeypatch.setenv("CTI_TEST_FLOAT", "0.25")
    assert env_float("CTI_TEST_FLOAT", default=0.4) == 0.25
    monkeypatch.setenv("CTI_TEST_FLOAT", "2")
    assert env_float("CTI_TEST_FLOAT", default=0.4) == 2.0
    monkeypatch.setenv("CTI_TEST_FLOAT", "0,25")  # a decimal comma
    with caplog.at_level("WARNING"):
        assert env_float("CTI_TEST_FLOAT", default=0.4) == 0.4
    assert "CTI_TEST_FLOAT" in caplog.text


def test_a_malformed_setting_no_longer_stops_the_import():
    """WORKER_MAX_CONCURRENT=abc used to raise ValueError while importing api.worker."""
    env = {**os.environ, "SKIP_HEAVY_MODELS": "1",
           "WORKER_MAX_CONCURRENT": "abc", "LLM_TIMEOUT": "2 minutes"}
    code = ("import api.worker, pipeline.stage3_llm as s3; "
            "print('RESULT', api.worker._MAX_CONCURRENT_JOBS, s3._LLM_TIMEOUT)")
    proc = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env,
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert _result_line(proc) == ["10", "120"]
    assert "WORKER_MAX_CONCURRENT='abc' is not an integer" in proc.stdout + proc.stderr


def test_cli_reads_logging_settings_from_dotenv(tmp_path):
    """main.py loads the .env beside it before any project import.

    Run on a copy of main.py so the .env it finds is a test one; the project
    modules still come from the repo.
    """
    shutil.copy(REPO / "main.py", tmp_path / "main.py")
    (tmp_path / ".env").write_text("LOG_BACKUP_COUNT=9\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "LOG_BACKUP_COUNT"}
    env.update({"SKIP_HEAVY_MODELS": "1", "PYTHONPATH": str(REPO)})
    code = ("import importlib.util as u; "
            f"spec = u.spec_from_file_location('cti_main', {str(tmp_path / 'main.py')!r}); "
            "spec.loader.exec_module(u.module_from_spec(spec)); "
            "import api.logging_config as lc; print('RESULT', lc.LOG_BACKUP_COUNT)")
    proc = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert _result_line(proc) == ["9"]
