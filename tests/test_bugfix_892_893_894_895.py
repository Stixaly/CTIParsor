"""Regression tests for the tooling bugs #892 to #895.

#892: backfill_rule_bytes accepts --batch 0 and runs on nothing; it is a usage error.
#893: download_attack validates the download before it replaces the bundle, and a
bundle that does not parse leaves enterprise-attack.json as it was.
#894: the DB-password secret is read from .env without running it: a CRLF file, a
space, a `#` and a `$` in the password all come through as written.
#895: an appended KEY=VALUE line starts on its own line when .env has no final newline.

No test reaches the network, the database or data/: the download is a fake and the
paths are temporary.
"""
from __future__ import annotations

import io
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import backfill_rule_bytes as backfill
from scripts import download_attack as da

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / "Makefile"
LIB = ROOT / "scripts" / "offline_lib_docker.sh"


# ── #892 ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("batch", ["0", "-1"])
def test_a_batch_below_one_is_a_usage_error_before_the_store_is_touched(monkeypatch, capsys, batch):
    touched = []

    def store_touched(*args, **kwargs):
        touched.append(args)
        raise AssertionError("the rule store must not be opened for a usage error")

    monkeypatch.setattr(backfill, "init_db", store_touched)
    monkeypatch.setattr(backfill, "get_rule_conn", store_touched)
    monkeypatch.setattr(sys, "argv", ["backfill_rule_bytes.py", "--batch", batch])

    with pytest.raises(SystemExit) as exc:
        backfill.main()

    assert exc.value.code == 2
    assert touched == []
    assert "--batch must be >= 1" in capsys.readouterr().err


# ── #893 ─────────────────────────────────────────────────────────────────────

GOOD_BUNDLE = b'{"objects": [{"type": "attack-pattern"}]}'


@pytest.mark.parametrize("bundle_already_there", [True, False])
def test_a_download_that_does_not_parse_never_replaces_the_bundle(
        monkeypatch, tmp_path, capsys, bundle_already_there):
    out = tmp_path / "data" / "enterprise-attack.json"
    out.parent.mkdir()
    if bundle_already_there:
        out.write_bytes(GOOD_BUNDLE)
    monkeypatch.setattr(da, "_OUT", out)
    monkeypatch.setattr(da, "_DEFAULT_MANIFEST", tmp_path / "none.json")
    monkeypatch.setattr(da.urllib.request, "urlopen",
                        lambda req, timeout=None: io.BytesIO(b"<html>not a bundle</html>"))
    monkeypatch.setattr(sys, "argv", ["download_attack.py", "--force"])

    with pytest.raises(SystemExit) as exc:
        da.main()

    assert exc.value.code == 1
    assert "validation failed" in capsys.readouterr().out
    if bundle_already_there:
        assert out.read_bytes() == GOOD_BUNDLE
    else:
        assert not out.exists()
    assert not out.with_suffix(".tmp").exists()             # the rejected download is removed


def test_a_download_that_parses_is_renamed_into_place(monkeypatch, tmp_path):
    out = tmp_path / "data" / "enterprise-attack.json"
    monkeypatch.setattr(da, "_OUT", out)
    monkeypatch.setattr(da, "_DEFAULT_MANIFEST", tmp_path / "none.json")
    monkeypatch.setattr(da.urllib.request, "urlopen", lambda req, timeout=None: io.BytesIO(GOOD_BUNDLE))
    monkeypatch.setattr(sys, "argv", ["download_attack.py", "--force"])

    da.main()

    assert out.read_bytes() == GOOD_BUNDLE
    assert sorted(p.name for p in out.parent.iterdir()) == ["enterprise-attack.json"]


# ── #894 ─────────────────────────────────────────────────────────────────────

requires_make = pytest.mark.skipif(not shutil.which("make") or not shutil.which("sh"),
                                   reason="the secret is written by a make recipe")


def _make_secret(tmp_path: Path, env_bytes: bytes) -> subprocess.CompletedProcess:
    (tmp_path / ".env").write_bytes(env_bytes)
    return subprocess.run(
        ["make", "-f", str(MAKEFILE), "-C", str(tmp_path), ".secrets/db_password"],
        capture_output=True, text=True, timeout=120)


@requires_make
def test_the_db_password_is_read_from_a_crlf_env_as_written(tmp_path):
    # A space, a `#` and a `$` are what `. .env` used to run or expand.
    done = _make_secret(tmp_path, b"CTI_DB_USER=ctiparsor\r\nCTI_DB_PASSWORD=p a#s$w0rd\r\n")

    assert done.returncode == 0, done.stderr
    assert (tmp_path / ".secrets" / "db_password").read_bytes() == b"p a#s$w0rd"


@requires_make
def test_an_empty_db_password_is_refused_and_no_secret_is_written(tmp_path):
    done = _make_secret(tmp_path, b"CTI_DB_PASSWORD=\r\n")

    assert done.returncode != 0
    assert "Set CTI_DB_PASSWORD" in done.stderr
    assert not (tmp_path / ".secrets" / "db_password").exists()


# ── #895 ─────────────────────────────────────────────────────────────────────

requires_bash = pytest.mark.skipif(not shutil.which("bash"), reason="offline_lib_docker.sh is bash")


def _run_lib_call(tmp_path: Path, existing: bytes, call: str) -> bytes:
    """Source the real library in a directory holding `existing` as .env, run `call`, return .env."""
    (tmp_path / ".env").write_bytes(existing)
    subprocess.run(["bash", "-c", f'source "{LIB}"\n{call}\n'], cwd=tmp_path,
                   check=True, capture_output=True, text=True)
    return (tmp_path / ".env").read_bytes()


@requires_bash
@pytest.mark.parametrize("call", ["_offline_set_key .env CTI_TEST_KEY value",
                                  "_offline_set_key_if_absent .env CTI_TEST_KEY value"])
def test_a_key_appended_to_an_env_without_a_final_newline_starts_its_own_line(tmp_path, call):
    assert _run_lib_call(tmp_path, b"LLM_PROVIDER=vllm", call) == b"LLM_PROVIDER=vllm\nCTI_TEST_KEY=value\n"


@requires_bash
@pytest.mark.parametrize("call", ["_offline_set_key .env CTI_TEST_KEY value",
                                  "_offline_set_key_if_absent .env CTI_TEST_KEY value"])
def test_a_key_appended_to_an_env_that_ends_with_a_newline_gets_no_blank_line(tmp_path, call):
    assert _run_lib_call(tmp_path, b"LLM_PROVIDER=vllm\n", call) == b"LLM_PROVIDER=vllm\nCTI_TEST_KEY=value\n"


@requires_bash
def test_a_key_appended_to_an_empty_env_is_the_only_line(tmp_path):
    assert _run_lib_call(tmp_path, b"", "_offline_set_key_if_absent .env CTI_TEST_KEY value") \
        == b"CTI_TEST_KEY=value\n"
