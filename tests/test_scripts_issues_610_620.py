"""scripts/probe_vlm_figures.py (#610), measure_image_surface.py (#611), check_stages.py (#619)
and lock_pypi_hashes.py (#620): --help and import must not crash or exit the process.

Subprocesses are used where the process-level behaviour is the point (exit code, stdout).
No test reaches the network: pypi_hashes is replaced in the lock tests."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


def _run(args: list[str], *, code: str | None = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-c", code] if code is not None else [sys.executable, *args]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)


def _run_without_pdf2image(script: str, args: list[str]) -> subprocess.CompletedProcess:
    """Run a script as __main__ with pdf2image unimportable (sys.modules entry set to None)."""
    code = (
        "import runpy, sys\n"
        "sys.modules['pdf2image'] = None\n"
        f"sys.argv = [{str(script)!r}, *{args!r}]\n"
        f"runpy.run_path({str(script)!r}, run_name='__main__')\n"
    )
    return _run([], code=code)


# ---- #610: probe_vlm_figures without pdf2image -------------------------------------------

def test_probe_help_works_without_pdf2image():  # (#610)
    result = _run_without_pdf2image(SCRIPTS / "probe_vlm_figures.py", ["--help"])

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout
    assert "Traceback" not in result.stderr


def test_probe_refuses_cleanly_without_pdf2image(tmp_path):  # (#610)
    result = _run_without_pdf2image(SCRIPTS / "probe_vlm_figures.py", [str(tmp_path)])

    assert result.returncode == 2, result.stderr
    assert "pdf2image is required" in result.stderr
    assert "Traceback" not in result.stderr


# ---- #611: measure_image_surface argparse -------------------------------------------------

def test_measure_help_exits_zero():  # (#611)
    result = _run([str(SCRIPTS / "measure_image_surface.py"), "--help"])

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout
    assert "No documents found" not in result.stdout


def test_measure_nonexistent_explicit_path_is_an_argparse_error(tmp_path):  # (#611)
    missing = tmp_path / "does-not-exist"
    result = _run([str(SCRIPTS / "measure_image_surface.py"), str(missing)])

    assert result.returncode == 2
    assert "no such file or directory" in result.stderr


def test_measure_empty_directory_still_reports_no_documents(tmp_path, capsys):  # (#611)
    sys.path.insert(0, str(ROOT))
    try:
        from scripts import measure_image_surface as mis
    finally:
        sys.path.pop(0)

    assert mis.main([str(tmp_path)]) == 1
    assert "No documents found." in capsys.readouterr().out


# ---- #619: check_stages importable without running the report -----------------------------

def test_importing_check_stages_does_not_run_or_exit():  # (#619)
    result = _run([], code="import scripts.check_stages; print('IMPORTED')")

    assert result.returncode == 0, result.stderr
    assert result.stdout == "IMPORTED\n"


def test_check_stages_main_returns_int_from_the_checks(monkeypatch, capsys):  # (#619)
    sys.path.insert(0, str(ROOT))
    try:
        from scripts import check_stages as cs
    finally:
        sys.path.pop(0)
    monkeypatch.setattr(cs, "chk_browser", lambda: True)
    monkeypatch.setattr(cs, "detection_store", lambda: (10, 0))
    monkeypatch.setattr(cs, "chk_import", lambda name: True)
    monkeypatch.setattr(cs, "chk_file", lambda path: True)

    assert cs.main() == 0
    assert "All pipeline stages available." in capsys.readouterr().out

    monkeypatch.setattr(cs, "chk_import", lambda name: False)
    assert cs.main() == 1


# ---- #620: lock_pypi_hashes ----------------------------------------------------------------

def test_lock_help_exits_zero():  # (#620)
    result = _run([str(SCRIPTS / "lock_pypi_hashes.py"), "--help"])

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout


@pytest.fixture
def lock_mod(monkeypatch):
    sys.path.insert(0, str(ROOT))
    try:
        from scripts import lock_pypi_hashes as lock
    finally:
        sys.path.pop(0)
    return lock


def test_old_hash_parsing_ignores_sha512_and_lowercases_sha256(lock_mod):  # (#620)
    block = [
        "    --hash=sha512:" + "A" * 128 + " \\",
        "    --hash=sha256:" + "ABCDEF" + "0" * 58 + " \\",
        "    --hash=sha384:" + "b" * 96,
    ]

    assert lock_mod.sha256_of(block) == ["abcdef" + "0" * 58]


def test_old_hash_parsing_of_a_block_without_sha256_is_empty(lock_mod):  # (#620)
    assert lock_mod.sha256_of(["    --hash=sha512:" + "c" * 128]) == []


def test_rewrite_survives_sha512_and_uppercase_hashes(tmp_path, monkeypatch, lock_mod):  # (#620)
    new_hash = "ab" * 32
    upper_old = new_hash.upper()
    lock_file = tmp_path / "req.lock.txt"
    lock_file.write_text(
        "markupsafe==3.0.2 \\\n"
        f"    --hash=sha512:{'c' * 128} \\\n"
        f"    --hash=sha256:{upper_old}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(lock_mod, "pypi_hashes", lambda name, version: [new_hash])

    total, changed = lock_mod.rewrite(str(lock_file))

    assert (total, changed) == (1, 0)  # the uppercase old hash equals PyPI's once lowercased
    assert lock_file.read_text(encoding="utf-8") == (
        f"markupsafe==3.0.2 \\\n    --hash=sha256:{new_hash}\n"
    )
