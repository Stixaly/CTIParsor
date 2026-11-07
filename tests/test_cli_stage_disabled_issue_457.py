"""Stage 5 that did not run is not a refusal (#457).

`--disable-stage 5`, `--disable-stage 4` (no bundle for Stage 5 to validate) or
a run without output path leaves `RunResult.valid` at None.  main.py used to
read that as False: it printed `VALIDATION ERRORS` and exited 1.  Only False,
which Stage 5 sets when it refuses the bundle, is a refusal now.

As in test_cli_exit_codes.py, the pipeline is replaced by a RunResult-shaped
namespace; what is checked is how main.py reports and exits.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

import main


def _result(valid, validation) -> SimpleNamespace:
    """What run_pipeline reads of a RunResult (pipeline/orchestrator.py)."""
    return SimpleNamespace(entities=[], llm_result=None, ran=lambda stage: False, ioc_coverage=None,
                           bundle=None, stages=[], valid=valid, validation=validation)


@pytest.fixture(autouse=True)
def _no_database_no_local_settings(monkeypatch):
    """No database, and none of the variables a developer's `.env` may set
    (main.py loads `.env` at import)."""
    import api.db as db

    monkeypatch.setattr(db, "DATABASE_URL", None)
    for var in ("PIPELINE_DISABLED_STAGES", "STIX_TLP", "TTP_MODE"):
        monkeypatch.delenv(var, raising=False)


def _run_one_file(monkeypatch, tmp_path, capsys, result, *extra: str) -> tuple[int, str]:
    """main.main() on one file with `result` as the pipeline's answer: the exit
    status and what was printed."""
    monkeypatch.setattr(main, "run_document", lambda document, options, hooks: result)
    out = str(tmp_path / "bundle.json")
    monkeypatch.setattr("sys.argv", ["main.py", "--no-llm", "report.txt", "--output", out, *extra])
    try:
        main.main()
    except SystemExit as exc:
        code = 0 if exc.code is None else exc.code
    else:
        code = 0
    return code, capsys.readouterr().out


@pytest.mark.parametrize("extra", [
    ("--disable-stage", "5"),
    ("--disable-stage", "4"),     # no bundle: Stage 5 is recorded as skipped
])
def test_a_stage_5_that_did_not_run_is_0_issue_457(monkeypatch, tmp_path, capsys, extra):
    code, out = _run_one_file(monkeypatch, tmp_path, capsys, _result(None, None), *extra)
    assert code == 0
    assert "VALIDATION ERRORS" not in out
    assert "validation skipped" in out


@pytest.mark.parametrize(("valid", "validation", "code", "status"), [
    (True, "validated", 0, "[OK] report.txt"),          # control: a validated run is still OK
    (False, "invalid", 1, "VALIDATION ERRORS"),         # control: a refused bundle is still 1
])
def test_stage_5_answer_still_decides_issue_457(monkeypatch, tmp_path, capsys, valid, validation, code, status):
    got, out = _run_one_file(monkeypatch, tmp_path, capsys, _result(valid, validation))
    assert got == code
    assert status in out
