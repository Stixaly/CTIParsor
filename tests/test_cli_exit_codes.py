"""The exit codes of the pipeline CLI, as docs/support-policy.md lists them.

0: the bundle was written and Stage 5 did not refuse it (`validated` or
`unverified`); every file of a folder gave 0, or the folder holds no
supported file.  1: Stage 5 refused the bundle; the file was not found; a
stage named by --require-stage did not run; the database cannot be migrated;
the folder does not exist; a file of the folder gave 1.  2: a usage error.

They are a stable surface (ADR-0094 item 1): changing one is a breaking
change.  `main()` runs in this process; where a real run would need models or
a database, the pipeline is replaced, so what is checked is how main.py turns
each outcome into its exit code.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

import main
from pipeline.orchestrator import StageOutcome, StageRequired


def _status(exc: SystemExit) -> int:
    """The process's exit status for `exc`, as the interpreter computes it:
    None is 0, an int is itself, anything else is printed and gives 1."""
    if exc.code is None:
        return 0
    if isinstance(exc.code, int):
        return exc.code
    return 1


def _exit_status(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr("sys.argv", ["main.py", *argv])
    try:
        main.main()
    except SystemExit as exc:
        return _status(exc)
    return 0          # main() returned: the interpreter exits 0


def _result(valid: bool, validation: str) -> SimpleNamespace:
    """What run_pipeline reads of a RunResult (pipeline/orchestrator.py)."""
    return SimpleNamespace(entities=[], llm_result=None, ran=lambda stage: False, ioc_coverage=None,
                           bundle=None, stages=[], valid=valid, validation=validation)


def _never(*args, **kwargs):
    pytest.fail("the pipeline ran, where the arguments should have been refused")


@pytest.fixture(autouse=True)
def _no_database_no_local_settings(monkeypatch):
    """No database: prepare_store() says so and the run goes on.  None of the
    variables a developer's `.env` may set that change how the arguments are
    read (main.py loads `.env` at import)."""
    import api.db as db

    monkeypatch.setattr(db, "DATABASE_URL", None)
    for var in ("PIPELINE_DISABLED_STAGES", "STIX_TLP", "TTP_MODE"):
        monkeypatch.delenv(var, raising=False)


# ── 2: usage errors ──────────────────────────────────────────────────────────

def test_help_is_0(monkeypatch):
    assert _exit_status(monkeypatch, "--help") == 0


@pytest.mark.parametrize("argv", [
    (),                                              # neither a file nor --input-dir
    ("report.txt", "--input-dir", "reports"),        # both
    ("--no-such-option", "report.txt"),
    ("--disable-stage", "1", "report.txt"),          # a mandatory stage
    ("--disable-stage", "3r", "report.txt"),
    ("--disable-stage", "zz", "report.txt"),         # an unknown stage id
    ("--require-stage", "9", "report.txt"),
])
def test_a_usage_error_is_2(monkeypatch, argv):
    monkeypatch.setattr(main, "run_pipeline", _never)
    monkeypatch.setattr(main, "run_directory", _never)
    assert _exit_status(monkeypatch, *argv) == 2


def test_a_refused_stix_tlp_is_2(monkeypatch):
    monkeypatch.setattr(main, "run_pipeline", _never)
    monkeypatch.setenv("STIX_TLP", "BOGUS")
    assert _exit_status(monkeypatch, "--no-llm", "report.txt") == 2


# ── One file ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(("valid", "validation", "code"), [
    (True, "validated", 0),
    (True, "unverified", 0),       # JSON schemas missing: not refused
    (False, "invalid", 1),         # Stage 5 refused the bundle
])
def test_one_file_exits_with_what_stage_5_said(monkeypatch, tmp_path, valid, validation, code):
    monkeypatch.setattr(main, "run_document", lambda document, options, hooks: _result(valid, validation))
    out = str(tmp_path / "bundle.json")
    assert _exit_status(monkeypatch, "--no-llm", "report.txt", "--output", out) == code


@pytest.mark.parametrize("error", [
    FileNotFoundError("Fichier introuvable : report.txt"),      # what Stage 1 raises
    StageRequired(StageOutcome(stage="3", status="skipped", reason="disabled")),
])
def test_a_missing_file_or_a_required_stage_that_did_not_run_is_1(monkeypatch, tmp_path, error):
    def run_document(document, options, hooks):
        raise error

    monkeypatch.setattr(main, "run_document", run_document)
    out = str(tmp_path / "bundle.json")
    assert _exit_status(monkeypatch, "--no-llm", "report.txt", "--output", out) == 1


# ── A folder ─────────────────────────────────────────────────────────────────

def test_a_missing_folder_is_1(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "run_pipeline", _never)
    assert _exit_status(monkeypatch, "--no-llm", "--input-dir", str(tmp_path / "absent")) == 1


def test_a_folder_without_a_supported_file_is_0(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "run_pipeline", _never)
    (tmp_path / "notes.xyz").write_text("not a report", encoding="utf-8")
    assert _exit_status(monkeypatch, "--no-llm", "--input-dir", str(tmp_path)) == 0


@pytest.mark.parametrize(("failing", "code"), [(set(), 0), ({"b.txt"}, 1)])
def test_a_folder_is_1_when_one_file_is(monkeypatch, tmp_path, failing, code):
    reports = tmp_path / "in"
    reports.mkdir()
    for name in ("a.txt", "b.txt"):
        (reports / name).write_text("report", encoding="utf-8")
    ran: list[str] = []

    def run_pipeline(input_file, output_file, options=None, policy_source="db"):
        name = input_file.replace("\\", "/").rsplit("/", 1)[-1]
        ran.append(name)
        return name not in failing

    monkeypatch.setattr(main, "run_pipeline", run_pipeline)
    argv = ("--no-llm", "--input-dir", str(reports), "--output-dir", str(tmp_path / "out"))
    assert _exit_status(monkeypatch, *argv) == code
    assert ran == ["a.txt", "b.txt"]          # a failure does not stop the batch


# ── The database ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("argv", [("--no-llm", "report.txt"), ("--no-llm", "--input-dir", "reports")])
def test_a_database_the_code_cannot_migrate_is_1(monkeypatch, argv):
    import api.db as db
    from api.migrate import DatabaseNewerThanCode

    def newer() -> None:
        raise DatabaseNewerThanCode("the database is at version 99, this code knows 13")

    monkeypatch.setattr(db, "DATABASE_URL", "postgresql://u@127.0.0.1:5432/d")
    monkeypatch.setattr(db, "init_db", newer)
    monkeypatch.setattr(main, "run_pipeline", _never)
    monkeypatch.setattr(main, "run_directory", _never)
    assert _exit_status(monkeypatch, *argv) == 1
