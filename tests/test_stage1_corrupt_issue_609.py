"""A corrupt PDF or DOCX is a ValueError from ingest(), and a batch survives it (#609).

ingest() used to let pdfplumber's PdfminerException and zipfile.BadZipFile out,
so main.py showed a traceback and `--input-dir` stopped at the first bad file.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

import main
from pipeline.stage1_ingestion import ingest


@pytest.fixture
def corrupt_pdf(tmp_path):
    path = tmp_path / "corrupt.pdf"
    path.write_bytes(b"%PDF-1.4\nthis is not a real pdf\n")
    return path


@pytest.fixture
def corrupt_docx(tmp_path):
    path = tmp_path / "corrupt.docx"
    path.write_bytes(b"PK\x03\x04garbage-not-a-zip")
    return path


def test_a_corrupt_pdf_is_a_value_error(corrupt_pdf):
    with pytest.raises(ValueError, match=r"^corrupt\.pdf: unreadable or corrupt pdf file \(\w+: ") as info:
        ingest(str(corrupt_pdf))
    assert info.value.__cause__ is not None      # the parser's exception is chained


def test_a_corrupt_docx_is_a_value_error(corrupt_docx):
    with pytest.raises(ValueError, match=r"^corrupt\.docx: unreadable or corrupt docx file \(BadZipFile: ") as info:
        ingest(str(corrupt_docx))
    assert info.value.__cause__ is not None


def test_a_value_error_from_a_reader_is_kept_as_is(monkeypatch, corrupt_pdf):
    import pipeline.stage1_ingestion as s1

    def reader(path):
        raise ValueError("Document trop volumineux : 1 octets décompressés")

    monkeypatch.setattr(s1, "_read_pdf", reader)
    with pytest.raises(ValueError) as info:
        ingest(str(corrupt_pdf))
    assert str(info.value) == "Document trop volumineux : 1 octets décompressés"
    assert info.value.__cause__ is None


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt()])
def test_resource_and_interrupt_exceptions_are_not_swallowed(monkeypatch, corrupt_pdf, error):
    import pipeline.stage1_ingestion as s1

    def reader(path):
        raise error

    monkeypatch.setattr(s1, "_read_pdf", reader)
    with pytest.raises(type(error)):
        ingest(str(corrupt_pdf))


# ── CLI batch ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _no_database_no_local_settings(monkeypatch):
    """No database, and none of the variables a developer's `.env` may set."""
    import api.db as db

    monkeypatch.setattr(db, "DATABASE_URL", None)
    for var in ("PIPELINE_DISABLED_STAGES", "STIX_TLP", "TTP_MODE"):
        monkeypatch.delenv(var, raising=False)


def _batch_argv(reports, out):
    return ["main.py", "--no-llm", "--input-dir", str(reports), "--output-dir", str(out)]


def _run_main(monkeypatch, capsys, argv) -> tuple[int, str]:
    monkeypatch.setattr("sys.argv", argv)
    try:
        main.main()
    except SystemExit as exc:
        code = 0 if exc.code is None else exc.code
    else:
        code = 0
    return code, capsys.readouterr().out


def _real_ingest_pipeline(document, options, hooks):
    """The pipeline's Stage 1 for real; the rest of the run is not needed here."""
    ingest(document.file_path)
    return SimpleNamespace(entities=[], llm_result=None, ran=lambda stage: False, ioc_coverage=None,
                           bundle=None, stages=[], valid=True, validation="validated")


def test_a_corrupt_pdf_does_not_stop_the_batch(monkeypatch, tmp_path, capsys, corrupt_pdf):
    reports = tmp_path / "in"
    reports.mkdir()
    (reports / "corrupt.pdf").write_bytes(corrupt_pdf.read_bytes())
    (reports / "ok.txt").write_text(
        "A real report text with enough characters to pass every gate, about a campaign "
        "using 185.220.101.4 and evil-domain[.]com and T1059.004.", encoding="utf-8")
    monkeypatch.setattr(main, "run_document", _real_ingest_pipeline)

    code, out = _run_main(monkeypatch, capsys, _batch_argv(reports, tmp_path / "out"))

    assert code == 1
    assert "Rapport : ok.txt" in out                       # the valid file was processed
    assert "corrupt.pdf: unreadable or corrupt pdf file" in out
    assert "Traceback" not in out
    assert "RÉSUMÉ — 2 rapport(s) traité(s)" in out
    assert "✔  ok.txt" in out
    assert "✖  corrupt.pdf" in out


def test_an_unexpected_exception_is_a_failure_of_that_file_only(monkeypatch, tmp_path, capsys):
    reports = tmp_path / "in"
    reports.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (reports / name).write_text("report", encoding="utf-8")
    ran: list[str] = []

    def run_pipeline(input_file, output_file, options=None, policy_source="db"):
        name = input_file.replace("\\", "/").rsplit("/", 1)[-1]
        ran.append(name)
        if name == "b.txt":
            raise RuntimeError("parser exploded")
        return True

    monkeypatch.setattr(main, "run_pipeline", run_pipeline)
    code, out = _run_main(monkeypatch, capsys, _batch_argv(reports, tmp_path / "out"))

    assert code == 1
    assert ran == ["a.txt", "b.txt", "c.txt"]              # the batch went on past b.txt
    assert "RuntimeError: parser exploded" in out
    assert "✔  a.txt" in out and "✖  b.txt" in out and "✔  c.txt" in out
