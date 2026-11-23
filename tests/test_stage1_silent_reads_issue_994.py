"""Issue #994: a read of Stage 1 or Stage 1f that fails on an exception and gives
an empty or partial result says so.  The stage is degraded with the reason (the
ADR-0104 rule); a reference date that is not found is a detail, not a degradation.

pdfplumber is replaced by fakes, and the orchestrator cases patch the functions
it imports at call time, as tests/test_orchestrator_degraded_issue_982.py does."""
from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from pipeline import stage1_ingestion as s1
from pipeline import stage1f_figures as figs
from pipeline.orchestrator import DEGRADED, RAN, Document, RunOptions, run_document


class _Pdf:
    def __init__(self, pages: list | None = None):
        self.pages = pages if pages is not None else []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Page:
    """A page with a text layer, whose table finder returns one table of two cells."""

    def extract_text(self):
        return "x" * 200

    def extract_tables(self):
        return [[["a", "b"]]]


def _opener(monkeypatch, module, pages: list | None = None, fail: Exception | None = None):
    def open_(path):
        if fail is not None:
            raise fail
        return _Pdf(pages)

    monkeypatch.setattr(module, "pdfplumber", SimpleNamespace(open=open_))


@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


def _opts(**kw) -> RunOptions:
    """Fixed options: nothing read from the developer's .env."""
    kw.setdefault("disabled", frozenset({"2f"}))   # the CVE cache needs a database
    kw.setdefault("verify_relationships", False)
    kw.setdefault("verify_ttps", False)
    return RunOptions(consensus=False, document_relations=False, llm_parallelism=1, **kw)


def _a_report(tmp_path) -> str:
    report = tmp_path / "report.txt"
    report.write_text("APT29 used SUNBURST.", encoding="utf-8")
    return str(report)


def _a_pdf(tmp_path):
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(b"%PDF-1.4\n")
    return pdf


@contextmanager
def _record(summary: dict):
    """What ocr_summary() yields for a document read inside it: the given counts."""
    yield summary


def _vision(monkeypatch):
    from pipeline import vlm

    monkeypatch.setattr(vlm, "get_backend", lambda: SimpleNamespace(name="vllm", model="Inferact/Qwen3.8"))


# ── Stage 1: the record of one document ──────────────────────────────────────

def test_scan_detection_that_fails_is_noted_and_the_pdf_is_read_as_text(monkeypatch, tmp_path):
    _opener(monkeypatch, s1, fail=ValueError("truncated xref"))

    with s1.ingestion_record():
        assert s1._is_scanned_pdf(tmp_path / "r.pdf") is False
        assert s1.ingestion_notes() == [
            "scan detection failed, read as text without OCR: ValueError: truncated xref"]


def test_table_rows_that_cannot_be_read_are_noted_and_return_nothing(monkeypatch, tmp_path):
    _opener(monkeypatch, s1, fail=RuntimeError("bad xref"))

    with s1.ingestion_record():
        assert s1._rejoined_table_rows(tmp_path / "r.pdf") == ""
        assert s1.ingestion_notes() == [
            "tables not read, IoCs wrapped in table cells may be lost: RuntimeError: bad xref"]


def test_the_table_pass_that_hits_its_ceiling_is_noted(monkeypatch, tmp_path):
    monkeypatch.setattr(s1, "_MAX_TABLES", 2)
    _opener(monkeypatch, s1, pages=[_Page(), _Page(), _Page()])

    with s1.ingestion_record():
        s1._rejoined_table_rows(tmp_path / "r.pdf")
        assert s1.ingestion_notes() == ["table pass stopped at 2 tables, 4 cells"]


def test_an_unreadable_reference_date_is_a_detail_not_a_note(monkeypatch, tmp_path):
    _opener(monkeypatch, s1, fail=RuntimeError("no metadata"))

    with s1.ingestion_record():
        assert s1.extract_reference_date(str(tmp_path / "r.pdf")) is None
        assert s1.reference_date_error() == "RuntimeError: no metadata"
        assert s1.ingestion_notes() == []


def test_an_ordinary_read_has_no_note_and_no_reference_date_error(monkeypatch, tmp_path):
    _opener(monkeypatch, s1, pages=[_Page()])

    with s1.ingestion_record():
        assert s1._is_scanned_pdf(tmp_path / "r.pdf") is False
        s1._rejoined_table_rows(tmp_path / "r.pdf")
        assert s1.ingestion_notes() == []
        assert s1.reference_date_error() is None


def test_the_record_is_empty_for_the_next_document(monkeypatch, tmp_path):
    _opener(monkeypatch, s1, fail=ValueError("truncated xref"))
    with s1.ingestion_record():
        s1._is_scanned_pdf(tmp_path / "r.pdf")
    assert s1.ingestion_notes() == []                     # outside the block: nothing collected

    _opener(monkeypatch, s1, pages=[])
    with s1.ingestion_record():
        assert s1.ingestion_notes() == []
        assert s1.reference_date_error() is None


# ── Stage 1f: figures ────────────────────────────────────────────────────────

def test_a_pdf_whose_images_cannot_be_listed_says_so(monkeypatch, tmp_path):
    _opener(monkeypatch, figs, fail=RuntimeError("broken index"))

    assert figs.find_figures(tmp_path / "r.pdf") == []
    assert figs.find_figures_error() == "RuntimeError: broken index"


def test_the_figure_error_is_reset_by_the_next_call(monkeypatch, tmp_path):
    _opener(monkeypatch, figs, fail=RuntimeError("broken index"))
    figs.find_figures(tmp_path / "r.pdf")

    _opener(monkeypatch, figs, pages=[])
    assert figs.find_figures(tmp_path / "r.pdf") == []
    assert figs.find_figures_error() is None


# ── The orchestrator: stage 1 ────────────────────────────────────────────────

def test_a_note_degrades_stage_1_with_the_note_in_reason_and_details(tmp_path, monkeypatch, mock_llm, sample_cti_text):
    monkeypatch.setattr("pipeline.stage1_ingestion.ingest", lambda path: sample_cti_text)
    monkeypatch.setattr("pipeline.stage1_ingestion.ingestion_notes",
                        lambda: ["tables not read, IoCs wrapped in table cells may be lost: RuntimeError: bad xref"])

    result = run_document(Document(file_path=_a_report(tmp_path)), _opts())

    stage1 = result.outcome("1")
    assert stage1.status == DEGRADED
    assert stage1.reason == ("tables not read, IoCs wrapped in table cells may be lost: "
                             "RuntimeError: bad xref")
    assert stage1.details == {"ingestion_notes": [
        "tables not read, IoCs wrapped in table cells may be lost: RuntimeError: bad xref"]}


def test_a_note_joins_the_ocr_degradation_in_stage_1(tmp_path, monkeypatch, mock_llm, sample_cti_text):
    monkeypatch.setattr("pipeline.stage1_ingestion.ingest", lambda path: sample_cti_text)
    monkeypatch.setattr("pipeline.stage1_ingestion.ocr_summary",
                        lambda: _record({"pages": 3, "pages_failed": 2, "pages_total": 5}))
    monkeypatch.setattr("pipeline.stage1_ingestion.ingestion_notes",
                        lambda: ["scan detection failed, read as text without OCR: ValueError: truncated xref"])

    result = run_document(Document(file_path=_a_report(tmp_path)), _opts())

    stage1 = result.outcome("1")
    assert stage1.status == DEGRADED
    assert stage1.reason == ("2 of 5 pages could not be read by OCR; "
                             "scan detection failed, read as text without OCR: ValueError: truncated xref")
    assert stage1.details["ocr"]["pages_failed"] == 2
    assert stage1.details["ingestion_notes"] == [
        "scan detection failed, read as text without OCR: ValueError: truncated xref"]


def test_an_unreadable_reference_date_is_in_stage_1_details_and_stage_1_ran(tmp_path, monkeypatch,
                                                                           mock_llm, sample_cti_text):
    monkeypatch.setattr("pipeline.stage1_ingestion.ingest", lambda path: sample_cti_text)
    _opener(monkeypatch, s1, fail=RuntimeError("no metadata"))

    result = run_document(Document(file_path=str(_a_pdf(tmp_path))),
                          _opts(disabled=frozenset({"2f", "1f"})))

    stage1 = result.outcome("1")
    assert stage1.status == RAN and stage1.reason == ""
    assert stage1.details == {"reference_date_error": "RuntimeError: no metadata"}
    assert result.reference_date is None


def test_an_ordinary_file_is_stage_1_ran(tmp_path, monkeypatch, mock_llm, sample_cti_text):
    monkeypatch.setattr("pipeline.stage1_ingestion.ingest", lambda path: sample_cti_text)

    result = run_document(Document(file_path=_a_report(tmp_path)), _opts())

    stage1 = result.outcome("1")
    assert stage1.status == RAN and not stage1.details


# ── The orchestrator: stage 1f ───────────────────────────────────────────────

def test_figures_that_cannot_be_detected_degrade_stage_1f(mock_llm, sample_cti_text, tmp_path, monkeypatch):
    _vision(monkeypatch)
    _opener(monkeypatch, figs, fail=RuntimeError("broken index"))

    result = run_document(Document(text=sample_cti_text, figure_pdf=_a_pdf(tmp_path)), _opts())

    outcome = result.outcome("1f")
    assert outcome.status == DEGRADED
    assert outcome.reason == "vllm/Inferact/Qwen3.8; figures not detected: RuntimeError: broken index"
    assert outcome.counts["figures"] == 0


def test_an_ordinary_figure_pass_is_stage_1f_ran(mock_llm, sample_cti_text, tmp_path, monkeypatch):
    _vision(monkeypatch)
    _opener(monkeypatch, figs, pages=[])

    result = run_document(Document(text=sample_cti_text, figure_pdf=_a_pdf(tmp_path)), _opts())

    outcome = result.outcome("1f")
    assert outcome.status == RAN and outcome.reason == "vllm/Inferact/Qwen3.8"
