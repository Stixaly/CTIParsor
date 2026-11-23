"""pipeline/orchestrator.py — a stage whose input or data was missing is degraded
or failed, not declared successful (issue #982).

Each case patches the function the orchestrator imports at call time, so the
stage sees what a missing library or a corrupt data file would give it.  The
LLM is the `mock_llm` fixture (conftest).
"""
import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from pipeline import orchestrator as orch
from pipeline.orchestrator import (
    DEGRADED,
    FAILED,
    RAN,
    SKIPPED,
    Document,
    RunOptions,
    StageOutcome,
    StageRequired,
    run_document,
)

_OCR_LIBS = "OCR libraries not installed (pytesseract, pdf2image)"


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


def _nlp(spacy_model="en_core_web_sm", spacy_skipped=False, iocextract=True) -> dict:
    """What nlp_status() reports for an installation."""
    return {"spacy_model": spacy_model, "spacy_skipped": spacy_skipped, "iocextract": iocextract}


def _a_report(tmp_path) -> str:
    report = tmp_path / "report.txt"
    report.write_text("APT29 used SUNBURST.", encoding="utf-8")
    return str(report)


def _a_pdf(tmp_path):
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(b"%PDF-1.4\n")
    return pdf


@contextmanager
def _ocr_record(summary: dict):
    """What ocr_summary() yields for a document read inside it: the given counts."""
    yield summary


def _read_as(monkeypatch, text: str, summary: dict) -> None:
    """Stage 1 reads `text` and its OCR record is `summary`."""
    monkeypatch.setattr("pipeline.stage1_ingestion.ingest", lambda path: text)
    monkeypatch.setattr("pipeline.stage1_ingestion.ocr_summary", lambda: _ocr_record(summary))


# ── Stage 1: ingestion ───────────────────────────────────────────────────────

def test_a_scanned_pdf_with_no_ocr_library_fails_stage_1_and_stops_the_run(tmp_path, monkeypatch, mock_llm):
    _read_as(monkeypatch, "", {"pages": 0, "pages_failed": 5, "pages_total": 5, "unavailable": _OCR_LIBS})

    with pytest.raises(StageRequired) as err:
        run_document(Document(file_path=_a_report(tmp_path)), _opts())

    assert err.value.outcome.stage == "1" and err.value.outcome.status == FAILED
    assert err.value.outcome.reason == f"no readable text: {_OCR_LIBS}"
    assert mock_llm.call_count == 0                       # no stage read the empty text


def test_an_empty_text_with_every_page_failed_says_so(tmp_path, monkeypatch, mock_llm):
    _read_as(monkeypatch, "", {"pages": 0, "pages_failed": 3, "pages_total": 3})

    with pytest.raises(StageRequired) as err:
        run_document(Document(file_path=_a_report(tmp_path)), _opts())

    assert err.value.outcome.reason == "no readable text: OCR failed on every page"


def test_an_empty_report_file_fails_stage_1(tmp_path, mock_llm):
    empty = tmp_path / "empty.txt"
    empty.write_text("", encoding="utf-8")

    with pytest.raises(StageRequired) as err:
        run_document(Document(file_path=str(empty)), _opts())

    assert err.value.outcome.stage == "1" and err.value.outcome.status == FAILED
    assert err.value.outcome.reason == "no readable text in the document"


def test_a_document_with_some_pages_unread_by_ocr_is_degraded(tmp_path, monkeypatch, mock_llm, sample_cti_text):
    _read_as(monkeypatch, sample_cti_text, {"pages": 3, "pages_failed": 2, "pages_total": 5,
                                             "languages": {"eng": 3}})

    result = run_document(Document(file_path=_a_report(tmp_path)), _opts())

    stage1 = result.outcome("1")
    assert stage1.status == DEGRADED and stage1.reason == "2 of 5 pages could not be read by OCR"
    assert stage1.details["ocr"]["pages_failed"] == 2
    assert result.llm_result is not None                 # the run goes on over the pages it read


# ── Stage 1f: figures ────────────────────────────────────────────────────────

def test_a_figure_answer_of_an_unexpected_type_degrades_stage_1f(mock_llm, sample_cti_text, tmp_path, monkeypatch):
    from pipeline import vlm

    monkeypatch.setattr(vlm, "get_backend", lambda: SimpleNamespace(name="vllm", model="Inferact/Qwen3.8"))
    monkeypatch.setattr("pipeline.stage1f_figures.read_figures", lambda *args, **kwargs: [])
    monkeypatch.setattr("pipeline.stage1f_figures.count_unexpected_kind", lambda reads: 1)

    result = run_document(Document(text=sample_cti_text, figure_pdf=_a_pdf(tmp_path)), _opts())

    outcome = result.outcome("1f")
    assert outcome.status == DEGRADED
    assert outcome.reason == ("vllm/Inferact/Qwen3.8; 1 figure answer(s) of an unexpected type left unread")
    assert outcome.counts["unexpected_kind"] == 1


# ── Stage 2: regex, spaCy, iocextract ────────────────────────────────────────

def test_a_missing_iocextract_degrades_stage_2(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.stage2_extraction.nlp_status", lambda: _nlp(iocextract=False))

    result = run_document(Document(text=sample_cti_text), _opts())

    stage2 = result.outcome("2")
    assert stage2.status == DEGRADED
    assert "iocextract not installed: IPv6 addresses are not extracted" in stage2.reason
    assert stage2.details == {"spacy_model": "en_core_web_sm", "iocextract": False, "discarded_iocs": {}}


def test_a_missing_spacy_model_degrades_stage_2(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.stage2_extraction.nlp_status", lambda: _nlp(spacy_model=None))

    result = run_document(Document(text=sample_cti_text), _opts())

    assert result.outcome("2").status == DEGRADED
    assert result.outcome("2").reason.endswith("spaCy model not installed: named-entity recognition is off")


def test_a_spacy_model_skipped_by_choice_is_not_a_fault(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.stage2_extraction.nlp_status",
                        lambda: _nlp(spacy_model=None, spacy_skipped=True))

    result = run_document(Document(text=sample_cti_text), _opts())

    stage2 = result.outcome("2")
    assert stage2.status == RAN and "spaCy" not in stage2.reason
    assert stage2.details == {"spacy_model": None, "iocextract": True, "discarded_iocs": {}}


# ── Stage 2b: gazetteer ──────────────────────────────────────────────────────

def test_an_unreadable_gazetteer_fails_stage_2b_and_the_run_goes_on(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.stage2b_gazetteer.load_error", lambda: "Expecting value: line 3 column 1")

    result = run_document(Document(text=sample_cti_text), _opts())

    stage2b = result.outcome("2b")
    assert stage2b.status == FAILED
    assert stage2b.reason == "gazetteer unreadable: Expecting value: line 3 column 1"
    assert result.llm_result is not None and result.bundle is not None


def test_an_unreadable_gazetteer_stops_a_run_that_requires_stage_2b(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.stage2b_gazetteer.load_error", lambda: "Expecting value: line 3 column 1")

    with pytest.raises(StageRequired) as err:
        run_document(Document(text=sample_cti_text), _opts(required=frozenset({"2b"})))

    assert err.value.outcome.stage == "2b" and err.value.outcome.status == FAILED


# ── Stage 3f: ATT&CK definitions ─────────────────────────────────────────────

def _select_answers(mock_llm, mock_llm_response):
    """The extraction prompt gets the usual answer; the selection prompt a valid one."""
    from pipeline import stage3f_ttp_select as sel

    def answer(system, user, provider=None, max_output_tokens=None):
        if system.startswith(sel._SELECT_SYSTEM):
            return '{"selected": []}'
        return json.dumps(mock_llm_response)
    mock_llm.side_effect = answer


def test_selected_techniques_without_their_definitions_degrade_stage_3f(mock_llm, mock_llm_response,
                                                                       sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.stage3f_ttp_select.definitions_error",
                        lambda: "ATT&CK definitions unreadable: RuntimeError: index cut in half")
    _select_answers(mock_llm, mock_llm_response)

    result = run_document(Document(text=sample_cti_text),
                          _opts(verify_ttps=True, ttp_mode="select", disabled=frozenset({"2f", "2c"})))

    stage3f = result.outcome("3f")
    assert stage3f.counts["ok"] >= 1
    assert stage3f.status == DEGRADED
    assert stage3f.reason.endswith("ATT&CK definitions unreadable: RuntimeError: index cut in half: "
                                   "techniques were selected without their ATT&CK definitions")


def test_nothing_to_select_is_not_degraded_by_a_definitions_error(mock_llm, mock_llm_response,
                                                                 sample_cti_text, monkeypatch):
    """No technique at all: the selection is never asked and no definition is read."""
    monkeypatch.setattr("pipeline.stage3f_ttp_select.definitions_error",
                        lambda: "ATT&CK definitions unreadable: RuntimeError: index cut in half")
    mock_llm.return_value = json.dumps({**mock_llm_response, "ttps": []})

    result = run_document(Document(text=sample_cti_text),
                          _opts(verify_ttps=True, ttp_mode="select", disabled=frozenset({"2f", "2c"})))

    stage3f = result.outcome("3f")
    assert (stage3f.status, stage3f.reason) == (RAN, "nothing to verify")


# ── The state itself ─────────────────────────────────────────────────────────

def test_a_degraded_stage_counts_as_ran_and_not_as_not_run():
    result = orch.RunResult(document=Document(text="x"))
    result.stages += [StageOutcome("2", DEGRADED, "spaCy model not installed"),
                      StageOutcome("2b", FAILED, "gazetteer unreadable"),
                      StageOutcome("2c", SKIPPED, "disabled")]

    assert result.ran("2") and not result.ran("2b") and not result.ran("2c")
    assert [o.stage for o in result.not_run()] == ["2b", "2c"]


def test_a_required_stage_that_is_degraded_does_not_stop_the_run(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.stage2_extraction.nlp_status", lambda: _nlp(iocextract=False))

    result = run_document(Document(text=sample_cti_text), _opts(required=frozenset({"2"})))

    assert result.outcome("2").status == DEGRADED and result.ran("2")


# ── Non-regression: nothing missing, nothing degraded ────────────────────────

def test_an_ordinary_report_with_nothing_missing_has_no_degraded_stage(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.stage2_extraction.nlp_status", lambda: _nlp())

    result = run_document(Document(text=sample_cti_text), _opts())

    assert not [o.stage for o in result.stages if o.status == DEGRADED]
    assert {o.status for o in result.stages} <= {RAN, SKIPPED}      # no failure either
    assert all(result.ran(stage) for stage in ("1", "2", "2b", "3", "4"))


def test_a_report_with_no_entities_is_ran_with_nothing_found(mock_llm, monkeypatch):
    monkeypatch.setattr("pipeline.stage2_extraction.nlp_status", lambda: _nlp())
    text = "The quarterly review was held on Monday. Attendance was good and the agenda was short."

    result = run_document(Document(text=text), _opts())

    assert result.outcome("1").status == RAN
    assert result.outcome("2").status == RAN and result.outcome("2").counts["entities"] == 0
    assert result.outcome("2b").status == RAN
