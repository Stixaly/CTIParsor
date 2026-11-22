"""The worker names its missing optional dependencies once at start (#982).

ocr_available() and nlp_status() are patched: no model is loaded and no binary is probed.
"""
from __future__ import annotations

import logging

import api.worker as worker
import pipeline.stage1_ingestion as stage1
import pipeline.stage2_extraction as stage2


def _state(monkeypatch, *, ocr=True, iocextract=True, spacy_model="en_core_web_sm", spacy_skipped=False):
    monkeypatch.setattr(stage1, "ocr_available", lambda: ocr)
    monkeypatch.setattr(stage2, "nlp_status", lambda: {
        "spacy_model": spacy_model, "spacy_skipped": spacy_skipped, "iocextract": iocextract})


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if "optional dependencies" in r.getMessage()]


def test_everything_present_logs_nothing_issue_982(monkeypatch, caplog):
    _state(monkeypatch)

    with caplog.at_level(logging.WARNING, logger=worker.logger.name):
        worker.log_missing_optional_dependencies()

    assert _warnings(caplog) == []


def test_every_missing_dependency_is_named_in_one_warning_issue_982(monkeypatch, caplog):
    _state(monkeypatch, ocr=False, iocextract=False, spacy_model=None)

    with caplog.at_level(logging.WARNING, logger=worker.logger.name):
        worker.log_missing_optional_dependencies()

    assert _warnings(caplog) == [
        "optional dependencies missing: OCR (tesseract/pdftoppm/pytesseract/pdf2image), "
        "iocextract (IPv6), spaCy model"]


def test_only_iocextract_missing_is_named_alone_issue_982(monkeypatch, caplog):
    _state(monkeypatch, iocextract=False)

    with caplog.at_level(logging.WARNING, logger=worker.logger.name):
        worker.log_missing_optional_dependencies()

    assert _warnings(caplog) == ["optional dependencies missing: iocextract (IPv6)"]


def test_spacy_turned_off_by_choice_is_not_missing_issue_982(monkeypatch, caplog):
    _state(monkeypatch, spacy_model=None, spacy_skipped=True)

    with caplog.at_level(logging.WARNING, logger=worker.logger.name):
        worker.log_missing_optional_dependencies()

    assert _warnings(caplog) == []
