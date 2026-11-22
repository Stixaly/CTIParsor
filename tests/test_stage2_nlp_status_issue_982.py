"""Stage 2 reports which NLP pieces it loaded (#982, points 2 and 3).

No network and no model load: the module state is set by monkeypatch.  The
warnings are logged once per process by _log_missing_models_once().
"""
from __future__ import annotations

import logging

import pytest

import pipeline.stage2_extraction as stage2


@pytest.fixture
def fresh_log_flag(monkeypatch):
    monkeypatch.setattr(stage2, "_nlp_status_logged", False)


def test_nlp_status_has_the_three_keys_issue_982():
    status = stage2.nlp_status()

    assert set(status) == {"spacy_model", "spacy_skipped", "iocextract"}
    assert status["spacy_model"] is None or isinstance(status["spacy_model"], str)
    assert isinstance(status["spacy_skipped"], bool)
    assert isinstance(status["iocextract"], bool)


def test_iocextract_absent_is_reported_issue_982(monkeypatch):
    monkeypatch.setattr(stage2, "_IOCEXTRACT_AVAILABLE", False)

    assert stage2.nlp_status()["iocextract"] is False


def test_iocextract_absent_warns_once_issue_982(monkeypatch, caplog, fresh_log_flag):
    monkeypatch.setattr(stage2, "_IOCEXTRACT_AVAILABLE", False)
    monkeypatch.setattr(stage2, "_SKIP_HEAVY", True)

    with caplog.at_level(logging.WARNING, logger=stage2.logger.name):
        stage2._log_missing_models_once()
        stage2._log_missing_models_once()

    messages = [r.getMessage() for r in caplog.records if "iocextract" in r.getMessage()]
    assert messages == ["iocextract not installed: IPv6 addresses are not extracted"]


def test_spacy_absent_not_by_choice_is_reported_issue_982(monkeypatch):
    monkeypatch.setattr(stage2, "_SKIP_HEAVY", False)
    monkeypatch.setattr(stage2, "_nlp", None)
    monkeypatch.setattr(stage2, "_nlp_model_name", None)

    status = stage2.nlp_status()

    assert status["spacy_model"] is None
    assert status["spacy_skipped"] is False


def test_spacy_absent_not_by_choice_warns_once_issue_982(monkeypatch, caplog, fresh_log_flag):
    monkeypatch.setattr(stage2, "_SKIP_HEAVY", False)
    monkeypatch.setattr(stage2, "_nlp", None)
    monkeypatch.setattr(stage2, "_nlp_model_name", None)

    with caplog.at_level(logging.WARNING, logger=stage2.logger.name):
        stage2._log_missing_models_once()
        stage2._log_missing_models_once()

    messages = [r.getMessage() for r in caplog.records if "named-entity" in r.getMessage()]
    assert messages == [
        "spaCy model en_core_web_lg/en_core_web_sm not installed: named-entity recognition is off",
    ]


def test_spacy_skipped_by_choice_does_not_warn_issue_982(monkeypatch, caplog, fresh_log_flag):
    monkeypatch.setattr(stage2, "_SKIP_HEAVY", True)
    monkeypatch.setattr(stage2, "_nlp", None)
    monkeypatch.setattr(stage2, "_nlp_model_name", None)

    with caplog.at_level(logging.WARNING, logger=stage2.logger.name):
        stage2._log_missing_models_once()

    assert not [r for r in caplog.records if "named-entity" in r.getMessage()]
    assert stage2.nlp_status()["spacy_skipped"] is True
