"""pipeline/stage2c_ttp_semantic.py and its orchestrator branch: a Stage 2c that
could not score is FAILED with the reason, not "ran with 0 entities" (issue #996,
ADR-0104).

No sentence-transformer is loaded: the model is a fake whose encode raises or
answers, `sentence_transformers.util` is a fake module, and the corpus is a
two-row cache written in tmp_path. The orchestrator tests replace Stage 2c's
availability and status, as tests/test_embedding_record.py does.
"""
from __future__ import annotations

import json
import sys
import types

import numpy as np
import pytest

from pipeline import stage2c_ttp_semantic as s2c
from pipeline.orchestrator import FAILED, RAN, Document, RunOptions, run_document

LEGACY = "all-MiniLM-L6-v2"
META = [
    {"id": "T1566.001", "name": "Spearphishing Attachment", "domain": "enterprise-attack"},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "domain": "enterprise-attack"},
]
TEXT = "The actor used spearphishing emails to deliver a payload."
HIGH_DEFAULT = s2c._MODEL_THRESHOLDS[LEGACY][0]
BAD_HIGH = f"TTP_HIGH_THRESHOLD='0,7' is not a number, the default {HIGH_DEFAULT} applies"


class _Scores:
    def __init__(self, array):
        self._array = array

    def numpy(self):
        return self._array


class _FakeModel:
    """encode() answers [1, 0, 0, 0] for every sentence (the first corpus row), or raises."""

    def __init__(self, error: Exception | None = None):
        self.error = error

    def encode(self, texts, **kwargs):
        if self.error is not None:
            raise self.error
        return np.tile(np.array([1.0, 0.0, 0.0, 0.0], dtype="float32"), (len(texts), 1))


@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


@pytest.fixture()
def scoring(monkeypatch, tmp_path):
    """A 2c that loads LEGACY and reads a two-row cache built with LEGACY."""
    st = types.ModuleType("sentence_transformers")
    st.util = types.SimpleNamespace(cos_sim=lambda a, b: _Scores(np.asarray(a) @ np.asarray(b).T))
    monkeypatch.setitem(sys.modules, "sentence_transformers", st)

    emb, meta, manifest = tmp_path / "emb.npy", tmp_path / "meta.json", tmp_path / "manifest.json"
    np.save(emb, np.eye(2, 4, dtype="float32"))
    meta.write_text(json.dumps(META), encoding="utf-8")
    manifest.write_text(json.dumps({"model": LEGACY}), encoding="utf-8")
    monkeypatch.setattr(s2c, "_EMB_PATH", emb)
    monkeypatch.setattr(s2c, "_META_PATH", meta)
    monkeypatch.setattr(s2c, "_MANIFEST_PATH", manifest)
    monkeypatch.setattr(s2c, "_TTP_EMBEDDING_MODEL", LEGACY)
    monkeypatch.setattr(s2c, "_active_model", None)
    monkeypatch.setattr(s2c, "_load_model", lambda: _FakeModel())
    monkeypatch.setattr(s2c, "_logged_threshold_warnings", set())
    monkeypatch.delenv("TTP_SEMANTIC_DOMAINS", raising=False)
    for var in ("TTP_HIGH_THRESHOLD", "TTP_MEDIUM_THRESHOLD"):
        monkeypatch.delenv(var, raising=False)
    # The corpus is cached by (domains, model), not by path: start and end empty.
    s2c._load_corpus_for.cache_clear()
    yield monkeypatch
    s2c._load_corpus_for.cache_clear()
    # last_error() is this thread's: a test that stubs detect_ttps_semantic
    # afterwards would read the error left here.
    s2c._errors.reason = None


def _verify() -> RunOptions:
    return RunOptions(consensus=False, document_relations=False, llm_parallelism=1, ttp_mode="verify",
                      disabled=frozenset({"2f", "3"}), verify_relationships=False, verify_ttps=False)


def _status() -> dict:
    return {"requested": LEGACY, "loaded": LEGACY, "fallback": False, "cache_model": LEGACY,
            "cache_matches": True, "thresholds": {"high": HIGH_DEFAULT, "medium": 0.48}}


def _run(monkeypatch, text: str = TEXT):
    monkeypatch.setattr(s2c, "semantic_available", lambda: True)
    monkeypatch.setattr(s2c, "embedding_status", _status)
    return run_document(Document(text=text, original_filename="r.txt"), _verify())


# ── The detector: last_error() ───────────────────────────────────────────────

def test_a_scoring_error_gives_no_entities_and_names_the_error(scoring):
    scoring.setattr(s2c, "_load_model", lambda: _FakeModel(RuntimeError("out of memory")))

    assert s2c.detect_ttps_semantic(TEXT) == []
    assert s2c.last_error() == "RuntimeError: out of memory"


def test_last_error_is_reset_by_the_next_call(scoring):
    scoring.setattr(s2c, "_load_model", lambda: _FakeModel(RuntimeError("out of memory")))
    s2c.detect_ttps_semantic(TEXT)

    scoring.setattr(s2c, "_load_model", lambda: _FakeModel())
    entities = s2c.detect_ttps_semantic(TEXT)

    assert [e.mitre_id for e in entities] == ["T1566.001"]
    assert s2c.last_error() is None


def test_a_text_with_no_candidate_sentence_is_not_an_error(scoring):
    assert s2c.detect_ttps_semantic("Nothing here.") == []
    assert s2c.last_error() is None


def test_an_unusable_corpus_is_named_and_not_cached(scoring):
    s2c._MANIFEST_PATH.write_text(json.dumps({"model": "other-model"}), encoding="utf-8")

    assert s2c._load_corpus() is None
    assert s2c.last_error() == f"embedding cache built for other-model, model in use {LEGACY}"

    # The failure is not cached: once the manifest matches, the corpus loads.
    s2c._MANIFEST_PATH.write_text(json.dumps({"model": LEGACY}), encoding="utf-8")
    embeddings, meta = s2c._load_corpus()
    assert embeddings.shape == (2, 4) and len(meta) == 2


# ── The threshold settings ───────────────────────────────────────────────────

def test_a_threshold_that_is_not_a_number_is_named_once(scoring, caplog):
    scoring.setenv("TTP_HIGH_THRESHOLD", "0,7")

    with caplog.at_level("WARNING"):
        assert s2c._thresholds() == (HIGH_DEFAULT, 0.48)
        assert s2c._thresholds() == (HIGH_DEFAULT, 0.48)

    warnings = [r for r in caplog.records if "TTP_HIGH_THRESHOLD" in r.getMessage()]
    assert len(warnings) == 1
    assert warnings[0].getMessage() == f"[Stage 2c] {BAD_HIGH}"


def test_threshold_warnings_say_the_same_sentence_on_every_call(scoring):
    scoring.setenv("TTP_HIGH_THRESHOLD", "0,7")

    assert s2c.threshold_warnings() == [BAD_HIGH]
    s2c._thresholds()
    assert s2c.threshold_warnings() == [BAD_HIGH]


def test_a_numeric_threshold_is_not_named(scoring):
    scoring.setenv("TTP_HIGH_THRESHOLD", "0.7")
    scoring.setenv("TTP_MEDIUM_THRESHOLD", "0.5")

    assert s2c._thresholds() == (0.7, 0.5)
    assert s2c.threshold_warnings() == []


# ── The orchestrator's Stage 2c record ───────────────────────────────────────

def test_a_scoring_error_fails_stage_2c_with_the_reason(scoring):
    scoring.setattr(s2c, "_load_model", lambda: _FakeModel(RuntimeError("out of memory")))

    outcome = _run(scoring).outcome("2c")

    assert outcome.status == FAILED
    assert outcome.reason == "semantic scoring failed: RuntimeError: out of memory"
    assert outcome.counts["entities"] == 0


def test_an_unusable_corpus_fails_stage_2c_with_the_reason(scoring):
    s2c._MANIFEST_PATH.write_text(json.dumps({"model": "other-model"}), encoding="utf-8")

    outcome = _run(scoring).outcome("2c")

    assert outcome.status == FAILED
    assert outcome.reason == (f"semantic scoring failed: embedding cache built for other-model, "
                              f"model in use {LEGACY}")


def test_a_bad_threshold_is_named_and_the_state_is_unchanged(scoring):
    scoring.setenv("TTP_HIGH_THRESHOLD", "0,7")

    outcome = _run(scoring).outcome("2c")

    assert outcome.status == RAN
    assert outcome.reason == BAD_HIGH


def test_a_bad_threshold_is_named_after_a_scoring_error(scoring):
    scoring.setenv("TTP_HIGH_THRESHOLD", "0,7")
    scoring.setattr(s2c, "_load_model", lambda: _FakeModel(RuntimeError("out of memory")))

    outcome = _run(scoring).outcome("2c")

    assert outcome.status == FAILED
    assert outcome.reason == "semantic scoring failed: RuntimeError: out of memory; " + BAD_HIGH


def test_a_nominal_run_of_stage_2c_is_unchanged(scoring):
    result = _run(scoring)

    outcome = result.outcome("2c")
    assert outcome.status == RAN and outcome.reason == ""
    assert outcome.counts["entities"] == 1
    assert [e.mitre_id for e in result.semantic_ttps] == ["T1566.001"]


def test_a_model_that_does_not_load_is_named(scoring):
    """The gate let 2c run, so no model is an error, not "no technique"."""
    scoring.setattr(s2c, "_load_model", lambda: None)
    scoring.setattr(s2c, "_SKIP_HEAVY", False)
    assert s2c.detect_ttps_semantic("The actor dumped credentials from LSASS memory.") == []
    assert s2c.last_error() == f"embedding model {LEGACY} could not be loaded"
