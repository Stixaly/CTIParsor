"""Stage 2d regressions: issue #775 and issue #768.

#775: a comma or slash left at the end of a CyNER span ("Emotet,") survived,
because _split_fragments returned the unsplit value when one part was left.

#768: an exception on the whole batch made extract_cyner_entities return []
with no retry, and the orchestrator recorded Stage 2d as RAN with 0 entities.
Now a failed batch is asked again one chunk at a time, and a stage that got
no answer for any chunk is recorded FAILED.
"""
from __future__ import annotations

import pytest

from models.schemas import EntityType
from pipeline import stage2d_cyner
from pipeline.orchestrator import Document, RunOptions, run_document

# ── #775: a separator left alone at the end of a span ───────────────────────

@pytest.mark.parametrize("value", ["Emotet,", "Emotet/"])
def test_a_trailing_separator_is_not_kept_on_the_single_part_left(value):
    assert stage2d_cyner._split_fragments(value) == ["Emotet"]
    assert [stage2d_cyner._normalize_candidate(f) for f in stage2d_cyner._split_fragments(value)] == ["Emotet"]


def test_a_lone_separator_is_returned_unchanged():
    assert stage2d_cyner._split_fragments(",") == [","]


def test_extract_does_not_keep_a_trailing_separator(monkeypatch):
    preds = [{"entity_group": "Malware", "score": 0.95, "word": "Emotet,"}]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: lambda _inputs, **_kw: preds)

    values = {r.value for r in stage2d_cyner.extract_cyner_entities("irrelevant text")}
    assert values == {"Emotet"}


# ── #768: a failed batch falls back to chunks; no answer at all is FAILED ───

# Three chunks: the poison marker sits at offset 0, so only the first chunk
# contains it (the next chunk starts about 1400 characters in).
_POISONED_TEXT = "POISON " + "Emotet dropped a loader on the host. " * 100


def _pipeline_refusing_poisoned_chunks(inputs, **_kw):
    if any("POISON" in chunk for chunk in inputs):
        raise RuntimeError("CUDA out of memory")
    return [[{"entity_group": "Malware", "score": 0.97, "word": "Emotet"}] for _ in inputs]


def _pipeline_always_failing(_inputs, **_kw):
    raise RuntimeError("CUDA out of memory")


def test_a_failed_batch_is_retried_chunk_by_chunk_and_healthy_chunks_survive(monkeypatch):
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _pipeline_refusing_poisoned_chunks)

    run = stage2d_cyner.run_cyner(_POISONED_TEXT)

    assert run.chunks >= 2
    assert run.retried_batches == 1
    assert run.unanswered == 1
    assert run.failure() == ""
    assert [(r.value, r.entity_type) for r in run.entities] == [("Emotet", EntityType.MALWARE)]


def test_extract_keeps_the_entities_of_the_chunks_that_answered(monkeypatch):
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _pipeline_refusing_poisoned_chunks)

    results = stage2d_cyner.extract_cyner_entities(_POISONED_TEXT)
    assert [(r.value, r.entity_type) for r in results] == [("Emotet", EntityType.MALWARE)]


def test_no_chunk_answered_is_a_failure_of_the_run(monkeypatch):
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _pipeline_always_failing)

    run = stage2d_cyner.run_cyner(_POISONED_TEXT)

    assert run.entities == [] and run.answered == 0
    assert run.failure().startswith(f"the model answered none of the {run.chunks} chunks")
    assert stage2d_cyner.extract_cyner_entities(_POISONED_TEXT) == []


def _run_document(monkeypatch, text):
    """A run of *text* whose other model stages and LLM are off."""
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)
    monkeypatch.setattr(stage2d_cyner, "cyner_available", lambda: True)
    options = RunOptions(disabled=frozenset({"1f", "2f", "3"}), consensus=False, document_relations=False,
                         verify_relationships=False, verify_ttps=False, llm_parallelism=1)
    return run_document(Document(text=text, original_filename="r.txt"), options)


def test_the_stage_report_says_ran_when_some_chunks_answered(monkeypatch):
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _pipeline_refusing_poisoned_chunks)

    result = _run_document(monkeypatch, _POISONED_TEXT)
    outcome = result.outcome("2d")

    assert outcome.status == "ran"
    assert outcome.counts["chunks_unanswered"] == 1
    assert [e.value for e in result.cyner] == ["Emotet"]


def test_the_stage_report_says_failed_when_the_model_answered_no_chunk(monkeypatch):
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _pipeline_always_failing)

    outcome = _run_document(monkeypatch, _POISONED_TEXT).outcome("2d")

    assert outcome.status == "failed"
    assert "answered none" in outcome.reason
