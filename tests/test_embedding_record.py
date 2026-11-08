"""A run records the embedding model it loaded (ADR-0094 item 13).

No model is loaded: `_active_model` is set by hand, the cache manifest is a file
in tmp_path, and the orchestrator tests replace Stage 2c's availability and
status with fakes.
"""
from __future__ import annotations

import json

import pytest

from pipeline import orchestrator as orch
from pipeline import stage2c_ttp_semantic as s2c
from pipeline.orchestrator import Document, RunOptions, run_document

PRIMARY = "ehsanaghaei/SecureBERT-Plus"
LEGACY = "all-MiniLM-L6-v2"


@pytest.fixture()
def manifest(tmp_path, monkeypatch):
    """Point the module at a cache in tmp_path (embeddings and metadata present);
    the caller writes the manifest."""
    path = tmp_path / "manifest.json"
    for name, attr in (("emb.npy", "_EMB_PATH"), ("meta.json", "_META_PATH")):
        (tmp_path / name).write_bytes(b"")
        monkeypatch.setattr(s2c, attr, tmp_path / name)
    monkeypatch.setattr(s2c, "_MANIFEST_PATH", path)
    monkeypatch.setattr(s2c, "_active_model", None)
    monkeypatch.setattr(s2c, "_TTP_EMBEDDING_MODEL", PRIMARY)
    for var in ("TTP_HIGH_THRESHOLD", "TTP_MEDIUM_THRESHOLD"):
        monkeypatch.delenv(var, raising=False)
    return path


def test_status_before_any_load_asks_for_the_requested_model(manifest):
    manifest.write_text(json.dumps({"model": PRIMARY}), encoding="utf-8")
    st = s2c.embedding_status()
    assert (st["requested"], st["loaded"], st["fallback"]) == (PRIMARY, None, False)
    assert st["cache_model"] == PRIMARY and st["cache_matches"] is True
    assert st["thresholds"] == dict(zip(("high", "medium"), s2c._thresholds(), strict=True))


def test_status_of_the_requested_model_loaded(manifest, monkeypatch):
    manifest.write_text(json.dumps({"model": PRIMARY}), encoding="utf-8")
    monkeypatch.setattr(s2c, "_active_model", PRIMARY)
    st = s2c.embedding_status()
    assert st["loaded"] == PRIMARY and st["fallback"] is False and st["cache_matches"] is True


def test_status_names_a_fallback_and_its_cache(manifest, monkeypatch):
    manifest.write_text(json.dumps({"model": PRIMARY}), encoding="utf-8")
    monkeypatch.setattr(s2c, "_active_model", LEGACY)
    st = s2c.embedding_status()
    assert st["fallback"] is True and st["loaded"] == LEGACY
    assert st["cache_matches"] is False       # the cache is for the encoder that failed to load


def test_status_of_a_cache_built_for_another_model(manifest):
    manifest.write_text(json.dumps({"model": LEGACY}), encoding="utf-8")
    st = s2c.embedding_status()
    assert st["cache_model"] == LEGACY and st["cache_matches"] is False


def test_status_without_a_manifest_reads_the_cache_as_legacy(manifest):
    assert not manifest.exists()
    st = s2c.embedding_status()
    assert st["cache_model"] == LEGACY and st["cache_matches"] is False


def test_status_with_an_unreadable_manifest_reads_the_cache_as_legacy(manifest):
    manifest.write_text("{not json", encoding="utf-8")
    assert s2c.embedding_status()["cache_model"] == LEGACY


def test_status_without_a_cache_has_no_cache_model_and_no_match(manifest, tmp_path, monkeypatch):
    manifest.write_text(json.dumps({"model": PRIMARY}), encoding="utf-8")
    monkeypatch.setattr(s2c, "_EMB_PATH", tmp_path / "absent.npy")
    st = s2c.embedding_status()
    assert st["cache_model"] is None and st["cache_matches"] is False


def test_status_loads_no_model(manifest, monkeypatch):
    def trapped():
        raise AssertionError("embedding_status() loaded a model")

    monkeypatch.setattr(s2c, "_load_model", trapped)
    s2c.embedding_status()


def test_retrieval_status_of_bm25_and_of_the_short_corpus(manifest, monkeypatch):
    from pipeline import ttp_retrieval as tr

    monkeypatch.setattr(tr, "_built_corpus", lambda *a: pytest.fail("the built corpus was read"))
    monkeypatch.setenv("TTP_RETRIEVAL_METHOD", "bm25")
    st = tr.retrieval_status()
    assert st["corpus_model"] is None and st["cache_matches"] is True       # no encoder, nothing to match

    monkeypatch.setenv("TTP_RETRIEVAL_METHOD", "rrf")
    monkeypatch.setenv("TTP_RETRIEVAL_CORPUS", "short")
    manifest.write_text(json.dumps({"model": LEGACY}), encoding="utf-8")
    st = tr.retrieval_status()                                              # the Stage 2c cache
    assert st["corpus_model"] == LEGACY and st["cache_matches"] is False
    manifest.write_text(json.dumps({"model": PRIMARY}), encoding="utf-8")
    assert tr.retrieval_status()["cache_matches"] is True


def test_retrieval_status_without_a_corpus_does_not_match(monkeypatch):
    from pipeline import ttp_retrieval as tr

    monkeypatch.setenv("TTP_RETRIEVAL_METHOD", "rrf")
    monkeypatch.setenv("TTP_RETRIEVAL_CORPUS", "both")
    monkeypatch.setattr(tr, "_built_corpus", lambda *a: None)
    st = tr.retrieval_status()
    assert st["corpus_model"] is None and st["cache_matches"] is False


def test_retrieval_status_compares_the_corpus_with_the_model_in_use(monkeypatch):
    from types import SimpleNamespace

    from pipeline import ttp_retrieval as tr

    monkeypatch.setattr(s2c, "_TTP_EMBEDDING_MODEL", PRIMARY)
    monkeypatch.setattr(s2c, "_active_model", None)
    monkeypatch.setenv("TTP_RETRIEVAL_METHOD", "rrf")
    monkeypatch.setenv("TTP_RETRIEVAL_CORPUS", "both")
    monkeypatch.setattr(tr, "_built_corpus", lambda *a: SimpleNamespace(model=LEGACY, embeddings=[[0.0]]))
    st = tr.retrieval_status()
    assert (st["corpus_model"], st["cache_matches"], st["fallback"]) == (LEGACY, False, False)

    monkeypatch.setattr(tr, "_built_corpus", lambda *a: SimpleNamespace(model=PRIMARY, embeddings=[[0.0]]))
    assert tr.retrieval_status()["cache_matches"] is True

    monkeypatch.setattr(s2c, "_active_model", LEGACY)
    st = tr.retrieval_status()
    assert st["fallback"] is True and st["cache_matches"] is False


# ── The stage report ─────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


def _verify() -> RunOptions:
    return RunOptions(consensus=False, document_relations=False, llm_parallelism=1, ttp_mode="verify",
                      disabled=frozenset({"2f", "3"}), verify_relationships=False, verify_ttps=False)


def _fake_status(cache_model: str) -> dict:
    return {"requested": PRIMARY, "loaded": PRIMARY, "fallback": False, "cache_model": cache_model,
            "cache_matches": cache_model == PRIMARY, "thresholds": {"high": 0.6, "medium": 0.5}}


def test_a_mismatched_cache_is_named_in_the_2c_record(sample_cti_text, monkeypatch):
    monkeypatch.setattr(s2c, "semantic_available", lambda: False)
    monkeypatch.setattr(s2c, "embedding_status", lambda: _fake_status(LEGACY))
    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"), _verify())

    out = result.outcome("2c")
    assert out.status == orch.SKIPPED
    assert out.reason == (f"embedding cache built for {LEGACY}, model in use {PRIMARY}: "
                          "rebuild with python scripts/build_indexes.py --only embeddings")
    entry = next(e for e in result.stage_report() if e["stage"] == "2c")
    assert entry["embedding"]["cache_model"] == LEGACY and entry["ttp_mode"] == "verify"
    json.dumps(result.stage_report())


def test_a_matching_cache_is_recorded_when_2c_runs(sample_cti_text, monkeypatch):
    monkeypatch.setattr(s2c, "semantic_available", lambda: True)
    monkeypatch.setattr(s2c, "detect_ttps_semantic", lambda text: [])
    monkeypatch.setattr(s2c, "embedding_status", lambda: _fake_status(PRIMARY))
    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"), _verify())

    assert result.ran("2c")
    entry = next(e for e in result.stage_report() if e["stage"] == "2c")
    assert entry["embedding"]["cache_matches"] is True and entry["ttp_mode"] == "verify"
    assert entry["counts"] == {"entities": 0}
    # Another stage's entry keeps its shape.
    assert "embedding" not in next(e for e in result.stage_report() if e["stage"] == "2")


def test_an_absent_cache_gets_the_generic_reason_with_the_build_command(sample_cti_text, monkeypatch):
    monkeypatch.setattr(s2c, "semantic_available", lambda: False)
    status = {**_fake_status(PRIMARY), "cache_model": None, "cache_matches": False}
    monkeypatch.setattr(s2c, "embedding_status", lambda: status)
    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"), _verify())
    reason = result.outcome("2c").reason
    assert "unavailable" in reason and "build_indexes.py --only embeddings" in reason
    assert "built for" not in reason


def test_a_stage_2c_that_ran_on_a_fallback_says_so(sample_cti_text, monkeypatch):
    monkeypatch.setattr(s2c, "semantic_available", lambda: True)
    monkeypatch.setattr(s2c, "detect_ttps_semantic", lambda text: [])
    status = {**_fake_status(PRIMARY), "loaded": LEGACY, "fallback": True, "cache_matches": False}
    monkeypatch.setattr(s2c, "embedding_status", lambda: status)
    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"), _verify())
    assert result.outcome("2c").reason == f"fallback to {LEGACY}; cache built for {PRIMARY}"


def test_a_disabled_2c_records_the_mode_and_reads_no_status(sample_cti_text, monkeypatch):
    def trapped(*a):
        raise AssertionError("a status was read for a disabled stage")

    monkeypatch.setattr(s2c, "embedding_status", trapped)
    opts = RunOptions(consensus=False, document_relations=False, llm_parallelism=1, ttp_mode="verify",
                      disabled=frozenset({"2f", "2c", "3"}), verify_relationships=False, verify_ttps=False)
    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"), opts)
    entry = next(e for e in result.stage_report() if e["stage"] == "2c")
    assert entry["reason"] == "disabled" and entry["ttp_mode"] == "verify"
    assert "embedding" not in entry


def test_select_mode_without_an_llm_records_the_detectors_status(sample_cti_text, monkeypatch):
    """The orchestrator falls back to the old detector: its status, not the retrieval one."""
    from pipeline import stage3_llm
    from pipeline import ttp_retrieval as tr

    monkeypatch.setattr(stage3_llm, "_provider_ready", lambda: False)
    monkeypatch.setattr(tr, "retrieval_status", lambda: pytest.fail("the retrieval status was read"))
    monkeypatch.setattr(s2c, "semantic_available", lambda: True)
    monkeypatch.setattr(s2c, "detect_ttps_semantic", lambda text: [])
    monkeypatch.setattr(s2c, "embedding_status", lambda: _fake_status(PRIMARY))
    opts = RunOptions(consensus=False, document_relations=False, llm_parallelism=1, ttp_mode="select",
                      disabled=frozenset({"2f"}), verify_relationships=False, verify_ttps=False)
    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"), opts)
    entry = next(e for e in result.stage_report() if e["stage"] == "2c")
    assert entry["ttp_mode"] == "select" and entry["embedding"]["cache_model"] == PRIMARY
    assert "offline fallback" in entry["reason"]


def test_select_mode_names_the_retrieval_corpus(mock_llm, sample_cti_text, monkeypatch):
    from pipeline import ttp_retrieval as tr

    status = {"requested": PRIMARY, "loaded": PRIMARY, "fallback": False, "corpus": "both",
              "method": "rrf", "corpus_model": LEGACY, "cache_matches": False}
    monkeypatch.setattr(tr, "retrieval_available", lambda: False)
    monkeypatch.setattr(tr, "retrieval_status", lambda: status)
    opts = RunOptions(consensus=False, document_relations=False, llm_parallelism=1, ttp_mode="select",
                      disabled=frozenset({"2f"}), verify_relationships=False, verify_ttps=False)
    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"), opts)

    out = result.outcome("2c")
    assert out.reason == (f"embedding cache built for {LEGACY}, model in use {PRIMARY}: "
                          "rebuild with python scripts/build_indexes.py --only retrieval")
    entry = next(e for e in result.stage_report() if e["stage"] == "2c")
    assert entry["embedding"] == status and entry["ttp_mode"] == "select"


def test_a_fallback_never_queries_a_corpus_built_for_the_requested_model(monkeypatch):
    """Requested A, fallback to B, corpus built for A: no dense retrieval with B."""
    from types import SimpleNamespace

    from pipeline import ttp_retrieval as tr

    monkeypatch.setattr(s2c, "_TTP_EMBEDDING_MODEL", PRIMARY)
    monkeypatch.setattr(s2c, "_active_model", None)

    def load():
        monkeypatch.setattr(s2c, "_active_model", LEGACY)     # what _load_model does on a fallback
        return object()

    corpus = SimpleNamespace(model=PRIMARY, embeddings=[[0.0]])
    monkeypatch.setattr(s2c, "_load_model", load)
    monkeypatch.setattr(tr, "load_corpus", lambda *a, **k: corpus)
    monkeypatch.setattr(tr, "Retriever", lambda *a: pytest.fail("a retriever was built on the fallback"))
    tr._production_retriever.cache_clear()
    try:
        assert tr._production_retriever("both", "rrf", "") is None
        monkeypatch.setattr(tr, "_built_corpus", lambda *a: corpus)      # same verdict from the status
        st = tr.retrieval_status()
        assert st["fallback"] is True and st["cache_matches"] is False
    finally:
        tr._production_retriever.cache_clear()
