"""Stage 2e — GLiNER parsing with a stubbed model (no ~800 MB download).

Locks the per-type cutoff contract of ADR-0051: GLiNER's predict_entities()
takes one threshold for every label, so the model is asked for the lowest
cutoff in force and each prediction is then held to its own type's cutoff.
"""
from __future__ import annotations

import pytest

import api.db as db
import pipeline.thresholds as thresholds
from models.schemas import EntityType
from pipeline import calibration as cal
from pipeline import stage2e_gliner


class _FakeGLiNER:
    """Mimics GLiNER.predict_entities for a list of chunks: one list per chunk."""

    def __init__(self, predictions: list[dict]):
        self.predictions = predictions
        self.calls: list[dict] = []

    def predict_entities(self, texts, labels, threshold, **kw):
        self.calls.append({"texts": texts, "labels": labels, "threshold": threshold})
        if isinstance(texts, str):
            return list(self.predictions)
        return [list(self.predictions) for _ in texts]


def _pred(label: str, score: float, text: str) -> dict:
    return {"label": label, "score": score, "text": text, "start": 0, "end": len(text)}


def _default_cutoff(source, entity_type, default):
    return default


def test_maps_labels_to_entity_types_and_keeps_the_best_score(monkeypatch):
    fake = _FakeGLiNER([
        _pred("malware family", 0.81, "Emotet"),
        _pred("malware family", 0.62, "emotet"),          # same span, lower score
        _pred("targeted sector", 0.55, "healthcare"),
        _pred("not a label", 0.99, "ignored"),
    ])
    monkeypatch.setattr(stage2e_gliner, "_load_gliner", lambda: fake)
    monkeypatch.setattr(stage2e_gliner, "get_threshold", _default_cutoff)

    results = stage2e_gliner.extract_gliner_entities("Emotet hit the healthcare sector.")
    by_key = {(r.value.lower(), r.entity_type): r for r in results}
    assert set(by_key) == {("emotet", EntityType.MALWARE), ("healthcare", EntityType.IDENTITY)}
    assert by_key[("emotet", EntityType.MALWARE)].confidence == 0.81
    assert all(r.source == "gliner" for r in results)


def test_each_type_is_held_to_its_own_cutoff(monkeypatch):
    fake = _FakeGLiNER([
        _pred("attack infrastructure", 0.50, "proxy network"),   # below its 0.60
        _pred("malware family", 0.50, "Emotet"),                 # above the default 0.40
    ])
    monkeypatch.setattr(stage2e_gliner, "_load_gliner", lambda: fake)
    monkeypatch.setattr(
        stage2e_gliner, "get_threshold",
        lambda source, etype, default: 0.60 if etype == "infrastructure" else default,
    )

    results = stage2e_gliner.extract_gliner_entities("Emotet used a proxy network.")
    assert [(r.value, r.entity_type) for r in results] == [("Emotet", EntityType.MALWARE)]
    # The model was asked at the lowest cutoff in force, not the raised one.
    assert fake.calls and fake.calls[0]["threshold"] == stage2e_gliner._GLINER_THRESHOLD


def test_a_lowered_cutoff_lowers_what_the_model_is_asked_for(monkeypatch):
    fake = _FakeGLiNER([_pred("targeted country", 0.33, "Ukraine")])
    monkeypatch.setattr(stage2e_gliner, "_load_gliner", lambda: fake)
    monkeypatch.setattr(
        stage2e_gliner, "get_threshold",
        lambda source, etype, default: 0.30 if etype == "location" else default,
    )

    results = stage2e_gliner.extract_gliner_entities("Ukraine was the target.")
    assert [(r.value, r.entity_type) for r in results] == [("Ukraine", EntityType.LOCATION)]
    assert fake.calls[0]["threshold"] == 0.30


def test_a_stored_cutoff_reaches_the_stage_through_the_store(temp_db, monkeypatch):
    """End to end: a `model_thresholds` row, not a patched lookup, drives the filter."""
    cal.set_override(temp_db.get_conn(), "gliner", "campaign", 0.70, db.now_iso())
    thresholds.reload()
    fake = _FakeGLiNER([
        _pred("attack campaign", 0.65, "Operation Ghost"),        # below the stored 0.70
        _pred("attack campaign", 0.72, "Operation Dust"),
    ])
    monkeypatch.setattr(stage2e_gliner, "_load_gliner", lambda: fake)
    try:
        results = stage2e_gliner.extract_gliner_entities("Operation Ghost preceded Operation Dust.")
    finally:
        thresholds.reload()
    assert [r.value for r in results] == ["Operation Dust"]


def test_an_active_deny_row_drops_the_value_end_to_end(temp_db, monkeypatch):
    """A `deny` row in the store removes the entity for its type only (ADR-0052)."""
    import pipeline.overrides as ov
    from pipeline import promotion as pm

    pm.add_manual(temp_db.get_conn(), "healthcare", "identity", "deny", temp_db.now_iso())
    ov.reload()
    fake = _FakeGLiNER([
        _pred("targeted sector", 0.8, "healthcare"),
        _pred("malware family", 0.8, "Emotet"),
    ])
    monkeypatch.setattr(stage2e_gliner, "_load_gliner", lambda: fake)
    monkeypatch.setattr(stage2e_gliner, "get_threshold", _default_cutoff)

    results = stage2e_gliner.extract_gliner_entities("Emotet hit the healthcare sector.")
    assert [(r.value, r.entity_type) for r in results] == [("Emotet", EntityType.MALWARE)]


def test_returns_nothing_when_the_model_is_unavailable(monkeypatch):
    monkeypatch.setattr(stage2e_gliner, "_load_gliner", lambda: None)
    assert stage2e_gliner.extract_gliner_entities("some text") == []


def test_bare_version_strings_and_short_spans_are_dropped(monkeypatch):
    fake = _FakeGLiNER([
        _pred("malware family", 0.9, "0.1.16"),
        _pred("malware family", 0.9, "ab"),
        _pred("malware family", 0.9, "Qakbot"),
    ])
    monkeypatch.setattr(stage2e_gliner, "_load_gliner", lambda: fake)
    monkeypatch.setattr(stage2e_gliner, "get_threshold", _default_cutoff)
    assert [r.value for r in stage2e_gliner.extract_gliner_entities("Qakbot 0.1.16 ab")] == ["Qakbot"]


# ── Loading the model and the batch fallback ─────────────────────────────────

class _FakeGLiNERClass:
    """Stands in for `gliner.GLiNER`: records how from_pretrained was called."""

    calls: list[tuple[str, dict]] = []
    fail: Exception | None = None

    @classmethod
    def from_pretrained(cls, model_id, **kw):
        cls.calls.append((model_id, kw))
        if cls.fail is not None:
            raise cls.fail
        return "model"


@pytest.fixture()
def fake_gliner_lib(monkeypatch):
    import sys
    import types

    module = types.ModuleType("gliner")
    module.GLiNER = _FakeGLiNERClass            # type: ignore[attr-defined]
    _FakeGLiNERClass.calls, _FakeGLiNERClass.fail = [], None
    monkeypatch.setitem(sys.modules, "gliner", module)
    monkeypatch.setattr(stage2e_gliner, "_SKIP_HEAVY", False)
    monkeypatch.setattr(stage2e_gliner, "_GLINER_ENABLED", True)
    stage2e_gliner._load_gliner.cache_clear()
    yield _FakeGLiNERClass
    stage2e_gliner._load_gliner.cache_clear()


def test_the_model_is_loaded_without_the_deprecated_resume_download(fake_gliner_lib):
    """GLiNER defaults resume_download=False and huggingface_hub warns on any
    value but None — the model-tests CI job printed that warning every run."""
    assert stage2e_gliner._load_gliner() == "model"
    assert fake_gliner_lib.calls == [(stage2e_gliner._GLINER_MODEL_ID, {"resume_download": None})]
    assert stage2e_gliner.gliner_available() is True


def test_a_model_that_fails_to_load_is_unavailable_not_an_error(fake_gliner_lib):
    fake_gliner_lib.fail = OSError("401 repo not found")
    assert stage2e_gliner._load_gliner() is None


def test_skip_heavy_models_or_disabling_gliner_loads_nothing(fake_gliner_lib, monkeypatch):
    monkeypatch.setattr(stage2e_gliner, "_SKIP_HEAVY", True)
    assert stage2e_gliner._load_gliner() is None and stage2e_gliner.gliner_available() is False
    stage2e_gliner._load_gliner.cache_clear()
    monkeypatch.setattr(stage2e_gliner, "_SKIP_HEAVY", False)
    monkeypatch.setattr(stage2e_gliner, "_GLINER_ENABLED", False)
    assert stage2e_gliner._load_gliner() is None and stage2e_gliner.gliner_available() is False
    assert fake_gliner_lib.calls == []


def test_without_the_gliner_library_the_stage_is_unavailable(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "gliner", None)       # import gliner -> ImportError
    monkeypatch.setattr(stage2e_gliner, "_SKIP_HEAVY", False)
    monkeypatch.setattr(stage2e_gliner, "_GLINER_ENABLED", True)
    stage2e_gliner._load_gliner.cache_clear()
    try:
        assert stage2e_gliner.gliner_available() is False
        assert stage2e_gliner._load_gliner() is None
    finally:
        stage2e_gliner._load_gliner.cache_clear()


class _NoBatchGLiNER(_FakeGLiNER):
    """A model whose batch call fails: each chunk is retried on its own, and a
    chunk that fails again contributes nothing instead of sinking the others."""

    def predict_entities(self, texts, labels, threshold, **kw):
        if not isinstance(texts, str):
            raise RuntimeError("batch API broken")
        if "Broken" in texts:
            raise RuntimeError("cannot read this chunk")
        return super().predict_entities(texts, labels, threshold, **kw)


def test_a_failing_batch_falls_back_to_one_call_per_chunk(monkeypatch):
    fake = _NoBatchGLiNER([_pred("malware family", 0.9, "Emotet")])
    monkeypatch.setattr(stage2e_gliner, "_load_gliner", lambda: fake)
    monkeypatch.setattr(stage2e_gliner, "get_threshold", _default_cutoff)
    monkeypatch.setattr(stage2e_gliner, "_CHUNK_CHARS", 40)
    monkeypatch.setattr(stage2e_gliner, "_OVERLAP_CHARS", 0)

    text = "Emotet spread through the mail again.   Broken chunk that the model rejects."
    results = stage2e_gliner.extract_gliner_entities(text)

    assert [r.value for r in results] == ["Emotet"]
    assert len(fake.calls) == 1            # the one chunk that answered


@pytest.mark.parametrize("raw", [[], [_pred("malware family", 0.9, "Emotet")]])
def test_degenerate_batch_shapes_are_normalised(monkeypatch, raw):
    """An empty answer, or a flat list for a one-chunk batch, is not an error."""
    class _Flat:
        def predict_entities(self, texts, labels, threshold, **kw):
            return list(raw)

    monkeypatch.setattr(stage2e_gliner, "_load_gliner", lambda: _Flat())
    monkeypatch.setattr(stage2e_gliner, "get_threshold", _default_cutoff)
    values = [r.value for r in stage2e_gliner.extract_gliner_entities("Emotet again.")]
    assert values == [p["text"] for p in raw]


def test_the_registry_wrapper_delegates_to_the_module(monkeypatch):
    monkeypatch.setattr(stage2e_gliner, "gliner_available", lambda: True)
    monkeypatch.setattr(stage2e_gliner, "extract_gliner_entities", lambda text: [text])
    stage = stage2e_gliner.GLiNERStage(config=None)
    assert stage.name == "gliner" and stage.available() is True
    assert stage.extract("x") == ["x"]


def test_merge_defers_to_precise_sources_for_names_only():
    from models.schemas import RawEntity

    existing = [
        RawEntity(value="Emotet", entity_type=EntityType.MALWARE, source="gazetteer"),
        RawEntity(value="Lazarus", entity_type=EntityType.THREAT_ACTOR, source="alias_list"),
        RawEntity(value="healthcare", entity_type=EntityType.IDENTITY, source="gliner"),
    ]
    found = [
        RawEntity(value="emotet", entity_type=EntityType.MALWARE, source="gliner"),       # gazetteer has it
        RawEntity(value="Lazarus", entity_type=EntityType.THREAT_ACTOR, source="gliner"),  # same key
        RawEntity(value="Healthcare", entity_type=EntityType.IDENTITY, source="gliner"),   # same key
        RawEntity(value="QakBot", entity_type=EntityType.MALWARE, source="gliner"),
        RawEntity(value="Emotet", entity_type=EntityType.CAMPAIGN, source="gliner"),      # other type
    ]

    merged = stage2e_gliner._merge_gliner_into(existing, found)

    assert merged[:3] == existing
    assert [(e.value, e.entity_type) for e in merged[3:]] == [
        ("QakBot", EntityType.MALWARE), ("Emotet", EntityType.CAMPAIGN)]
