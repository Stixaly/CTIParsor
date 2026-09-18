"""Stage 2e — GLiNER parsing with a stubbed model (no ~800 MB download).

Locks the per-type cutoff contract of ADR-0051: GLiNER's predict_entities()
takes one threshold for every label, so the model is asked for the lowest
cutoff in force and each prediction is then held to its own type's cutoff.
"""
from __future__ import annotations

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
