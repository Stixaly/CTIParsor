"""Stage 2e — two regressions from the bug triage (issues #767 and #774).

#767: a prediction whose offsets are None raised TypeError in run_gliner, outside
its try, and sank the whole stage.  The offsets are read as ints or not at all.

#774: without offsets, the casing GLiNER gave the value was lost: "Emotet" came
out as "emotet" when the context had no whole-word match.  The model is stubbed:
nothing is downloaded.
"""
from __future__ import annotations

import pytest

from models.schemas import EntityType
from pipeline import stage2e_gliner


class _FakeGLiNER:
    """Mimics GLiNER.inference for a list of chunks: one list per chunk."""

    def __init__(self, predictions: list[dict]):
        self.predictions = predictions

    def inference(self, texts, labels, threshold=0.5, **kw):
        return [list(self.predictions) for _ in texts]


def _default_cutoff(source, entity_type, default):
    return default


def _stub(monkeypatch, predictions: list[dict]) -> None:
    monkeypatch.setattr(stage2e_gliner, "_load_gliner", lambda: _FakeGLiNER(predictions))
    monkeypatch.setattr(stage2e_gliner, "get_threshold", _default_cutoff)
    # The six labels, whatever GLINER_ENTITY_TYPES says in the environment (ADR-0098).
    monkeypatch.setattr(stage2e_gliner, "_GLINER_LABELS", list(stage2e_gliner._LABEL_MAP))


# ── #767: offsets that are None ──────────────────────────────────────────────

def test_767_a_prediction_with_none_offsets_is_kept_and_does_not_raise(monkeypatch):
    _stub(monkeypatch, [
        {"label": "malware family", "score": 0.9, "text": "Emotet",
         "start": None, "end": None},
    ])

    run = stage2e_gliner.run_gliner("Emotet hit the healthcare sector.")

    assert [(r.value, r.entity_type) for r in run.entities] == [("Emotet", EntityType.MALWARE)]
    assert run.failure() == "" and run.note() == ""


# ── #774: no offsets, the casing of the value is kept ────────────────────────

def test_774_without_offsets_the_value_keeps_its_casing(monkeypatch):
    """The context is the first 50 characters, which do not hold "Emotet":
    there is no whole-word match to recover the casing from."""
    text = "x" * 500 + " Emotet spread through the mail."
    _stub(monkeypatch, [
        {"label": "malware family", "score": 0.9, "text": "Emotet"},
    ])

    [result] = stage2e_gliner.extract_gliner_entities(text)

    assert (result.value, result.entity_type) == ("Emotet", EntityType.MALWARE)


# ── #771: the cached model is loaded first, without asking the Hub ──────────

class _FakeGLiNERClass:
    """Stands in for gliner.GLiNER: records how from_pretrained was called, and
    raises OSError on the first call when `missing_from_cache` is set."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.missing_from_cache = False

    def from_pretrained(self, model_id, **kw):
        self.calls.append((model_id, kw))
        if self.missing_from_cache and len(self.calls) == 1:
            raise OSError("not in the local cache")
        return "model"


@pytest.fixture()
def gliner_lib(monkeypatch):
    import sys
    import types

    lib = _FakeGLiNERClass()
    module = types.ModuleType("gliner")
    module.GLiNER = lib                              # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gliner", module)
    monkeypatch.setattr(stage2e_gliner, "_SKIP_HEAVY", False)
    monkeypatch.setattr(stage2e_gliner, "_GLINER_ENABLED", True)
    stage2e_gliner._load_gliner.cache_clear()
    yield lib
    stage2e_gliner._load_gliner.cache_clear()


def test_771_the_cached_model_is_loaded_without_asking_the_hub(gliner_lib):
    assert stage2e_gliner._load_gliner() == "model"
    assert gliner_lib.calls == [
        (stage2e_gliner._GLINER_MODEL_ID, {"resume_download": None, "local_files_only": True}),
    ]


def test_771_a_model_missing_from_the_cache_is_downloaded(gliner_lib):
    gliner_lib.missing_from_cache = True

    assert stage2e_gliner._load_gliner() == "model"

    model_id = stage2e_gliner._GLINER_MODEL_ID
    assert gliner_lib.calls == [
        (model_id, {"resume_download": None, "local_files_only": True}),
        (model_id, {"resume_download": None}),
    ]
