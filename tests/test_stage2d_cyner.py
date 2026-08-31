"""
Stage 2d — CyNER 2.0 label mapping & parsing tests.

These tests do NOT download the ~0.8 GB model. They validate:
  1. The static label map matches CyNER 2.0's config.json entity types.
  2. extract_cyner_entities() correctly maps model predictions to RawEntity,
     using a stub pipeline monkeypatched in place of the real model.

CyNER 2.0 (PranavaKailash/CyNER-2.0-DeBERTa-v3-base) emits these entity_group
values after aggregation: Malware, Threat_group, Organization, Indicator,
System, Vulnerability, Date, Location.
"""
from __future__ import annotations

from models.schemas import EntityType
from pipeline import stage2d_cyner

# ── 1. Static label-map contract ────────────────────────────────────────────

def test_label_map_uses_cyner2_labels():
    """The map keys must match CyNER 2.0's real labels, not the old model's."""
    assert stage2d_cyner._LABEL_MAP["Malware"] == EntityType.MALWARE
    assert stage2d_cyner._LABEL_MAP["Threat_group"] == EntityType.THREAT_ACTOR
    # Old label names must be gone — they would silently drop every entity.
    assert "MalwareFamily" not in stage2d_cyner._LABEL_MAP
    # Organization is intentionally NOT mapped (victim orgs, not threat actors).
    assert "Organization" not in stage2d_cyner._LABEL_MAP


# ── 2. Parsing logic with a stubbed pipeline ────────────────────────────────

def _fake_pipeline(predictions):
    """Return a callable that mimics a HuggingFace NER pipeline."""
    def _run(_text):
        return predictions
    return _run


def test_extract_maps_malware_and_threat_group(monkeypatch):
    preds = [
        {"entity_group": "Malware",      "score": 0.98, "word": "WannaCry"},
        {"entity_group": "Threat_group", "score": 0.95, "word": "APT29"},
    ]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    by_type = {(r.value, r.entity_type) for r in results}

    assert ("WannaCry", EntityType.MALWARE) in by_type
    assert ("APT29", EntityType.THREAT_ACTOR) in by_type


def test_extract_skips_organization_and_low_confidence(monkeypatch):
    preds = [
        # Organization is not mapped → dropped
        {"entity_group": "Organization", "score": 0.99, "word": "Microsoft"},
        # Below the medium threshold (0.70) → dropped
        {"entity_group": "Malware",      "score": 0.40, "word": "Emotet"},
        # Blocklisted vendor mislabelled as a threat group → dropped
        {"entity_group": "Threat_group", "score": 0.99, "word": "cloudflare"},
    ]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    assert results == []


def test_extract_returns_empty_when_model_unavailable(monkeypatch):
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: None)
    assert stage2d_cyner.extract_cyner_entities("some text") == []


# ── 4. Loader failures must not escape ──────────────────────────────────────

def test_load_pipeline_returns_none_when_the_loader_raises(monkeypatch, tmp_path):
    """A loader error must degrade to None, never propagate.

    transformers 5 rejects `local_files_only` as a pipeline() keyword, and the
    handler here only caught (OSError, EnvironmentError, ValueError).  The
    resulting TypeError escaped _load_pipeline(), travelled out through
    cyner_available(), and aborted every job that reached Stage 2d -- while the
    tests above stayed green, because they all replace _load_pipeline with a
    stub and never execute it.
    """
    import sys
    import types

    def _boom(*args, **kwargs):
        raise TypeError("_sanitize_parameters() got an unexpected keyword argument 'x'")

    class _Auto:
        from_pretrained = staticmethod(_boom)

    fake = types.ModuleType("transformers")
    fake.AutoModelForTokenClassification = _Auto        # type: ignore[attr-defined]
    fake.AutoTokenizer = _Auto                          # type: ignore[attr-defined]
    fake.pipeline = _boom                               # type: ignore[attr-defined]
    fake.logging = types.SimpleNamespace(set_verbosity_error=lambda: None)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "transformers", fake)

    monkeypatch.setattr(stage2d_cyner, "_SKIP_HEAVY", False)
    monkeypatch.setattr(stage2d_cyner, "_CYNER_ENABLED", True)
    # Point the sentinel at a path that does not exist, so the early return
    # cannot make this pass for the wrong reason.
    monkeypatch.setattr(stage2d_cyner, "_SENTINEL_PATH", tmp_path / "absent")

    stage2d_cyner._load_pipeline.cache_clear()
    try:
        assert stage2d_cyner._load_pipeline() is None
        stage2d_cyner._load_pipeline.cache_clear()
        assert stage2d_cyner.cyner_available() is False
    finally:
        stage2d_cyner._load_pipeline.cache_clear()
