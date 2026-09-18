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
    """Return a callable that mimics a HuggingFace NER pipeline.

    The real pipeline is called with a *list* of chunks and a ``batch_size``
    keyword and returns one prediction list per chunk; a flat list is what a
    single-string call returns.  Returning the flat list for any input keeps
    the older tests meaningful and exercises the single-chunk branch.
    """
    def _run(_inputs, **_kw):
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


# ── 3. Calibrated per-type cutoffs (ADR-0051) ──────────────────────────────

def test_calibrated_cutoff_replaces_the_medium_threshold_per_type(monkeypatch):
    preds = [
        {"entity_group": "Malware",      "score": 0.80, "word": "Emotet"},   # below malware's 0.85
        {"entity_group": "Threat_group", "score": 0.80, "word": "APT29"},    # threat_actor keeps 0.70
    ]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))
    monkeypatch.setattr(
        stage2d_cyner, "get_threshold",
        lambda source, etype, default: 0.85 if (source, etype) == ("cyner", "malware") else default,
    )

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    assert [(r.value, r.entity_type) for r in results] == [("APT29", EntityType.THREAT_ACTOR)]


# ── 4. Analyst deny rows (ADR-0052) ────────────────────────────────────────

def test_an_active_deny_row_drops_the_value_end_to_end(temp_db, monkeypatch):
    """A `deny` row in the store, not a patched lookup, removes the entity."""
    import pipeline.overrides as ov
    from pipeline import promotion as pm

    pm.add_manual(temp_db.get_conn(), "Emotet", "malware", "deny", temp_db.now_iso())
    ov.reload()
    preds = [
        {"entity_group": "Malware",      "score": 0.98, "word": "Emotet"},
        {"entity_group": "Threat_group", "score": 0.95, "word": "APT29"},
    ]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    assert [(r.value, r.entity_type) for r in results] == [("APT29", EntityType.THREAT_ACTOR)]


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


# ── 5. The document is never handed to the model in one piece ───────────────
#
# Regression for the 2026-09-02/03 OOM kills: `extract_cyner_entities` used to
# call the pipeline once with `text[:50_000]`.  DeBERTa-v3 does not truncate —
# it runs, and attention memory grows with the square of the token count
# (10.3 GB RSS on a 27 KB report, 15.5 GB on a 77 KB one).  This test fails
# if any single input to the model exceeds the chunk window, or if a long
# document produces only one call.

def test_long_text_is_chunked_before_inference(monkeypatch):
    calls: list[dict] = []

    def _recording_pipeline(inputs, **kw):
        calls.append({"inputs": inputs, "kw": kw})
        # One prediction list per chunk, each naming the same malware so the
        # overlap dedup is exercised as well.
        return [[{"entity_group": "Malware", "score": 0.97, "word": "Emotet"}]
                for _ in inputs]

    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _recording_pipeline)

    text = ("Emotet was observed dropping a second-stage loader on the host. " * 900)
    assert len(text) > 50_000

    results = stage2d_cyner.extract_cyner_entities(text)

    assert calls, "pipeline was never called"
    every_input = [c for call in calls for c in call["inputs"]]
    assert len(every_input) > 1, "a 57 KB document reached the model as one input"
    assert all(len(c) <= stage2d_cyner._CHUNK_CHARS for c in every_input), \
        "a chunk exceeds the model window — the O(n²) attention path is back"
    assert all(call["kw"].get("batch_size") == stage2d_cyner._BATCH_SIZE for call in calls)
    # The same span re-reported from every overlapping chunk collapses to one entity.
    assert [(r.value, r.entity_type) for r in results] == [("Emotet", EntityType.MALWARE)]


def test_iter_chunks_covers_text_without_empty_or_oversized_pieces():
    text = "word " * 2_000                      # 10 000 chars of plain prose
    pieces = list(stage2d_cyner._iter_chunks(text))
    assert pieces and all(p for p, _ in pieces)
    assert all(len(p) <= stage2d_cyner._CHUNK_CHARS for p, _ in pieces)
    assert pieces[0][1] == 0 and pieces[-1][1] + len(pieces[-1][0]) == len(text)
    # An unbroken token longer than the window must still advance.
    blob = "x" * (stage2d_cyner._CHUNK_CHARS * 3)
    assert sum(len(p) for p, _ in stage2d_cyner._iter_chunks(blob)) >= len(blob)


# ── 6. Generic-language filtering (real production noise) ──────────────────
#
# CyNER's Malware/Threat_group labels fire on any span discussing malware or
# threat-actor activity, not only on named entities. These are real spans
# extracted from a real report (apt44-unearthing-sandworm.pdf, 2026-09-17)
# that must now be rejected, alongside the real named entities from the same
# report that must still survive.

def test_generic_malware_language_is_rejected(monkeypatch):
    noise = [
        "malware", "backdoor", "ransomware family", "disruptive tool",
        "commodity malware", "wiper malware", "malicious macro dropper",
        "shellcode payload", "trojanized software installers",
        "post-exploitation framework", "PHP webshell", "tool HTTP-Shell",
        "C++ based infostealer malware", "dropper, custom boot loader",
    ]
    preds = [{"entity_group": "Malware", "score": 0.90, "word": w} for w in noise]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    assert results == []


def test_generic_threat_actor_language_is_rejected(monkeypatch):
    noise = [
        "threat actor", "actors", "cyber espionage", "hacker group",
        "Russian government-backed cyber groups", "Russian state",
        "Russian military-linked actors", "backed threat groups",
        "campaign", "CIKR operators", "Wartime Cyber Operations",
    ]
    preds = [{"entity_group": "Threat_group", "score": 0.90, "word": w} for w in noise]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    # Every one of these is pure generic language and must be dropped.
    assert results == []


def test_real_named_entities_survive_the_generic_filter(monkeypatch):
    real = [
        ("Malware", "ARGUEPATCH"),
        ("Malware", "ARGUEPATCH Launcher payload"),
        ("Malware", "BLACKENERGY malware variants"),
        ("Threat_group", "APT44"),
        ("Threat_group", "the GRU"),
        ("Threat_group", "Seashell Blizzard"),
        ("Threat_group", "XakNet Team"),
    ]
    preds = [{"entity_group": g, "score": 0.92, "word": w} for g, w in real]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    values = {r.value for r in results}
    assert "ARGUEPATCH" in values
    assert "ARGUEPATCH Launcher payload" in values
    assert "BLACKENERGY malware variants" in values
    assert "APT44" in values
    assert "GRU" in values          # the leading "the " is stripped
    assert "Seashell Blizzard" in values
    assert "XakNet Team" in values


def test_comma_separated_list_is_split_into_separate_entities(monkeypatch):
    preds = [{
        "entity_group": "Malware", "score": 0.93,
        "word": "AZORULT, FORMBOOK, REMCOS, URSNIF, SILENTNIGHT, TRICKBOT",
    }]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    values = {r.value for r in results}
    assert values == {"AZORULT", "FORMBOOK", "REMCOS", "URSNIF", "SILENTNIGHT", "TRICKBOT"}


def test_list_split_drops_fragments_that_are_themselves_generic(monkeypatch):
    preds = [{"entity_group": "Malware", "score": 0.81, "word": "SDELETE, WinRAR"}]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    values = {r.value for r in results}
    # WinRAR is a known-non-malware product name, denylisted specifically.
    assert values == {"SDELETE"}


def test_sentence_boundary_and_script_garbage_is_rejected(monkeypatch):
    preds = [
        {"entity_group": "Threat_group", "score": 0.74, "word": "sponsor. CyberА"},
        {"entity_group": "Threat_group", "score": 0.70, "word": "Народная group"},
        {"entity_group": "Threat_group", "score": 0.71, "word": "s Information Operations"},
        {"entity_group": "Threat_group", "score": 0.70, "word": "s Primary"},
    ]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    assert results == []


def test_known_non_malware_and_non_actor_denylists(monkeypatch):
    preds = [
        {"entity_group": "Malware", "score": 0.92, "word": "MicroSCADA binary"},
        {"entity_group": "Threat_group", "score": 0.79, "word": "Russia"},
        {"entity_group": "Threat_group", "score": 0.81, "word": "Moscow"},
    ]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    assert results == []


def test_denylisted_word_does_not_veto_a_larger_distinct_name(monkeypatch):
    """A denylisted token (e.g. "Russia") must not sink a fragment that also
    carries real identifying content -- regression for a fix that initially
    rejected the real hacktivist-front name "XAKNET Cyber Army of Russia
    Reborn" outright because it contains the word "Russia"."""
    preds = [{
        "entity_group": "Threat_group", "score": 0.75,
        "word": "XAKNET Cyber Army of Russia Reborn",
    }]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    values = {r.value for r in results}
    assert values == {"XAKNET Cyber Army of Russia Reborn"}


def test_dotted_names_are_not_mistaken_for_sentence_boundaries(monkeypatch):
    """A bare interior period with no following whitespace is a real name
    (a version-style suffix), not a sentence-boundary artifact."""
    preds = [
        {"entity_group": "Malware", "score": 0.76, "word": "BLACKENERGY.V2"},
        {"entity_group": "Malware", "score": 0.72, "word": "REGEORG.NEO"},
    ]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))

    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    values = {r.value for r in results}
    assert values == {"BLACKENERGY.V2", "REGEORG.NEO"}


def test_bare_apt_is_rejected_but_numbered_apt_group_survives(monkeypatch):
    preds = [
        {"entity_group": "Threat_group", "score": 0.86, "word": "APT"},
        {"entity_group": "Threat_group", "score": 0.88, "word": "APT44"},
    ]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: _fake_pipeline(preds))
    results = stage2d_cyner.extract_cyner_entities("irrelevant text")
    values = {r.value for r in results}
    assert values == {"APT44"}
