"""Regression tests for the TTP-count controls (follow-up to ADR-0011).

A 12-page report with *zero* explicit T-IDs produced 65 TTP rows in the review
UI against 51 attack-patterns in its bundle.  Four defects compounded:

  1. semantic + LLM rows for the same technique were both persisted, so the UI
     double-counted every technique both stages found;
  2. a parent technique found semantically survived next to its sub-technique
     found by the LLM (T1027 beside T1027.004);
  3. Stage 3f's "already corroborated" exemption ignored confidence, so a
     medium semantic match (≥ 0.48) waived quote-verification for its LLM twin;
  4. CAPEC is ~40% of the embedding corpus and shadowed the ATT&CK technique
     that belonged in the bundle.

These tests pin each fix.  All are offline — no model, no LLM, no network.
"""
import pytest

from api.worker import _ttp_ids_covered
from models.schemas import EntityType, RawEntity
from pipeline.stage3_llm import LLMEnrichmentResult, TTPExtracted, corroborated_ttp_ids


def _ttp(mitre_id, name="X"):
    return TTPExtracted(technique_name=name, mitre_id=mitre_id)


def _sem(mitre_id, confidence, name="X"):
    return RawEntity(value=name, entity_type=EntityType.TTP,
                     mitre_id=mitre_id, confidence=confidence, source="semantic")


# ── 1 + 2. persistence dedup and parent subsumption ───────────────────────────
def test_covered_ids_include_llm_technique_ids():
    res = LLMEnrichmentResult(ttps=[_ttp("T1566.001"), _ttp("T1113")])
    ids, parents = _ttp_ids_covered(res)
    assert ids == {"T1566.001", "T1113"}


def test_covered_parents_derived_from_subtechniques():
    """A sub-technique covers its parent, so the vaguer parent is not re-added."""
    res = LLMEnrichmentResult(ttps=[_ttp("T1027.004"), _ttp("T1027.008")])
    ids, parents = _ttp_ids_covered(res)
    assert parents == {"T1027"}
    assert "T1027" not in ids          # parent itself was never an LLM entry


def test_bare_technique_contributes_no_parent():
    res = LLMEnrichmentResult(ttps=[_ttp("T1055")])
    _ids, parents = _ttp_ids_covered(res)
    assert parents == set()


def test_covered_ids_are_uppercased_and_tolerate_missing_ids():
    res = LLMEnrichmentResult(ttps=[_ttp("t1059.001"), _ttp(None)])
    ids, parents = _ttp_ids_covered(res)
    assert ids == {"T1059.001"}
    assert parents == {"T1059"}


def test_empty_result_is_safe():
    ids, parents = _ttp_ids_covered(LLMEnrichmentResult())
    assert ids == set() and parents == set()


# ── 3. Stage 3f corroboration floor ───────────────────────────────────────────
def test_medium_confidence_semantic_does_not_waive_verification():
    """The bug: 0.52 corroboration let an unsupported technique skip Stage 3f."""
    assert corroborated_ttp_ids([_sem("T0873", 0.52)]) == set()


def test_high_confidence_semantic_still_waives_verification():
    assert corroborated_ttp_ids([_sem("T1566.002", 0.72)]) == {"T1566.002"}


def test_corroboration_uses_the_model_high_threshold():
    from pipeline.stage2c_ttp_semantic import high_confidence_threshold
    hi = high_confidence_threshold()
    assert corroborated_ttp_ids([_sem("T1113", hi)]) == {"T1113"}          # at
    assert corroborated_ttp_ids([_sem("T1113", hi - 0.01)]) == set()       # below


def test_corroboration_ignores_entities_without_mitre_id():
    assert corroborated_ttp_ids([_sem(None, 0.99)]) == set()


def test_corroboration_handles_none():
    assert corroborated_ttp_ids(None) == set()


# ── 4. semantic corpus taxonomy filter ────────────────────────────────────────
def test_default_domains_exclude_capec(monkeypatch):
    """CAPEC catalogues abstract patterns, not observed behaviour — excluding it
    lets the real ATT&CK technique surface instead of a near-duplicate."""
    monkeypatch.delenv("TTP_SEMANTIC_DOMAINS", raising=False)
    from pipeline.stage2c_ttp_semantic import _enabled_domains
    domains = _enabled_domains()
    assert domains is not None
    assert "capec" not in domains
    assert "enterprise-attack" in domains


def test_domains_all_disables_filtering(monkeypatch):
    monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", "all")
    from pipeline.stage2c_ttp_semantic import _enabled_domains
    assert _enabled_domains() is None


def test_domains_empty_disables_filtering(monkeypatch):
    monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", "  ")
    from pipeline.stage2c_ttp_semantic import _enabled_domains
    assert _enabled_domains() is None


def test_domains_custom_list_is_parsed(monkeypatch):
    monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", "enterprise-attack, CAPEC ")
    from pipeline.stage2c_ttp_semantic import _enabled_domains
    assert _enabled_domains() == {"enterprise-attack", "capec"}


@pytest.mark.parametrize("domains,expect_capec", [("all", True), (None, False)])
def test_corpus_filter_applied_to_meta(monkeypatch, domains, expect_capec):
    """End-to-end on the shipped cache: the filter really removes CAPEC rows."""
    pytest.importorskip("numpy")
    import pipeline.stage2c_ttp_semantic as s2c

    if not (s2c._EMB_PATH.exists() and s2c._META_PATH.exists()):
        pytest.skip("embedding cache not built")
    if domains is None:
        monkeypatch.delenv("TTP_SEMANTIC_DOMAINS", raising=False)
    else:
        monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", domains)

    # _load_corpus is lru_cached (one load per process), so the previous
    # parametrisation would otherwise be served from cache.
    s2c._load_corpus.cache_clear()
    corpus = s2c._load_corpus()
    if corpus is None:
        pytest.skip("embedding cache unreadable (model mismatch)")
    _emb, meta = corpus
    has_capec = any(m.get("domain") == "capec" for m in meta)
    assert has_capec is expect_capec
    assert len(_emb) == len(meta)      # embeddings stay aligned with meta
    s2c._load_corpus.cache_clear()     # don't leak this corpus to other tests
