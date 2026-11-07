"""Stage 2c's corpus follows TTP_SEMANTIC_DOMAINS and the model really loaded (#389).

`_load_corpus` was lru_cached on no argument, so a change of
TTP_SEMANTIC_DOMAINS in the same process was ignored; and its manifest check
compared the cache with the configured model, not with the fallback model
`_load_model` had loaded.  No sentence-transformer is loaded here: a fake
module stands in for it, and the embedding cache is a few rows written to
a temporary directory.
"""
from __future__ import annotations

import json
import sys
import types

import numpy as np
import pytest

from pipeline import stage2c_ttp_semantic as s2c

PRIMARY = "ehsanaghaei/SecureBERT-Plus"
LEGACY = "all-MiniLM-L6-v2"

META = [
    {"id": "T1566.001", "name": "Spearphishing Attachment", "domain": "enterprise-attack"},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "domain": "enterprise-attack"},
    {"id": "CAPEC-163", "name": "Spear Phishing", "domain": "capec"},
]


def _install(tmp_path, monkeypatch, cache_model: str) -> None:
    """A three-row cache built with `cache_model`, read through the module's paths."""
    emb, meta, manifest = tmp_path / "emb.npy", tmp_path / "meta.json", tmp_path / "manifest.json"
    np.save(emb, np.eye(3, 4, dtype="float32"))
    meta.write_text(json.dumps(META), encoding="utf-8")
    manifest.write_text(json.dumps({"model": cache_model}), encoding="utf-8")
    monkeypatch.setattr(s2c, "_EMB_PATH", emb)
    monkeypatch.setattr(s2c, "_META_PATH", meta)
    monkeypatch.setattr(s2c, "_MANIFEST_PATH", manifest)


@pytest.fixture()
def clean(monkeypatch):
    monkeypatch.delenv("TTP_SEMANTIC_DOMAINS", raising=False)
    monkeypatch.delenv("TTP_HIGH_THRESHOLD", raising=False)
    monkeypatch.delenv("TTP_MEDIUM_THRESHOLD", raising=False)
    monkeypatch.setattr(s2c, "_active_model", None)
    s2c._load_corpus_for.cache_clear()
    s2c._load_model.cache_clear()
    yield
    s2c._load_corpus_for.cache_clear()
    s2c._load_model.cache_clear()


def test_a_domain_change_in_the_same_process_takes_effect_issue_389(tmp_path, monkeypatch, clean):
    _install(tmp_path, monkeypatch, cache_model=s2c._TTP_EMBEDDING_MODEL)
    monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", "all")
    emb, meta = s2c._load_corpus()
    assert [m["id"] for m in meta] == ["T1566.001", "T1059", "CAPEC-163"]

    monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", "enterprise-attack")
    emb, meta = s2c._load_corpus()
    assert [m["id"] for m in meta] == ["T1566.001", "T1059"] and emb.shape[0] == 2

    # The default (ATT&CK only) is a domain value too, not the first one ever read.
    monkeypatch.delenv("TTP_SEMANTIC_DOMAINS")
    _, meta = s2c._load_corpus()
    assert [m["id"] for m in meta] == ["T1566.001", "T1059"]


class _FakeSentenceTransformer:
    """Loads only the legacy model: the primary one stands for a failed download."""

    def __init__(self, name: str):
        if name != LEGACY:
            raise OSError(f"{name} cannot be downloaded")
        self.name = name


@pytest.fixture()
def fallback(monkeypatch, clean):
    st = types.ModuleType("sentence_transformers")
    st.SentenceTransformer = _FakeSentenceTransformer
    monkeypatch.setitem(sys.modules, "sentence_transformers", st)
    monkeypatch.setitem(sys.modules, "transformers", None)     # the optional log silencing: skipped
    monkeypatch.setattr(s2c, "_SKIP_HEAVY", False)
    monkeypatch.setattr(s2c, "_TTP_EMBEDDING_MODEL", PRIMARY)


def test_a_cache_of_the_primary_model_is_not_used_after_a_fallback_issue_389(tmp_path, monkeypatch, fallback):
    _install(tmp_path, monkeypatch, cache_model=PRIMARY)
    assert s2c._load_corpus() is not None           # before any load: the configured model is taken
    assert s2c._load_model() is not None            # the primary fails, the legacy model loads
    assert s2c._active_model == LEGACY
    assert s2c._load_corpus() is None               # 768-d SecureBERT rows against a 384-d model


def test_a_cache_of_the_fallback_model_is_used_after_a_fallback_issue_389(tmp_path, monkeypatch, fallback):
    _install(tmp_path, monkeypatch, cache_model=LEGACY)
    assert s2c._load_model() is not None
    emb, meta = s2c._load_corpus()
    assert len(meta) == 2 and emb.shape == (2, 4)     # ATT&CK only by default: the CAPEC row is out


def test_thresholds_follow_the_model_loaded_issue_389(tmp_path, monkeypatch, fallback):
    _install(tmp_path, monkeypatch, cache_model=LEGACY)
    assert s2c._thresholds() == s2c._MODEL_THRESHOLDS[PRIMARY]
    s2c._load_model()
    assert s2c._thresholds() == s2c._MODEL_THRESHOLDS[LEGACY]
