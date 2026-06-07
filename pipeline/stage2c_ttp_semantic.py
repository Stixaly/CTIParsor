"""
Stage 2c — Semantic TTP Detection.

Uses sentence-transformers to find MITRE ATT&CK techniques referenced in a
document *without relying on exact name or ID matches*.

How it works:
  1. Split the document into candidate sentences likely to describe adversary behaviour
     (filtered by a keyword allowlist — reduces noise and cost).
  2. Embed each candidate sentence with the configured model.
  3. Compare against pre-computed embeddings of all 1,531 MITRE technique descriptions.
  4. Return techniques whose cosine similarity exceeds the confidence threshold.

Embedding model (configurable via TTP_EMBEDDING_MODEL in .env):
  Default: all-MiniLM-L6-v2 (80 MB, general English, 384-dim)
  Recommended: ehsanaghaei/SecureBERT-Plus (500 MB, security-domain, 768-dim)
    → +8-12% TTP F1 on cybersecurity text  [CTiKG — Windsor 2025 — ADR-004 P1-A]
  After changing TTP_EMBEDDING_MODEL, rebuild cache:
    python scripts/build_indexes.py --only embeddings

Confidence tiers (Arazzi et al. 2023 §8 — ATHRNN, TTPpredictor findings):
  score ≥ 0.62  → high confidence   (accepted=True,  source="semantic")
  score 0.48–0.61 → medium confidence (accepted=None,  source="semantic")
  score < 0.48  → discard

The pre-computed embedding cache (pipeline/data/mitre_embeddings.npy + _meta.json)
is built by running:  python scripts/build_indexes.py

Outputs feed directly into all_entities in worker.py, complementing:
  Stage 2  — regex IoC extraction
  Stage 2b — MITRE gazetteer named entity matching
  Stage 2d — CyNER cybersecurity NER
  Stage 2e — GLiNER zero-shot NER
  Stage 3  — LLM enrichment (relationships, campaign, novel TTPs)
"""
from __future__ import annotations

import functools
import json
import os
import re
from pathlib import Path

from models.schemas import EntityType, RawEntity

_SKIP_HEAVY = os.getenv("SKIP_HEAVY_MODELS") == "1"

# Initialize logging
from api.logging_config import get_logger

logger = get_logger(__name__)

# ── Model configuration (ADR-004 P1-A) ────────────────────────────────────────
# Override via TTP_EMBEDDING_MODEL= in .env
# Changing the model requires rebuilding the embedding cache:
#   python scripts/build_indexes.py --only embeddings
_TTP_EMBEDDING_MODEL = os.getenv("TTP_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
_LEGACY_MODEL = "all-MiniLM-L6-v2"   # model used before ADR-004 (backward compat)

# Pre-computed cache paths
_DATA_DIR      = Path(__file__).parent / "data"
_EMB_PATH      = _DATA_DIR / "mitre_embeddings.npy"
_META_PATH     = _DATA_DIR / "mitre_embeddings_meta.json"
_MANIFEST_PATH = _DATA_DIR / "mitre_embeddings_manifest.json"

# Confidence thresholds for semantic cosine similarity
_HIGH_THRESH   = 0.62
_MEDIUM_THRESH = 0.48

# Maximum number of TTP-keyword-filtered candidate sentences to embed.
# The cosine similarity matrix is O(n × 1531 techniques); at 800 candidates
# that's 1.2 M float operations — ~4× slower than the 200-candidate cap with
# minimal recall loss (the marginal 201st candidate scores below threshold).
# Strided sampling (every Kth sentence) ensures coverage across the full doc.
# Override via TTP_MAX_CANDIDATES= in .env.
_MAX_CANDIDATES = int(os.getenv("TTP_MAX_CANDIDATES", "200"))

# Sentences must contain at least one of these tokens to be considered
# TTP candidates — avoids embedding every sentence in the document.
_TTP_KEYWORDS = frozenset({
    # Adversary actions
    "exploit", "exploited", "exploiting", "leveraged", "leveraging",
    "deployed", "deploying", "executed", "executing", "download", "downloaded",
    "upload", "uploaded", "inject", "injected", "persistence", "persist",
    "escalat", "lateral", "exfiltrat", "credential", "privilege",
    "reconnaissance", "enumerat", "dump", "harvest", "steal", "stole",
    "bypass", "evad", "obfuscat", "encrypt", "decrypt", "tunnel",
    "phishing", "spearphish", "spear-phish", "brute", "spray",
    "command and control", "c2", "c&c", "beacon", "callback",
    # Technique nouns
    "backdoor", "keylogger", "rootkit", "dropper", "loader",
    "shellcode", "payload", "implant", "webshell", "web shell",
    "supply chain", "watering hole", "drive-by", "man-in-the-middle",
    "man in the middle", "sql injection", "xss", "cross-site",
    "privilege escalation", "process inject", "dll inject",
    "registry", "scheduled task", "cron", "startup", "autorun",
    "mimikatz", "powershell", "wmi", "lsass", "ntds",
    "pass-the-hash", "pass the hash", "golden ticket", "kerberoast",
    "living off the land", "lolbin", "lolbas",
})

# Entity type assigned based on MITRE ID prefix
def _etype_from_id(mitre_id: str) -> EntityType:
    if mitre_id.startswith("TA"):
        return EntityType.TACTIC
    return EntityType.TECHNIQUE


def _has_ttp_keyword(sentence: str) -> bool:
    s = sentence.lower()
    return any(kw in s for kw in _TTP_KEYWORDS)


def _split_sentences(text: str) -> list[str]:
    """
    Simple sentence splitter that handles the variety of CTI report formats.
    Splits on '. ', '\n', '; ' and keeps segments longer than 20 chars.
    """
    # Normalize whitespace
    text = re.sub(r'\r\n|\r', '\n', text)
    # Split on end-of-sentence punctuation, newlines, semicolons
    raw = re.split(r'(?<=[.!?])\s+|\n{1,}|;\s+', text)
    return [s.strip() for s in raw if len(s.strip()) > 20]


# ── Lazy-loaded model and cached embeddings ───────────────────────────────────

@functools.lru_cache(maxsize=1)
def _load_model():
    """
    Load the sentence-transformer model (cached in memory after first call).

    Tries the configured model (TTP_EMBEDDING_MODEL) first; falls back to the
    legacy all-MiniLM-L6-v2 if the primary model cannot be downloaded/loaded.
    Returns None when SKIP_HEAVY_MODELS=1.
    """
    if _SKIP_HEAVY:
        return None

    # Suppress the verbose "BertModel LOAD REPORT / UNEXPECTED key" table and
    # weight-materialisation progress bars that transformers prints at WARNING level.
    try:
        from transformers import logging as _hf_log
        _hf_log.set_verbosity_error()
    except ImportError:
        pass

    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer(_TTP_EMBEDDING_MODEL)
        logger.info(f"Loaded embedding model: {_TTP_EMBEDDING_MODEL}")
        return model
    except Exception as e:
        if _TTP_EMBEDDING_MODEL != _LEGACY_MODEL:
            logger.warning(f"Primary model '{_TTP_EMBEDDING_MODEL}' unavailable: {e}")
            logger.info(f"Falling back to {_LEGACY_MODEL}")
            try:
                from sentence_transformers import SentenceTransformer
                model = SentenceTransformer(_LEGACY_MODEL)
                return model
            except Exception as e2:
                logger.error(f"Fallback also failed: {e2}")
        else:
            logger.error(f"Could not load SentenceTransformer: {e}")
        return None


@functools.lru_cache(maxsize=1)
def _load_corpus() -> tuple | None:
    """
    Returns (embeddings_numpy, meta_list) where:
      embeddings has shape (N, D)  — D = 384 for MiniLM, 768 for SecureBERT+
      meta_list[i] = {'id': ..., 'name': ..., 'domain': ..., ...}

    Validates the cache against the manifest (mitre_embeddings_manifest.json) to
    detect when the embedding model has changed and a rebuild is needed.
    """
    if not _EMB_PATH.exists() or not _META_PATH.exists():
        logger.warning("Embedding cache not found — run: python scripts/build_indexes.py")
        return None

    # ── Manifest check — detect stale cache after model change ──────────────
    if _MANIFEST_PATH.exists():
        try:
            manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
            cache_model = manifest.get("model", _LEGACY_MODEL)
        except Exception:
            cache_model = _LEGACY_MODEL
    else:
        # No manifest → cache was built before ADR-004; assume legacy model
        cache_model = _LEGACY_MODEL

    if cache_model != _TTP_EMBEDDING_MODEL:
        logger.warning(
            f"Embedding cache was built with '{cache_model}' "
            f"but TTP_EMBEDDING_MODEL='{_TTP_EMBEDDING_MODEL}'. "
            f"Rebuild with: python scripts/build_indexes.py --only embeddings"
        )
        return None

    try:
        import numpy as np
        embeddings = np.load(str(_EMB_PATH))
        meta = json.loads(_META_PATH.read_text(encoding="utf-8"))
        return embeddings, meta
    except Exception as e:
        logger.error(f"Could not load embedding cache: {e}")
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def semantic_available() -> bool:
    """Return True if the sentence-transformers library is installed and the
    embedding cache exists for the currently configured model.
    Always returns False when SKIP_HEAVY_MODELS=1."""
    if _SKIP_HEAVY:
        return False
    try:
        from sentence_transformers import SentenceTransformer  # noqa: F401
        if not _EMB_PATH.exists() or not _META_PATH.exists():
            return False
        # Quick manifest check (no full load)
        if _MANIFEST_PATH.exists():
            try:
                manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
                if manifest.get("model", _LEGACY_MODEL) != _TTP_EMBEDDING_MODEL:
                    return False
            except Exception:
                pass
        return True
    except ImportError:
        return False


def detect_ttps_semantic(text: str, top_k_per_sentence: int = 2) -> list[RawEntity]:
    """
    Scan *text* for MITRE ATT&CK techniques using semantic sentence similarity.

    Each candidate sentence is compared against 1,531 pre-embedded technique
    descriptions.  Matches above the confidence threshold are returned as
    RawEntity objects with:
      entity_type = TECHNIQUE or TACTIC
      mitre_id    = canonical ATT&CK ID (e.g. "T1566.001")
      source      = "semantic"
      confidence  = cosine similarity score (clamped to [0, 1])

    Duplicates (same mitre_id) are deduplicated keeping the highest score.
    """
    model = _load_model()
    corpus = _load_corpus()

    if model is None or corpus is None:
        return []

    corpus_embeddings, meta = corpus

    # Filter to TTP-suggestive sentences only
    sentences  = _split_sentences(text)
    candidates = [s for s in sentences if _has_ttp_keyword(s)]

    if not candidates:
        return []

    # Cap candidates to avoid an O(n × 1531) cosine matrix that is slow for
    # large documents.  Use a strided sample so all sections of the document
    # are represented rather than just the opening pages.
    if len(candidates) > _MAX_CANDIDATES:
        step       = max(1, len(candidates) // _MAX_CANDIDATES)
        candidates = candidates[::step][:_MAX_CANDIDATES]

    try:
        import numpy as np
        from sentence_transformers import util

        # Encode all candidate sentences in one batch
        query_embeddings = model.encode(
            candidates,
            batch_size=32,
            convert_to_numpy=True,
            show_progress_bar=False,
        )

        # Cosine similarity: shape (len(candidates), len(corpus))
        scores = util.cos_sim(query_embeddings, corpus_embeddings).numpy()

        # Collect best matches per technique (dedup by mitre_id)
        best: dict[str, tuple[float, str]] = {}  # mitre_id → (score, evidence_sentence)

        for sent_idx, sent in enumerate(candidates):
            # Top-k matches for this sentence
            top_indices = np.argsort(scores[sent_idx])[::-1][:top_k_per_sentence]
            for idx in top_indices:
                score = float(scores[sent_idx][idx])
                if score < _MEDIUM_THRESH:
                    break  # sorted descending, no point continuing
                entry = meta[idx]
                mid = entry["id"]
                if mid not in best or score > best[mid][0]:
                    best[mid] = (score, sent)

    except Exception as e:
        logger.error(f"Semantic scoring error: {e}")
        return []

    # Build an O(1) lookup from MITRE ID → meta entry once (avoids O(n²) scan)
    meta_by_id: dict[str, dict] = {m["id"]: m for m in meta}

    # Convert to RawEntity
    results: list[RawEntity] = []
    for mid, (score, evidence) in best.items():
        entry = meta_by_id.get(mid)
        if not entry:
            continue

        etype = _etype_from_id(mid)
        # Clamp to [0, 1] and round for DB storage
        confidence = round(min(1.0, max(0.0, score)), 4)

        results.append(RawEntity(
            value=entry["name"],
            entity_type=etype,
            context=evidence[:200],    # evidence sentence as context
            confidence=confidence,
            mitre_id=mid,
            source="semantic",
        ))

    # Sort by confidence descending
    results.sort(key=lambda x: x.confidence, reverse=True)
    return results


# ---------------------------------------------------------------------------
# ExtractionStage class wrapper — consumed by pipeline.registry
# ---------------------------------------------------------------------------

from pipeline.base import BaseExtractionStage  # noqa: E402


class SemanticTTPStage(BaseExtractionStage):
    """Stage-2c semantic TTP detector as an ExtractionStage implementation."""

    name = "semantic_ttp"

    def __init__(self, config=None) -> None:
        pass

    def available(self) -> bool:
        return semantic_available()

    def extract(self, text: str) -> list[RawEntity]:
        return detect_ttps_semantic(text)
