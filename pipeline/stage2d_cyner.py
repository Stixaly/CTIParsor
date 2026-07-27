"""
Stage 2d — CyNER Cybersecurity Named Entity Recognition.

Uses the PranavaKailash/CyNER-2.0-DeBERTa-v3-base model (DeBERTa-v3 fine-tuned on
cybersecurity NER corpora, F1 91.88%) to extract named entities from CTI text.

Why CyNER instead of generic spaCy?
  SpaCy's en_core_web_lg was trained on newswire and Wikipedia.  It labels every
  organisation, cloud provider, and package registry as ORG / PRODUCT and cannot
  reliably distinguish a threat-actor name from a victim company.  CyNER 2.0 was
  fine-tuned specifically on cybersecurity text and recognises:

    Malware        — specific named malware families (Emotet, WannaCry, …)
    Threat_group   — threat-actor groups (APT29, Lazarus Group, FIN7, …)
    Organization   — victim companies / vendors (skipped — not threat actors)
    Vulnerability  — descriptive vulnerability references ("EternalBlue exploit")
    Indicator      — network/file indicators (skipped here — regex handles these)
    System         — operating-system / software names (skipped — too noisy)

Confidence tiers:
  score ≥ 0.90  → high confidence   (accepted=True)
  score 0.70–0.89 → medium confidence (accepted=None)
  score < 0.70  → discard

The model is downloaded from HuggingFace Hub on first use (~0.8 GB, cached in
~/.cache/huggingface/).  Subsequent runs load from the local cache.
"""
from __future__ import annotations

import functools
import os
import re
from pathlib import Path

from models.schemas import EntityType, RawEntity

_SKIP_HEAVY = os.getenv("SKIP_HEAVY_MODELS") == "1"

# Initialize logging
from api.logging_config import get_logger

logger = get_logger(__name__)

# Model ID — configurable via CYNER_MODEL in .env.
# Default: PranavaKailash/CyNER-2.0-DeBERTa-v3-base — a publicly available
# DeBERTa-v3 NER model fine-tuned on cybersecurity corpora (F1 91.88%).
# It replaces the old aiforsec/cyner-xlm-roberta-base, which is gated / removed
# from HuggingFace Hub.  CyNER 2.0 exposes a dedicated "Threat_group" label
# distinct from "Organization", so threat-actor detection no longer relies on
# the _ORG_BLOCKLIST heuristic below.
# NOTE: model_type is deberta-v2 → the `sentencepiece` package is required.
# If the model cannot be loaded, Stage 2e (GLiNER) covers the same entity types
# (malware families, threat actor groups) via zero-shot NER.
# Set CYNER_ENABLED=false in .env to skip this stage and silence all warnings.
_MODEL_ID      = os.getenv("CYNER_MODEL",   "PranavaKailash/CyNER-2.0-DeBERTa-v3-base")
_CYNER_ENABLED = os.getenv("CYNER_ENABLED", "true").lower() not in ("false", "0", "no")

# Sentinel file written to the project root the first time the model is detected
# as inaccessible (private/removed).  Future subprocess invocations check for this
# file and skip the HuggingFace Hub network request entirely, so the 401 warning
# only ever appears once per server installation (not once per job).
_SENTINEL_PATH = Path(__file__).parent.parent / ".cyner_model_unavailable"

# Confidence thresholds
_HIGH_THRESH   = 0.90
_MEDIUM_THRESH = 0.70

# CyNER 2.0 label → our EntityType.
# Labels come from the model's config.json (entity_group after aggregation):
#   Malware, Threat_group, Organization, Indicator, System, Vulnerability,
#   Date, Location.
_LABEL_MAP: dict[str, EntityType] = {
    "Malware":      EntityType.MALWARE,
    "Threat_group": EntityType.THREAT_ACTOR,
    # "Organization": skip — victim companies / vendors, not threat actors
    # "Vulnerability": EntityType.CVE — CVEs are handled more precisely by regex
    # "Indicator": skip — regex is more reliable for IoCs
    # "System": skip — too noisy (e.g. "Windows", "Linux")
    # "Date" / "Location": skip — not modelled as CTI entities here
}

# Tokens/terms to block from THREAT_ACTOR mapping (safety net).
# CyNER 2.0 has a dedicated Threat_group label, so mislabelled victim companies
# should be rare — but the model occasionally tags a well-known vendor as a
# threat group, so this blocklist stays as a cheap guardrail.
_ORG_BLOCKLIST = frozenset({
    # Victim/neutral orgs often mentioned in CTI reports
    "microsoft", "google", "amazon", "apple", "facebook", "meta",
    "cloudflare", "akamai", "fastly",
    # Package registries / platforms
    "npm", "pypi", "github", "gitlab", "bitbucket",
    # Generic terms
    "security", "team", "group", "organization", "company", "vendor",
    "researcher", "analyst", "government", "agency", "institute",
})

# Regex: bare version numbers ("1.2.3") — spaCy and some NER models label these
_VERSION_RE = re.compile(r"^\d[\d.\-]*\d$")


# ── Lazy-loaded model ─────────────────────────────────────────────────────────

@functools.lru_cache(maxsize=1)
def _load_pipeline():
    """
    Load the CyNER HuggingFace NER pipeline (cached in memory after first call).
    Returns None if disabled, transformers is unavailable, or the model cannot be loaded.

    Load strategy (avoids unnecessary network traffic):
      1. Sentinel file present → return None immediately (no HTTP, no import)
      2. local_files_only=True → load from ~/.cache/huggingface/ with no network
      3. Network download → only if not already cached locally
      4. On 401/403/not-found → write sentinel so all future subprocesses skip step 3
    """
    if _SKIP_HEAVY or not _CYNER_ENABLED:
        return None

    # Fast path: a previous subprocess already determined the model is inaccessible.
    if _SENTINEL_PATH.exists():
        return None

    try:
        from transformers import logging as hf_logging
        from transformers import pipeline
        hf_logging.set_verbosity_error()  # suppress download-progress noise
    except ImportError:
        return None

    # ── Step 1: try local HuggingFace cache (zero network I/O) ──────────────
    try:
        ner = pipeline(
            "ner",
            model=_MODEL_ID,
            aggregation_strategy="simple",  # merges B-/I- tokens → full entity spans
            device=-1,                      # CPU; set device=0 to use GPU
            local_files_only=True,
        )
        logger.info(f"CyNER model loaded from local cache: {_MODEL_ID}")
        return ner
    except (OSError, EnvironmentError, ValueError):
        pass  # Model not in local cache — try downloading below

    # ── Step 2: attempt a one-time download from HuggingFace Hub ────────────
    logger.info(f"CyNER model '{_MODEL_ID}' not in local cache — attempting download…")
    try:
        ner = pipeline(
            "ner",
            model=_MODEL_ID,
            aggregation_strategy="simple",
            device=-1,
        )
        logger.info(f"CyNER model downloaded and loaded: {_MODEL_ID}")
        return ner
    except Exception as e:
        msg = str(e)
        _ACCESS_ERRORS = ("401", "403", "unauthorized", "Repository Not Found",
                          "not a valid model identifier", "not a local folder",
                          "gated repo", "access to model")
        if any(x.lower() in msg.lower() for x in _ACCESS_ERRORS):
            logger.warning(
                f"CyNER model '{_MODEL_ID}' is not accessible on HuggingFace Hub "
                f"(private, gated, or removed). "
                f"Stage 2e (GLiNER) covers the same entity types as a fallback.\n"
                f"To disable CyNER and silence this warning permanently, add to your .env:\n"
                f"  CYNER_ENABLED=false"
            )
            # Write a sentinel so every subsequent subprocess skips the network check.
            # One warning total per server installation, not one per job.
            try:
                _SENTINEL_PATH.touch()
                logger.debug(f"CyNER unavailability sentinel written: {_SENTINEL_PATH}")
            except OSError:
                pass
        else:
            logger.error(f"Could not load CyNER model '{_MODEL_ID}': {e}")
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def cyner_available() -> bool:
    """
    Return True only if the CyNER pipeline is actually loaded and ready.

    This calls _load_pipeline() (which is lru_cached) so the model is loaded at
    most once per subprocess.  Returning False here means worker.py skips the
    cyner_entities branch entirely — no inference attempt, no misleading empty list.
    """
    if _SKIP_HEAVY or not _CYNER_ENABLED:
        return False
    if _SENTINEL_PATH.exists():
        return False
    try:
        import transformers  # noqa: F401
    except ImportError:
        return False
    return _load_pipeline() is not None


def extract_cyner_entities(text: str) -> list[RawEntity]:
    """
    Run CyNER over *text* and return cybersecurity named entities.

    Entities already found by the regex IoC extractor (Stage 2) or the MITRE
    gazetteer (Stage 2b) are NOT filtered here — the caller (worker.py) handles
    deduplication so that the higher-precision source wins.

    Returns an empty list if the model cannot be loaded.
    """
    ner_pipeline = _load_pipeline()
    if ner_pipeline is None:
        return []

    try:
        predictions: list[dict] = ner_pipeline(text[:50_000])   # cap at 50K chars
    except Exception as e:
        logger.error(f"CyNER inference error: {e}")
        return []

    results: list[RawEntity] = []

    for pred in predictions:
        label    = pred.get("entity_group", "")
        score    = float(pred.get("score", 0.0))
        value    = pred.get("word", "").strip()

        etype = _LABEL_MAP.get(label)
        if etype is None:
            continue                        # skip Indicator, System, Vulnerability
        if score < _MEDIUM_THRESH:
            continue
        if not value or len(value) < 3:
            continue
        if _VERSION_RE.match(value):
            continue
        if value.startswith("@"):           # npm scoped package scope-names
            continue

        # Organization filter — only keep plausible threat-actor names
        if etype == EntityType.THREAT_ACTOR:
            if value.lower() in _ORG_BLOCKLIST:
                continue
            # Skip single common words
            if len(value.split()) == 1 and value.lower() in {
                "the", "a", "an", "this", "that", "we", "they", "he", "she",
                "it", "our", "their", "us", "you", "all", "some", "new",
            }:
                continue

        results.append(RawEntity(
            value=value,
            entity_type=etype,
            context="",
            confidence=round(score, 4),
            source="cyner",
        ))

    return results


# ---------------------------------------------------------------------------
# ExtractionStage class wrapper — consumed by pipeline.registry
# ---------------------------------------------------------------------------

from pipeline.base import BaseExtractionStage  # noqa: E402


class CyNERStage(BaseExtractionStage):
    """Stage-2d CyNER cybersecurity NER as an ExtractionStage implementation."""

    name = "cyner"

    def __init__(self, config=None) -> None:
        pass

    def available(self) -> bool:
        return cyner_available()

    def extract(self, text: str) -> list[RawEntity]:
        return extract_cyner_entities(text)


def _merge_cyner_into(
    all_entities: list[RawEntity],
    cyner_entities: list[RawEntity],
) -> list[RawEntity]:
    """
    Merge CyNER results into an existing entity list.

    Rules:
      • Any (value, type) pair already present is skipped — the earlier source
        (regex or gazetteer) already covers it, often with a more precise value.
      • For THREAT_ACTOR entities specifically, CyNER is considered more
        reliable than spaCy-derived actors but less reliable than the gazetteer.
    """
    existing_keys = {(e.value.lower(), e.entity_type) for e in all_entities}
    added = list(all_entities)

    for ce in cyner_entities:
        key = (ce.value.lower(), ce.entity_type)
        if key not in existing_keys:
            added.append(ce)
            existing_keys.add(key)

    return added
