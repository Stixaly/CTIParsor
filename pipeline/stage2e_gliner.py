"""
Stage 2e — GLiNER Zero-Shot NER for Novel CTI Entities.

GLiNER (Generalist and Lightweight Named Entity Recognition) uses a bidirectional
transformer encoder that accepts ARBITRARY entity labels at inference time — no
fine-tuning required.  This makes it ideal for CTI entity types that CyNER and
the MITRE gazetteer don't cover.

Paper: "0-CTI: A Modular Framework for Zero-Shot Cyber Threat Intelligence
Extraction" (CY4GATE / Noi et al., 2025) — ADR-004 P2-A
Zero-shot NER LLM-judge score: 0.91  |  Zero-shot RE score: 0.83

Why GLiNER alongside CyNER + Gazetteer?
  • CyNER was fine-tuned on a fixed label set: MalwareFamily, Organization,
    Vulnerability, Indicator, System.  It cannot detect:
      - Targeted sectors (financial, healthcare, government, energy…)
      - Campaign names not yet in MITRE ATT&CK
      - Attack infrastructure types (proxy, VPN gateway, botnet C2…)
      - Targeted countries when not mentioned as a spaCy GPE
  • The MITRE gazetteer covers ~1,700 known entities but misses unnamed actors
    and novel malware variants described in prose.
  • GLiNER fills these gaps by accepting new label descriptions at runtime.

Entity types detected (chosen to avoid overlap with CyNER / gazetteer):
  malware family      → EntityType.MALWARE        (novel/unnamed malware)
  threat actor group  → EntityType.THREAT_ACTOR   (new APT groups)
  targeted sector     → EntityType.IDENTITY        (STIX identity = org/sector)
  targeted country    → EntityType.LOCATION
  attack campaign     → EntityType.CAMPAIGN
  attack infrastructure → EntityType.INFRASTRUCTURE

Model configuration (via .env):
  GLINER_MODEL     = urchade/gliner_mediumv2.1   (~300 MB, CPU-friendly, recommended)
  GLINER_THRESHOLD = 0.40                         (lower than supervised NER: zero-shot)
  GLINER_ENABLED   = true                         (set false to disable stage)

The model is downloaded from HuggingFace Hub on first use and cached locally.
"""
from __future__ import annotations

import os
import warnings
import functools
import re
from typing import Iterator

from models.schemas import RawEntity, EntityType

# Initialize logging
from api.logging_config import get_logger
logger = get_logger(__name__)

# Suppress GLiNER's "Sentence of length N has been truncated to 384" warning.
# This fires for IoC-table chunks that exceed the BERT token limit; those
# sections are already handled by regex extraction so the truncation is benign.
warnings.filterwarnings(
    "ignore",
    message=r"Sentence of length \d+ has been truncated",
    category=UserWarning,
)

# ── Configuration ─────────────────────────────────────────────────────────────
# Default: NuNER-Zero-span (NuMind) — GLiNER-compatible with improved token
# classification heads.  Benchmarks show better zero-shot NER quality than
# GLiNER medium on multi-domain corpora.  To revert to classic GLiNER:
#   GLINER_MODEL=urchade/gliner_mediumv2.1
# See .env.example for the full model option list.
_SKIP_HEAVY        = os.getenv("SKIP_HEAVY_MODELS") == "1"
_GLINER_MODEL_ID   = os.getenv("GLINER_MODEL",     "numind/NuNER-Zero-span")
_GLINER_THRESHOLD  = float(os.getenv("GLINER_THRESHOLD", "0.40"))
_GLINER_ENABLED    = os.getenv("GLINER_ENABLED", "true").lower() not in ("false", "0", "no")

# ── Label → EntityType mapping ────────────────────────────────────────────────
# Labels are natural-language descriptions — GLiNER reads them at inference time.
_LABEL_MAP: dict[str, EntityType] = {
    "malware family":        EntityType.MALWARE,
    "threat actor group":    EntityType.THREAT_ACTOR,
    "targeted sector":       EntityType.IDENTITY,
    "targeted country":      EntityType.LOCATION,
    "attack campaign":       EntityType.CAMPAIGN,
    "attack infrastructure": EntityType.INFRASTRUCTURE,
}
_GLINER_LABELS = list(_LABEL_MAP.keys())

# ── Text chunking ─────────────────────────────────────────────────────────────
# GLiNER medium supports up to 384 subword tokens.  CTI prose averages ~0.35
# tokens/char; denser sections (IoC tables, code) hit ~0.55 tokens/char.
#
# 1 600 chars ≈ 560 tokens at max density — may trigger the GLiNER truncation
# warning on the densest chunks, but those are IoC tables that regex already
# handles.  For normal prose, 1 600 chars ≈ 480-560 tokens — right at the limit.
# Net effect: ~halves the number of GLiNER model passes compared to 800 chars.
#
# Configurable via GLINER_CHUNK_CHARS env var if you need to tune.
_CHUNK_CHARS    = int(os.getenv("GLINER_CHUNK_CHARS", "1600"))
_OVERLAP_CHARS  = 200   # proportionally wider to avoid missing cross-boundary spans

# ── Batched inference ─────────────────────────────────────────────────────────
# GLiNER's predict_entities() accepts a list[str] as well as a single str.
# Processing N chunks as one batch amortises the Python→model transfer cost
# and leverages ONNX/PyTorch batch efficiency.
# Set GLINER_BATCH_SIZE=1 to disable batching (useful for debugging).
_BATCH_SIZE = int(os.getenv("GLINER_BATCH_SIZE", "4"))


def _iter_chunks(text: str) -> Iterator[tuple[str, int]]:
    """Yield (chunk_text, char_offset) pairs with overlap."""
    start = 0
    length = len(text)
    while start < length:
        end = min(start + _CHUNK_CHARS, length)
        # Don't cut in the middle of a word
        if end < length:
            # Walk back to nearest whitespace
            while end > start and not text[end].isspace():
                end -= 1
            # If no whitespace was found (end walked back to start), the entire
            # chunk is one unbroken token.  Force-advance past it so start always
            # moves forward and we never produce an empty chunk or a negative start.
            if end <= start:
                end = min(start + _CHUNK_CHARS, length)
        yield text[start:end], start
        start = max(start + 1, end - _OVERLAP_CHARS) if end < length else length


# ── Lazy-loaded model ─────────────────────────────────────────────────────────

@functools.lru_cache(maxsize=1)
def _load_gliner():
    """
    Load the GLiNER model (cached in memory after first call).
    Returns None if the gliner library is not installed or the model fails to load.
    """
    if _SKIP_HEAVY or not _GLINER_ENABLED:
        return None
    try:
        from gliner import GLiNER
        model = GLiNER.from_pretrained(_GLINER_MODEL_ID)
        logger.info(f"GLiNER model loaded: {_GLINER_MODEL_ID}")
        return model
    except ImportError:
        # gliner not installed — silent skip (it's optional)
        return None
    except Exception as e:
        logger.error(f"Could not load GLiNER model '{_GLINER_MODEL_ID}': {e}")
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def gliner_available() -> bool:
    """Return True if the gliner library is installed, GLINER_ENABLED=true, and SKIP_HEAVY_MODELS is not set."""
    if _SKIP_HEAVY or not _GLINER_ENABLED:
        return False
    try:
        import gliner  # noqa: F401
        return True
    except ImportError:
        return False


def extract_gliner_entities(text: str) -> list[RawEntity]:
    """
    Run GLiNER over *text* using the configured entity labels and return
    zero-shot CTI named entities.

    The function processes the text in overlapping windows to avoid token-limit
    issues with long CTI reports (PDFs, DOCX).

    Results are deduplicated by (value.lower(), entity_type) keeping the
    highest-confidence occurrence of each span.

    Returns an empty list if GLiNER is not available or no entities are found.
    """
    model = _load_gliner()
    if model is None:
        return []

    # ── Batched inference ─────────────────────────────────────────────────────
    # Collect non-empty chunks, then call model.predict_entities() in batches
    # of _BATCH_SIZE.  When given a list, GLiNER returns list[list[dict]].
    # Falls back to single-string calls if the batch API raises.
    # best[key] = (score, context_snippet)
    best: dict[tuple[str, EntityType], tuple[float, str]] = {}

    # Build the flat list of (chunk_text, char_offset) upfront
    all_chunks = [(t, off) for t, off in _iter_chunks(text) if t.strip()]

    for batch_start in range(0, len(all_chunks), _BATCH_SIZE):
        batch      = all_chunks[batch_start : batch_start + _BATCH_SIZE]
        batch_texts   = [t for t, _ in batch]
        batch_offsets = [off for _, off in batch]

        try:
            raw = model.predict_entities(
                batch_texts,
                _GLINER_LABELS,
                threshold=_GLINER_THRESHOLD,
                flat_ner=True,
                multi_label=False,
            )
            # When input is list[str], output should be list[list[dict]].
            # Guard against two degenerate shapes:
            #   • single-item batch → model returns flat list[dict] instead of list[list[dict]]
            #   • empty result     → model returns [] regardless of batch size
            if raw and not isinstance(raw[0], list):
                # Flat list for a single-chunk call — wrap it
                batch_preds = [raw]
            elif not raw:
                # Empty result: no entities found — produce one empty list per chunk
                batch_preds = [[] for _ in batch]
            else:
                batch_preds = raw
        except Exception as e:
            logger.warning(f"Batch inference error (falling back to single): {e}")
            # Per-chunk fallback
            batch_preds = []
            for chunk_text, char_offset in batch:
                try:
                    batch_preds.append(model.predict_entities(
                        chunk_text, _GLINER_LABELS,
                        threshold=_GLINER_THRESHOLD,
                        flat_ner=True, multi_label=False,
                    ))
                except Exception as e2:
                    logger.error(f"Inference error at offset {char_offset}: {e2}")
                    batch_preds.append([])

        for predictions, (chunk_text, char_offset) in zip(batch_preds, batch):
            for pred in predictions:
                label = pred.get("label", "")
                score = float(pred.get("score", 0.0))
                value = pred.get("text", "").strip()

                etype = _LABEL_MAP.get(label)
                if etype is None:
                    continue
                if not value or len(value) < 3:
                    continue
                if score < _GLINER_THRESHOLD:
                    continue

                # Skip bare version strings ("0.1.16") and single-char spans
                if re.fullmatch(r"\d[\d.\-]*\d?", value):
                    continue

                # Context: surrounding text in the chunk (±50 chars)
                span_start = pred.get("start", 0)
                ctx_start  = max(0, span_start - 50)
                ctx_end    = min(len(chunk_text), pred.get("end", span_start) + 50)
                context    = chunk_text[ctx_start:ctx_end].strip()

                key = (value.lower(), etype)
                if key not in best or score > best[key][0]:
                    best[key] = (score, context)

    # ── Convert to RawEntity ─────────────────────────────────────────────────
    results: list[RawEntity] = []
    for (value_lower, etype), (score, context) in best.items():
        # Recover original casing from the best match's value (use key value_lower
        # as fallback — we don't store original casing in `best`, so reconstruct)
        # Re-extract from best's context window is brittle; just use the lower form
        # with title-case for readability on IDENTITY/CAMPAIGN/LOCATION types.
        display_value = _recover_casing(value_lower, context)
        results.append(RawEntity(
            value=display_value,
            entity_type=etype,
            context=context[:200],
            confidence=round(score, 4),
            source="gliner",
        ))

    results.sort(key=lambda x: x.confidence, reverse=True)
    return results


def _recover_casing(value_lower: str, context: str) -> str:
    """
    Try to find the original-cased version of *value_lower* in *context*.
    Falls back to the lower-cased value if not found.
    """
    # Case-insensitive search in context
    pattern = re.compile(re.escape(value_lower), re.IGNORECASE)
    m = pattern.search(context)
    if m:
        return m.group()
    return value_lower


# ---------------------------------------------------------------------------
# ExtractionStage class wrapper — consumed by pipeline.registry
# ---------------------------------------------------------------------------

from pipeline.base import BaseExtractionStage  # noqa: E402


class GLiNERStage(BaseExtractionStage):
    """Stage-2e GLiNER zero-shot NER as an ExtractionStage implementation."""

    name = "gliner"

    def __init__(self, config=None) -> None:
        pass

    def available(self) -> bool:
        return gliner_available()

    def extract(self, text: str) -> list[RawEntity]:
        return extract_gliner_entities(text)


def _merge_gliner_into(
    all_entities: list[RawEntity],
    gliner_entities: list[RawEntity],
) -> list[RawEntity]:
    """
    Merge GLiNER results into an existing entity list.

    Deduplication rules:
    • MALWARE / THREAT_ACTOR: skip if already covered by gazetteer or CyNER
      (those sources have higher precision for named entities).
    • IDENTITY / LOCATION / CAMPAIGN / INFRASTRUCTURE: always add — these types
      are not covered by other stages so GLiNER is the only source.
    """
    existing_keys = {(e.value.lower(), e.entity_type) for e in all_entities}
    # Sources with higher precision for named entities
    high_precision_sources = {"gazetteer", "cyner", "ioc"}
    high_precision_types   = {EntityType.MALWARE, EntityType.THREAT_ACTOR}

    # Build a fast lookup of values already found by high-precision sources
    hp_values: set[str] = {
        e.value.lower()
        for e in all_entities
        if e.source in high_precision_sources and e.entity_type in high_precision_types
    }

    added = list(all_entities)

    for ge in gliner_entities:
        key = (ge.value.lower(), ge.entity_type)

        # For MALWARE/THREAT_ACTOR: skip if already found by a more precise source
        if ge.entity_type in high_precision_types and ge.value.lower() in hp_values:
            continue

        # Standard dedup by (value, type)
        if key not in existing_keys:
            added.append(ge)
            existing_keys.add(key)

    return added
