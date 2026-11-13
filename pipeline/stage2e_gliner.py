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

Entity types the stage can ask for (GLINER_ENTITY_TYPES names the ones it does):
  malware family      → EntityType.MALWARE        (novel/unnamed malware)
  threat actor group  → EntityType.THREAT_ACTOR   (new APT groups)
  targeted sector     → EntityType.IDENTITY        (STIX identity = org/sector)
  targeted country    → EntityType.LOCATION
  attack campaign     → EntityType.CAMPAIGN
  attack infrastructure → EntityType.INFRASTRUCTURE

Model configuration (via .env):
  GLINER_MODEL        = urchade/gliner_large-v2.1   (~800 MB, best zero-shot NER accuracy)
  GLINER_THRESHOLD    = 0.40                         (lower than supervised NER: zero-shot)
  GLINER_ENABLED      = true                         (set false to disable stage)
  GLINER_ENTITY_TYPES = identity,location            (the types asked for; empty = stage off, ADR-0098)

The model is downloaded from HuggingFace Hub on first use and cached locally.
"""
from __future__ import annotations

import functools
import os
import re
import warnings
from dataclasses import dataclass, field
from typing import Any, Iterator

# Initialize logging
from api.logging_config import get_logger
from models.schemas import EntityType, RawEntity
from pipeline.env_flags import env_bool, env_float, env_int
from pipeline.overrides import drop_denied
from pipeline.thresholds import get_threshold

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
# Default: GLiNER large v2.1 (urchade) — best zero-shot NER accuracy in the
# GLiNER v2.1 family.  numind/NuNER-Zero-span (the previous default) was
# removed from HuggingFace (401/repo-not-found).  For a smaller/faster model:
#   GLINER_MODEL=urchade/gliner_medium-v2.1
# See .env.example for the full model option list.
_SKIP_HEAVY        = env_bool("SKIP_HEAVY_MODELS")
_GLINER_MODEL_ID   = os.getenv("GLINER_MODEL",     "urchade/gliner_large-v2.1")
_GLINER_THRESHOLD  = env_float("GLINER_THRESHOLD", default=0.40)
_GLINER_ENABLED    = env_bool("GLINER_ENABLED", default=True)

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


def _labels_for(raw: str | None) -> list[str]:
    """The labels of `_LABEL_MAP` whose entity type *raw* names (the value of
    GLINER_ENTITY_TYPES: entity types separated by commas), in `_LABEL_MAP`'s
    order.  None or blank names none.  A name that is not one of the six types
    is left out with a warning."""
    known = {etype.value for etype in _LABEL_MAP.values()}
    wanted = {token.strip().lower().replace("-", "_") for token in (raw or "").split(",")} - {""}
    unknown = sorted(wanted - known)
    if unknown:
        logger.warning(f"GLINER_ENTITY_TYPES: {', '.join(unknown)} not among "
                       f"{', '.join(sorted(known))}; left out")
    return [label for label, etype in _LABEL_MAP.items() if etype.value in wanted]


# ADR-0098 — the labels the model is asked for.  Unset, the stage asks for
# sectors and countries (the maintainer's choice of 2026-11-12); set to an
# empty value, the stage is off and the model is not loaded.
_DEFAULT_ENTITY_TYPES = "identity,location"


def _configured_labels() -> list[str]:
    """The labels GLINER_ENTITY_TYPES names; the default's when it is unset."""
    return _labels_for(os.getenv("GLINER_ENTITY_TYPES", _DEFAULT_ENTITY_TYPES))


_GLINER_LABELS = _configured_labels()

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
_CHUNK_CHARS    = env_int("GLINER_CHUNK_CHARS", default=1600)
_OVERLAP_CHARS  = 200   # proportionally wider to avoid missing cross-boundary spans
_MIN_CHUNK_CHARS = _CHUNK_CHARS // 4

# ── Batched inference ─────────────────────────────────────────────────────────
# N chunks go to the model as one batch, through GLiNER's batch API (see
# _ask_batch): it amortises the Python→model transfer cost and leverages
# ONNX/PyTorch batch efficiency.  predict_entities() is for one string.
# Set GLINER_BATCH_SIZE=1 to disable batching (useful for debugging).
_BATCH_SIZE = env_int("GLINER_BATCH_SIZE", default=4)


def _iter_chunks(text: str) -> Iterator[tuple[str, int]]:
    """Yield (chunk_text, char_offset) pairs with overlap."""
    start = 0
    length = len(text)
    while start < length:
        end = min(start + _CHUNK_CHARS, length)
        # Don't cut in the middle of a word
        if end < length:
            # Walk back to nearest whitespace, but not into the first _MIN_CHUNK_CHARS:
            # sparse whitespace would make the chunks a crawl of a few characters each.
            boundary = end
            while boundary > start and not text[boundary].isspace():
                boundary -= 1
            if boundary - start >= _MIN_CHUNK_CHARS:
                end = boundary
            # else: a mid-token cut at full width
        yield text[start:end], start
        start = max(start + 1, end - _OVERLAP_CHARS) if end < length else length


# ── Lazy-loaded model ─────────────────────────────────────────────────────────

@functools.lru_cache(maxsize=1)
def _load_gliner():
    """
    Load the GLiNER model (cached in memory after first call).
    Returns None if the gliner library is not installed or the model fails to load.
    Not gated on GLINER_ENTITY_TYPES: a run with no type to ask for never gets
    here (gliner_available, run_gliner), and scripts/measure_cold_start.py
    calls this to weigh the model.
    """
    if _SKIP_HEAVY or not _GLINER_ENABLED:
        return None
    try:
        from gliner import GLiNER
        # GLiNER defaults resume_download to False and forwards it to
        # huggingface_hub's snapshot_download, which warns on any value but
        # None ("deprecated and ignored").  None is the hub's own "not passed".
        model = GLiNER.from_pretrained(_GLINER_MODEL_ID, resume_download=None)
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
    """Return True if the gliner library is installed, GLINER_ENABLED=true,
    GLINER_ENTITY_TYPES names a type, and SKIP_HEAVY_MODELS is not set."""
    if _SKIP_HEAVY or not _GLINER_ENABLED or not _GLINER_LABELS:
        return False
    try:
        import gliner  # noqa: F401
        return True
    except ImportError:
        return False


def gliner_unavailable_reason() -> str:
    """What the stage report says when gliner_available() is False.  A stage
    that is on with no entity type to ask for is off by configuration, and
    says so with the word the smoke test accepts ("disabled")."""
    if not _SKIP_HEAVY and _GLINER_ENABLED and not _GLINER_LABELS:
        return "disabled: GLINER_ENTITY_TYPES names no entity type"
    return "model or index unavailable"


@dataclass
class GLiNERRun:
    """What one pass of the stage over a text did, for the stage report: the
    entities, and whether the model was asked and answered (ADR-0098)."""

    entities: list[RawEntity] = field(default_factory=list)
    loaded: bool = False          # there was a model and a label to ask it for
    chunks: int = 0               # non-empty windows of the text
    answered: int = 0             # windows with a well-formed answer from the model
    retried_batches: int = 0      # batch answers refused, asked again chunk by chunk
    error: str = ""               # why nothing was loaded, or the last unanswered chunk's error

    @property
    def unanswered(self) -> int:
        """The windows of the text that the model did not answer: chunks minus answered."""
        return self.chunks - self.answered

    def failure(self) -> str:
        """Why the stage cannot be recorded as run, "" when it can: no model,
        or a model that answered none of the chunks it was given."""
        if not self.loaded:
            return self.error or "the model was not loaded"
        if self.chunks and not self.answered:
            return f"the model answered none of the {self.chunks} chunks: {self.error}"
        return ""

    def note(self) -> str:
        """What a stage that ran still has to say: chunks left unanswered, and
        batches the batch API did not answer."""
        parts = []
        if self.unanswered:
            parts.append(f"{self.unanswered} of {self.chunks} chunks unanswered: {self.error}")
        if self.retried_batches:
            parts.append(f"{self.retried_batches} batch answers refused, asked again chunk by chunk")
        return "; ".join(parts)


def _checked_chunk(raw: Any) -> list[dict]:
    """*raw* if it is the answer for one chunk, a list of prediction dicts;
    else ValueError."""
    if isinstance(raw, list) and all(isinstance(pred, dict) for pred in raw):
        return raw
    raise ValueError(f"expected a list of predictions, got {_shape(raw)}")


def _shape(raw: Any) -> str:
    if not isinstance(raw, list):
        return type(raw).__name__
    kinds = ", ".join(sorted({type(item).__name__ for item in raw}))
    return f"a list of {len(raw)}" + (f" ({kinds})" if kinds else "")


def _ask_batch(model: Any, texts: list[str], labels: list[str], threshold: float) -> list[list[dict]]:
    """One list of predictions per text, from GLiNER's batch API, or ValueError.

    `inference` is that API (gliner 0.2.29); `batch_predict_entities` is its
    older name, deprecated there and the only one before it.  Not
    `predict_entities`: it takes one string, wraps its argument in a list, and
    for a list of texts returns [] without raising — a stage that read that as
    "no entity" recorded `ran` with a model it had never asked (ADR-0098).

    The answer is held to its shape, one list for each text: an empty or flat
    answer is an error here, never "nothing found"."""
    ask = getattr(model, "inference", None)
    if callable(ask):
        raw = ask(texts, labels, flat_ner=True, threshold=threshold, multi_label=False,
                  batch_size=len(texts))
    else:
        raw = model.batch_predict_entities(texts, labels, flat_ner=True, threshold=threshold,
                                           multi_label=False)
    if not isinstance(raw, list) or len(raw) != len(texts):
        raise ValueError(f"expected one list of predictions for each of {len(texts)} chunks, "
                         f"got {_shape(raw)}")
    return [_checked_chunk(preds) for preds in raw]


def extract_gliner_entities(text: str) -> list[RawEntity]:
    """
    Run GLiNER over *text* using the configured entity labels and return
    zero-shot CTI named entities.

    Returns an empty list if GLiNER is not available or no entities are found.
    run_gliner() also says whether the model answered.
    """
    return run_gliner(text).entities


def run_gliner(text: str) -> GLiNERRun:
    """
    Run GLiNER over *text* for the labels of GLINER_ENTITY_TYPES; return the
    entities and what the model was asked (see GLiNERRun).

    The function processes the text in overlapping windows to avoid token-limit
    issues with long CTI reports (PDFs, DOCX).

    Results are deduplicated by (value.lower(), entity_type) keeping the
    highest-confidence occurrence of each span.
    """
    labels = list(_GLINER_LABELS)
    if not labels:
        return GLiNERRun(error="GLINER_ENTITY_TYPES names no entity type")
    model = _load_gliner()
    if model is None:
        return GLiNERRun(error="the model could not be loaded")
    label_map = {label: _LABEL_MAP[label] for label in labels}

    # ADR-0051 — one cutoff per entity type, calibrated from analyst decisions
    # when a `model_thresholds` row exists, else GLINER_THRESHOLD.  GLiNER
    # takes a single threshold for every label, so the model is asked for the
    # lowest of them and each prediction is then held to its own type's cutoff
    # below.
    cutoff = {etype: get_threshold("gliner", etype.value, _GLINER_THRESHOLD) for etype in label_map.values()}
    model_threshold = min(_GLINER_THRESHOLD, *cutoff.values())

    # ── Batched inference ─────────────────────────────────────────────────────
    # Collect non-empty chunks, then ask the model in batches of _BATCH_SIZE.
    # A batch that raises, or whose answer is not one list per chunk, is asked
    # again one chunk at a time.
    # best[key] = (score, context_snippet, span_text)
    best: dict[tuple[str, EntityType], tuple[float, str, str]] = {}

    # Build the flat list of (chunk_text, char_offset) upfront
    all_chunks = [(t, off) for t, off in _iter_chunks(text) if t.strip()]
    run = GLiNERRun(loaded=True, chunks=len(all_chunks))

    for batch_start in range(0, len(all_chunks), _BATCH_SIZE):
        batch      = all_chunks[batch_start : batch_start + _BATCH_SIZE]
        batch_texts = [t for t, _ in batch]

        try:
            batch_preds = _ask_batch(model, batch_texts, labels, model_threshold)
            run.answered += len(batch)
        except Exception as e:
            logger.warning(f"Batch inference error (falling back to single): {e}")
            run.retried_batches += 1
            # Per-chunk fallback
            batch_preds = []
            for chunk_text, char_offset in batch:
                try:
                    batch_preds.append(_checked_chunk(model.predict_entities(
                        chunk_text, labels,
                        threshold=model_threshold,
                        flat_ner=True, multi_label=False,
                    )))
                    run.answered += 1
                except Exception as e2:
                    logger.error(f"Inference error at offset {char_offset}: {e2}")
                    run.error = f"{type(e2).__name__}: {e2}"
                    batch_preds.append([])

        for predictions, (chunk_text, _offset) in zip(batch_preds, batch, strict=True):
            for pred in predictions:
                label = pred.get("label", "")
                score = float(pred.get("score", 0.0))
                value = pred.get("text", "").strip()

                etype = label_map.get(label)
                if etype is None:
                    continue
                if not value or len(value) < 3:
                    continue
                if score < cutoff[etype]:
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
                    best[key] = (score, context, _span_text(chunk_text, pred, value))

    # ── Convert to RawEntity ─────────────────────────────────────────────────
    results: list[RawEntity] = []
    for (value_lower, etype), (score, context, span_text) in best.items():
        # The casing the span has in the text (GLiNER's offsets), else the first
        # whole-word match of the value in the context.
        display_value = span_text or _recover_casing(value_lower, context)
        results.append(RawEntity(
            value=display_value,
            entity_type=etype,
            context=context[:200],
            confidence=round(score, 4),
            source="gliner",
        ))

    results.sort(key=lambda x: x.confidence, reverse=True)
    run.entities = drop_denied(results)
    return run


def _span_text(chunk_text: str, pred: dict, value: str) -> str:
    """
    The text GLiNER's own offsets point at in *chunk_text*, with the casing it
    has there, or "" when the offsets do not select *value* (missing, out of
    range, or pointing at other text).
    """
    start, end = pred.get("start"), pred.get("end")
    if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start < end <= len(chunk_text):
        return ""
    span = chunk_text[start:end].strip()
    return span if span.lower() == value.lower() else ""


def _recover_casing(value_lower: str, context: str) -> str:
    """
    Try to find the original-cased version of *value_lower* in *context*, as a
    whole word: "rat" is not the "rat" inside "crates".  Falls back to the
    lower-cased value if no whole-word match is found.
    """
    # Case-insensitive search in context.  glued_to_a_word, not `\b`: it reads
    # non-ASCII letters as word characters, and a value that starts or ends with
    # a symbol ("C++") has no `\b` around it.
    from pipeline.regex_safety import compile_pattern, glued_to_a_word
    pattern = compile_pattern(re.escape(value_lower), re.IGNORECASE)
    for m in pattern.finditer(context):
        if not glued_to_a_word(context, *m.span()):
            return m.group()
    return value_lower


# ---------------------------------------------------------------------------
# ExtractionStage class wrapper (pipeline.base)
# ---------------------------------------------------------------------------

from pipeline.base import BaseExtractionStage  # noqa: E402


class GLiNERStage(BaseExtractionStage):
    """Stage-2e GLiNER zero-shot NER as an ExtractionStage implementation."""

    name = "gliner"

    def __init__(self, config=None) -> None:
        pass

    def available(self) -> bool:
        """True when the GLiNER model can run."""
        return gliner_available()

    def extract(self, text: str) -> list[RawEntity]:
        """Return the entities that GLiNER finds in the text."""
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
