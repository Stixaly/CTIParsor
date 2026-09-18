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
from pipeline.env_flags import env_bool
from pipeline.thresholds import get_threshold

_SKIP_HEAVY = env_bool("SKIP_HEAVY_MODELS")

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
_CYNER_ENABLED = env_bool("CYNER_ENABLED", default=True)

# Sentinel file written to the project root the first time the model is detected
# as inaccessible (private/removed).  Future subprocess invocations check for this
# file and skip the HuggingFace Hub network request entirely, so the 401 warning
# only ever appears once per server installation (not once per job).
_SENTINEL_PATH = Path(__file__).parent.parent / ".cyner_model_unavailable"

# Confidence thresholds.  _MEDIUM_THRESH is the discard cutoff; a
# `model_thresholds` row calibrated from analyst decisions overrides it per
# entity type (ADR-0051, see pipeline/thresholds.py).
_HIGH_THRESH   = 0.90
_MEDIUM_THRESH = 0.70

# ── Text chunking ─────────────────────────────────────────────────────────────
# Same scheme as stage2e_gliner: ~1 600 chars ≈ 480–560 subword tokens, which is
# the DeBERTa-v3 window.  Overlap catches spans cut at a boundary; the caller
# dedups what the overlap re-reports.  The batch size only bounds how many
# chunks one forward pass holds — memory is per chunk, not per document.
_CHUNK_CHARS   = int(os.getenv("CYNER_CHUNK_CHARS", "1600"))
_OVERLAP_CHARS = 200
_BATCH_SIZE    = int(os.getenv("CYNER_BATCH_SIZE", "4"))


def _iter_chunks(text: str):
    """Yield (chunk_text, char_offset) pairs with overlap, never an empty chunk."""
    start, length = 0, len(text)
    while start < length:
        end = min(start + _CHUNK_CHARS, length)
        if end < length:
            while end > start and not text[end].isspace():
                end -= 1
            if end <= start:                      # one unbroken token: force advance
                end = min(start + _CHUNK_CHARS, length)
        yield text[start:end], start
        start = max(start + 1, end - _OVERLAP_CHARS) if end < length else length

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

# Generic technical/operational vocabulary that describes a CATEGORY of
# malware or threat activity rather than naming one. CyNER's Malware and
# Threat_group labels fire on any span discussing malware or threat-actor
# activity, not only on named entities, so a span built ENTIRELY out of this
# vocabulary carries no identifying content and must be dropped. Enumerated
# from real noise observed in production (a real CTI report processed
# 2026-09-17): out of 212 raw "malware" and 64 raw "threat_actor" CyNER
# predictions, more than half were spans made entirely of these words.
_GENERIC_TOKENS: frozenset[str] = frozenset({
    # malware/tool category nouns
    "malware", "ransomware", "backdoor", "backdoors", "downloader", "downloaders",
    "dropper", "droppers", "rootkit", "rootkits", "webshell", "webshells",
    "wiper", "wipers", "payload", "payloads", "exploit", "exploits", "macro",
    "macros", "framework", "frameworks", "rat", "trojan", "trojans", "trojanized",
    "stealer", "stealers", "infostealer", "shellcode", "launcher", "launchers",
    "variant", "variants", "module", "modules", "tool", "tools", "tooling",
    "tunneler", "tunnelers", "utility", "utilities", "generator", "builder",
    "installer", "installers", "loader", "loaders", "boot", "interpreter",
    "binary", "software", "program", "code", "shell", "http", "apt",
    # actor/operation category nouns
    "actor", "actors", "operator", "operators", "operation", "operations",
    "campaign", "campaigns", "cluster", "clusters", "espionage", "group",
    "groups", "hacker", "hackers", "hack", "sponsor", "attacker", "attackers",
    "unit", "units", "attack", "attacks", "cyber", "state", "government",
    "agency", "army", "team", "teams", "threat", "threats", "cikr",
    # adjectives / modifiers that never carry a name by themselves
    "commodity", "custom", "destructive", "disruptive", "disruption",
    "malicious", "modular", "lightweight", "embedded", "based", "stage",
    "stager", "post", "exploitation", "only", "new", "serious", "primary",
    "information", "wartime", "military", "linked", "backed", "sponsored",
    "russian", "c++", "php", "python", "dll", "file", "family", "class",
    "delivery",
    # articles / pronoun fragments
    "the", "a", "an", "this", "that", "we", "they", "he", "she", "it", "our",
    "their", "us", "you", "all", "some", "s",
})

# Specific terms CyNER mislabels as MALWARE that are legitimate software
# products, not generic language (so _GENERIC_TOKENS does not catch them) —
# observed on a real report. Exact lowercase match against the whole fragment.
_KNOWN_NON_MALWARE: frozenset[str] = frozenset({
    "winrar", "microscada",
})

# Specific terms CyNER mislabels as THREAT_ACTOR that are countries/cities,
# not actors — observed on a real report. Exact lowercase match against the
# whole fragment.
_KNOWN_NON_ACTORS: frozenset[str] = frozenset({
    "russia", "moscow",
})

# A single leading article, stripped before further checks (CyNER sometimes
# includes it in the span).
_LEADING_ARTICLE_RE = re.compile(r"^(the|a|an)\s+", re.IGNORECASE)

# A single trailing period, stripped before further checks.
_TRAILING_PERIOD_RE = re.compile(r"\.$")

# A single lowercase letter followed by a space at the very start of the
# string: the leftover of a possessive ("APT44's Operations" truncated to
# "s Operations" when the span starts mid-token).
_FRAGMENT_RE = re.compile(r"^[a-z]\s")

# Regex: bare version numbers ("1.2.3") — spaCy and some NER models label these
_VERSION_RE = re.compile(r"^\d[\d.\-]*\d$")


def _normalize_candidate(value: str) -> str:
    """Strip one leading article and one trailing period. Never touches
    interior text."""
    value = _LEADING_ARTICLE_RE.sub("", value).strip()
    value = _TRAILING_PERIOD_RE.sub("", value).strip()
    return value


def _has_boundary_artifact(value: str) -> bool:
    """True if the span crossed a sentence boundary (a period followed by
    whitespace -- a bare interior period, as in "BLACKENERGY.V2" or
    "Guccifer 2.0", is a real name and must not be rejected), contains a
    non-ASCII character (OCR or script-mixing garbage), or starts with a
    truncated possessive fragment."""
    if re.search(r"\.\s", value):
        return True
    if any(ord(ch) > 127 for ch in value):
        return True
    if _FRAGMENT_RE.match(value):
        return True
    return False


def _is_generic_fragment(fragment: str, extra_denylist: frozenset[str] = frozenset()) -> bool:
    """True if every token of length >= 3 (splitting on whitespace and
    hyphens) is in _GENERIC_TOKENS or extra_denylist — i.e. the fragment
    carries no name-like content at all. A fragment with at least one token
    outside both sets is NOT generic, even if it also contains generic or
    denylisted words: "XAKNET Cyber Army of Russia Reborn" survives despite
    "Russia" being denylisted on its own, because "XAKNET" and "Reborn" are
    not — one denylisted word must not veto an otherwise distinct name."""
    tokens = re.split(r"[\s\-]+", fragment.lower())
    named_tokens = [
        t for t in tokens
        if len(t) >= 3 and t not in _GENERIC_TOKENS and t not in extra_denylist
    ]
    return not named_tokens


def _split_fragments(value: str) -> list[str]:
    """Split a comma- or slash-separated list span into its parts (CyNER
    sometimes merges several distinct malware names named in a list into one
    span). A value with no such separator is returned unchanged as a
    single-item list."""
    parts = [p.strip() for p in re.split(r"[,/]", value)]
    parts = [p for p in parts if p]
    return parts if len(parts) > 1 else [value]


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
        from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline
        from transformers import logging as hf_logging
        hf_logging.set_verbosity_error()  # suppress download-progress noise
    except ImportError:
        return None

    # ── Step 1: try local HuggingFace cache (zero network I/O) ──────────────
    try:
        # The model and tokenizer are built here, rather than letting pipeline()
        # fetch them from `_MODEL_ID`, because there is no working way to ask
        # pipeline() for an offline load on transformers 5:
        #   local_files_only=True      -> forwarded to the pipeline class, which
        #                                 rejects it with a TypeError
        #   model_kwargs={"local_...": True}
        #                              -> collides with the value pipeline()
        #                                 already passes to AutoConfig
        # from_pretrained takes it directly, and passing objects to pipeline()
        # does not depend on how it routes keywords internally.
        _model = AutoModelForTokenClassification.from_pretrained(_MODEL_ID, local_files_only=True)
        _tokenizer = AutoTokenizer.from_pretrained(_MODEL_ID, local_files_only=True)
        ner = pipeline(
            "ner",
            model=_model,
            tokenizer=_tokenizer,
            aggregation_strategy="simple",  # merges B-/I- tokens → full entity spans
            device=-1,                      # CPU; set device=0 to use GPU
        )
        logger.info(f"CyNER model loaded from local cache: {_MODEL_ID}")
        return ner
    except Exception as exc:
        # Any failure here just means "not usable from cache" — fall through to
        # the download below. Narrowing this tuple is what let a TypeError from
        # an API change escape and abort every job that reached Stage 2d.
        logger.debug(f"CyNER not loadable from local cache ({type(exc).__name__}: {exc})")

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

    # Never hand the whole document to the model in one call.  DeBERTa-v3 uses
    # relative positions, so a 50 000-character input does not raise — it runs,
    # and its attention memory grows with the SQUARE of the token count.
    # Measured 2026-09-02/03: a 27 KB report reached 10.3 GB RSS and a 77 KB
    # report (capped to 50 K chars) reached 15.5 GB before the OOM killer took
    # the worker, both a few seconds after "CyNER model loaded".  Chunks of
    # ~1 600 characters (≈ 500 tokens, the model's window) with an overlap keep
    # each forward pass bounded; the pipeline accepts a list and batches it.
    chunks = [c for c, _ in _iter_chunks(text) if c.strip()]
    if not chunks:
        return []
    try:
        per_chunk = ner_pipeline(chunks, batch_size=_BATCH_SIZE)
    except Exception as e:
        logger.error(f"CyNER inference error: {e}")
        return []
    # A single-chunk call returns a flat list rather than a list of lists.
    if per_chunk and isinstance(per_chunk[0], dict):
        per_chunk = [per_chunk]
    predictions: list[dict] = [p for preds in per_chunk for p in (preds or [])]

    cutoff = {etype: get_threshold("cyner", etype.value, _MEDIUM_THRESH) for etype in _LABEL_MAP.values()}

    results: list[RawEntity] = []
    seen: set[tuple[str, EntityType]] = set()

    for pred in predictions:
        label     = pred.get("entity_group", "")
        score     = float(pred.get("score", 0.0))
        raw_value = pred.get("word", "").strip()

        etype = _LABEL_MAP.get(label)
        if etype is None:
            continue                        # skip Indicator, System, Vulnerability
        if score < cutoff[etype]:
            continue
        if not raw_value or len(raw_value) < 3:
            continue
        if _VERSION_RE.match(raw_value):
            continue
        if raw_value.startswith("@"):        # npm scoped package scope-names
            continue

        # CyNER occasionally merges a comma-separated list of names into one
        # span ("AZORULT, FORMBOOK, TRICKBOT") — split before filtering so
        # each real name is evaluated (and can survive) on its own.
        for fragment in _split_fragments(raw_value):
            value = _normalize_candidate(fragment)
            if not value or len(value) < 3:
                continue
            if _has_boundary_artifact(value):
                continue

            if etype == EntityType.THREAT_ACTOR:
                if value.lower() in _ORG_BLOCKLIST:
                    continue
                if _is_generic_fragment(value, _KNOWN_NON_ACTORS):
                    continue
            if etype == EntityType.MALWARE:
                if _is_generic_fragment(value, _KNOWN_NON_MALWARE):
                    continue

            # The overlap between chunks re-reports spans on the boundary;
            # keep the first (highest-scoring predictions are not ordered,
            # so this is a dedup by identity, not a ranking).
            key = (value.lower(), etype)
            if key in seen:
                continue
            seen.add(key)

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
