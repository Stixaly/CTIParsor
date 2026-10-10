import json
import os
import re
import time
from datetime import datetime
from typing import cast

import anthropic
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError
from tenacity import RetryError, retry, retry_if_exception_type, stop_after_attempt, wait_exponential

# Initialize logging
from api.logging_config import get_logger
from models.schemas import EntityType, EvidenceLabel, RawEntity
from pipeline.env_flags import env_int
from pipeline.llm_parse import SPOTLIGHT_RULE, fit_report
from pipeline.stage3f_ttp_select import TtpReview
from pipeline.temporal import (
    ROLES as _TIME_ROLES,
)
from pipeline.temporal import (
    Anchor,
    DocumentTime,
    TemporalAssertion,
    check_assertions,
    merge_times,
    status_counts,
)
from pipeline.vllm_options import vllm_extra_body

logger = get_logger(__name__)

# Stage 3b and 3c are imported lazily inside functions to avoid circular imports

load_dotenv()

# ---------------------------------------------------------------------------
# Retry configuration for LLM calls
# ---------------------------------------------------------------------------
_MAX_RETRIES = 3
_RETRY_WAIT = wait_exponential(multiplier=1, min=2, max=10)
_RETRY_STOP = stop_after_attempt(_MAX_RETRIES)

# Exception types that should trigger a retry
_RETRY_EXCEPTIONS = (
    anthropic.APITimeoutError,
    anthropic.APIConnectionError,
    ConnectionError,
    TimeoutError,
)

# ---------------------------------------------------------------------------
# Input/Output length limits for LLM calls
# ---------------------------------------------------------------------------
# Maximum prompt length (characters) to prevent overly large requests
_MAX_PROMPT_LENGTH = env_int("LLM_MAX_PROMPT_LENGTH", default=32000)
# Separate, much larger ceiling for the document-level relation pass (ADR-0057)
# — that call reads the WHOLE report, not a ~3000-char chunk, and 32000 chars
# would truncate away most of a typical report before the model even sees the
# entity list at the end of the prompt. 300000 chars (~75-100k tokens with
# headroom for the system prompt, entity list and output) comfortably covers
# every report seen in this corpus (largest so far: ~110k chars) while staying
# well inside Claude's context window. A provider with a much smaller context
# (a local Ollama model, say) should lower this via LLM_DOC_MAX_PROMPT_LENGTH
# rather than rely on the default — this feature was validated against
# Anthropic only.
_DOC_MAX_PROMPT_LENGTH = env_int("LLM_DOC_MAX_PROMPT_LENGTH", default=300000)
# Maximum response length (characters) to prevent overly large responses.
#
# This cap TRUNCATES the string, so a value below what the token ceiling allows
# turns a complete, valid reply into invalid JSON and loses the whole chunk.
# Measured on GREYVIBE under the ADR-0028 contract: the model returned 23,324
# valid characters and this guard cut them to 16,000.  It must therefore stay
# above `_MAX_OUTPUT_TOKENS` x ~4 characters per token; the two are raised
# together or not at all.
_MAX_RESPONSE_LENGTH = env_int("LLM_MAX_RESPONSE_LENGTH", default=48000)
# Output token ceiling.  ADR-0028 gave every TTP a verbatim `evidence_text`
# sentence, which roughly doubles the size of a TTP-heavy response: measured on
# GREYVIBE, the reply hit the previous 4096 ceiling at 14,812 characters and was
# cut off mid-object, losing the WHOLE chunk — TTPs, relationships and malware
# families alike, because a truncated JSON body salvages poorly.  Raised in
# proportion to the payload the new contract adds.
_MAX_OUTPUT_TOKENS = env_int("LLM_MAX_OUTPUT_TOKENS", default=8192)

# Minimum prompt length to ensure meaningful input
_MIN_PROMPT_LENGTH = 100


_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]')
# Zero-width characters, direction marks, bidi embeddings/overrides/isolates and
# the BOM: invisible to the analyst, able to hide or reorder what the model reads.
_INVISIBLE_CHARS = re.compile('[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]')
# Strings a chat template turns into control tokens.  vLLM renders the template
# to text and tokenizes it whole, so `<|im_end|>` written in a report becomes the
# real end-of-turn token and `<|im_start|>system` opens a system turn (checked
# on the Qwen3.8 server, 2026-10-03; `<think>` and `<tool_call>` are single
# tokens too).  Ollama and LM Studio template the same way.
_CHAT_MARKUP = re.compile(
    r'<\|[^<>|\s]{1,64}\|>'
    r'|</?(?:think|tool_call|tool_response|start_of_turn|end_of_turn|s)>'
    r'|\[/?INST\]|<</?SYS>>',
    re.IGNORECASE,
)


def _defuse(match: re.Match) -> str:
    """`<|im_start|>` -> `< |im_start|>`: still readable, no longer the token."""
    s = match.group(0)
    return s[0] + " " + s[1:]


def _sanitize_text_for_prompt(text: str, max_length: int = 10000) -> str:
    """
    Prepare the user message for the model without deleting intelligence.

    Removes control and invisible characters and defuses chat-template markup;
    the report itself reaches the model between spotlighting markers
    (`llm_parse.fit_report`), which is the defence against instructions in it.
    Counts what it changed in llm_stats.

    Args:
        text: The raw text to sanitize
        max_length: Maximum length of the sanitized text

    Returns:
        The text as the model should see it
    """
    if not text:
        return ""

    # Truncate to max length first
    text = text[:max_length]

    text = _CONTROL_CHARS.sub('', text)
    text, n = _INVISIBLE_CHARS.subn('', text)
    if n:
        llm_stats.bump("prompt_invisible_chars_removed", n)
    text, n = _CHAT_MARKUP.subn(_defuse, text)
    if n:
        llm_stats.bump("prompt_chat_markup_defused", n)

    # NOTE: backslashes are intentionally NOT escaped.  The previous
    # `text.replace('\\', '\\\\')` corrupted every Windows path in the report
    # (C:\Windows → C:\\Windows) as seen by the model, which also broke Stage 3b's
    # "does this name appear in the source text" check.  The text is placed into a
    # plain message body, not into JSON or a code context, so escaping has no
    # security value here — only corruption.

    # Nothing else is removed (ADR-0074).  HTML tags used to be stripped and
    # four "injection" phrasings replaced by [REDACTED]: that deleted
    # `<iframe src=…>` (an IoC), redacted from "ignore" to "prior" in a line
    # describing execution guardrails (T1480), and let a synonym, another
    # language or an invisible character through.

    # Normalize whitespace while PRESERVING line structure.  The system prompt
    # instructs the model to use Markdown layout (headers, tables, bullet lists)
    # to locate IoC sections, attribution tables, and TTP lists — so newlines
    # must survive.  Collapsing everything to single spaces (the previous
    # behaviour) flattened the document and stripped that structure.
    text = re.sub(r'[^\S\n]+', ' ', text)    # collapse runs of spaces/tabs, keep \n
    text = re.sub(r' *\n *', '\n', text)     # trim spaces hugging line breaks
    text = re.sub(r'\n{3,}', '\n\n', text)   # cap blank-line runs at one
    text = text.strip()

    return text

# ---------------------------------------------------------------------------
# Provider selection — set LLM_PROVIDER in .env
#
#   anthropic  (default) — Claude via Anthropic API
#   gemini               — Google Gemini via OpenAI compatible API
#   mistral              — Mistral AI API  (OpenAI-compatible endpoint)
#   ollama               — Self-hosted or remote Ollama (OpenAI-compatible)
#   lmstudio             — Self-hosted LM Studio (OpenAI-compatible)
#   vllm                 — Self-hosted vLLM (OpenAI-compatible)
#
# Each provider is independently configurable via env vars (see .env.example).
# ---------------------------------------------------------------------------

_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic").lower()

#: One place for the Anthropic default, because it was three and they disagreed:
#: the call site said `claude-3-5-sonnet-latest` while the log label and
#: .env.example both said `claude-sonnet-4-6`, so the model actually used was not
#: the one the logs reported. 3-5-sonnet is also several generations behind.
_DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"

# --- Lazy client initialization ---
_anthropic_client = None
_mistral_client = None
_ollama_client = None
_gemini_client = None
_lmstudio_client = None
_vllm_client = None
_OPENAI_SDK_AVAILABLE = False

try:
    from openai import OpenAI as _OpenAIClient
    _OPENAI_SDK_AVAILABLE = True
except ImportError:
    _OpenAIClient = None          # type: ignore[assignment,misc]


def _get_anthropic_client():
    """Lazily initialize and return Anthropic client."""
    global _anthropic_client
    if _anthropic_client is None:
        _anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        _ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", _DEFAULT_ANTHROPIC_MODEL)
        if _anthropic_key:
            _anthropic_client = anthropic.Anthropic(api_key=_anthropic_key)
            return _anthropic_client
        return None
    return _anthropic_client


def _get_mistral_client():
    """Lazily initialize and return Mistral client."""
    global _mistral_client
    if _mistral_client is None:
        _mistral_key = os.environ.get("MISTRAL_API_KEY", "").strip()
        _MISTRAL_MODEL = os.environ.get("MISTRAL_MODEL", "mistral-small-latest")
        if _OPENAI_SDK_AVAILABLE and _mistral_key and _OpenAIClient is not None:
            _mistral_client = _OpenAIClient(api_key=_mistral_key, base_url="https://api.mistral.ai/v1")
            return _mistral_client
        return None
    return _mistral_client


def _get_ollama_client():
    """Lazily initialize and return Ollama client."""
    global _ollama_client
    if _ollama_client is None:
        _ollama_base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        _OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
        if _OPENAI_SDK_AVAILABLE and _OpenAIClient is not None:
            _ollama_client = _OpenAIClient(api_key="ollama", base_url=f"{_ollama_base}/v1")
            return _ollama_client
        return None
    return _ollama_client


def _get_gemini_client():
    """Lazily initialize and return Gemini client via OpenAI compat layer."""
    global _gemini_client
    if _gemini_client is None:
        _gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
        if _OPENAI_SDK_AVAILABLE and _gemini_key and _OpenAIClient is not None:
            _gemini_client = _OpenAIClient(api_key=_gemini_key, base_url="https://generativelanguage.googleapis.com/v1beta/openai/")
            return _gemini_client
        return None
    return _gemini_client


def _get_lmstudio_client():
    """Lazily initialize and return LM Studio client."""
    global _lmstudio_client
    if _lmstudio_client is None:
        _lmstudio_base = os.environ.get("LMSTUDIO_BASE_URL", "http://localhost:1234").rstrip("/")
        if _OPENAI_SDK_AVAILABLE and _OpenAIClient is not None:
            _lmstudio_client = _OpenAIClient(api_key="lmstudio", base_url=f"{_lmstudio_base}/v1")
            return _lmstudio_client
        return None
    return _lmstudio_client


def _get_vllm_client():
    """Lazily initialize and return vLLM client."""
    global _vllm_client
    if _vllm_client is None:
        _vllm_base = os.environ.get("VLLM_BASE_URL", "http://localhost:8000").rstrip("/")
        if _OPENAI_SDK_AVAILABLE and _OpenAIClient is not None:
            _vllm_client = _OpenAIClient(api_key="vllm", base_url=f"{_vllm_base}/v1")
            return _vllm_client
        return None
    return _vllm_client


def _get_provider_diagnostics():
    """Run startup diagnostics for provider configuration."""
    if _PROVIDER == "anthropic":
        _anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not _anthropic_key:
            logger.warning("LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY not set — stage 3 will be skipped.")
    elif _PROVIDER == "gemini":
        _gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
        if not _OPENAI_SDK_AVAILABLE:
            logger.warning("LLM_PROVIDER=gemini requires the 'openai' package: pip install openai")
        elif not _gemini_key:
            logger.warning("LLM_PROVIDER=gemini but GEMINI_API_KEY not set — stage 3 will be skipped.")
        else:
            _GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-pro")
            logger.info(f"LLM_PROVIDER=gemini — model: {_GEMINI_MODEL}")
    elif _PROVIDER == "mistral":
        _mistral_key = os.environ.get("MISTRAL_API_KEY", "").strip()
        if not _OPENAI_SDK_AVAILABLE:
            logger.warning("LLM_PROVIDER=mistral requires the 'openai' package: pip install openai")
        elif not _mistral_key:
            logger.warning("LLM_PROVIDER=mistral but MISTRAL_API_KEY not set — stage 3 will be skipped.")
        else:
            _MISTRAL_MODEL = os.environ.get("MISTRAL_MODEL", "mistral-small-latest")
            logger.info(f"LLM_PROVIDER=mistral — model: {_MISTRAL_MODEL}")
    elif _PROVIDER == "ollama":
        if not _OPENAI_SDK_AVAILABLE:
            logger.warning("LLM_PROVIDER=ollama requires the 'openai' package: pip install openai")
        else:
            _ollama_base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
            _OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
            logger.info(f"LLM_PROVIDER=ollama — endpoint: {_ollama_base} — model: {_OLLAMA_MODEL}")
    elif _PROVIDER == "lmstudio":
        if not _OPENAI_SDK_AVAILABLE:
            logger.warning("LLM_PROVIDER=lmstudio requires the 'openai' package: pip install openai")
        else:
            _lmstudio_base = os.environ.get("LMSTUDIO_BASE_URL", "http://localhost:1234").rstrip("/")
            _LMSTUDIO_MODEL = os.environ.get("LMSTUDIO_MODEL", "lmstudio-model")
            logger.info(f"LLM_PROVIDER=lmstudio — endpoint: {_lmstudio_base} — model: {_LMSTUDIO_MODEL}")
    elif _PROVIDER == "vllm":
        if not _OPENAI_SDK_AVAILABLE:
            logger.warning("LLM_PROVIDER=vllm requires the 'openai' package: pip install openai")
        else:
            _vllm_base = os.environ.get("VLLM_BASE_URL", "http://localhost:8000").rstrip("/")
            _VLLM_MODEL = os.environ.get("VLLM_MODEL", "vllm-model")
            _thinking = vllm_extra_body()["chat_template_kwargs"]["enable_thinking"]
            logger.info(f"LLM_PROVIDER=vllm — endpoint: {_vllm_base} — model: {_VLLM_MODEL} "
                        f"— thinking: {'on' if _thinking else 'off'}")
    else:
        logger.warning(
            f"Unknown LLM_PROVIDER='{_PROVIDER}'. Valid values: "
            "anthropic | gemini | mistral | ollama | lmstudio | vllm"
        )


# Run diagnostics at module load time (keeps existing behavior)
# Only run if not in production mode (to avoid log pollution)
if os.environ.get("ENV", "development") == "development":
    _get_provider_diagnostics()


# Terms too generic to be a malware family name — the LLM often returns these
_GENERIC_MALWARE_TERMS = {
    "infostealer", "malware", "payload", "backdoor", "trojan", "ransomware",
    "spyware", "adware", "worm", "virus", "rat", "dropper", "loader", "stager",
    "implant", "stealer", "keylogger", "rootkit", "bootkit", "exploit",
    "shellcode", "script", "binary", "executable",
}

# Terms that are NOT threat actors — the LLM sometimes returns victim companies,
# package registries, tech platforms, or generic nouns when processing supply-chain
# reports.  Names in this set are silently dropped from the threat_actors list.
_GENERIC_ACTOR_TERMS = frozenset({
    # Package registries & package managers
    "npm", "pypi", "pip", "crates.io", "nuget", "maven", "rubygems", "packagist",
    # Development platforms
    "github", "gitlab", "bitbucket", "sourceforge", "codeberg",
    # Cloud & CDN providers
    "aws", "azure", "gcp", "cloudflare", "fastly", "akamai",
    "amazon", "microsoft", "google", "google cloud", "oracle",
    # Generic technology abbreviations
    "api", "sdk", "ide", "cli", "rest", "rpc", "grpc", "graphql",
    "oauth", "jwt", "ldap", "saml", "sso", "mfa", "2fa",
    "ioc", "ttp", "cve", "cpe", "stix", "taxii", "c2",
    # Programming languages & runtimes
    "python", "javascript", "typescript", "java", "golang", "go", "rust",
    "node", "nodejs", "node.js", "deno", "bun", "php",
    # Frameworks & common libraries
    "react", "vue", "angular", "svelte", "django", "flask", "fastapi",
    "spring", "express", "rails",
    # Infrastructure
    "docker", "kubernetes", "k8s", "terraform", "ansible",
    "linux", "windows", "macos", "ubuntu", "debian",
    # Generic noun-phrases that slip through
    "package", "library", "framework", "module", "plugin", "extension",
    "repository", "registry", "open source", "open-source",
    "victim", "target", "organization", "company", "vendor",
    "researcher", "analyst", "developer", "maintainer", "contributor",
    "security", "threat", "attack", "campaign", "supply chain",
    "user", "team", "group", "community",
})


# --- Output schemas ---

class TTPExtracted(BaseModel):
    technique_name: str
    mitre_id: str | None = None
    # A summary the model writes.  Useful, but NOT evidence — measured over 280
    # stored TTPs, only 36.8% of these can be found in the report, while 79.4%
    # of the verbatim quotes asked for below can.  The two fields do two jobs;
    # reading `description` as evidence was the ADR-0028 defect.
    description: str = ""
    evidence_text: str | None = None   # verbatim quote from source text
    # How well the source supports this technique.  Defaults to "reported" so
    # older data / models that omit the field validate without error.
    evidence_label: EvidenceLabel = EvidenceLabel.REPORTED


class RelationshipExtracted(BaseModel):
    source_value: str
    relationship_type: str
    target_value: str
    confidence: float = 0.8
    evidence_text: str | None = None   # verbatim quote from source text
    # How well the source supports this claim.  Defaults to "reported" so older
    # data / models that omit the field validate without error.
    evidence_label: EvidenceLabel = EvidenceLabel.REPORTED
    # Every date the source attaches to this relationship, as the source states
    # it (ADR-0063): the quote, the role, the unpadded value, the status the
    # pipeline computed.  Stage 4 decides which of them may fill the SRO's
    # start_time / stop_time (`pipeline.temporal.export_plan`).
    times: list[TemporalAssertion] = Field(default_factory=list)


class RelationshipReview(RelationshipExtracted):
    """A claim Stage 3d could not decide (ADR-0082): its call failed, its answer
    was unreadable or silent on it, or the quote it gave is not in the text.
    Kept out of the bundle, stored pending with `reason`; ships if an analyst
    accepts it."""
    reason: str


class IoCAssociation(BaseModel):
    """Links a specific IoC value (hash, domain, IP, URL) to a named malware family."""
    ioc_value: str
    malware_name: str | None = None
    relationship_type: str = "indicates"


class LLMEnrichmentResult(BaseModel):
    threat_actors: list[str] = []
    malware_families: list[str] = []
    tools: list[str] = []
    ttps: list[TTPExtracted] = []
    relationships: list[RelationshipExtracted] = []
    ioc_associations: list[IoCAssociation] = []
    targeted_sectors: list[str] = []
    targeted_countries: list[str] = []
    campaign_name: str | None = None
    course_of_action: list[str] = []   # recommended mitigations / remediation steps
    # ADR-0072 select mode: candidates Stage 3f could not decide (its call
    # failed, or the quote did not validate).  Kept out of the bundle, stored
    # pending for an analyst (ADR-0082).
    ttp_review: list[TtpReview] = []
    # ADR-0082: relationships Stage 3d could not decide.  Same treatment.
    rel_review: list[RelationshipReview] = []


# --- Prompts ---

# ADR-0063 — the model NAMES and PLACES a date; the code reads, resolves and
# judges it (pipeline/temporal.py).  Shared by the chunk and the document-level
# prompts so the two passes return the same shape.
_TIMES_RULE = """- Dates of a relationship go in its "times" list, one item per date the
  text attaches to THAT relationship:
    role      = "start"      it began then ("since March 2023", "began in 2021")
                "end"        it ended then ("until June 2023", "stopped in 2024")
                "within"     it happened at some point in that period, bounds
                             unstated ("used in 2021", "active in 2021",
                             "in mid-2025")
                "throughout" it held over the whole period ("active throughout 2022")
                "observed"   the source observed or detected it then ("observed in
                             March 2023"); add "first": true for "first seen/observed"
    time_text = the date expression COPIED CHARACTER FOR CHARACTER from the
                text, with its preposition ("since March 2023", "between January
                and April 2026", "last month"). Never reformat it, never compute it.
    value     = optional — your reading as YYYY, YYYY-MM or YYYY-MM-DD. Omit it
                for a relative expression ("last month", "three weeks ago"): do
                not calculate dates, the pipeline does.
  "active in 2021" is "within", not a start and an end. "no activity observed
  since March" is NOT a start. A date that belongs to something else in the
  sentence (the publication, a CVE number, another relationship) is not this
  relationship's. Omit "times" when the text gives no date for the
  relationship — never invent one because a relationship exists.
"""

_SYSTEM_PROMPT = """You are a Cyber Threat Intelligence (CTI) expert.
You analyze security report excerpts and extract structured threat intelligence.
The input text may be Markdown-formatted (headers, tables, bullet lists) —
use that structure to identify IoC sections, attribution tables, and TTP lists.

IMPORTANT — automatic passes have already run before you:
  1. Regular expressions extracted IoCs (IPs, hashes, domains, CVEs, URLs).
  2. A list of MITRE ATT&CK names was matched against the text for malware
     families, tools and threat groups.
  3. A named-entity model proposed malware family and threat-actor names.
  4. A sentence-embedding model proposed ATT&CK techniques whose descriptions
     resemble passages of the text.
  What they found is listed in the prompt as "Already detected entities/TTPs".

Your job is therefore focused on what deterministic models cannot do:
  1. Discover RELATIONSHIPS between the already-detected entities.
  2. Find NOVEL entities NOT in the gazetteer (new/unnamed malware, zero-day APT groups).
  3. Identify MITRE ATT&CK TTPs NOT already found by semantic matching — focus on
     TTPs that require contextual understanding (multi-sentence reasoning, implicit
     references, novel phrasing not covered by embedding similarity).
  4. Extract campaign-level intelligence: name, targeted sectors/countries, remediation.
  5. Link IoCs to specific malware families (ioc_associations).

Rules:
- Never invent a value. If unsure, omit it.
- Do NOT invent URLs, dates, IDs, or hostnames. If a value is not in the text, omit it.
- For every relationship, attach an evidence_label describing how well the source
  text supports it (do NOT upgrade the label — when support is weak, use a weaker one):
    observed = directly shown in telemetry/sample/log/screenshot/source artifact
    reported = the source states it (assertion-level)
    assessed = the source's analytical judgment
    inferred = your conclusion combining multiple facts across sentences
    gap      = you believe it is implied but cannot find explicit support in the text
- When you cannot find explicit support for a relationship, still emit it with
  evidence_label "gap" and evidence_text "" — never fabricate a supporting quote.
  A missing answer expressed as "gap" is correct and useful; a fabricated answer is a failure.
""" + _TIMES_RULE + """- EVERY TTP carries the SAME two fields, under the SAME rules:
    description   = your summary, in your own words. Keep writing it.
    evidence_text = a sentence COPIED CHARACTER FOR CHARACTER from the text
                    above. Not a paraphrase, not a merge of two sentences, not
                    a tidied version. Copy and paste one sentence.
                    If no single sentence supports the technique, set it to ""
                    and set evidence_label to "gap".
    evidence_label = the same five-grade scale, chosen the same way, never upgraded.
  A TTP whose evidence_text cannot be found in the text is treated as unsupported,
  so rewriting the sentence costs the technique its grade. Copying costs nothing.
- MITRE ATT&CK IDs follow the format T1234 or T1234.001.
- Valid STIX 2.1 relationship types (use ONLY these):
  uses, attributed-to, targets, indicates, mitigates, remediates,
  delivers, drops, downloads, exploits, originates-from, compromises,
  communicates-with, beacons-to, exfiltrates-to, controls, has, hosts,
  owns, authored-by, impersonates, based-on, consists-of, analysis-of,
  static-analysis-of, dynamic-analysis-of, characterizes, investigates,
  located-at, resolves-to, belongs-to, variant-of,
  duplicate-of, derived-from, related-to.
- Return ONLY valid JSON, no surrounding text.
- DO NOT re-list entities already present in "Already detected entities" in the
  threat_actors, malware_families, or tools fields — only add genuinely new ones.
- Use the EXACT name as it appears in the text for novel entities.
- Do NOT use generic terms like "infostealer", "malware", "payload", "stealer"
  as malware names — only specific named families (e.g. LummaC2, RedLine).
- In ioc_associations, only reference IoC values from the "Already detected" list.

CRITICAL — Threat actor definition:
  A threat actor is ONLY a malicious individual or group PERFORMING the attack
  (e.g. APT29, Lazarus Group, FIN7, UNC2452, a named hacker alias).
  DO NOT include victim organisations, package registries, cloud providers,
  programming languages, frameworks, or generic technology terms.
  If you cannot identify a clearly named attacker, return an empty list."""

_USER_PROMPT_TEMPLATE = """CTI report excerpt:

---
{text}
---

Document-level context (key entities from the FULL report — use this to correctly
link IoCs in indicator/appendix sections to the malware or actor they belong to):
{doc_context}

Already detected entities (IoCs — from regex):
{detected_ioc_entities}

Already detected named entities (from MITRE gazetteer — DO NOT re-extract these):
{detected_gazetteer_entities}

Already detected TTPs (from semantic matching — DO NOT re-extract these as TTPs):
{detected_semantic_ttps}

Extract the following as strict JSON.
For threat_actors / malware_families / tools: ONLY include entities NOT already
listed in the gazetteer section above.
For ttps: ONLY include techniques NOT already listed in the semantic TTPs section above.
{{
  "threat_actors": ["novel APT groups or attackers NOT already in the gazetteer list above"],
  "malware_families": ["novel named malware families NOT already in the gazetteer list above"],
  "tools": ["offensive tools NOT already in the gazetteer list above"],
  "ttps": [
    {{
      "technique_name": "MITRE technique name",
      "mitre_id": "T1234.001 or null",
      "description": "brief description of how this technique was used",
      "evidence_text": "VERBATIM sentence copied from the text (empty string if none)",
      "evidence_label": "observed|reported|assessed|inferred|gap"
    }}
  ],
  "relationships": [
    {{
      "source_value": "exact source entity name (from any detected list)",
      "relationship_type": "uses|attributed-to|targets|delivers|drops|exploits|communicates-with|
beacons-to|exfiltrates-to|compromises|hosts|owns|indicates|mitigates|
remediates|originates-from|authored-by|impersonates|variant-of|
related-to|...",
      "target_value": "exact target entity name (from any detected list)",
      "confidence": 0.0-1.0,
      "evidence_text": "verbatim sentence from the text supporting this relationship",
      "evidence_label": "observed|reported|assessed|inferred|gap",
      "times": [
        {{"role": "start|end|within|throughout|observed",
          "time_text": "the date expression copied verbatim from the text",
          "value": "YYYY, YYYY-MM or YYYY-MM-DD — optional, omit for relative expressions"}}
      ]
    }}
  ],
  "ioc_associations": [
    {{
      "ioc_value": "exact IoC value from the IoC detected list above",
      "malware_name": "specific named malware family this IoC belongs to",
      "relationship_type": "indicates or delivers"
    }}
  ],
  "targeted_sectors": ["targeted sectors (e.g. financial, government, healthcare)"],
  "targeted_countries": ["targeted countries (e.g. Ukraine, United States)"],
  "campaign_name": "campaign name or null",
  "course_of_action": ["concrete remediation step 1", "concrete remediation step 2"]
}}"""


# --- Document-level relation extraction (ADR-0057) ------------------------
#
# enrich_chunk() above is precise but structurally blind to a relationship
# whose two facts are stated far apart in the document: a chunk call only
# ever sees ~3000 characters, so "malware X is a variant of malware Y" in
# paragraph 2 and "Y is attributed to actor Z" in paragraph 40 can never be
# connected by any single chunk call, no matter how good the model is.
# Measured on this project's own corpus (2026-09-20): a single full-document
# LLM read found roughly 3x the relationships the chunked pipeline did on the
# same reports, and completion (ADR-0013/0055's long_distance engine) already
# recovers much of that gap cheaply for reports that already have SOME base
# relationships — but does nothing for a report Stage 3 extracted zero
# relationships from in the first place, since it only bridges existing
# components.
#
# This prompt deliberately asks for RELATIONSHIPS ONLY. It does NOT ask the
# model to (re)discover entities, TTPs, campaign names, sectors, or IoC
# associations — a full-document entity read was measured to be WORSE than
# the existing chunked+NER pipeline for those (~25% recall of what the mix
# pipeline finds), so re-running that here would add lower-quality duplicate
# proposals rather than value. Entity discovery keeps working exactly as it
# already does; only the relation-finding gets a wider window.
_DOC_RELATIONS_SYSTEM_PROMPT = """You are a Cyber Threat Intelligence (CTI) expert.
You are given an ENTIRE CTI report — not an excerpt — specifically so you can
connect facts that are stated far apart in the document: one paragraph may
name a malware family, and a much later paragraph may attribute that malware
to an actor. A reader who only saw one paragraph at a time would miss this
connection; you have the whole report, so you should not.

Your ONLY job is to find relationships between the entities in the list below.
The list already contains EVERY kind of entity this report has — malware,
threat actors, tools, TTPs, campaigns, sectors, countries, IPs, domains,
hashes, files, CVEs, and everything else — found by an earlier, separate
process. You are NOT asked to find more entities of any kind, only the
relationships BETWEEN the ones already listed. This means every entity in
the list, regardless of its type, is a valid relationship endpoint — do not
skip an entity just because it looks like a TTP, an indicator, or a sector
rather than a named actor or malware family; a relationship like
"malware uses TTP" or "malware communicates-with domain" is exactly the kind
of fact this pass exists to find.

Rules (identical to the standard extraction contract):
- Never invent a value. Only use source_value/target_value strings that
  appear verbatim in the entity list below — never a name, IP, domain, or
  any other value that is not in that list.
- For every relationship, attach an evidence_label describing how well the
  source text supports it (do NOT upgrade the label — when support is weak,
  use a weaker one):
    observed = directly shown in telemetry/sample/log/screenshot/source artifact
    reported = the source states it (assertion-level)
    assessed = the source's analytical judgment
    inferred = your conclusion combining multiple facts across sentences —
               this is expected to be common here, since connecting distant
               facts is exactly what this pass is for
    gap      = you believe it is implied but cannot find explicit support
- evidence_text must be a sentence (or, for an inferred relationship
  combining two facts, the two supporting sentences) COPIED CHARACTER FOR
  CHARACTER from the text. Not a paraphrase. If you cannot find supporting
  text, use evidence_label "gap" and evidence_text "" — never fabricate a quote.
""" + _TIMES_RULE + """- Valid STIX 2.1 relationship types (use ONLY these):
  uses, attributed-to, targets, indicates, mitigates, remediates,
  delivers, drops, downloads, exploits, originates-from, compromises,
  communicates-with, beacons-to, exfiltrates-to, controls, has, hosts,
  owns, authored-by, impersonates, based-on, consists-of, analysis-of,
  static-analysis-of, dynamic-analysis-of, characterizes, investigates,
  located-at, resolves-to, belongs-to, variant-of,
  duplicate-of, derived-from, related-to.
- Return ONLY valid JSON, no surrounding text."""

_DOC_RELATIONS_USER_PROMPT_TEMPLATE = """Full CTI report text:

---
{text}
---

Known entities in this report — use ONLY these exact values as source_value
or target_value (do not invent a name not in this list):
{entity_list}

Return ONLY this JSON shape:
{{
  "relationships": [
    {{
      "source_value": "exact entity name from the list above",
      "relationship_type": "one of the verbs listed in the rules",
      "target_value": "exact entity name from the list above",
      "confidence": 0.0-1.0,
      "evidence_text": "verbatim sentence(s) from the text supporting this relationship",
      "evidence_label": "observed|reported|assessed|inferred|gap",
      "times": [
        {{"role": "start|end|within|throughout|observed",
          "time_text": "the date expression copied verbatim from the text",
          "value": "YYYY, YYYY-MM or YYYY-MM-DD — optional, omit for relative expressions"}}
      ]
    }}
  ]
}}"""


# --- LLM call implementations ---

# Per-request timeout in seconds.  Prevents the pipeline from hanging forever
# if the LLM server stops responding.  Override with LLM_TIMEOUT= in .env.
# Ollama users on slower hardware may need to raise this (e.g. LLM_TIMEOUT=300).
_LLM_TIMEOUT = env_int("LLM_TIMEOUT", default=120)


@retry(
    retry=retry_if_exception_type(_RETRY_EXCEPTIONS),
    stop=_RETRY_STOP,
    wait=_RETRY_WAIT,
    reraise=True
)
def _call_anthropic_impl(system: str, user: str) -> str:
    """Internal implementation of Anthropic call with retry."""
    client = _get_anthropic_client()
    if not client:
        return ""
    t0 = time.monotonic()
    try:
        _ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", _DEFAULT_ANTHROPIC_MODEL)
        # The system prompt is a module constant, identical on every chunk, so it
        # is the one part of the request worth caching.  No beta header: prompt
        # caching is GA — `anthropic-beta: prompt-caching-2024-07-31` is a 2024
        # artefact.  Whether the cache actually fires is worth checking against
        # `usage.cache_read_input_tokens`; the minimum cacheable prefix is
        # model-dependent (512-4096 tokens) and _SYSTEM_PROMPT sits at ~1170.
        response = client.messages.create(
            model=_ANTHROPIC_MODEL,
            max_tokens=_MAX_OUTPUT_TOKENS,
            system=[
                {
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user}],
            timeout=_LLM_TIMEOUT,
            **sampling_options(seed_ok=False),
        )
        elapsed = time.monotonic() - t0
        tokens_out = getattr(getattr(response, "usage", None), "output_tokens", "?")
        logger.debug(f"Anthropic responded in {elapsed:.1f}s ({tokens_out} output tokens)")
        if not response.content:
            logger.error("Anthropic returned an empty content list (possible content filter)")
            return ""
        text = "".join(b.text for b in response.content if b.type == "text")
        if not text:
            logger.error("Anthropic returned no text block (only thinking?)")
            return ""
        return text.strip()
    except anthropic.APITimeoutError:
        logger.error(f"Anthropic timed out after {_LLM_TIMEOUT}s — raise LLM_TIMEOUT in .env if your model is slow")
        raise
    except anthropic.AuthenticationError:
        logger.error("Invalid Anthropic API key — check ANTHROPIC_API_KEY in .env")
        raise
    except anthropic.APIConnectionError:
        logger.error("Cannot reach Anthropic API — check network")
        raise
    except Exception as e:
        logger.error(f"Anthropic ({time.monotonic()-t0:.1f}s): {e}")
        raise


# Every provider call ends in one of the two wrappers below, which log a
# failure and return "" so one bad chunk never fails a report.  The price was
# that a run where EVERY call failed (a wrong model name: 404 on each request)
# looked like a run where the model found nothing.  pipeline/llm_stats counts
# them so the orchestrator can tell the two apart (ADR-0060).
from pipeline import llm_stats  # noqa: E402

_record_call = llm_stats.record_call


def _call_anthropic(system: str, user: str) -> str:
    """Call Anthropic with retry logic."""
    try:
        out = _call_anthropic_impl(system, user)
        _record_call()
        return out
    except RetryError as e:
        logger.error(f"Anthropic failed after {_MAX_RETRIES} retries: {e}")
        _record_call(f"Anthropic failed after {_MAX_RETRIES} retries: {e}")
        return ""
    except Exception as e:
        logger.error(f"Anthropic call failed: {e}")
        _record_call(f"Anthropic: {e}")
        return ""


@retry(
    retry=retry_if_exception_type(_RETRY_EXCEPTIONS),
    stop=_RETRY_STOP,
    wait=_RETRY_WAIT,
    reraise=True
)
def _call_openai_compatible_impl(client_param, model: str, system: str, user: str, label: str,
                                 extra_body: dict | None = None, sampling: dict | None = None) -> str:
    """Internal implementation of OpenAI-compatible call with retry.

    `extra_body` carries server-specific fields the OpenAI SDK has no parameter
    for — vLLM's `chat_template_kwargs` (see pipeline.vllm_options).
    """
    if not client_param:
        return ""
    t0 = time.monotonic()
    try:
        response = client_param.chat.completions.create(
            model=model,
            max_tokens=_MAX_OUTPUT_TOKENS,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            timeout=_LLM_TIMEOUT,
            extra_body=extra_body,
            **(sampling or {}),
        )
        elapsed = time.monotonic() - t0
        usage  = getattr(response, "usage", None)
        tokens = getattr(usage, "completion_tokens", "?") if usage else "?"
        logger.debug(f"{label} responded in {elapsed:.1f}s ({tokens} output tokens)")
        if not response.choices:
            logger.error(f"{label} returned an empty choices list (possible content filter)")
            return ""
        content = response.choices[0].message.content
        if content is None:
            logger.error(f"{label} returned null message content")
            return ""
        return content.strip()
    except Exception as e:
        elapsed = time.monotonic() - t0
        if "timeout" in str(e).lower() or "timed out" in str(e).lower():
            logger.error(f"{label} timed out after {_LLM_TIMEOUT}s — raise LLM_TIMEOUT in .env if your model is slow")
        else:
            logger.error(f"{label} ({elapsed:.1f}s): {e}")
        raise


def _call_openai_compatible(client_param, model: str, system: str, user: str, label: str,
                            extra_body: dict | None = None, sampling: dict | None = None) -> str:
    """Shared call logic for OpenAI-compatible endpoints (Mistral, Ollama) with retry."""
    try:
        out = _call_openai_compatible_impl(client_param, model, system, user, label, extra_body,
                                           sampling)
        _record_call()
        return out
    except RetryError as e:
        logger.error(f"{label} failed after {_MAX_RETRIES} retries: {e}")
        _record_call(f"{label} failed after {_MAX_RETRIES} retries: {e}")
        return ""
    except Exception as e:
        logger.error(f"{label} call failed: {e}")
        _record_call(f"{label}: {e}")
        return ""


def _call_llm(system: str, user: str, provider: str | None = None,
              max_prompt_length: int | None = None) -> str:
    """Dispatches to an LLM provider with retry logic.

    `provider` overrides the global LLM_PROVIDER for this call only — used by the
    Stage 3e consensus pass to run the same prompt through a second model.
    `max_prompt_length` overrides the LLM_MAX_PROMPT_LENGTH cut for this call —
    the document-level pass reads a whole report, not a chunk.
    """
    # Sanitize ONLY the user message — it embeds untrusted report text, so it is
    # the prompt-injection vector.  The system prompt is developer-controlled;
    # running it through the sanitizer would needlessly escape its content and
    # corrupt the Markdown layout the model relies on.
    #
    # The cut keeps the head of the prompt, so a caller whose prompt may be
    # longer must shorten its own text first (see llm_parse.fit_text): cut
    # here, the instructions after the text are what goes.  The document-level
    # pass used to reach this line with its 300 000-char budget and lose its
    # entity list and answer format to the 32 000 default.
    sanitized_user = _sanitize_text_for_prompt(user, max_length=max_prompt_length or _MAX_PROMPT_LENGTH)

    prov = (provider or _PROVIDER).lower()
    # The seed is a standard parameter on these servers only; Mistral names it
    # differently and Gemini's compatibility layer does not document it.
    sampling = sampling_options(seed_ok=prov in ("vllm", "ollama", "lmstudio"))
    if prov == "anthropic":
        return _call_anthropic(system, sanitized_user)
    elif prov == "gemini":
        client = _get_gemini_client()
        _GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-pro")
        return _call_openai_compatible(client, _GEMINI_MODEL, system, sanitized_user, "Gemini",
                                       sampling=sampling)
    elif prov == "mistral":
        client = _get_mistral_client()
        _MISTRAL_MODEL = os.environ.get("MISTRAL_MODEL", "mistral-small-latest")
        return _call_openai_compatible(client, _MISTRAL_MODEL, system, sanitized_user, "Mistral",
                                       sampling=sampling)
    elif prov == "ollama":
        client = _get_ollama_client()
        _OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
        return _call_openai_compatible(client, _OLLAMA_MODEL, system, sanitized_user, "Ollama",
                                       sampling=sampling)
    elif prov == "lmstudio":
        client = _get_lmstudio_client()
        _LMSTUDIO_MODEL = os.environ.get("LMSTUDIO_MODEL", "lmstudio-model")
        return _call_openai_compatible(client, _LMSTUDIO_MODEL, system, sanitized_user, "LMStudio",
                                       sampling=sampling)
    elif prov == "vllm":
        client = _get_vllm_client()
        _VLLM_MODEL = os.environ.get("VLLM_MODEL", "vllm-model")
        return _call_openai_compatible(client, _VLLM_MODEL, system, sanitized_user, "vLLM",
                                       extra_body=vllm_extra_body(), sampling=sampling)
    return ""


def sampling_options(seed_ok: bool = True) -> dict:
    """LLM_TEMPERATURE and LLM_SEED, when set; {} otherwise.

    Unset (the default) keeps the provider's own sampling — for vLLM the
    model's generation_config (Qwen: temperature 0.7), for Anthropic 1.0 — so
    two runs of one report can differ.  An evaluation that compares two
    configurations needs them fixed, or has to measure that spread.
    """
    from pipeline.env_flags import env_float, env_int

    opts: dict = {}
    if os.getenv("LLM_TEMPERATURE", "").strip():
        opts["temperature"] = env_float("LLM_TEMPERATURE", default=0.0)
    if seed_ok and os.getenv("LLM_SEED", "").strip():
        opts["seed"] = env_int("LLM_SEED", default=0)
    return opts


def provider_label(provider: str | None = None) -> str:
    """'Provider/model' for the given (or global) provider — what a run used."""
    prov = (provider or _PROVIDER).lower()
    return {
        "anthropic": f"Anthropic/{os.environ.get('ANTHROPIC_MODEL', _DEFAULT_ANTHROPIC_MODEL)}",
        "gemini":    f"Gemini/{os.environ.get('GEMINI_MODEL', 'gemini-2.5-pro')}",
        "mistral":   f"Mistral/{os.environ.get('MISTRAL_MODEL', 'mistral-small-latest')}",
        "ollama":    f"Ollama/{os.environ.get('OLLAMA_MODEL', 'llama3.2')}",
        "lmstudio":  f"LMStudio/{os.environ.get('LMSTUDIO_MODEL', 'lmstudio-model')}",
        "vllm":      f"vLLM/{os.environ.get('VLLM_MODEL', 'vllm-model')}",
    }.get(prov, prov)


def prompt_fingerprint() -> str:
    """Short hash of the Stage 3 extraction prompts — changes whenever their wording does."""
    import hashlib
    digest = hashlib.sha256("\x00".join((_SYSTEM_PROMPT, _USER_PROMPT_TEMPLATE, SPOTLIGHT_RULE))
                            .encode("utf-8"))
    return digest.hexdigest()[:16]


def all_prompts_fingerprint() -> str:
    """Hash of every Stage 3 prompt: extraction, document-level relations, and
    the 3d / 3f verification prompts."""
    import hashlib

    from pipeline import stage3d_verify, stage3f_ttp_select, stage3f_ttp_verify
    parts = [_SYSTEM_PROMPT, _USER_PROMPT_TEMPLATE,
             _DOC_RELATIONS_SYSTEM_PROMPT, _DOC_RELATIONS_USER_PROMPT_TEMPLATE,
             stage3d_verify._VERIFY_SYSTEM, stage3d_verify._VERIFY_USER_TEMPLATE,
             stage3f_ttp_verify._VERIFY_SYSTEM, stage3f_ttp_verify._VERIFY_USER_TEMPLATE,
             stage3f_ttp_select._SELECT_SYSTEM, stage3f_ttp_select._SELECT_USER_TEMPLATE,
             SPOTLIGHT_RULE]
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:16]


def stage3_settings(*, consensus: bool, verify_rels: bool, verify_ttps: bool,
                    ttp_mode: str = "verify") -> dict:
    """Every setting that changes what Stage 3 returns for a given input — the
    Stage 3 checkpoint must not resume across a change in any of them."""
    from pipeline.stage3e_consensus import consensus_provider
    from pipeline.ttp_retrieval import retrieval_settings
    from pipeline.vllm_options import vllm_extra_body

    second = consensus_provider() if consensus else ""
    return {
        "ttp_mode": ttp_mode,
        "ttp_select": ({**retrieval_settings(),
                        "min_quote_words": env_int("TTP_SELECT_MIN_QUOTE_WORDS", default=3),
                        "skipped_chunks": os.getenv("TTP_SELECT_SKIPPED_CHUNKS", "")}
                       if ttp_mode == "select" else {}),
        "model": provider_label(),
        "consensus_model": provider_label(second) if second else "",
        "prompts": all_prompts_fingerprint(),
        "sampling": sampling_options(),
        "vllm": vllm_extra_body() if _PROVIDER == "vllm" else {},
        "verify_relationships": verify_rels,
        "verify_ttps": verify_ttps,
        "max_output_tokens": _MAX_OUTPUT_TOKENS,
        "max_prompt_length": _MAX_PROMPT_LENGTH,
    }


def _provider_ready(provider: str | None = None) -> bool:
    """Returns False if the given (or global) provider cannot make API calls."""
    prov = (provider or _PROVIDER).lower()
    if prov == "anthropic":
        _anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        return bool(_anthropic_key)
    if prov == "gemini":
        _gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
        return _OPENAI_SDK_AVAILABLE and bool(_gemini_key)
    if prov == "mistral":
        _mistral_key = os.environ.get("MISTRAL_API_KEY", "").strip()
        return _OPENAI_SDK_AVAILABLE and bool(_mistral_key)
    if prov in ("ollama", "lmstudio", "vllm"):
        return _OPENAI_SDK_AVAILABLE
    return False


# --- LLM output normalisation ---

_TIME_LIST_KEYS = ("times", "dates", "temporal", "time", "time_assertions", "temporal_assertions")
_TIME_TEXT_KEYS = ("time_text", "text", "quote", "expression", "time_expression", "date_text",
                   "evidence")
_TIME_VALUE_KEYS = ("value", "iso", "normalized", "normalised", "date", "iso_date")
_TIME_ROLE_ALIASES = {
    "begin": "start", "began": "start", "since": "start", "first_activity": "start",
    "stop": "end", "ended": "end", "until": "end", "last_activity": "end",
    "during": "within", "in": "within", "active": "within", "date": "within",
    "over": "throughout", "covering": "throughout",
    "seen": "observed", "observation": "observed", "detected": "observed",
    "first_seen": "observed", "last_seen": "observed",
}
# The keys an older prompt (or a model's habit) uses for a bare date.  A value
# with no quote cannot be located, so it becomes an assertion with no
# time_text: kept for the analyst, never verified, never exported.
_LEGACY_TIME_KEYS = (
    ("start", ("start_time", "start_date", "begin_time", "begin_date", "date_start", "from_date")),
    ("end", ("stop_time", "end_time", "end_date", "stop_date", "date_end", "to_date", "until")),
)


def _normalize_times(r: dict) -> list[dict]:
    """The model's dates for one relationship, as TemporalAssertion fields.

    Its reading goes to `model_value`, never to `value`: `value` is what the
    code reads from the quote (pipeline/temporal.check_assertions).
    """
    raw: list = next((r.pop(k) for k in _TIME_LIST_KEYS if isinstance(r.get(k), list)), [])
    items: list[dict] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            item = {"role": "within", "time_text": item}
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or item.get("type") or item.get("kind") or "").lower().strip()
        role = _TIME_ROLE_ALIASES.get(role, role)
        if role not in _TIME_ROLES:
            continue
        text = next((item[k] for k in _TIME_TEXT_KEYS if isinstance(item.get(k), str)), "")
        value = next((item[k] for k in _TIME_VALUE_KEYS if isinstance(item.get(k), str)), None)
        if not text.strip() and not (value or "").strip():
            continue
        first = item.get("first") is True or str(item.get("first_last", "")).lower() == "first"
        last = item.get("last") is True or str(item.get("first_last", "")).lower() == "last"
        items.append({
            "role": role, "time_text": text.strip(),
            "model_value": value.strip() if value and value.strip() else None,
            "first_last": "first" if first else "last" if last else None,
        })
    for role, keys in _LEGACY_TIME_KEYS:
        for k in keys:
            v = r.pop(k, None)
            if isinstance(v, str) and v.strip() and not any(
                    i["role"] == role and i["model_value"] == v.strip() for i in items):
                items.append({"role": role, "time_text": "", "model_value": v.strip(),
                              "first_last": None})
    return items


def check_relationship_times(result: "LLMEnrichmentResult", text: str,
                             document: DocumentTime | None) -> "LLMEnrichmentResult":
    """ADR-0063 §3 — locate, read and judge every relationship date of one
    result against the text it came from (a chunk, or the whole document for
    the ADR-0057 pass).  Counts each status in llm_stats."""
    if not any(rel.times for rel in result.relationships):
        return result
    checked: list[RelationshipExtracted] = []
    for rel in result.relationships:
        if not rel.times:
            checked.append(rel)
            continue
        times = check_assertions(rel.times, text, document=document,
                                 evidence_text=rel.evidence_text, rel_label=rel.evidence_label)
        for status, n in status_counts(times).items():
            llm_stats.bump(f"temporal_{status}", n)
        checked.append(rel.model_copy(update={"times": times}))
    return result.model_copy(update={"relationships": checked})



# Spellings a model writes instead of a STIX verb; only the unambiguous ones.
# Any other unknown verb still reaches Stage 4, which ships it as related-to
# and records `unknown_verb` in the ledger.  The user template itself said
# `originated-from` until 2026-10.
_VERB_SPELLINGS = {"originated-from": "originates-from"}


def _normalize_verb(verb: str) -> str:
    """'Attributed_To ' -> 'attributed-to'; 'originated-from' -> 'originates-from'."""
    v = re.sub(r"[\s_]+", "-", verb.strip().lower())
    return _VERB_SPELLINGS.get(v, v)


def _normalize_llm_json(data: dict) -> dict:
    """
    Coerce common LLM schema-deviation patterns into the field names and types
    that LLMEnrichmentResult expects.

    Claude sometimes returns more descriptive objects than the strict schema:

      threat_actors / malware_families / tools
        Expected: list[str]
        Seen:     list[{"name": "X", "category": "...", "aliases": []}]
        Fix:      extract the "name" (or "value"/"label") key as a bare string.

      ttps[*]
        Expected: {"technique_name": "...", "mitre_id": "T1234"}
        Seen:     {"name": "...", "id": "T1234"}   OR  {"technique": "...", "id": ...}
        Fix:      rename "name"→"technique_name" and "id"→"mitre_id".

      relationships[*]
        Expected: {"source_value": "X", "relationship_type": "uses", "target_value": "Y"}
        Seen:     {"source": "X", "relationship": "uses", "target": "Y"}
                  OR {"source": "X", "type": "uses", "target": "Y"}
        Fix:      rename "source"→"source_value", "relationship"/"type"→"relationship_type",
                  "target"→"target_value".

    Entries that are still malformed after normalisation are silently dropped
    (Pydantic will catch them and the caller logs the ValidationError).
    """
    out = dict(data)

    # ── String-list fields — extract name from dicts ──────────────────────────
    for field in ("threat_actors", "malware_families", "tools",
                  "targeted_sectors", "targeted_countries", "course_of_action"):
        raw = out.get(field)
        if not isinstance(raw, list):
            continue
        fixed: list[str] = []
        for item in raw:
            if isinstance(item, str):
                if item.strip():
                    fixed.append(item.strip())
            elif isinstance(item, dict):
                # Try common name-carrying keys in priority order
                for key in ("name", "value", "label", "actor", "family", "title"):
                    v = item.get(key)
                    if isinstance(v, str) and v.strip():
                        fixed.append(v.strip())
                        break
        out[field] = fixed

    # ── TTPs — rename "name"→"technique_name", "id"→"mitre_id" ───────────────
    raw_ttps = out.get("ttps")
    if isinstance(raw_ttps, list):
        norm_ttps: list[dict] = []
        for item in raw_ttps:
            if not isinstance(item, dict):
                continue
            t = dict(item)
            if "technique_name" not in t:
                for k in ("name", "technique", "label", "title"):
                    if isinstance(t.get(k), str) and t[k].strip():
                        t["technique_name"] = t.pop(k)
                        break
            if "mitre_id" not in t:
                for k in ("id", "mitre", "attack_id", "technique_id", "mitre_technique_id"):
                    if isinstance(t.get(k), str) and t[k].strip():
                        t["mitre_id"] = t.pop(k)
                        break
            # ADR-0028 — accept the aliases models reach for instead of
            # `evidence_text`, the same way relationship keys are normalised
            # below.  Without this the quote is silently dropped and the
            # technique looks unsupported.
            if "evidence_text" not in t:
                for k in ("evidence", "quote", "evidence_quote", "supporting_text",
                          "source_text", "excerpt"):
                    if isinstance(t.get(k), str):
                        t["evidence_text"] = t.pop(k)
                        break
            if "evidence_label" not in t:
                for k in ("label", "evidence_grade", "support", "confidence_label"):
                    if isinstance(t.get(k), str) and t[k].strip():
                        t["evidence_label"] = t.pop(k)
                        break
            if "technique_name" in t:
                norm_ttps.append(t)
        out["ttps"] = norm_ttps

    # ── Relationships — rename source/target/relationship keys ────────────────
    raw_rels = out.get("relationships")
    if isinstance(raw_rels, list):
        norm_rels: list[dict] = []
        for item in raw_rels:
            if not isinstance(item, dict):
                continue
            r = dict(item)
            if "source_value" not in r:
                for k in ("source", "from", "subject", "source_entity", "actor"):
                    if isinstance(r.get(k), str) and r[k].strip():
                        r["source_value"] = r.pop(k)
                        break
            if "target_value" not in r:
                for k in ("target", "to", "object", "target_entity", "victim"):
                    if isinstance(r.get(k), str) and r[k].strip():
                        r["target_value"] = r.pop(k)
                        break
            if "relationship_type" not in r:
                for k in ("relationship", "type", "rel_type", "relation", "rel"):
                    if isinstance(r.get(k), str) and r[k].strip():
                        r["relationship_type"] = r.pop(k)
                        break
            if isinstance(r.get("relationship_type"), str):
                r["relationship_type"] = _normalize_verb(r["relationship_type"])
            # Coerce evidence_label to a known value; unknown/missing → "reported"
            # so a malformed label never discards an otherwise-valid relationship.
            _lbl = str(r.get("evidence_label", "")).lower().strip()
            r["evidence_label"] = _lbl if _lbl in {
                "observed", "reported", "assessed", "inferred", "gap"
            } else "reported"
            # Dates (ADR-0063): the model's `times` list, shaped for
            # TemporalAssertion.  Nothing is parsed or judged here — the check
            # needs the chunk, and runs in enrich_chunk.
            r["times"] = _normalize_times(r)
            # Only keep entries that have all three required fields
            if all(r.get(f) for f in ("source_value", "relationship_type", "target_value")):
                norm_rels.append(r)
        out["relationships"] = norm_rels

    return out


# --- Truncated-response recovery ---

# All list-valued fields in LLMEnrichmentResult — used to salvage partial
# results when the LLM response is cut off mid-array (hit max_tokens).
_LIST_FIELDS = (
    "threat_actors", "malware_families", "tools", "ttps",
    "relationships", "ioc_associations", "targeted_sectors",
    "targeted_countries", "course_of_action",
)


def _unclosed_stack(text: str) -> tuple[list[str], bool]:
    """
    Walk text tracking string state, returning the stack of still-open
    '{'/'[' (in open order) and whether the text ends inside a string.
    """
    stack: list[str] = []
    in_string = False
    escaped = False
    for ch in text:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_string:
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if stack:
                stack.pop()
    return stack, in_string


def _try_complete_truncated_json(text: str) -> str | None:
    """
    Best-effort repair of a response cut off mid-object (hit max_tokens):
    drop the dangling fragment at the cut point and close whatever
    structures are still open, in the correct nesting order.
    Returns None if the text has no unclosed structures (nothing to repair).
    """
    stack, in_string = _unclosed_stack(text)
    if not stack and not in_string:
        return None

    completed = text
    if in_string:
        completed += '"'

    # Drop a dangling key/value fragment left at the cut point, e.g.
    # `..., "evidence_text": "the attacker us` or `..., "confidence": 0.`
    completed = re.sub(r',\s*"[^"]*"\s*:\s*"[^"]*$', "", completed)
    completed = re.sub(r',\s*"[^"]*"\s*:\s*[^,{\[\]}]*$', "", completed)
    completed = re.sub(r',\s*"[^"]*$', "", completed)
    completed = re.sub(r',\s*\{[^{}]*$', "", completed)
    completed = re.sub(r',\s*$', "", completed)

    # Recompute after trimming — dropping a partial nested object/key can
    # change which brackets are still open.
    stack, _ = _unclosed_stack(completed)
    for opener in reversed(stack):
        completed += "]" if opener == "[" else "}"
    return completed


def _extract_complete_array_items(text: str, array_start: int) -> list[str]:
    """
    Return the raw source slice of each fully-closed top-level item (object
    or string) inside a JSON array starting at array_start, stopping at the
    first incomplete item or the array's closing bracket.
    """
    items: list[str] = []
    depth = 0
    item_start = -1
    in_string = False
    escaped = False
    for i in range(array_start, len(text)):
        ch = text[i]
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_string:
            escaped = True
            continue
        if ch == '"':
            if in_string:
                in_string = False
                if depth == 0 and item_start != -1:
                    items.append(text[item_start:i + 1])
                    item_start = -1
            else:
                in_string = True
                if depth == 0 and item_start == -1:
                    item_start = i
            continue
        if in_string:
            continue
        if ch in "{[":
            if depth == 0 and item_start == -1:
                item_start = i
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0 and item_start != -1:
                items.append(text[item_start:i + 1])
                item_start = -1
            elif depth < 0:
                break  # closing bracket of the outer array itself
    return items


def _try_extract_complete_items(text: str) -> dict | None:
    """
    Last-resort salvage: pull whatever complete list items can be found for
    each known LLMEnrichmentResult field, even when the response is
    truncated mid-item.
    """
    result: dict = {}
    for field in _LIST_FIELDS:
        m = re.search(rf'"{field}"\s*:\s*\[', text)
        if not m:
            continue
        items = []
        for raw in _extract_complete_array_items(text, m.end()):
            try:
                items.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        if items:
            result[field] = items
    return result or None


# --- Public API ---

def _parse_llm_response(raw_text: str) -> LLMEnrichmentResult | None:
    """
    Turn a raw LLM text response into an LLMEnrichmentResult, or None if
    nothing usable could be recovered.

    Factored out of enrich_chunk so enrich_document_relations (ADR-0057) can
    reuse the exact same truncation-repair and normalise-then-validate path
    instead of a second, drifting copy of it.
    """
    # Use raw_decode() to find the first syntactically valid JSON object in
    # the LLM output, ignoring any surrounding prose or markdown fences.
    decoder = json.JSONDecoder()
    parsed_json: dict | None = None
    first = raw_text.find("{")
    for i, ch in enumerate(raw_text):
        if ch == "{":
            try:
                obj, _ = decoder.raw_decode(raw_text, i)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                # An object nested in an outer one that never closes is one
                # TTP or relationship of a truncated answer, not the answer:
                # taking it returned an empty result for the whole chunk.
                # Repair or salvage the outer object below instead.
                if i > first and _unclosed_stack(raw_text[first:i])[0]:
                    break
                parsed_json = obj
                break

    # Response was likely cut off by max_tokens — try to repair the dangling
    # structure before giving up entirely.  From the first "{": a ```json
    # fence or a sentence before it would otherwise defeat the repair.
    if parsed_json is None and first >= 0:
        completed = _try_complete_truncated_json(raw_text[first:])
        if completed is not None:
            try:
                parsed_json = json.loads(completed)
                logger.warning("LLM response was truncated — recovered by closing dangling structures")
            except json.JSONDecodeError:
                parsed_json = None

    # Still nothing — salvage whatever complete array items survived the cut.
    if parsed_json is None:
        parsed_json = _try_extract_complete_items(raw_text)
        if parsed_json is not None:
            logger.warning("LLM response was truncated — salvaged partial results from complete array items")

    if parsed_json is None:
        logger.warning(f"LLM returned no valid JSON (raw preview: {raw_text[:120]!r})")
        return None

    # Normalise field names/types before Pydantic validation.
    # Claude sometimes returns richer objects than the schema expects —
    # e.g. {"name": "GREYVIBE", "aliases": []} where a plain string is required,
    # or {"id": "T1587.003", "name": "..."} where "mitre_id"/"technique_name" are
    # expected.  Discarding the whole result on a field-name mismatch would lose
    # all real intelligence from the chunk.  Normalise instead, then validate.
    normalized_json = _normalize_llm_json(parsed_json)
    try:
        return LLMEnrichmentResult.model_validate(normalized_json)
    except ValidationError as e:
        logger.warning(f"JSON schema validation failed after normalization: {e}")
        return None


def corroborated_ttp_ids(semantic_ttp_entities) -> set[str]:
    """MITRE IDs a semantic match corroborates strongly enough to waive Stage 3f.

    Only a **high-confidence** match (cosine ≥ the model's high cut-point) may
    exempt an LLM technique from quote-verification.  Without this floor every
    *medium* match (≥ 0.48 — precisely the nearest-but-wrong tier ADR-0011
    Phase A added the margin gate to suppress) whitelists its LLM twin, so the
    weakest signal in the pipeline silently grants the strongest claim a free
    pass.  Measured on a real report: 13 of 16 corroborators sat below the 0.62
    cut-point, waving through techniques with no textual support at all
    (e.g. T0873 "Project File Infection" at 0.52, in a report with no ICS
    content whatsoever).
    """
    try:
        from pipeline.stage2c_ttp_semantic import high_confidence_threshold
        floor = high_confidence_threshold()
    except Exception:
        floor = 0.62
    return {
        e.mitre_id.upper()
        for e in (semantic_ttp_entities or [])
        if getattr(e, "mitre_id", None)
        and float(getattr(e, "confidence", 0.0) or 0.0) >= floor
    }


def enrich_chunk(
    text: str,
    detected_entities: list[RawEntity],
    gazetteer_entities: list[RawEntity] | None = None,
    semantic_ttp_entities: list[RawEntity] | None = None,
    cyner_entities: list[RawEntity] | None = None,
    doc_context: str | None = None,
    ner_allow_list: set[str] | None = None,
    provider: str | None = None,
    reference_date: datetime | None = None,
    verify_rels: bool | None = None,
    verify_ttps_on: bool | None = None,
    document_time: DocumentTime | None = None,
    ttp_mode: str = "verify",
    ttp_candidates: list | None = None,
) -> LLMEnrichmentResult:
    """
    Enrich a text chunk with LLM intelligence.

    `verify_rels` / `verify_ttps_on` switch Stages 3d / 3f for this call;
    None follows ENABLE_STIX_VERIFICATION / ENABLE_TTP_VERIFICATION.
    `ttp_mode="select"` makes 3f choose among `ttp_candidates` (this chunk's
    retrieved techniques) and the LLM's own proposals instead of verifying the
    latter (ADR-0072).

    Args:
        text:                   The raw CTI text chunk.
        detected_entities:      Entities from Stage 2 regex (IoCs).
        gazetteer_entities:     Entities from Stage 2b MITRE gazetteer.
        semantic_ttp_entities:  TTPs found by Stage 2c semantic matching.
        cyner_entities:         Entities found by Stage 2d CyNER model.
        doc_context:            Document-level entity summary (ADR-004 P2-B).
                                Passed to every chunk so the LLM can link IoC
                                appendix entries back to the correct malware/actor.
        document_time:          The document anchor and folded text the
                                relationship dates are checked against
                                (ADR-0063, pipeline.temporal).  The model no
                                longer sees a reference date: it copies a
                                relative expression, the code resolves it.
        reference_date:         Deprecated — a file metadata timestamp, used
                                only when `document_time` is not given, as a
                                weak anchor (it never resolves "last month").
    """
    if document_time is None and reference_date is not None:
        document_time = DocumentTime(anchor=Anchor(
            value=reference_date.date().isoformat(), source="file_metadata"))
    if not _provider_ready(provider):
        return LLMEnrichmentResult()

    # IoC summary — regex-extracted technical indicators.
    # Cap at 30 entries so IoC-appendix chunks don't inflate the prompt by
    # hundreds of lines.  Prioritise diversity across types; add a count suffix
    # when entries are omitted so the LLM knows more IoCs exist.
    _ioc_candidates = [
        e for e in detected_entities
        if e.entity_type.value not in ("malware", "threat_actor", "tool", "campaign")
    ]
    _IOC_CAP = 30
    if len(_ioc_candidates) > _IOC_CAP:
        # Keep a representative sample: sort by type so we get type diversity,
        # then take the first _IOC_CAP entries.
        _ioc_candidates_sorted = sorted(_ioc_candidates, key=lambda e: e.entity_type.value)
        _omitted = len(_ioc_candidates) - _IOC_CAP
        _shown   = _ioc_candidates_sorted[:_IOC_CAP]
        ioc_summary = "\n".join(f"- [{e.entity_type.value}] {e.value}" for e in _shown)
        ioc_summary += f"\n  ... and {_omitted} more IoCs (omitted to keep prompt size manageable)"
    else:
        ioc_summary = "\n".join(
            f"- [{e.entity_type.value}] {e.value}" for e in _ioc_candidates
        ) or "None"

    # Named-entity summary — gazetteer + CyNER (both tell LLM "don't re-extract")
    gaz_list = list(gazetteer_entities or [])
    cyn_list = list(cyner_entities or [])
    # Merge CyNER into gaz list, de-dup by (value.lower, type)
    gaz_keys = {(e.value.lower(), e.entity_type) for e in gaz_list}
    for ce in cyn_list:
        key = (ce.value.lower(), ce.entity_type)
        if key not in gaz_keys:
            gaz_list.append(ce)
            gaz_keys.add(key)

    gaz_summary = "\n".join(
        f"- [{e.entity_type.value}] {e.value}"
        + (f" ({e.mitre_id})" if e.mitre_id else "")
        + (f" [CyNER conf={e.confidence:.2f}]" if e.source == "cyner" else "")
        for e in gaz_list
    ) or "None"

    # Semantic TTP summary — already-detected ATT&CK techniques
    sem_list = semantic_ttp_entities or []
    sem_summary = "\n".join(
        f"- [{e.entity_type.value}] {e.value} ({e.mitre_id}) — conf={e.confidence:.2f}"
        for e in sem_list
        if e.mitre_id
    ) or "None"

    # Document context (P2-B): helps LLM link IoC appendix entries to malware/actor
    ctx_summary = doc_context.strip() if doc_context else "None"

    # Past the ceiling the CHUNK is cut, never the lists and answer format after it.
    prompt, spotlight = fit_report(
        _USER_PROMPT_TEMPLATE, text, _MAX_PROMPT_LENGTH,
        doc_context=ctx_summary,
        detected_ioc_entities=ioc_summary,
        detected_gazetteer_entities=gaz_summary,
        detected_semantic_ttps=sem_summary,
    )

    # Validate prompt length
    if text not in prompt:
        logger.warning(f"Prompt too long (> {_MAX_PROMPT_LENGTH} chars) — the chunk's end is not sent")
    elif len(prompt) < _MIN_PROMPT_LENGTH:
        logger.warning(f"Prompt too short ({len(prompt)} chars < {_MIN_PROMPT_LENGTH} min) — skipping chunk")
        return LLMEnrichmentResult()

    logger.debug(f"Calling {provider_label()} ({len(prompt)} prompt chars)")

    llm_stats.reset_last_call()
    raw_text = _call_llm(f"{_SYSTEM_PROMPT}\n\n{spotlight}", prompt, provider=provider)
    if not raw_text:
        # Three different things return "": a failed request, an answer with no
        # content, a blocked prompt.  Counted apart (ADR-0060), still skipped.
        if llm_stats.last_call_failed():
            llm_stats.bump("extraction_provider_failed")
        else:
            llm_stats.bump("extraction_empty")
            logger.warning("LLM returned empty response — skipping chunk")
        return LLMEnrichmentResult()

    # Validate response length
    if len(raw_text) > _MAX_RESPONSE_LENGTH:
        logger.warning(f"Response too long ({len(raw_text)} chars > {_MAX_RESPONSE_LENGTH} max) — truncating")
        raw_text = raw_text[:_MAX_RESPONSE_LENGTH]

    result = _parse_llm_response(raw_text)
    if result is None:
        llm_stats.bump("extraction_invalid")
        return LLMEnrichmentResult()
    llm_stats.bump("extraction_ok")

    # Stage 3b — remove hallucinated entity names not present in the source text.
    # Pass doc_context and ner_allow_list so the filter can short-circuit the
    # O(n) fuzzy scan for names that high-precision NER already confirmed as real.
    from pipeline.stage3b_validate import validate_llm_result
    result = validate_llm_result(
        result, text,
        doc_context=doc_context or "",
        ner_allow_list=ner_allow_list,
    )

    # ADR-0063 — the relationship dates, checked against this chunk BEFORE
    # Stage 3d, which may replace evidence_text (the check uses it to pick the
    # right occurrence) but never touches `times`.
    result = check_relationship_times(result, text, document_time)

    # Stage 3d — self-verification of relationship claims (ADR-004 P3-A)
    # Sends a second LLM call to find the supporting sentence for each relationship.
    # Relationships without textual support are removed (reduces hallucination ~27%→8%).
    # Only runs when ENABLE_STIX_VERIFICATION=true in .env (default: false).
    if result.relationships:
        from pipeline.stage3d_verify import verify_enabled, verify_relationships
        if verify_enabled() if verify_rels is None else verify_rels:
            # verify_relationships() returns `object` to avoid a circular
            # import with LLMEnrichmentResult (defined in this module); it's
            # always an LLMEnrichmentResult at runtime.  Bind the same provider
            # override so verification runs on the model that produced the claims.
            def _verify_call(s, u):
                return _call_llm(s, u, provider=provider)
            result = cast(LLMEnrichmentResult,
                          verify_relationships(text, result, _verify_call, enabled=True,
                                               max_prompt_chars=_MAX_PROMPT_LENGTH))

    # Stage 3f, select mode (ADR-0072) — the chunk's candidates (retrieved +
    # the LLM's proposals) go through one selection call; only what the code
    # validates becomes a technique.  With 3f off, the LLM's techniques pass
    # unchecked and the retrieved candidates are dropped.
    if ttp_mode == "select":
        from pipeline.stage3f_ttp_verify import verify_enabled as ttp_verify_enabled
        if not (ttp_verify_enabled() if verify_ttps_on is None else verify_ttps_on):
            return result
        sel = select_chunk_ttps(text, ttp_candidates or [], result.ttps, provider=provider)
        return result.model_copy(update={"ttps": sel.ttps, "ttp_review": sel.ttp_review})

    # Stage 3f — self-verification of TTP claims (ADR precision §3)
    # Mirrors Stage 3d for techniques: each LLM-extracted TTP must be supported by
    # a sentence describing its use, or it is dropped.  TTPs already corroborated
    # by a high-confidence semantic match are trusted and skipped.
    # Only runs when ENABLE_TTP_VERIFICATION=true in .env (default: false).
    if result.ttps:
        from pipeline.stage3f_ttp_verify import verify_enabled as ttp_verify_enabled
        from pipeline.stage3f_ttp_verify import verify_ttps
        if ttp_verify_enabled() if verify_ttps_on is None else verify_ttps_on:
            corroborated_ids = corroborated_ttp_ids(semantic_ttp_entities)

            def _ttp_verify_call(s, u):
                return _call_llm(s, u, provider=provider)
            result = cast(
                LLMEnrichmentResult,
                verify_ttps(text, result, _ttp_verify_call, corroborated_ids, enabled=True,
                            max_prompt_chars=_MAX_PROMPT_LENGTH),
            )

    return result


def select_chunk_ttps(text: str, retrieved: list, llm_ttps: list | None = None,
                      provider: str | None = None) -> LLMEnrichmentResult:
    """Stage 3f, select mode, on one chunk: the retrieved candidates and the
    LLM's proposals (`llm_ttps`, possibly none) through one selection call.
    Returns only techniques and review items (ADR-0072).

    Also called with no proposals for a chunk Stage 3 skipped (no IoC, no
    known name) that retrieval still found behaviour in."""
    from pipeline.stage3f_ttp_select import chunk_candidates, llm_proposals_as_candidates, select_ttps

    proposals, labels, no_id = llm_proposals_as_candidates(llm_ttps or [])
    if no_id:
        llm_stats.bump("ttp_selection_proposals_without_id", no_id)
    cands = chunk_candidates(retrieved, proposals)
    if not cands:
        return LLMEnrichmentResult()

    def _select_call(s, u):
        return _call_llm(s, u, provider=provider)
    sel = select_ttps(text, cands, _select_call, llm_labels=labels, max_prompt_chars=_MAX_PROMPT_LENGTH)
    return LLMEnrichmentResult(ttps=sel.selected, ttp_review=sel.review)


def enrich_all_chunks(
    chunks: list[str],
    entities_per_chunk: list[list[RawEntity]],
    gazetteer_entities: list[RawEntity] | None = None,
    cyner_entities: list[RawEntity] | None = None,
    semantic_ttp_entities: list[RawEntity] | None = None,
    doc_context: str | None = None,
    ner_allow_list: set[str] | None = None,
    reference_date: datetime | None = None,
    document_time: DocumentTime | None = None,
) -> LLMEnrichmentResult:
    """
    CLI-facing wrapper: calls enrich_chunk for each chunk with the same
    quality arguments that the API worker passes.  Previously these were
    silently omitted, so the CLI produced lower-quality output than the API
    (no gazetteer context, no doc_context, no hallucination allow-list).
    """
    all_results = []
    total = len(chunks)

    for i, (chunk, entities) in enumerate(zip(chunks, entities_per_chunk, strict=True), 1):
        logger.info(f"LLM chunk {i}/{total}...")
        result = enrich_chunk(
            chunk, entities,
            gazetteer_entities=gazetteer_entities,
            cyner_entities=cyner_entities,
            semantic_ttp_entities=semantic_ttp_entities,  # tells LLM which TTPs already found
            doc_context=doc_context,
            ner_allow_list=ner_allow_list,
            reference_date=reference_date,
            document_time=document_time,
        )
        all_results.append(result)

    # Stage 3 document-level relation pass (ADR-0057, opt-in) — CLI parity
    # with the API worker's wiring of the same capability.
    if document_level_relations_enabled():
        known_entities: list[RawEntity] = list(gazetteer_entities or []) + list(cyner_entities or [])
        known_keys = {(e.value.lower(), e.entity_type) for e in known_entities}
        for entities in entities_per_chunk:
            for e in entities:
                key = (e.value.lower(), e.entity_type)
                if key not in known_keys:
                    known_entities.append(e)
                    known_keys.add(key)
        for r in all_results:
            for name, etype in (
                [(n, EntityType.THREAT_ACTOR) for n in r.threat_actors]
                + [(n, EntityType.MALWARE) for n in r.malware_families]
                + [(n, EntityType.TOOL) for n in r.tools]
            ):
                key = (name.lower(), etype)
                if key not in known_keys:
                    known_entities.append(RawEntity(value=name, entity_type=etype, source="llm"))
                    known_keys.add(key)

        full_text = "\n\n".join(chunks)
        logger.info(f"[Stage 3 doc-relations] {len(known_entities)} known entities, "
                    f"{len(full_text)} chars of report text")
        doc_rel_result = enrich_document_relations(full_text, known_entities,
                                                   document_time=document_time)
        logger.info(f"[Stage 3 doc-relations] {len(doc_rel_result.relationships)} relationships found")
        all_results.append(doc_rel_result)

    return _merge_results(
        all_results,
        gazetteer_entities=gazetteer_entities,
        semantic_ttp_entities=semantic_ttp_entities,
        cyner_entities=cyner_entities,
    )


def document_level_relations_enabled() -> bool:
    """True when the Stage 3 document-level relation pass (ADR-0057) should
    run. Off by default, same convention as Stage 3d/3e/completion.long_distance
    — a new capability ships opt-in until measured on real jobs."""
    from pipeline.env_flags import env_bool
    return env_bool("ENABLE_DOCUMENT_LEVEL_RELATIONS", default=False)


def enrich_document_relations(
    full_text: str,
    known_entities: list[RawEntity],
    provider: str | None = None,
    document_time: DocumentTime | None = None,
    verify_rels: bool | None = None,
) -> LLMEnrichmentResult:
    """
    Stage 3 document-level relation pass (ADR-0057) — opt-in via
    ENABLE_DOCUMENT_LEVEL_RELATIONS=true (see document_level_relations_enabled()).

    `verify_rels` switches Stage 3d for this call, as in enrich_chunk; None
    follows ENABLE_STIX_VERIFICATION.

    Sends the WHOLE report (not a chunk) plus the full known-entity list and
    asks for relationships only. Intended to be appended to the list of
    per-chunk LLMEnrichmentResults passed to _merge_results() — its output is
    just another LLMEnrichmentResult with every field but `relationships`
    left at its default, so it needs no dedicated merge logic: the existing
    (source, verb, target) dedup in _merge_results, including its
    better-evidence-wins tie-break, applies to it exactly as it does to any
    chunk's result.

    Returns LLMEnrichmentResult() (empty) when the provider is not ready, no
    entities are known yet, or the call/parse fails — a caller can always
    append the result unconditionally without checking first.
    """
    if not _provider_ready(provider):
        return LLMEnrichmentResult()
    if not known_entities:
        return LLMEnrichmentResult()

    entity_list = "\n".join(
        f"- [{e.entity_type.value}] {e.value}" for e in known_entities
    )

    # Past the ceiling the REPORT is cut, never the entity list and answer
    # format that follow it: without them the model has nothing to answer.
    prompt, spotlight = fit_report(_DOC_RELATIONS_USER_PROMPT_TEMPLATE, full_text,
                                   _DOC_MAX_PROMPT_LENGTH, entity_list=entity_list)
    if full_text not in prompt:
        logger.warning(
            f"[Stage 3 doc-relations] Report too long for LLM_DOC_MAX_PROMPT_LENGTH="
            f"{_DOC_MAX_PROMPT_LENGTH} — its end is not sent. Raise the limit if "
            "this report should fit whole."
        )

    logger.info(f"[Stage 3 doc-relations] Calling LLM ({len(prompt)} prompt chars, "
                f"{len(known_entities)} known entities)")

    raw_text = _call_llm(f"{_DOC_RELATIONS_SYSTEM_PROMPT}\n\n{spotlight}", prompt, provider=provider,
                         max_prompt_length=_DOC_MAX_PROMPT_LENGTH)
    if not raw_text:
        logger.warning("[Stage 3 doc-relations] LLM returned empty response")
        return LLMEnrichmentResult()

    if len(raw_text) > _MAX_RESPONSE_LENGTH:
        logger.warning(f"[Stage 3 doc-relations] Response too long ({len(raw_text)} "
                        f"chars > {_MAX_RESPONSE_LENGTH} max) — truncating")
        raw_text = raw_text[:_MAX_RESPONSE_LENGTH]

    result = _parse_llm_response(raw_text)
    if result is None:
        return LLMEnrichmentResult()

    # Defense in depth: the prompt says "relationships only", but nothing
    # forces the model to comply. Strip anything else it returned rather than
    # trust the instruction — this pass must never become a second, lower-
    # quality source of entities/TTPs/campaign data.
    result = LLMEnrichmentResult(relationships=result.relationships)

    # Stage 3b — remove hallucinated relationship endpoints not present in
    # the source text. `full_text` IS the whole document here (not a 3000-
    # char slice), so this check is at its most meaningful: no tier-2
    # doc_context fallback is needed the way chunk-level extraction needs it.
    from pipeline.stage3b_validate import validate_llm_result
    result = validate_llm_result(result, full_text)

    # ADR-0063 — dates checked against the whole document, the text this
    # pass quoted from.
    result = check_relationship_times(result, full_text, document_time)

    # Stage 3d — self-verification of relationship claims (ADR-004 P3-A),
    # against the full document text so a claim connecting two distant
    # sentences can still be verified.
    if result.relationships:
        from pipeline.stage3d_verify import verify_enabled, verify_relationships
        if verify_enabled() if verify_rels is None else verify_rels:
            def _verify_call(s, u):
                return _call_llm(s, u, provider=provider, max_prompt_length=_DOC_MAX_PROMPT_LENGTH)
            result = cast(LLMEnrichmentResult,
                          verify_relationships(full_text, result, _verify_call, enabled=True,
                                               max_prompt_chars=_DOC_MAX_PROMPT_LENGTH,
                                               document=True))

    return result


def _dedup_names(names: list[str], blacklist: set[str] | None = None) -> list[str]:
    """
    Case-insensitive deduplication — keeps the first occurrence of each name.
    Optionally filters names that appear in blacklist.
    """
    seen: dict[str, str] = {}
    for name in names:
        name = name.strip()
        if not name:
            continue
        key = name.lower()
        if blacklist and key in blacklist:
            continue
        if key not in seen:
            seen[key] = name
    return list(seen.values())


def _evidence_rank(obj: object) -> tuple[int, int]:
    """How well-evidenced an extracted item is, for merge tie-breaking.

    `(has_quote, quote_length)`.  Length is the tie-break because a merge
    between two quoted duplicates should keep the one carrying more of the
    sentence: measured, a one-word quote ("downloaded") was replacing a full
    clause purely because its chunk came later.
    """
    evidence = getattr(obj, "evidence_text", None)
    if not isinstance(evidence, str) or not evidence.strip():
        return (0, 0)
    return (1, len(evidence.strip()))


def _prefer(incumbent, candidate):
    """Pick the better of two duplicates, keeping the incumbent on a tie.

    Duplicates are the SAME claim seen in two chunks, so the merge is free to
    keep whichever carries more support.  Plain last-write-wins made the result
    depend on chunk order, and silently dropped an evidence quote whenever a
    later chunk restated the technique without one — which is precisely what
    ADR-0028 exists to prevent.

    Keeping the incumbent on a tie is what makes the merge deterministic: the
    first chunk that made a claim owns it unless a later one is strictly better.
    """
    if incumbent is None:
        return candidate

    cand_rank = _evidence_rank(candidate)
    inc_rank = _evidence_rank(incumbent)

    if cand_rank > inc_rank:
        return candidate
    if inc_rank > cand_rank:
        return incumbent

    cand_conf = getattr(candidate, "confidence", None)
    inc_conf = getattr(incumbent, "confidence", None)

    if (
        isinstance(cand_conf, (int, float))
        and not isinstance(cand_conf, bool)
        and isinstance(inc_conf, (int, float))
        and not isinstance(inc_conf, bool)
        and cand_conf > inc_conf
    ):
        return candidate

    return incumbent


def _merge_results(
    results: list[LLMEnrichmentResult],
    gazetteer_entities: list[RawEntity] | None = None,
    semantic_ttp_entities: list[RawEntity] | None = None,
    cyner_entities: list[RawEntity] | None = None,
) -> LLMEnrichmentResult:
    """
    Merge results from all chunks, deduplicating by semantic key.

    If gazetteer_entities is provided, any LLM-extracted malware/actor/tool name
    that the gazetteer already found is silently dropped — the gazetteer version
    (with correct MITRE ID and canonical name) takes precedence.

    If cyner_entities is provided, any LLM-extracted entity that CyNER already
    found is silently dropped — CyNER has higher precision for named entities.

    If semantic_ttp_entities is provided, they are seeded into the TTP list
    before LLM TTPs are merged (semantic matches have higher precision).
    """
    # Build a set of lower-cased names already covered by gazetteer + CyNER
    gaz_covered: set[str] = set()
    if gazetteer_entities:
        for ge in gazetteer_entities:
            gaz_covered.add(ge.value.lower())
    if cyner_entities:
        for ce in cyner_entities:
            gaz_covered.add(ce.value.lower())

    # Dedup TTPs: prefer the entry with a mitre_id.
    # Using `mitre_id or name` as the key means the same technique appearing in
    # two chunks — once with a mitre_id and once without — gets two different keys
    # and produces duplicate AttackPattern SDOs.  Instead, normalise: index by
    # mitre_id when available; for id-less entries only insert if the name isn't
    # already covered by an id-bearing entry.
    ttp_map: dict[str, TTPExtracted] = {}
    for r in results:
        for t in r.ttps:
            if t.mitre_id:
                # Always prefer the id-keyed entry
                # Better-evidenced wins, not last-seen.
                ttp_map[t.mitre_id] = _prefer(ttp_map.get(t.mitre_id), t)
                # Also remove any earlier name-only entry for this technique
                ttp_map.pop(t.technique_name.lower(), None)
            else:
                name_key = t.technique_name.lower()
                # Only insert if no id-bearing entry covers this name
                already_covered = any(
                    v.technique_name.lower() == name_key
                    for v in ttp_map.values()
                    if v.mitre_id
                )
                if not already_covered and name_key not in ttp_map:
                    ttp_map[name_key] = t

    rel_map: dict[tuple, RelationshipExtracted] = {}
    for r in results:
        for rel in r.relationships:
            key = (rel.source_value.lower(), rel.relationship_type, rel.target_value.lower())
            # Better-evidenced wins, not last-seen — for the claim.  Its dates
            # are the union of every copy's (ADR-0063 §6): "in 2021" in one
            # chunk and "in 2024" in another are two assertions, and the same
            # occurrence read through two overlapping chunks is one.
            incumbent = rel_map.get(key)
            chosen = _prefer(incumbent, rel)
            if incumbent is not None and (incumbent.times or rel.times):
                chosen = chosen.model_copy(update={"times": merge_times(incumbent.times, rel.times)})
            rel_map[key] = chosen

    ioc_map: dict[tuple, IoCAssociation] = {}
    for r in results:
        for assoc in r.ioc_associations:
            if not assoc.ioc_value or not assoc.malware_name:
                continue
            # Distinct variable name from `key` above — mypy infers a
            # variable's type from its first assignment (a 3-tuple there),
            # so reusing it for this 2-tuple would be a type error.
            ioc_key = (assoc.ioc_value.lower(), assoc.malware_name.lower())
            # No evidence or confidence on this model — last-seen is harmless here.
            ioc_map[ioc_key] = assoc

    # Undecided candidates (ADR-0072), once per id, and only while no chunk
    # selected that technique.
    review_map: dict[str, TtpReview] = {}
    for r in results:
        for rv in r.ttp_review:
            review_map.setdefault(rv.attack_id.upper(), rv)
    # Undecided relationships (ADR-0082), the same way: once per claim, and
    # only while no chunk (nor the document pass) verified it.
    rel_review_map: dict[tuple, RelationshipReview] = {}
    for r in results:
        for held in r.rel_review:
            key = (held.source_value.lower(), held.relationship_type, held.target_value.lower())
            rel_review_map.setdefault(key, held)

    all_actors = [a for r in results for a in r.threat_actors]
    all_malware = [m for r in results for m in r.malware_families]
    all_tools = [t for r in results for t in r.tools]
    all_sectors = [s for r in results for s in r.targeted_sectors]
    all_countries = [c for r in results for c in r.targeted_countries]
    all_coas = [c for r in results for c in r.course_of_action]

    # Stage 3c — verify/correct LLM MITRE IDs and merge with semantic TTPs
    from pipeline.stage3c_mitre import normalize_ttps
    normalized_ttps = normalize_ttps(
        list(ttp_map.values()),
        semantic_entities=semantic_ttp_entities,
    )

    selected_ids = {(t.mitre_id or "").upper() for t in normalized_ttps}

    # Pick the campaign name that appears most often across chunks;
    # fall back to the first non-None name if all are unique.
    all_campaigns = [r.campaign_name for r in results if r.campaign_name]
    if all_campaigns:
        from collections import Counter
        campaign_name: str | None = Counter(c.strip() for c in all_campaigns).most_common(1)[0][0]
    else:
        campaign_name = None

    # Merge gazetteer blacklist + generic term blocklist to suppress known/generic names
    # `_GENERIC_ACTOR_TERMS` is a frozenset; `frozenset | set` yields a
    # frozenset, but `_dedup_names` declares `blacklist: set[str] | None` —
    # coerce to `set` so the union matches the expected type.
    actor_blacklist  = set(_GENERIC_ACTOR_TERMS) | gaz_covered
    malware_blacklist = set(_GENERIC_MALWARE_TERMS) | gaz_covered
    tool_blacklist   = gaz_covered

    return LLMEnrichmentResult(
        threat_actors=_dedup_names(all_actors, blacklist=actor_blacklist),
        malware_families=_dedup_names(all_malware, blacklist=malware_blacklist),
        tools=_dedup_names(all_tools, blacklist=tool_blacklist),
        ttps=normalized_ttps,
        relationships=list(rel_map.values()),
        ioc_associations=list(ioc_map.values()),
        targeted_sectors=_dedup_names(all_sectors),
        targeted_countries=_dedup_names(all_countries),
        campaign_name=campaign_name,
        course_of_action=_dedup_names(all_coas),
        ttp_review=[rv for key, rv in review_map.items() if key not in selected_ids],
        rel_review=[held for key, held in rel_review_map.items() if key not in rel_map],
    )
