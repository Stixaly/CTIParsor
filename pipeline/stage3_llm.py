import json
import os
import re
import time
from typing import cast

import anthropic
from dotenv import load_dotenv
from pydantic import BaseModel, ValidationError
from tenacity import RetryError, retry, retry_if_exception_type, stop_after_attempt, wait_exponential

# Initialize logging
from api.logging_config import get_logger
from models.schemas import EvidenceLabel, RawEntity

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
_MAX_PROMPT_LENGTH = int(os.environ.get("LLM_MAX_PROMPT_LENGTH", "32000"))
# Maximum response length (characters) to prevent overly large responses
_MAX_RESPONSE_LENGTH = int(os.environ.get("LLM_MAX_RESPONSE_LENGTH", "16000"))
# Minimum prompt length to ensure meaningful input
_MIN_PROMPT_LENGTH = 100


def _sanitize_text_for_prompt(text: str, max_length: int = 10000) -> str:
    """
    Sanitize text to prevent prompt injection attacks.

    Args:
        text: The raw text to sanitize
        max_length: Maximum length of the sanitized text

    Returns:
        Sanitized text safe for LLM prompts
    """
    if not text:
        return ""

    # Truncate to max length first
    text = text[:max_length]

    # Remove null bytes and control characters
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)

    # Escape special characters that could be used for prompt injection
    # Replace problematic sequences with safe alternatives
    text = text.replace('\\', '\\\\')  # Escape backslashes

    # Remove markdown code blocks that could hide malicious content
    text = re.sub(r'```[\s\S]*?```', '[code block removed]', text)

    # Remove XML/HTML tags that could be used for injection
    text = re.sub(r'<[^>]+>', '', text)

    # Remove sequences that look like prompt injection attempts
    injection_patterns = [
        r'\b(ignore|forget|disregard)\b.*\b(previous|above|prior)\b',
        r'\brole\s*[:=]\s*system\b',
        r'\buser\s*[:=]\s*assistant\b',
        r'\bassistant\s*[:=]\s*user\b',
        r'\bDAN\b.*\bmode\b',
        r'\bdeveloper\s*mode\b',
        r'\bjailbreak\b',
    ]
    for pattern in injection_patterns:
        text = re.sub(pattern, '[REDACTED]', text, flags=re.IGNORECASE)

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
#   mistral              — Mistral AI API  (OpenAI-compatible endpoint)
#   ollama               — Self-hosted or remote Ollama (OpenAI-compatible)
#
# Each provider is independently configurable via env vars (see .env.example).
# ---------------------------------------------------------------------------

_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic").lower()

# --- Lazy client initialization ---
_anthropic_client = None
_mistral_client = None
_ollama_client = None
_OPENAI_SDK_AVAILABLE = False

try:
    from openai import OpenAI as _OpenAIClient
    _OPENAI_SDK_AVAILABLE = True
except ImportError:
    _OpenAIClient = None          # type: ignore[assignment]


def _get_anthropic_client():
    """Lazily initialize and return Anthropic client."""
    global _anthropic_client
    if _anthropic_client is None:
        _anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        _ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
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
        if _OPENAI_SDK_AVAILABLE and _mistral_key and _OpenAIClient:
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
        if _OPENAI_SDK_AVAILABLE and _OpenAIClient:
            _ollama_client = _OpenAIClient(api_key="ollama", base_url=f"{_ollama_base}/v1")
            return _ollama_client
        return None
    return _ollama_client


def _get_provider_diagnostics():
    """Run startup diagnostics for provider configuration."""
    if _PROVIDER == "anthropic":
        _anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not _anthropic_key:
            logger.warning("LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY not set — stage 3 will be skipped.")
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
    else:
        logger.warning(f"Unknown LLM_PROVIDER='{_PROVIDER}'. Valid values: anthropic | mistral | ollama")


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
    description: str = ""


class RelationshipExtracted(BaseModel):
    source_value: str
    relationship_type: str
    target_value: str
    confidence: float = 0.8
    evidence_text: str | None = None   # verbatim quote from source text
    # How well the source supports this claim.  Defaults to "reported" so older
    # data / models that omit the field validate without error.
    evidence_label: EvidenceLabel = EvidenceLabel.REPORTED


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


# --- Prompts ---

_SYSTEM_PROMPT = """You are a Cyber Threat Intelligence (CTI) expert.
You analyze security report excerpts and extract structured threat intelligence.
The input text may be Markdown-formatted (headers, tables, bullet lists) —
use that structure to identify IoC sections, attribution tables, and TTP lists.

IMPORTANT — Four deterministic/ML NER passes have already run before you:
  1. A regex engine extracted all IoCs (IPs, hashes, domains, CVEs, URLs).
  2. A MITRE ATT&CK gazetteer matched 1,792 known malware families, tools, and
     APT groups against the text with high precision.
  3. A CyNER model (XLM-RoBERTa fine-tuned on cybersecurity corpora) extracted
     malware family names and threat-actor organization names.
  4. A semantic sentence-embedding model (all-MiniLM-L6-v2) matched ATT&CK
     technique descriptions against the text and found TTPs with high cosine-
     similarity confidence.
  All sets are listed in the prompt as "Already detected entities/TTPs".

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
      "description": "brief description of how this technique was used"
    }}
  ],
  "relationships": [
    {{
      "source_value": "exact source entity name (from any detected list)",
      "relationship_type": "uses|attributed-to|targets|delivers|drops|exploits|communicates-with|
beacons-to|exfiltrates-to|compromises|hosts|owns|indicates|mitigates|
remediates|originated-from|authored-by|impersonates|variant-of|
related-to|...",
      "target_value": "exact target entity name (from any detected list)",
      "confidence": 0.0-1.0,
      "evidence_text": "verbatim sentence from the text supporting this relationship",
      "evidence_label": "observed|reported|assessed|inferred|gap"
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


# --- LLM call implementations ---

# Per-request timeout in seconds.  Prevents the pipeline from hanging forever
# if the LLM server stops responding.  Override with LLM_TIMEOUT= in .env.
# Ollama users on slower hardware may need to raise this (e.g. LLM_TIMEOUT=300).
_LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "120"))


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
        _ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
        response = client.messages.create(
            model=_ANTHROPIC_MODEL,
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": user}],
            timeout=_LLM_TIMEOUT,
        )
        elapsed = time.monotonic() - t0
        tokens_out = getattr(getattr(response, "usage", None), "output_tokens", "?")
        logger.debug(f"Anthropic responded in {elapsed:.1f}s ({tokens_out} output tokens)")
        if not response.content:
            logger.error("Anthropic returned an empty content list (possible content filter)")
            return ""
        return response.content[0].text.strip()
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


def _call_anthropic(system: str, user: str) -> str:
    """Call Anthropic with retry logic."""
    try:
        return _call_anthropic_impl(system, user)
    except RetryError as e:
        logger.error(f"Anthropic failed after {_MAX_RETRIES} retries: {e}")
        return ""
    except Exception as e:
        logger.error(f"Anthropic call failed: {e}")
        return ""


@retry(
    retry=retry_if_exception_type(_RETRY_EXCEPTIONS),
    stop=_RETRY_STOP,
    wait=_RETRY_WAIT,
    reraise=True
)
def _call_openai_compatible_impl(client_param, model: str, system: str, user: str, label: str) -> str:
    """Internal implementation of OpenAI-compatible call with retry."""
    if not client_param:
        return ""
    t0 = time.monotonic()
    try:
        response = client_param.chat.completions.create(
            model=model,
            max_tokens=4096,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            timeout=_LLM_TIMEOUT,
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


def _call_openai_compatible(client_param, model: str, system: str, user: str, label: str) -> str:
    """Shared call logic for OpenAI-compatible endpoints (Mistral, Ollama) with retry."""
    try:
        return _call_openai_compatible_impl(client_param, model, system, user, label)
    except RetryError as e:
        logger.error(f"{label} failed after {_MAX_RETRIES} retries: {e}")
        return ""
    except Exception as e:
        logger.error(f"{label} call failed: {e}")
        return ""


def _call_llm(system: str, user: str, provider: str | None = None) -> str:
    """Dispatches to an LLM provider with retry logic.

    `provider` overrides the global LLM_PROVIDER for this call only — used by the
    Stage 3e consensus pass to run the same prompt through a second model.
    """
    # Sanitize ONLY the user message — it embeds untrusted report text, so it is
    # the prompt-injection vector.  The system prompt is developer-controlled;
    # running it through the sanitizer would needlessly escape its content and
    # corrupt the Markdown layout the model relies on.
    #
    # Use the full prompt-length budget (_MAX_PROMPT_LENGTH) here.  The previous
    # default of 10 000 chars silently truncated the assembled prompt — cutting
    # off the JSON output schema at the end of the template for larger chunks —
    # even though enrich_chunk had already validated it against the 32 000 cap.
    sanitized_user = _sanitize_text_for_prompt(user, max_length=_MAX_PROMPT_LENGTH)

    prov = (provider or _PROVIDER).lower()
    if prov == "anthropic":
        return _call_anthropic(system, sanitized_user)
    elif prov == "mistral":
        client = _get_mistral_client()
        _MISTRAL_MODEL = os.environ.get("MISTRAL_MODEL", "mistral-small-latest")
        return _call_openai_compatible(client, _MISTRAL_MODEL, system, sanitized_user, "Mistral")
    elif prov == "ollama":
        client = _get_ollama_client()
        _OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
        return _call_openai_compatible(client, _OLLAMA_MODEL, system, sanitized_user, "Ollama")
    return ""


def _provider_ready(provider: str | None = None) -> bool:
    """Returns False if the given (or global) provider cannot make API calls."""
    prov = (provider or _PROVIDER).lower()
    if prov == "anthropic":
        _anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        return bool(_anthropic_key)
    if prov == "mistral":
        _mistral_key = os.environ.get("MISTRAL_API_KEY", "").strip()
        return _OPENAI_SDK_AVAILABLE and bool(_mistral_key)
    if prov == "ollama":
        return _OPENAI_SDK_AVAILABLE
    return False


# --- LLM output normalisation ---

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
            # Coerce evidence_label to a known value; unknown/missing → "reported"
            # so a malformed label never discards an otherwise-valid relationship.
            _lbl = str(r.get("evidence_label", "")).lower().strip()
            r["evidence_label"] = _lbl if _lbl in {
                "observed", "reported", "assessed", "inferred", "gap"
            } else "reported"
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

def enrich_chunk(
    text: str,
    detected_entities: list[RawEntity],
    gazetteer_entities: list[RawEntity] | None = None,
    semantic_ttp_entities: list[RawEntity] | None = None,
    cyner_entities: list[RawEntity] | None = None,
    doc_context: str | None = None,
    ner_allow_list: set[str] | None = None,
    provider: str | None = None,
) -> LLMEnrichmentResult:
    """
    Enrich a text chunk with LLM intelligence.

    Args:
        text:                   The raw CTI text chunk.
        detected_entities:      Entities from Stage 2 regex (IoCs).
        gazetteer_entities:     Entities from Stage 2b MITRE gazetteer.
        semantic_ttp_entities:  TTPs found by Stage 2c semantic matching.
        cyner_entities:         Entities found by Stage 2d CyNER model.
        doc_context:            Document-level entity summary (ADR-004 P2-B).
                                Passed to every chunk so the LLM can link IoC
                                appendix entries back to the correct malware/actor.
    """
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

    prompt = _USER_PROMPT_TEMPLATE.format(
        text=text,
        doc_context=ctx_summary,
        detected_ioc_entities=ioc_summary,
        detected_gazetteer_entities=gaz_summary,
        detected_semantic_ttps=sem_summary,
    )

    # Validate prompt length
    if len(prompt) > _MAX_PROMPT_LENGTH:
        logger.warning(f"Prompt too long ({len(prompt)} chars > {_MAX_PROMPT_LENGTH} max) — truncating")
        prompt = prompt[:_MAX_PROMPT_LENGTH]
    elif len(prompt) < _MIN_PROMPT_LENGTH:
        logger.warning(f"Prompt too short ({len(prompt)} chars < {_MIN_PROMPT_LENGTH} min) — skipping chunk")
        return LLMEnrichmentResult()

    provider_label = {
        "anthropic": f"Anthropic/{os.environ.get('ANTHROPIC_MODEL', 'claude-sonnet-4-6')}",
        "mistral":   f"Mistral/{os.environ.get('MISTRAL_MODEL', 'mistral-small-latest')}",
        "ollama":    f"Ollama/{os.environ.get('OLLAMA_MODEL', 'llama3.2')}",
    }.get(_PROVIDER, _PROVIDER)
    logger.debug(f"Calling {provider_label} ({len(prompt)} prompt chars)")

    raw_text = _call_llm(_SYSTEM_PROMPT, prompt, provider=provider)
    if not raw_text:
        logger.warning("LLM returned empty response — skipping chunk")
        return LLMEnrichmentResult()

    # Validate response length
    if len(raw_text) > _MAX_RESPONSE_LENGTH:
        logger.warning(f"Response too long ({len(raw_text)} chars > {_MAX_RESPONSE_LENGTH} max) — truncating")
        raw_text = raw_text[:_MAX_RESPONSE_LENGTH]

    # Use raw_decode() to find the first syntactically valid JSON object in
    # the LLM output, ignoring any surrounding prose or markdown fences.
    decoder = json.JSONDecoder()
    parsed_json: dict | None = None
    for i, ch in enumerate(raw_text):
        if ch == "{":
            try:
                obj, _ = decoder.raw_decode(raw_text, i)
                if isinstance(obj, dict):
                    parsed_json = obj
                    break
            except json.JSONDecodeError:
                continue

    # Response was likely cut off by max_tokens — try to repair the dangling
    # structure before giving up on the whole chunk.
    if parsed_json is None:
        completed = _try_complete_truncated_json(raw_text)
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
        return LLMEnrichmentResult()

    # Normalise field names/types before Pydantic validation.
    # Claude sometimes returns richer objects than the schema expects —
    # e.g. {"name": "GREYVIBE", "aliases": []} where a plain string is required,
    # or {"id": "T1587.003", "name": "..."} where "mitre_id"/"technique_name" are
    # expected.  Discarding the whole result on a field-name mismatch would lose
    # all real intelligence from the chunk.  Normalise instead, then validate.
    normalized_json = _normalize_llm_json(parsed_json)
    try:
        result = LLMEnrichmentResult.model_validate(normalized_json)
    except ValidationError as e:
        logger.warning(f"JSON schema validation failed after normalization: {e}")
        return LLMEnrichmentResult()

    # Stage 3b — remove hallucinated entity names not present in the source text.
    # Pass doc_context and ner_allow_list so the filter can short-circuit the
    # O(n) fuzzy scan for names that high-precision NER already confirmed as real.
    from pipeline.stage3b_validate import validate_llm_result
    result = validate_llm_result(
        result, text,
        doc_context=doc_context or "",
        ner_allow_list=ner_allow_list,
    )

    # Stage 3d — self-verification of relationship claims (ADR-004 P3-A)
    # Sends a second LLM call to find the supporting sentence for each relationship.
    # Relationships without textual support are removed (reduces hallucination ~27%→8%).
    # Only runs when ENABLE_STIX_VERIFICATION=true in .env (default: false).
    if result.relationships:
        from pipeline.stage3d_verify import verify_enabled, verify_relationships
        if verify_enabled():
            # verify_relationships() returns `object` to avoid a circular
            # import with LLMEnrichmentResult (defined in this module); it's
            # always an LLMEnrichmentResult at runtime.  Bind the same provider
            # override so verification runs on the model that produced the claims.
            def _verify_call(s, u):
                return _call_llm(s, u, provider=provider)
            result = cast(LLMEnrichmentResult, verify_relationships(text, result, _verify_call))

    return result


def enrich_all_chunks(
    chunks: list[str],
    entities_per_chunk: list[list[RawEntity]],
    gazetteer_entities: list[RawEntity] | None = None,
    cyner_entities: list[RawEntity] | None = None,
    semantic_ttp_entities: list[RawEntity] | None = None,
    doc_context: str | None = None,
    ner_allow_list: set[str] | None = None,
) -> LLMEnrichmentResult:
    """
    CLI-facing wrapper: calls enrich_chunk for each chunk with the same
    quality arguments that the API worker passes.  Previously these were
    silently omitted, so the CLI produced lower-quality output than the API
    (no gazetteer context, no doc_context, no hallucination allow-list).
    """
    all_results = []
    total = len(chunks)

    for i, (chunk, entities) in enumerate(zip(chunks, entities_per_chunk), 1):
        logger.info(f"LLM chunk {i}/{total}...")
        result = enrich_chunk(
            chunk, entities,
            gazetteer_entities=gazetteer_entities,
            cyner_entities=cyner_entities,
            semantic_ttp_entities=semantic_ttp_entities,  # tells LLM which TTPs already found
            doc_context=doc_context,
            ner_allow_list=ner_allow_list,
        )
        all_results.append(result)

    return _merge_results(
        all_results,
        gazetteer_entities=gazetteer_entities,
        semantic_ttp_entities=semantic_ttp_entities,
        cyner_entities=cyner_entities,
    )


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
                ttp_map[t.mitre_id] = t
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
            rel_map[key] = rel

    ioc_map: dict[tuple, IoCAssociation] = {}
    for r in results:
        for assoc in r.ioc_associations:
            if not assoc.ioc_value or not assoc.malware_name:
                continue
            # Distinct variable name from `key` above — mypy infers a
            # variable's type from its first assignment (a 3-tuple there),
            # so reusing it for this 2-tuple would be a type error.
            ioc_key = (assoc.ioc_value.lower(), assoc.malware_name.lower())
            ioc_map[ioc_key] = assoc

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
    )
