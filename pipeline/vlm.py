# pipeline/vlm.py
from __future__ import annotations

import base64
import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

try:
    import anthropic
except ImportError:
    anthropic = None

logger = logging.getLogger(__name__)

# The JSON contract every provider must return.  Passed to each provider's own
# structured-output mechanism, which is what keeps the keys stable: measured on
# Ollama, `response_format: json_object` invented the key `first_2_text_lines`
# where the schema form returned the requested `lines`.
FIGURE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "figure_kind": {
            "type": "string",
            "enum": ["network-diagram", "attack-chain", "screenshot",
                     "code-listing", "table", "chart", "logo", "none"],
        },
        "verbatim_text": {"type": "array", "items": {"type": "string"}},
        "edges": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "src": {"type": "string"},
                    "dst": {"type": "string"},
                    "label": {"type": "string"},
                },
                "required": ["src", "dst", "label"],
                "additionalProperties": False,
            },
        },
        "iocs": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["figure_kind", "verbatim_text", "edges", "iocs"],
    "additionalProperties": False,
}

FIGURE_KINDS: frozenset[str] = frozenset(
    FIGURE_SCHEMA["properties"]["figure_kind"]["enum"]
)

# Bumped whenever PROMPT or FIGURE_SCHEMA changes; part of the read cache key so
# a stored read is never served against a contract it did not answer.
PROMPT_VERSION = 1

PROMPT = """You are reading one figure cropped from a cyber threat intelligence report.

Transcribe what the image shows. Do not interpret, summarise or explain.

- verbatim_text: every text string visible in the figure, exactly as written,
  in reading order. Preserve redaction markers as [REDACTED]. Preserve command
  syntax, paths and indentation exactly.
- edges: only for figure_kind "network-diagram" or "attack-chain", and only
  where the figure DRAWS a connector between two labelled nodes. An empty list
  otherwise. Never infer an edge from two elements merely being adjacent.
- iocs: any IP, domain, URL, hash, file name, file path, registry key or mutex
  visible in the figure.

If the image carries no figure - a logo, a page header or footer, boilerplate,
a decorative banner - return figure_kind "none" or "logo" with empty lists."""

# Vision model defaults per provider.  `mistral` has NO default on purpose: the
# vision-capable model names were not verified against a live account, and an
# invented default would fail the capability probe with a confusing message
# instead of an actionable one.
_DEFAULT_MODEL: dict[str, str] = {
    "anthropic": "claude-haiku-4-5",
    "ollama": "qwen3.8",
}

_MISTRAL_BASE = "https://api.mistral.ai/v1"

# Ollama's OpenAI-compatible route ignores `think: false`, so a thinking model
# spends the token budget on reasoning before it writes any JSON.  Budget high.
_MAX_TOKENS = 4000


@dataclass(frozen=True)
class FigureEdge:
    src: str
    dst: str
    label: str = ""


@dataclass(frozen=True)
class FigureRead:
    kind: str
    verbatim_text: list[str]
    edges: list[FigureEdge]
    iocs: list[str]
    provider: str
    model: str
    elapsed_s: float
    input_tokens: int | None = None
    output_tokens: int | None = None
    error: str | None = None


def _http_json(url: str, payload: dict, headers: dict[str, str], timeout: float) -> dict:
    """POST JSON and return the decoded response."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"HTTP {e.code}: {body}") from e


def _http_get_json(url: str, headers: dict[str, str], timeout: float) -> dict:
    """GET JSON and return the decoded response."""
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"HTTP {e.code}: {body}") from e


def _parse_payload(raw: str) -> dict:
    """Extract and parse a JSON object from raw model output."""
    s = raw.strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if len(lines) > 1:
            s = "\n".join(lines[1:])
        if s.rstrip().endswith("```"):
            s = s.rstrip()[:-3].rstrip()

    if not s.startswith("{"):
        start = s.find("{")
        end = s.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("No JSON object found")
        s = s[start:end + 1]

    try:
        data = json.loads(s)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Parsed JSON is not an object")

    return data


def _to_read(data: dict, provider: str, model: str, elapsed: float,
             in_tok: int | None, out_tok: int | None) -> FigureRead:
    """Convert raw model data into a validated FigureRead."""
    kind = data.get("figure_kind")
    if not isinstance(kind, str) or kind not in FIGURE_KINDS:
        kind = "none"

    vt_raw = data.get("verbatim_text")
    verbatim_text = [x for x in vt_raw if isinstance(x, str)] if isinstance(vt_raw, list) else []

    iocs_raw = data.get("iocs")
    iocs = [x for x in iocs_raw if isinstance(x, str)] if isinstance(iocs_raw, list) else []

    edges_raw = data.get("edges")
    edges: list[FigureEdge] = []
    if isinstance(edges_raw, list):
        for e in edges_raw:
            if not isinstance(e, dict):
                continue
            src = e.get("src")
            dst = e.get("dst")
            if not isinstance(src, str) or not src or not isinstance(dst, str) or not dst:
                continue
            label = e.get("label")
            if not isinstance(label, str):
                label = ""
            edges.append(FigureEdge(src=src, dst=dst, label=label))

    return FigureRead(
        kind=kind,
        verbatim_text=verbatim_text,
        edges=edges,
        iocs=iocs,
        provider=provider,
        model=model,
        elapsed_s=elapsed,
        input_tokens=in_tok,
        output_tokens=out_tok,
        error=None
    )


def _unread(provider: str, model: str, elapsed: float, error: str) -> FigureRead:
    """Create a FigureRead representing a failed read."""
    return FigureRead(
        kind="unread",
        verbatim_text=[],
        edges=[],
        iocs=[],
        provider=provider,
        model=model,
        elapsed_s=elapsed,
        input_tokens=None,
        output_tokens=None,
        error=error
    )


class VisionBackend(Protocol):
    name: str
    model: str
    max_concurrency: int
    def available(self) -> bool: ...
    def read_figure(self, png: bytes, prompt: str = PROMPT) -> FigureRead: ...


class AnthropicVisionBackend:
    def __init__(self, model: str, timeout: float = 120.0):
        self.name = "anthropic"
        self.model = model
        self.timeout = timeout
        self.max_concurrency = 4
        self._client = None
        self._available = None

    def _get_client(self):
        if self._client is None:
            if anthropic is None:
                raise RuntimeError("anthropic SDK not installed")
            self._client = anthropic.Anthropic()
        return self._client

    def available(self) -> bool:
        if self._available is not None:
            return self._available
        if anthropic is None or not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            self._available = False
            return False
        if _assume_capable():
            logger.warning(
                "VISION_ASSUME_CAPABLE set — skipping the image_input probe for %s",
                self.model,
            )
            self._available = True
            return True
        try:
            caps = self._get_client().models.retrieve(self.model).capabilities
            # The SDK returns a Pydantic `ModelCapabilities`, not a dict — it is
            # not subscriptable.  `model_dump()` is recursive, so one call gives
            # plain nested dicts; the isinstance branch keeps a raw dict working
            # if the SDK ever returns one.
            if not isinstance(caps, dict) and hasattr(caps, "model_dump"):
                caps = caps.model_dump()
            ok = bool((caps.get("image_input") or {}).get("supported"))
        except Exception as e:
            # The message is the whole value of this probe: without it a
            # misconfiguration reads as "unavailable" and gives no way to tell a
            # wrong model name from a wrong key from a text-only model.
            logger.warning(
                "Vision capability probe failed for anthropic/%s: %s: %s",
                self.model, type(e).__name__, e,
            )
            ok = False
        self._available = ok
        return ok

    def read_figure(self, png: bytes, prompt: str = PROMPT) -> FigureRead:
        t0 = time.monotonic()
        try:
            b64 = base64.b64encode(png).decode("ascii")
            response = self._get_client().messages.create(
                model=self.model,
                max_tokens=_MAX_TOKENS,
                output_config={"format": {"type": "json_schema", "schema": FIGURE_SCHEMA}},
                messages=[{"role": "user", "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": b64}},
                    {"type": "text", "text": prompt}
                ]}]
            )
            text = "".join(b.text for b in response.content if b.type == "text")
            data = _parse_payload(text)
            elapsed = time.monotonic() - t0
            return _to_read(data, self.name, self.model, elapsed,
                            response.usage.input_tokens, response.usage.output_tokens)
        except Exception as e:
            elapsed = time.monotonic() - t0
            return _unread(self.name, self.model, elapsed, f"{type(e).__name__}: {e}")


class OpenAICompatVisionBackend:
    def __init__(self, name: str, base_url: str, model: str,
                 api_key: str | None = None, timeout: float = 120.0,
                 max_concurrency: int = 1):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self._available = None

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def available(self) -> bool:
        if self._available is not None:
            return self._available
        if _assume_capable():
            logger.warning(
                "VISION_ASSUME_CAPABLE set — skipping the vision probe for %s/%s",
                self.name, self.model,
            )
            self._available = True
            return True
        try:
            if self.name == "ollama":
                root = self.base_url
                if root.endswith("/v1"):
                    root = root[:-3]
                data = _http_get_json(f"{root}/api/tags", self._headers(), self.timeout)
                models = data.get("models", [])
                entry = None
                wanted = {self.model, f"{self.model}:latest"}
                for m in models:
                    if not isinstance(m, dict):
                        continue
                    # Check BOTH keys, not `name or model`: a short-circuit on a
                    # present-but-different `name` would skip a matching `model`.
                    if wanted & {m.get("name"), m.get("model")}:
                        entry = m
                        break
                if entry is None:
                    available_names = [
                        m.get("name") for m in models if isinstance(m, dict)
                    ]
                    logger.warning(
                        "Ollama model %s not found at %s — pulled models: %s",
                        self.model, root, available_names,
                    )
                    self._available = False
                    return False
                ok = "vision" in (entry.get("capabilities") or [])
                if not ok:
                    logger.warning(
                        "Ollama model %s has no `vision` capability (has: %s)",
                        self.model, entry.get("capabilities"),
                    )
            else:
                if not self.api_key:
                    logger.warning("%s vision backend needs an API key", self.name)
                    self._available = False
                    return False
                data = _http_get_json(
                    f"{self.base_url}/models/{self.model}", self._headers(), self.timeout
                )
                ok = bool((data.get("capabilities") or {}).get("vision"))
        except Exception as e:
            logger.warning(
                "Vision capability probe failed for %s/%s: %s: %s",
                self.name, self.model, type(e).__name__, e,
            )
            ok = False
        self._available = ok
        return ok

    def read_figure(self, png: bytes, prompt: str = PROMPT) -> FigureRead:
        t0 = time.monotonic()
        try:
            b64 = base64.b64encode(png).decode("ascii")
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64," + b64}}
                ]}],
                "max_tokens": _MAX_TOKENS,
                "temperature": 0,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "figure_read",
                        "schema": FIGURE_SCHEMA,
                        "strict": True,
                    },
                },
            }
            out = _http_json(f"{self.base_url}/chat/completions", payload, self._headers(), self.timeout)
            text = out["choices"][0]["message"]["content"]
            usage = out.get("usage") or {}
            in_tok = usage.get("prompt_tokens")
            out_tok = usage.get("completion_tokens")
            data = _parse_payload(text)
            elapsed = time.monotonic() - t0
            return _to_read(data, self.name, self.model, elapsed, in_tok, out_tok)
        except Exception as e:
            elapsed = time.monotonic() - t0
            return _unread(self.name, self.model, elapsed, f"{type(e).__name__}: {e}")


_UNSET = object()
_backend_cache = _UNSET


def _assume_capable() -> bool:
    """True when the operator has explicitly waived the vision capability probe.

    The probe is the guard that stops an image reaching a text-only model, which
    answers by inventing rather than by failing.  It is waivable because not
    every provider publishes a readable capability endpoint — Mistral's
    `/v1/models` response schema is undocumented — and a provider we cannot
    interrogate should not be unusable to someone who knows their model sees.

    Deliberately an env var with no default and no per-provider variant: waiving
    it is a decision an operator makes once, knowingly, for their own deployment.
    """
    return os.environ.get("VISION_ASSUME_CAPABLE", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _ollama_concurrency() -> int:
    """How many figure reads to keep in flight against Ollama.

    Stays at 1 where `anthropic` and `mistral` run 4. ADR-0033 §5 set it there
    because the single GPU is also the delegation target the project's workflow
    depends on; the numbers below are the independent second reason, measured
    rather than assumed. On the reference station (27B Q4 on a DGX GB10),
    raising it to 4 did overlap the work — the per-call times summed to 1392.7s
    inside 737s of wall clock, so 1.89x of real concurrency — but each call
    inflated from ~43s to ~127s, and throughput per figure came out slightly
    WORSE: 40.9s against 36.3s sequential.

    A synthetic benchmark says the opposite (2.34x on two 120-token text
    generations) and is worth distrusting: a figure read ships a 600-2400 token
    image and generates hundreds of tokens back, so four in flight contend for
    memory bandwidth rather than filling an idle pipe. The station is
    bandwidth-bound on this workload, not latency-bound.

    Kept configurable because the right number is a property of the server, not
    of this client — a hosted endpoint or a multi-GPU host will want more.
    Beyond its own `OLLAMA_NUM_PARALLEL`, Ollama queues, and a queued request
    still burns `VISION_TIMEOUT_S`.
    """
    raw = os.environ.get("VISION_CONCURRENCY", "").strip()
    if not raw:
        return 1
    try:
        n = int(raw)
    except ValueError:
        logger.warning("VISION_CONCURRENCY=%r is not an integer — using 1", raw)
        return 1
    if n < 1:
        logger.warning("VISION_CONCURRENCY=%d is below 1 — using 1", n)
        return 1
    return n


def get_backend() -> VisionBackend | None:
    """Get or create the configured vision backend."""
    global _backend_cache
    if _backend_cache is not _UNSET:
        return _backend_cache

    provider = os.environ.get("VISION_PROVIDER", "none").strip().lower()
    if provider in ("", "none"):
        logger.info("VISION_PROVIDER not set - Stage 1f disabled")
        _backend_cache = None
        return None

    valid_providers = ["anthropic", "mistral", "ollama"]
    if provider not in valid_providers:
        logger.warning("Unknown VISION_PROVIDER %s. Valid: %s", provider, valid_providers)
        _backend_cache = None
        return None

    model = os.environ.get("VISION_MODEL", "").strip()
    if not model:
        model = _DEFAULT_MODEL.get(provider, "")
        if not model:
            logger.warning(
                "VISION_PROVIDER=%s requires VISION_MODEL to be set — no default "
                "vision model is assumed for this provider", provider,
            )
            _backend_cache = None
            return None

    try:
        timeout = float(os.environ.get("VISION_TIMEOUT_S", "120.0"))
    except ValueError:
        timeout = 120.0

    if provider == "anthropic":
        backend: VisionBackend = AnthropicVisionBackend(model, timeout)
    elif provider == "ollama":
        base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        backend = OpenAICompatVisionBackend(
            "ollama", f"{base}/v1", model,
            api_key="ollama", timeout=timeout, max_concurrency=_ollama_concurrency(),
        )
    else: # mistral
        api_key = os.environ.get("MISTRAL_API_KEY", "")
        backend = OpenAICompatVisionBackend(
            "mistral", _MISTRAL_BASE, model,
            api_key=api_key, timeout=timeout, max_concurrency=4,
        )

    if not backend.available():
        logger.warning("Vision backend %s/%s unavailable - Stage 1f will be skipped", provider, model)
        _backend_cache = None
        return None

    logger.info("Vision backend ready: %s/%s", provider, model)
    _backend_cache = backend
    return backend

def reset_backend_cache() -> None:
    """Reset the backend cache."""
    global _backend_cache
    _backend_cache = _UNSET


def _main(argv: list[str] | None = None) -> int:
    """Config check: report what the current environment resolves to.

    `python -m pipeline.vlm [figure.png]` — answers "will Stage 1f run, and if
    not, why" without starting the pipeline.  Pass a PNG to also perform one
    real read against the configured backend.
    """
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    argv = sys.argv[1:] if argv is None else argv

    provider = os.environ.get("VISION_PROVIDER", "none").strip().lower() or "none"
    model = os.environ.get("VISION_MODEL", "").strip() or _DEFAULT_MODEL.get(provider, "")
    print(f"VISION_PROVIDER = {provider}")
    print(f"VISION_MODEL    = {model or '(unset, no default for this provider)'}")
    print(f"probe waived    = {_assume_capable()}")

    backend = get_backend()
    if backend is None:
        print("\nRESULT: no usable vision backend — Stage 1f would be skipped.")
        print("The warning above says why.")
        return 1

    print(f"\nRESULT: {backend.name}/{backend.model} is ready "
          f"(max_concurrency={backend.max_concurrency}).")

    if not argv:
        print("Pass a PNG path to perform one real read.")
        return 0

    from pathlib import Path
    png = Path(argv[0])
    if not png.is_file():
        print(f"No such file: {png}")
        return 1

    read = backend.read_figure(png.read_bytes())
    print(f"\n{png.name}: kind={read.kind} in {read.elapsed_s:.1f}s "
          f"(in={read.input_tokens} out={read.output_tokens})")
    if read.error:
        print(f"error: {read.error}")
        return 1
    print(f"{len(read.verbatim_text)} text runs, {len(read.edges)} edges, "
          f"{len(read.iocs)} observables")
    for line in read.verbatim_text[:8]:
        print(f"  | {line[:100]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
