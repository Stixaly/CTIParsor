# tests/test_vlm.py
from __future__ import annotations

import json

import pytest

from pipeline import vlm
from pipeline.vlm import (
    PROMPT,
    FigureEdge,
    OpenAICompatVisionBackend,
    _ollama_concurrency,
    _parse_payload,
    _to_read,
    get_backend,
    reset_backend_cache,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    reset_backend_cache()
    monkeypatch.delenv("VISION_PROVIDER", raising=False)
    monkeypatch.delenv("VISION_MODEL", raising=False)
    monkeypatch.delenv("VISION_TIMEOUT_S", raising=False)
    # Without this, a developer who has waived the probe in their own shell makes
    # every capability test pass for the wrong reason — available() would return
    # True before reaching the code under test.
    monkeypatch.delenv("VISION_ASSUME_CAPABLE", raising=False)
    yield
    reset_backend_cache()

def test_parse_payload_strips_markdown_fence():
    raw = "```json\n{\"a\": 1}\n```"
    assert _parse_payload(raw) == {"a": 1}

def test_parse_payload_recovers_json_with_leading_prose():
    raw = 'Here it is: {"a": 1} hope that helps'
    assert _parse_payload(raw) == {"a": 1}

def test_parse_payload_rejects_non_object():
    with pytest.raises(ValueError):
        _parse_payload("[1, 2]")

def test_to_read_falls_back_to_none_on_unknown_kind():
    data = {"figure_kind": "diagram-of-doom", "verbatim_text": [], "edges": [], "iocs": []}
    r = _to_read(data, "p", "m", 0.0, None, None)
    assert r.kind == "none"

def test_to_read_drops_non_string_verbatim_entries():
    data = {"figure_kind": "none", "verbatim_text": ["ok", 42, None], "edges": [], "iocs": []}
    r = _to_read(data, "p", "m", 0.0, None, None)
    assert r.verbatim_text == ["ok"]

def test_to_read_survives_verbatim_text_that_is_not_a_list():
    data = {"figure_kind": "none", "verbatim_text": "oops", "edges": [], "iocs": []}
    r = _to_read(data, "p", "m", 0.0, None, None)
    assert r.verbatim_text == []

def test_to_read_drops_edges_missing_src_or_dst():
    data = {
        "figure_kind": "none",
        "verbatim_text": [],
        "edges": [
            {"src": "a", "dst": "b", "label": "x"},
            {"src": "a"},
            "nope",
            {"src": "", "dst": "b"}
        ],
        "iocs": []
    }
    r = _to_read(data, "p", "m", 0.0, None, None)
    assert r.edges == [FigureEdge("a", "b", "x")]

def test_to_read_coerces_non_string_edge_label():
    data = {
        "figure_kind": "none",
        "verbatim_text": [],
        "edges": [{"src": "a", "dst": "b", "label": 7}],
        "iocs": []
    }
    r = _to_read(data, "p", "m", 0.0, None, None)
    assert r.edges == [FigureEdge("a", "b", "")]

def test_get_backend_returns_none_when_provider_unset():
    assert get_backend() is None

def test_get_backend_returns_none_for_mistral_without_model(monkeypatch):
    monkeypatch.setenv("VISION_PROVIDER", "mistral")
    assert get_backend() is None

def test_get_backend_returns_none_when_capability_probe_says_no(monkeypatch):
    monkeypatch.setenv("VISION_PROVIDER", "ollama")
    monkeypatch.setenv("VISION_MODEL", "llama3.2")

    def fake_get(url, headers, timeout):
        return {"models": [{"name": "llama3.2:latest", "capabilities": ["completion"]}]}

    monkeypatch.setattr("pipeline.vlm._http_get_json", fake_get)
    assert get_backend() is None

def test_get_backend_accepts_ollama_model_with_vision_capability(monkeypatch):
    monkeypatch.setenv("VISION_PROVIDER", "ollama")
    monkeypatch.setenv("VISION_MODEL", "qwen3.8")

    def fake_get(url, headers, timeout):
        return {"models": [{"name": "qwen3.8:latest", "capabilities": ["completion", "vision"]}]}

    monkeypatch.setattr("pipeline.vlm._http_get_json", fake_get)
    b = get_backend()
    assert b is not None
    assert b.name == "ollama"
    # Stays 1 where anthropic and mistral run 4. ADR-0033 §5 set it there (one
    # GPU, shared with the delegation workflow); measurement agrees separately:
    # raising it to 4 on the reference station overlapped the work (1.89x) but
    # inflated each call from ~43s to ~127s, so throughput per figure got WORSE
    # (40.9s against 36.3s). The station is bandwidth-bound on this workload.
    assert b.max_concurrency == 1


def test_ollama_concurrency_is_configurable(monkeypatch):
    """The right value is a property of the server, so it has to be overridable."""
    monkeypatch.setenv("VISION_PROVIDER", "ollama")
    monkeypatch.setenv("VISION_MODEL", "qwen3.8")
    monkeypatch.setenv("VISION_CONCURRENCY", "4")

    def fake_get(url, headers, timeout):
        return {"models": [{"name": "qwen3.8:latest", "capabilities": ["completion", "vision"]}]}

    monkeypatch.setattr("pipeline.vlm._http_get_json", fake_get)
    reset_backend_cache()
    b = get_backend()
    assert b is not None
    assert b.max_concurrency == 4


def test_ollama_concurrency_rejects_nonsense(monkeypatch):
    """A bad value must fall back, never crash the stage or yield 0 workers."""
    monkeypatch.setenv("VISION_CONCURRENCY", "abc")
    assert _ollama_concurrency() == 1
    monkeypatch.setenv("VISION_CONCURRENCY", "0")
    assert _ollama_concurrency() == 1


def test_openai_compat_read_figure_returns_unread_on_http_error(monkeypatch):
    b = OpenAICompatVisionBackend("ollama", "http://x/v1", "qwen3.8", api_key="ollama")

    def fake_post(url, payload, headers, timeout):
        raise RuntimeError("HTTP 400: nope")

    monkeypatch.setattr("pipeline.vlm._http_json", fake_post)
    r = b.read_figure(b"notapng")
    assert r.kind == "unread"
    assert "HTTP 400" in r.error
    assert r.verbatim_text == []
    assert r.edges == []
    assert r.iocs == []

def test_openai_compat_read_figure_parses_a_good_response(monkeypatch):
    b = OpenAICompatVisionBackend("ollama", "http://x/v1", "qwen3.8", api_key="ollama")

    def fake_post(url, payload, headers, timeout):
        return {
            "choices": [
                {"message": {"content": json.dumps({
                    "figure_kind": "none", "verbatim_text": ["hello"],
                    "edges": [], "iocs": [],
                })}}
            ],
            "usage": {"prompt_tokens": 11, "completion_tokens": 22}
        }

    monkeypatch.setattr("pipeline.vlm._http_json", fake_post)
    r = b.read_figure(b"notapng")
    assert r.kind == "none"
    assert r.verbatim_text == ["hello"]
    assert r.edges == []
    assert r.iocs == []
    assert r.input_tokens == 11
    assert r.output_tokens == 22

def test_prompt_forbids_inferring_edges_from_adjacency():
    assert "adjacent" in PROMPT


def test_anthropic_probe_reads_pydantic_capabilities(monkeypatch):
    """The SDK returns a non-subscriptable ModelCapabilities, not a dict.

    Locked because the first implementation used `caps["image_input"]` and every
    Anthropic probe failed with a TypeError — which disabled the stage rather
    than mis-enabling it, but disabled it for the wrong reason.
    """
    class _Caps:
        def model_dump(self):
            return {"image_input": {"supported": True}}

    class _Model:
        capabilities = _Caps()

    class _Models:
        def retrieve(self, _model):
            return _Model()

    class _Client:
        models = _Models()

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    backend = vlm.AnthropicVisionBackend("claude-haiku-4-5")
    monkeypatch.setattr(backend, "_get_client", lambda: _Client())
    assert backend.available() is True
