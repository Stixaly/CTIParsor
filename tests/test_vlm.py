# tests/test_vlm.py
from __future__ import annotations

import io
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
    # Same reason: stage3_llm's load_dotenv() can put a developer's vLLM
    # settings into the test process.
    monkeypatch.delenv("VLLM_MODEL", raising=False)
    monkeypatch.delenv("VLLM_BASE_URL", raising=False)
    monkeypatch.delenv("VLLM_ENABLE_THINKING", raising=False)
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
    # GPU, shared with other local workloads); measurement agrees separately:
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


def _vllm_server(monkeypatch, served, post_error=None):
    """Fake a vLLM server serving `served` ids; every GET and POST is recorded."""
    calls: dict[str, list] = {"get": [], "post": []}

    def fake_get(url, headers, timeout):
        calls["get"].append(url)
        return {"object": "list", "data": [{"id": m, "object": "model"} for m in served]}

    def fake_post(url, payload, headers, timeout):
        calls["post"].append((url, payload))
        if post_error:
            raise RuntimeError(post_error)
        return {"choices": [{"message": {"content": "A"}}]}

    monkeypatch.setattr("pipeline.vlm._http_get_json", fake_get)
    monkeypatch.setattr("pipeline.vlm._http_json", fake_post)
    return calls


def test_get_backend_vllm_reuses_the_stage3_server_and_model(monkeypatch):
    monkeypatch.setenv("VISION_PROVIDER", "vllm")
    monkeypatch.setenv("VLLM_BASE_URL", "http://gpu:8000/")
    monkeypatch.setenv("VLLM_MODEL", "Inferact/Qwen3.8-27B-NVFP4")
    monkeypatch.delenv("VISION_CONCURRENCY", raising=False)
    calls = _vllm_server(monkeypatch, ["Inferact/Qwen3.8-27B-NVFP4"])

    b = get_backend()
    assert b is not None
    assert (b.name, b.model, b.max_concurrency) == ("vllm", "Inferact/Qwen3.8-27B-NVFP4", 1)
    assert calls["get"] == ["http://gpu:8000/v1/models"]
    # vLLM publishes no capability flag, so the probe sends one real image.
    (url, payload), = calls["post"]
    assert url == "http://gpu:8000/v1/chat/completions"
    assert payload["max_tokens"] == 1
    assert payload["messages"][0]["content"][1]["type"] == "image_url"
    assert payload["chat_template_kwargs"] == {"enable_thinking": False}


def test_vllm_probe_names_the_served_models_when_the_name_is_wrong(monkeypatch, caplog):
    """vLLM matches the name exactly: the bare name 404s on every read."""
    monkeypatch.setenv("VISION_PROVIDER", "vllm")
    monkeypatch.setenv("VISION_MODEL", "Qwen3.8-27B-NVFP4")
    calls = _vllm_server(monkeypatch, ["Inferact/Qwen3.8-27B-NVFP4"])

    with caplog.at_level("WARNING"):
        assert get_backend() is None
    assert "Inferact/Qwen3.8-27B-NVFP4" in caplog.text
    assert calls["post"] == []  # no image goes to a model the server does not have


def test_vllm_probe_rejects_a_model_that_refuses_images(monkeypatch):
    monkeypatch.setenv("VISION_PROVIDER", "vllm")
    monkeypatch.setenv("VLLM_MODEL", "text-only")
    _vllm_server(monkeypatch, ["text-only"],
                 post_error="HTTP 400: At most 0 image(s) may be provided in one prompt.")
    assert get_backend() is None


def test_get_backend_vllm_needs_a_model_name(monkeypatch):
    monkeypatch.setenv("VISION_PROVIDER", "vllm")
    assert get_backend() is None


@pytest.mark.parametrize("flag, expected", [(None, False), ("true", True), ("off", False)])
def test_vllm_read_figure_sends_the_thinking_switch(monkeypatch, flag, expected):
    monkeypatch.setenv("VISION_PROVIDER", "vllm")
    monkeypatch.setenv("VLLM_MODEL", "m")
    monkeypatch.setenv("VISION_ASSUME_CAPABLE", "1")
    if flag is not None:
        monkeypatch.setenv("VLLM_ENABLE_THINKING", flag)
    b = get_backend()
    assert b is not None

    sent: dict = {}

    def fake_post(url, payload, headers, timeout):
        sent.update(payload)
        return {"choices": [{"message": {"content": json.dumps({
            "figure_kind": "screenshot", "verbatim_text": ["x"], "edges": [], "iocs": [],
        })}}]}

    monkeypatch.setattr("pipeline.vlm._http_json", fake_post)
    assert b.read_figure(b"png").kind == "screenshot"
    assert sent["chat_template_kwargs"] == {"enable_thinking": expected}
    # The schema contract is untouched by the extra field.
    assert sent["response_format"]["type"] == "json_schema"


def test_ollama_read_figure_sends_no_chat_template_kwargs(monkeypatch):
    b = OpenAICompatVisionBackend("ollama", "http://x/v1", "qwen3.8", api_key="ollama")
    sent: dict = {}

    def fake_post(url, payload, headers, timeout):
        sent.update(payload)
        return {"choices": [{"message": {"content": "{}"}}]}

    monkeypatch.setattr("pipeline.vlm._http_json", fake_post)
    b.read_figure(b"png")
    assert "chat_template_kwargs" not in sent


def test_blank_png_decodes_and_clears_the_qwen_patch_size():
    """A 1 px probe would be refused by Qwen-VL's processor and read as blindness."""
    image_mod = pytest.importorskip("PIL.Image")
    img = image_mod.open(io.BytesIO(vlm._blank_png()))
    img.load()
    assert img.size == (64, 64)
