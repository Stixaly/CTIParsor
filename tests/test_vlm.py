# tests/test_vlm.py
from __future__ import annotations

import io
import json
import logging
import re
import urllib.error

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
    # `auto` follows the text provider; a test about it sets it.
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    # `python -m pipeline.vlm` reads the repository's .env; not in a test.
    monkeypatch.setattr(vlm, "load_dotenv", lambda *args, **kwargs: False)
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

def test_get_backend_returns_none_when_provider_is_none(monkeypatch):
    monkeypatch.setenv("VISION_PROVIDER", "none")
    assert get_backend() is None
    assert vlm.skip_reason() == "VISION_PROVIDER=none"

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

def test_openai_compat_read_figure_names_a_null_answer_cut_at_max_tokens(monkeypatch):
    b = OpenAICompatVisionBackend("ollama", "http://x/v1", "qwen3.8", api_key="ollama")

    def fake_post(url, payload, headers, timeout):
        return {"choices": [{"message": {"content": None}, "finish_reason": "length"}]}

    monkeypatch.setattr("pipeline.vlm._http_json", fake_post)
    r = b.read_figure(b"notapng")
    assert r.kind == "unread"
    assert "finish_reason=length" in r.error

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


def test_a_vision_provider_url_must_be_http(monkeypatch):
    """The base URLs come from settings; a file: one must not read local files."""
    opened = []
    monkeypatch.setattr("pipeline.vlm.urllib.request.urlopen", lambda *a, **k: opened.append(a))
    for url in ("file:///etc/passwd", "ftp://host/models", "gopher://x"):
        with pytest.raises(ValueError, match="http"):
            vlm._http_get_json(url, {}, 1.0)
        with pytest.raises(ValueError, match="http"):
            vlm._http_json(url, {}, {}, 1.0)
    assert opened == []


# ── VISION_PROVIDER=auto: the provider chosen for the text (ADR-0094, decision 14) ──

@pytest.fixture()
def builds(monkeypatch):
    """The names of the backends built, in order: `auto` must build the text
    provider's and no other."""
    built: list[str] = []
    for cls in (vlm.AnthropicVisionBackend, vlm.OpenAICompatVisionBackend):
        original = cls.__init__

        def spy(self, *args, _original=original, **kwargs):
            _original(self, *args, **kwargs)
            built.append(self.name)

        monkeypatch.setattr(cls, "__init__", spy)
    return built


def _every_model_sees(monkeypatch):
    """Both backends pass their capability probe, without a request."""
    monkeypatch.setattr(vlm.AnthropicVisionBackend, "available", lambda self: True)
    monkeypatch.setattr(vlm.OpenAICompatVisionBackend, "available", lambda self: True)


def _ollama_tags(monkeypatch, model="qwen3.8", capabilities=("completion", "vision")):
    def fake_get(url, headers, timeout):
        return {"models": [{"name": f"{model}:latest", "capabilities": list(capabilities)}]}

    monkeypatch.setattr("pipeline.vlm._http_get_json", fake_get)


def test_the_text_provider_default_is_the_one_stage3_uses():
    """`auto` reads LLM_PROVIDER without importing stage3_llm (the LLM stack);
    the two defaults must not drift apart."""
    from pathlib import Path

    # Read, not imported: importing stage3_llm loads the developer's .env.
    source = (Path(vlm.__file__).parent / "stage3_llm.py").read_text(encoding="utf-8")
    found = re.search(r'os\.environ\.get\("LLM_PROVIDER",\s*"([^"]*)"\)\.lower\(\)', source)
    assert found is not None, "stage3_llm no longer reads LLM_PROVIDER this way; update vlm._text_provider"
    assert vlm._TEXT_PROVIDER_DEFAULT == found.group(1)


@pytest.mark.parametrize("setting", [None, "", "   ", "auto", "AUTO"])
def test_an_unset_or_empty_vision_provider_is_auto(monkeypatch, builds, setting):
    if setting is not None:
        monkeypatch.setenv("VISION_PROVIDER", setting)
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    _ollama_tags(monkeypatch)
    b = get_backend()
    assert b is not None and (b.name, b.model) == ("ollama", "qwen3.8")
    assert builds == ["ollama"]
    assert vlm.skip_reason() == ""


def test_auto_with_anthropic_reads_with_the_default_vision_model(monkeypatch, builds):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    _every_model_sees(monkeypatch)
    b = get_backend()
    assert isinstance(b, vlm.AnthropicVisionBackend)
    assert (b.name, b.model, b.max_concurrency) == ("anthropic", "claude-haiku-5-5", 4)
    assert builds == ["anthropic"]


def test_auto_with_llm_provider_unset_is_anthropic_as_stage3_is(monkeypatch, builds):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    _every_model_sees(monkeypatch)
    b = get_backend()
    assert b is not None and b.name == "anthropic"


def test_auto_takes_vision_model_and_timeout_like_a_named_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("VISION_MODEL", "claude-sonnet-4-5")
    monkeypatch.setenv("VISION_TIMEOUT_S", "30")
    _every_model_sees(monkeypatch)
    b = get_backend()
    assert isinstance(b, vlm.AnthropicVisionBackend)
    assert (b.model, b.timeout) == ("claude-sonnet-4-5", 30.0)


def test_auto_with_anthropic_and_no_key_is_skipped_and_says_so(monkeypatch, caplog):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    with caplog.at_level(logging.INFO, logger="pipeline.vlm"):
        assert get_backend() is None
    assert vlm.skip_reason() == "auto: anthropic/claude-haiku-5-5 unavailable (no ANTHROPIC_API_KEY)"
    assert [r.levelno for r in caplog.records] == [logging.INFO]
    assert "no ANTHROPIC_API_KEY" in caplog.text


def test_auto_with_vllm_probes_and_reads_with_the_text_model(monkeypatch, builds):
    monkeypatch.setenv("LLM_PROVIDER", "vllm")
    monkeypatch.setenv("VLLM_BASE_URL", "http://gpu:8000")
    monkeypatch.setenv("VLLM_MODEL", "Inferact/Qwen3.8-27B-NVFP4")
    monkeypatch.delenv("VISION_CONCURRENCY", raising=False)
    calls = _vllm_server(monkeypatch, ["Inferact/Qwen3.8-27B-NVFP4"])
    b = get_backend()
    assert b is not None
    assert (b.name, b.model, b.max_concurrency) == ("vllm", "Inferact/Qwen3.8-27B-NVFP4", 1)
    assert calls["get"] == ["http://gpu:8000/v1/models"]
    (url, payload), = calls["post"]
    assert payload["max_tokens"] == 1 and payload["messages"][0]["content"][1]["type"] == "image_url"
    assert builds == ["vllm"]


def test_auto_with_vllm_whose_model_cannot_see_is_skipped(monkeypatch, caplog):
    monkeypatch.setenv("LLM_PROVIDER", "vllm")
    monkeypatch.setenv("VLLM_MODEL", "text-only")
    _vllm_server(monkeypatch, ["text-only"],
                 post_error="HTTP 400: At most 0 image(s) may be provided in one prompt.")
    with caplog.at_level(logging.INFO, logger="pipeline.vlm"):
        assert get_backend() is None
    assert vlm.skip_reason().startswith("auto: vllm/text-only unavailable (the probe failed (RuntimeError: HTTP 400")
    assert max(r.levelno for r in caplog.records) == logging.INFO


def test_auto_with_vllm_and_no_model_name_is_skipped(monkeypatch, builds):
    monkeypatch.setenv("LLM_PROVIDER", "vllm")
    assert get_backend() is None
    assert vlm.skip_reason() == "auto: vllm has no vision model: set VLLM_MODEL or VISION_MODEL"
    assert builds == []


def test_auto_with_ollama_reads_with_the_default_vision_model(monkeypatch, builds):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://box:11434")
    seen: list[str] = []

    def fake_get(url, headers, timeout):
        seen.append(url)
        return {"models": [{"name": "qwen3.8:latest", "capabilities": ["completion", "vision"]}]}

    monkeypatch.setattr("pipeline.vlm._http_get_json", fake_get)
    b = get_backend()
    assert b is not None and (b.name, b.model) == ("ollama", "qwen3.8")
    assert seen == ["http://box:11434/api/tags"]


def test_auto_with_ollama_names_the_model_that_is_not_pulled(monkeypatch, caplog):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://box:11434")
    _ollama_tags(monkeypatch, model="llama3.2", capabilities=("completion",))
    with caplog.at_level(logging.INFO, logger="pipeline.vlm"):
        assert get_backend() is None
    assert vlm.skip_reason() == "auto: ollama/qwen3.8 unavailable (qwen3.8 is not pulled at http://box:11434)"
    assert max(r.levelno for r in caplog.records) == logging.INFO


def test_a_failing_api_show_is_a_failed_probe_not_a_cached_no_vision(monkeypatch):
    # /api/tags carries no `capabilities`, so the probe asks /api/show; if that
    # call raises, no definitive verdict may be cached for the process.
    monkeypatch.setenv("VISION_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://box:11434")
    monkeypatch.setattr("pipeline.vlm._http_get_json",
                        lambda url, headers, timeout: {"models": [{"name": "qwen3.8:latest"}]})
    show = {"fail": True}

    def fake_post(url, payload, headers, timeout):
        if show["fail"]:
            raise OSError("connection reset")
        return {"capabilities": ["completion", "vision"]}

    monkeypatch.setattr("pipeline.vlm._http_json", fake_post)
    assert get_backend() is None
    assert "the probe failed (OSError" in vlm.skip_reason()
    show["fail"] = False
    b = get_backend()                         # not stuck on the first answer
    assert b is not None and (b.name, b.model) == ("ollama", "qwen3.8")


def test_a_named_provider_that_cannot_serve_still_warns(monkeypatch, caplog):
    monkeypatch.setenv("VISION_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://box:11434")
    _ollama_tags(monkeypatch, model="llama3.2", capabilities=("completion",))
    with caplog.at_level(logging.INFO, logger="pipeline.vlm"):
        assert get_backend() is None
    assert vlm.skip_reason() == "ollama/qwen3.8 unavailable (qwen3.8 is not pulled at http://box:11434)"
    assert {r.levelno for r in caplog.records} == {logging.WARNING}


def test_auto_with_mistral_needs_a_vision_model_name(monkeypatch, builds):
    monkeypatch.setenv("LLM_PROVIDER", "mistral")
    monkeypatch.setenv("MISTRAL_API_KEY", "m-key")
    assert get_backend() is None
    assert vlm.skip_reason() == "auto: mistral has no vision model: set VISION_MODEL"
    assert builds == []


def test_auto_with_mistral_and_a_vision_model_reads_with_it(monkeypatch, builds):
    monkeypatch.setenv("LLM_PROVIDER", "mistral")
    monkeypatch.setenv("MISTRAL_API_KEY", "m-key")
    monkeypatch.setenv("VISION_MODEL", "pixtral-12b-latest")
    monkeypatch.setattr("pipeline.vlm._http_get_json",
                        lambda url, headers, timeout: {"capabilities": {"vision": True}})
    b = get_backend()
    assert b is not None and (b.name, b.model, b.max_concurrency) == ("mistral", "pixtral-12b-latest", 4)


def test_auto_with_mistral_and_no_key_is_skipped(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mistral")
    monkeypatch.setenv("VISION_MODEL", "pixtral-12b-latest")
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    assert get_backend() is None
    assert vlm.skip_reason() == "auto: mistral/pixtral-12b-latest unavailable (no MISTRAL_API_KEY)"


@pytest.mark.parametrize("text_provider, shown", [
    ("gemini", "gemini"), ("lmstudio", "lmstudio"), ("", "(empty)"), ("something-else", "something-else"),
])
def test_auto_without_a_vision_backend_for_the_text_provider_is_skipped(
        monkeypatch, caplog, builds, text_provider, shown):
    monkeypatch.setenv("LLM_PROVIDER", text_provider)
    # A key for another provider must not be used: a figure goes where the text goes.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    _every_model_sees(monkeypatch)
    with caplog.at_level(logging.INFO, logger="pipeline.vlm"):
        assert get_backend() is None
    assert vlm.skip_reason() == f"auto: LLM_PROVIDER={shown} has no vision backend"
    assert builds == []
    assert [r.levelno for r in caplog.records] == [logging.INFO]


def test_auto_never_falls_back_to_another_provider(monkeypatch, builds):
    """The text goes to vLLM, so a figure goes to vLLM or nowhere: an Anthropic
    key in the environment is not a reason to send it there."""
    monkeypatch.setenv("LLM_PROVIDER", "vllm")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("VLLM_MODEL", "text-only")
    _vllm_server(monkeypatch, ["text-only"], post_error="HTTP 400: no image")
    assert get_backend() is None
    assert builds == ["vllm"]

    reset_backend_cache()
    builds.clear()
    _vllm_server(monkeypatch, ["text-only"])
    b = get_backend()
    assert b is not None and b.name == "vllm"
    assert builds == ["vllm"]


def test_none_turns_figure_reading_off_whatever_the_text_provider(monkeypatch, builds):
    monkeypatch.setenv("VISION_PROVIDER", "none")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    _every_model_sees(monkeypatch)
    assert get_backend() is None
    assert vlm.skip_reason() == "VISION_PROVIDER=none"
    assert builds == []


@pytest.mark.parametrize("named, text_provider", [("ollama", "gemini"), ("ollama", "vllm"), ("anthropic", "vllm")])
def test_a_named_provider_overrides_the_text_provider(monkeypatch, builds, named, text_provider):
    monkeypatch.setenv("VISION_PROVIDER", named)
    monkeypatch.setenv("LLM_PROVIDER", text_provider)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    _every_model_sees(monkeypatch)
    b = get_backend()
    assert b is not None and b.name == named
    assert builds == [named]


def test_an_unknown_named_provider_is_refused(monkeypatch, caplog):
    monkeypatch.setenv("VISION_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    with caplog.at_level(logging.INFO, logger="pipeline.vlm"):
        assert get_backend() is None
    assert vlm.skip_reason() == "unknown VISION_PROVIDER=gemini"
    assert [r.levelno for r in caplog.records] == [logging.WARNING]
    assert "auto, none, anthropic, mistral, ollama, vllm" in caplog.text.replace("'", "")


def test_the_skip_reason_is_forgotten_with_the_cache(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    assert vlm.skip_reason() == ""            # nothing resolved yet
    assert get_backend() is None
    assert get_backend() is None              # the cached answer keeps its reason
    assert vlm.skip_reason() == "auto: LLM_PROVIDER=gemini has no vision backend"
    reset_backend_cache()
    assert vlm.skip_reason() == ""


def test_the_config_check_names_the_provider_auto_resolved_to(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "vllm")
    monkeypatch.setenv("VLLM_MODEL", "Inferact/Qwen3.8-27B-NVFP4")
    _vllm_server(monkeypatch, ["Inferact/Qwen3.8-27B-NVFP4"])
    assert vlm._main([]) == 0
    out = capsys.readouterr().out
    assert "VISION_PROVIDER = auto -> vllm" in out
    assert "VISION_MODEL    = Inferact/Qwen3.8-27B-NVFP4" in out
    assert "RESULT: vllm/Inferact/Qwen3.8-27B-NVFP4 is ready" in out


def test_the_config_check_says_why_there_is_no_backend(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    assert vlm._main([]) == 1
    out = capsys.readouterr().out
    assert "VISION_PROVIDER = auto -> none" in out
    assert "Why: auto: LLM_PROVIDER=gemini has no vision backend" in out


# ── A probe that raised is not an answer ─────────────────────────────────────

def _flaky_vllm(monkeypatch, failures):
    """A vLLM server that is unreachable for its first `failures` model lists."""
    seen = {"get": 0}

    def fake_get(url, headers, timeout):
        seen["get"] += 1
        if seen["get"] <= failures:
            raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        return {"data": [{"id": "m"}]}

    monkeypatch.setattr("pipeline.vlm._http_get_json", fake_get)
    monkeypatch.setattr("pipeline.vlm._http_json", lambda *a, **k: {"choices": [{"message": {"content": "A"}}]})
    return seen


def test_a_probe_that_raised_is_asked_again_for_the_next_document(monkeypatch, builds):
    """`main.py --input-dir` and `evaluation inhouse-run` share one process: a
    network error on the first PDF must not skip the figures of the others."""
    monkeypatch.setenv("LLM_PROVIDER", "vllm")
    monkeypatch.setenv("VLLM_MODEL", "m")
    seen = _flaky_vllm(monkeypatch, failures=1)

    assert get_backend() is None
    assert vlm.skip_reason().startswith("auto: vllm/m unavailable (the probe failed (URLError")

    b = get_backend()
    assert b is not None and b.name == "vllm"
    assert vlm.skip_reason() == ""
    assert get_backend() is b                      # a definite answer is kept
    assert seen["get"] == 2 and builds == ["vllm", "vllm"]


def test_an_anthropic_probe_that_raised_is_asked_again(monkeypatch, builds):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    class _Caps:
        def model_dump(self):
            return {"image_input": {"supported": True}}

    class _Model:
        capabilities = _Caps()

    answers = [ConnectionError("network unreachable"), _Model()]

    class _Models:
        def retrieve(self, _model):
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

    class _Client:
        models = _Models()

    monkeypatch.setattr(vlm.AnthropicVisionBackend, "_get_client", lambda self: _Client())

    assert get_backend() is None
    assert vlm.skip_reason().startswith(
        "auto: anthropic/claude-haiku-5-5 unavailable (the capability probe failed (ConnectionError")
    assert get_backend() is not None
    assert builds == ["anthropic", "anthropic"]


def _anthropic_without_a_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def _ollama_without_the_model(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    _ollama_tags(monkeypatch, model="llama3.2")


def _ollama_model_without_vision(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    _ollama_tags(monkeypatch, capabilities=("completion",))


def _vllm_not_serving_the_model(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "vllm")
    monkeypatch.setenv("VLLM_MODEL", "m")
    _vllm_server(monkeypatch, ["other"])


@pytest.mark.parametrize("setup", [
    _anthropic_without_a_key, _ollama_without_the_model, _ollama_model_without_vision,
    _vllm_not_serving_the_model,
])
def test_a_definite_answer_is_kept_for_the_process(monkeypatch, builds, setup):
    setup(monkeypatch)
    assert get_backend() is None
    reason = vlm.skip_reason()
    assert reason and "probe failed" not in reason
    assert get_backend() is None
    assert vlm.skip_reason() == reason
    assert len(builds) == 1                         # resolved once, not once per document


# ── A reason never carries credentials ───────────────────────────────────────

@pytest.mark.parametrize("url, shown", [
    ("http://user:secret@gpu:8000/v1", "http://gpu:8000/v1"),
    ("http://user@gpu:8000", "http://gpu:8000"),
    ("http://user:p@ss@gpu:8000/v1", "http://gpu:8000/v1"),
    ("https://user:secret@[::1]:8000/v1?token=abc#x", "https://[::1]:8000/v1"),
    ("http://gpu:8000/v1", "http://gpu:8000/v1"),
])
def test_credentials_are_dropped_from_a_url_shown_in_a_reason(url, shown):
    assert vlm._without_credentials(url) == shown


def test_a_vllm_reason_and_log_keep_the_credentials_of_the_base_url_out(monkeypatch, caplog):
    monkeypatch.setenv("LLM_PROVIDER", "vllm")
    monkeypatch.setenv("VLLM_BASE_URL", "http://user:secret@gpu:8000")
    monkeypatch.setenv("VLLM_MODEL", "m")
    _vllm_server(monkeypatch, ["other"])
    with caplog.at_level(logging.INFO, logger="pipeline.vlm"):
        assert get_backend() is None
    assert vlm.skip_reason() == "auto: vllm/m unavailable (http://gpu:8000/v1 does not serve m)"
    assert "secret" not in caplog.text and "user:" not in caplog.text


def test_an_ollama_reason_and_log_keep_the_credentials_of_the_base_url_out(monkeypatch, caplog):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://user:secret@box:11434")
    _ollama_tags(monkeypatch, model="llama3.2")
    with caplog.at_level(logging.INFO, logger="pipeline.vlm"):
        assert get_backend() is None
    assert vlm.skip_reason() == "auto: ollama/qwen3.8 unavailable (qwen3.8 is not pulled at http://box:11434)"
    assert "secret" not in caplog.text and "user:" not in caplog.text


def test_a_refused_scheme_does_not_echo_the_credentials():
    with pytest.raises(ValueError, match="http") as refused:
        vlm._http_get_json("ftp://user:secret@host/models", {}, 1.0)
    assert "secret" not in str(refused.value)


# ── The orchestrator asks before it calls ────────────────────────────────────

@pytest.mark.parametrize("setting, follows", [
    (None, True), ("", True), ("auto", True), ("AUTO", True),
    ("none", False), ("vllm", False), ("anthropic", False),
])
def test_figures_follow_the_text_only_under_auto(monkeypatch, setting, follows):
    if setting is not None:
        monkeypatch.setenv("VISION_PROVIDER", setting)
    assert vlm.follows_text() is follows


# ── The config check reads the env file ──────────────────────────────────────

def test_the_config_check_reads_the_env_file_without_overriding_the_shell(monkeypatch, tmp_path, capsys):
    """As Stage 3's import does: `auto` reads LLM_PROVIDER, which a host checkout keeps in .env."""
    import dotenv

    envfile = tmp_path / ".env"
    envfile.write_text("LLM_PROVIDER=gemini\nOLLAMA_BASE_URL=http://from-the-file:11434\n", encoding="utf-8")
    real = dotenv.load_dotenv
    monkeypatch.setattr(vlm, "load_dotenv", lambda: real(envfile))
    monkeypatch.setenv("LLM_PROVIDER", "ollama")                 # the shell wins over the file
    monkeypatch.setenv("OLLAMA_BASE_URL", "")                    # registered, so the file's value is undone
    monkeypatch.delenv("OLLAMA_BASE_URL")
    seen: list[str] = []

    def fake_get(url, headers, timeout):
        seen.append(url)
        return {"models": [{"name": "qwen3.8:latest", "capabilities": ["vision"]}]}

    monkeypatch.setattr("pipeline.vlm._http_get_json", fake_get)
    assert vlm._main([]) == 0
    assert "VISION_PROVIDER = auto -> ollama" in capsys.readouterr().out
    assert seen == ["http://from-the-file:11434/api/tags"]
