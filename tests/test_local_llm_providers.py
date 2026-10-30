"""Local LLM servers that want a key, and the reasoning block a model writes before
its answer.

No request leaves the process: the OpenAI client is a fake, and the vision probe is
waived with VISION_ASSUME_CAPABLE, so get_backend makes no HTTP call.
"""
from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import pytest

from pipeline import stage3_llm as s3
from pipeline import vlm
from pipeline.llm_parse import strip_reasoning

_ANSWER = '{"threat_actors": ["APT29"]}'


# ── strip_reasoning ──────────────────────────────────────────────────────────

def test_a_reply_without_reasoning_is_returned_unchanged():
    assert strip_reasoning('  {"a": 1} ') == '  {"a": 1} '


def test_a_closed_reasoning_block_is_dropped():
    assert strip_reasoning('<think>Plan first.</think>{"a": 1}') == '{"a": 1}'


def test_braces_inside_the_reasoning_are_dropped_before_the_answer():
    text = '<think>Maybe {"x": 1}, or a lone { brace.</think>\n' + _ANSWER
    assert strip_reasoning(text) == _ANSWER
    assert s3._parse_llm_response(strip_reasoning(text)).threat_actors == ["APT29"]


def test_a_reasoning_block_with_no_closing_tag_leaves_no_answer():
    assert strip_reasoning('<think>I should answer with {"x": 1} and then') == ""


def test_a_closing_tag_without_an_opening_one_ends_the_reasoning():
    """Qwen3: the chat template puts <think> in the prompt, so the reply opens with the reasoning."""
    assert strip_reasoning('Reasoning with a { brace.</think>\n' + _ANSWER) == _ANSWER


def test_leading_whitespace_is_tolerated():
    assert strip_reasoning('\n  <think>r</think>  ' + _ANSWER + '\n') == _ANSWER
    assert strip_reasoning('  r</think>' + _ANSWER) == _ANSWER
    assert strip_reasoning('\n <think>cut') == ""


# A JSON answer or a code block is never cut: a closing tag inside one of its strings is data.
_JSON_WITH_CLOSE = '{"threat_actors":[{"name":"APT29","evidence":"the loader prints </think> then exits"}]}'


def test_a_json_answer_with_a_closing_tag_in_a_string_is_returned_unchanged():
    assert strip_reasoning(_JSON_WITH_CLOSE) == _JSON_WITH_CLOSE


def test_a_json_array_with_a_closing_tag_in_a_string_is_returned_unchanged():
    text = '[{"name": "APT29", "evidence": "the loader prints </think> then exits"}]'
    assert strip_reasoning(text) == text


def test_a_code_block_with_a_closing_tag_in_a_string_is_returned_unchanged():
    text = '```json\n' + _JSON_WITH_CLOSE + '\n```'
    assert strip_reasoning(text) == text


def test_spaces_before_a_json_answer_change_nothing():
    text = '\n   ' + _JSON_WITH_CLOSE
    assert strip_reasoning(text) == text


def test_prose_before_a_closing_tag_is_still_cut_when_it_mentions_json():
    assert strip_reasoning('Let me check {"x": 1} first.</think>\n' + _ANSWER) == _ANSWER


# ── Replies of an OpenAI-compatible server ───────────────────────────────────

def _client(content, finish_reason="stop"):
    def create(**kwargs):
        choice = SimpleNamespace(message=SimpleNamespace(content=content), finish_reason=finish_reason)
        return SimpleNamespace(choices=[choice], usage=None)

    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))


@pytest.mark.parametrize("finish_reason,at_ceiling", [("stop", False), ("length", True)])
def test_the_reasoning_block_is_not_in_the_answer_and_the_ceiling_flag_is_kept(caplog, finish_reason, at_ceiling):
    client = _client('<think>{"x": 1} is an example.</think>\n' + _ANSWER, finish_reason)

    with caplog.at_level(logging.DEBUG, logger="pipeline.stage3_llm"):
        out = s3._call_openai_compatible_impl(client, "m", "s", "u", "vLLM")

    assert out == _ANSWER and out.at_ceiling is at_ceiling
    assert s3._parse_llm_response(out).threat_actors == ["APT29"]
    # The debug line counts the characters removed; the reasoning itself is never logged.
    assert "vLLM reasoning block removed (" in caplog.text
    assert "is an example" not in caplog.text


def test_a_reasoning_block_cut_at_the_ceiling_is_an_empty_answer_still_at_the_ceiling():
    client = _client('<think>Let me work out {"x"', finish_reason="length")

    out = s3._call_openai_compatible_impl(client, "m", "s", "u", "vLLM", max_tokens=2048)

    assert out == "" and out.at_ceiling is True


# ── API keys of the local servers ────────────────────────────────────────────

@pytest.fixture()
def openai_sdk(monkeypatch):
    """A fake OpenAI client that records the key it is built with; no cached client."""
    built: list[dict] = []

    class _FakeOpenAI:
        def __init__(self, api_key, base_url):
            built.append({"api_key": api_key, "base_url": base_url})

    monkeypatch.setattr(s3, "_OPENAI_SDK_AVAILABLE", True)
    monkeypatch.setattr(s3, "_OpenAIClient", _FakeOpenAI)
    for name in ("_ollama_client", "_lmstudio_client", "_vllm_client"):
        monkeypatch.setattr(s3, name, None)
    return built


_LOCAL_SERVERS = [
    (s3._get_ollama_client, "OLLAMA_API_KEY", "ollama"),
    (s3._get_lmstudio_client, "LMSTUDIO_API_KEY", "lmstudio"),
    (s3._get_vllm_client, "VLLM_API_KEY", "vllm"),
]


@pytest.mark.parametrize("getter,variable,placeholder", _LOCAL_SERVERS)
def test_a_local_server_gets_its_key_when_one_is_set(openai_sdk, monkeypatch, getter, variable, placeholder):
    monkeypatch.setenv(variable, "  s3cret  ")
    getter()
    assert openai_sdk[-1]["api_key"] == "s3cret"


@pytest.mark.parametrize("value", [None, "", "   "])
@pytest.mark.parametrize("getter,variable,placeholder", _LOCAL_SERVERS)
def test_a_local_server_keeps_the_placeholder_when_no_key_is_set(openai_sdk, monkeypatch, getter, variable,
                                                                  placeholder, value):
    if value is None:
        monkeypatch.delenv(variable, raising=False)
    else:
        monkeypatch.setenv(variable, value)
    getter()
    assert openai_sdk[-1]["api_key"] == placeholder


# ── API keys of the vision backends ──────────────────────────────────────────

@pytest.fixture()
def probe_waived(monkeypatch):
    """A vision backend whose capability probe is waived, so get_backend makes no request."""
    for name in ("OLLAMA_API_KEY", "VLLM_API_KEY", "VISION_CONCURRENCY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VISION_ASSUME_CAPABLE", "1")
    monkeypatch.setenv("VISION_MODEL", "vision-model")
    vlm.reset_backend_cache()
    yield monkeypatch
    vlm.reset_backend_cache()


def _headers_sent(monkeypatch, backend) -> dict:
    """The headers of the request read_figure sends, with the network replaced."""
    sent: dict = {}

    def fake_post(url, payload, headers, timeout):
        sent.update(headers)
        return {"choices": [{"message": {"content": json.dumps({
            "figure_kind": "none", "verbatim_text": [], "edges": [], "iocs": [],
        })}}]}

    monkeypatch.setattr(vlm, "_http_json", fake_post)
    backend.read_figure(b"png")
    return sent


@pytest.mark.parametrize("value,authorization", [
    (None, None),
    ("", None),
    ("  ", None),
    ("  v-key  ", "Bearer v-key"),
])
def test_vllm_vision_sends_authorization_only_when_a_key_is_set(probe_waived, value, authorization):
    probe_waived.setenv("VISION_PROVIDER", "vllm")
    if value is not None:
        probe_waived.setenv("VLLM_API_KEY", value)
    backend = vlm.get_backend()
    assert backend is not None
    assert _headers_sent(probe_waived, backend).get("Authorization") == authorization


@pytest.mark.parametrize("value,authorization", [
    (None, "Bearer ollama"),
    ("", "Bearer ollama"),
    ("  o-key  ", "Bearer o-key"),
])
def test_ollama_vision_sends_its_key_or_the_placeholder(probe_waived, value, authorization):
    probe_waived.setenv("VISION_PROVIDER", "ollama")
    if value is not None:
        probe_waived.setenv("OLLAMA_API_KEY", value)
    backend = vlm.get_backend()
    assert backend is not None
    assert _headers_sent(probe_waived, backend).get("Authorization") == authorization
