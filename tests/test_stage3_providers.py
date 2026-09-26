from __future__ import annotations

from types import SimpleNamespace

from pipeline.stage3_llm import _call_llm, _provider_ready


def test_provider_ready_anthropic(monkeypatch):
    monkeypatch.setattr('pipeline.stage3_llm._PROVIDER', 'anthropic')
    monkeypatch.delenv('ANTHROPIC_API_KEY', raising=False)
    assert _provider_ready() is False

    monkeypatch.setenv('ANTHROPIC_API_KEY', 'sk-ant-test')
    assert _provider_ready() is True

def test_provider_ready_gemini(monkeypatch):
    monkeypatch.setattr('pipeline.stage3_llm._OPENAI_SDK_AVAILABLE', True)
    monkeypatch.setattr('pipeline.stage3_llm._PROVIDER', 'gemini')
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    assert _provider_ready() is False

    monkeypatch.setenv('GEMINI_API_KEY', 'AIzaSyTest')
    assert _provider_ready() is True

def test_provider_ready_mistral(monkeypatch):
    monkeypatch.setattr('pipeline.stage3_llm._OPENAI_SDK_AVAILABLE', True)
    monkeypatch.setattr('pipeline.stage3_llm._PROVIDER', 'mistral')
    monkeypatch.delenv('MISTRAL_API_KEY', raising=False)
    assert _provider_ready() is False

    monkeypatch.setenv('MISTRAL_API_KEY', 'mistral-key')
    assert _provider_ready() is True

def test_provider_ready_local_providers(monkeypatch):
    monkeypatch.setattr('pipeline.stage3_llm._OPENAI_SDK_AVAILABLE', True)
    for provider in ['ollama', 'lmstudio', 'vllm']:
        monkeypatch.setattr('pipeline.stage3_llm._PROVIDER', provider)
        assert _provider_ready() is True

def test_provider_ready_no_sdk(monkeypatch):
    monkeypatch.setattr('pipeline.stage3_llm._OPENAI_SDK_AVAILABLE', False)
    monkeypatch.setenv('GEMINI_API_KEY', 'AIzaSyTest')
    monkeypatch.setenv('MISTRAL_API_KEY', 'mistral-key')
    for provider in ['gemini', 'mistral', 'ollama', 'lmstudio', 'vllm']:
        monkeypatch.setattr('pipeline.stage3_llm._PROVIDER', provider)
        assert _provider_ready() is False


class _FakeCompletions:
    """Records the kwargs of the chat.completions.create call."""

    def __init__(self):
        self.kwargs: dict = {}

    def create(self, **kwargs):
        self.kwargs = kwargs
        message = SimpleNamespace(content='{"threat_actors": []}')
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=None)


def _fake_client(completions):
    return SimpleNamespace(chat=SimpleNamespace(completions=completions))


def test_vllm_call_turns_thinking_off_by_default(monkeypatch):
    """Qwen3 on vLLM thinks unless told not to; on the Stage 3 prompt that spent
    the whole 8192-token budget reasoning and returned no JSON."""
    monkeypatch.delenv('VLLM_ENABLE_THINKING', raising=False)
    completions = _FakeCompletions()
    monkeypatch.setattr('pipeline.stage3_llm._get_vllm_client', lambda: _fake_client(completions))
    assert _call_llm('system', 'user text', provider='vllm') == '{"threat_actors": []}'
    assert completions.kwargs['extra_body'] == {'chat_template_kwargs': {'enable_thinking': False}}


def test_vllm_call_turns_thinking_on_when_asked(monkeypatch):
    monkeypatch.setenv('VLLM_ENABLE_THINKING', 'true')
    completions = _FakeCompletions()
    monkeypatch.setattr('pipeline.stage3_llm._get_vllm_client', lambda: _fake_client(completions))
    _call_llm('system', 'user text', provider='vllm')
    assert completions.kwargs['extra_body'] == {'chat_template_kwargs': {'enable_thinking': True}}


def test_other_openai_compatible_providers_send_no_extra_body(monkeypatch):
    """chat_template_kwargs is a vLLM field; Ollama and the hosted APIs never see it."""
    monkeypatch.setenv('VLLM_ENABLE_THINKING', 'false')
    completions = _FakeCompletions()
    monkeypatch.setattr('pipeline.stage3_llm._get_ollama_client', lambda: _fake_client(completions))
    _call_llm('system', 'user text', provider='ollama')
    assert completions.kwargs['extra_body'] is None
