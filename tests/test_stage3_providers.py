from __future__ import annotations

from pipeline.stage3_llm import _provider_ready


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
