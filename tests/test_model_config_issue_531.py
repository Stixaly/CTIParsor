"""Issue #531: PipelineConfig.from_env() reads the model of the provider it runs.

Each provider names its model in `<PROVIDER>_MODEL` (.env.example and ADR-0059):
ANTHROPIC_MODEL, GEMINI_MODEL, MISTRAL_MODEL, OLLAMA_MODEL, LMSTUDIO_MODEL,
VLLM_MODEL.  The ANTHROPIC_MODEL that .env.example sets must not stand in for
the model of another provider.
"""
from __future__ import annotations

import pytest

from models.config import PipelineConfig

_MODEL_VARS = (
    "LLM_PROVIDER", "LLM_MODEL", "ANTHROPIC_MODEL", "GEMINI_MODEL", "MISTRAL_MODEL",
    "OLLAMA_MODEL", "LMSTUDIO_MODEL", "VLLM_MODEL",
)


@pytest.fixture()
def llm_env(monkeypatch):
    for name in _MODEL_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.mark.parametrize("provider,variable", [
    ("anthropic", "ANTHROPIC_MODEL"),
    ("gemini", "GEMINI_MODEL"),
    ("mistral", "MISTRAL_MODEL"),
    ("ollama", "OLLAMA_MODEL"),
    ("lmstudio", "LMSTUDIO_MODEL"),
    ("vllm", "VLLM_MODEL"),
])
def test_each_provider_reads_its_own_model_variable_issue_531(llm_env, provider, variable):
    llm_env.setenv("LLM_PROVIDER", provider)
    llm_env.setenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")     # what .env.example sets
    llm_env.setenv(variable, "the-chosen-model")
    assert PipelineConfig.from_env().llm.model == "the-chosen-model"


def test_a_local_provider_does_not_take_the_anthropic_model_issue_531(llm_env):
    llm_env.setenv("LLM_PROVIDER", "vllm")
    llm_env.setenv("ANTHROPIC_MODEL", "claude-opus-not-for-vllm")
    assert PipelineConfig.from_env().llm.model != "claude-opus-not-for-vllm"


def test_llm_model_is_the_fallback_when_the_provider_variable_is_unset_issue_531(llm_env):
    llm_env.setenv("LLM_PROVIDER", "vllm")
    llm_env.setenv("LLM_MODEL", "shared-model")
    assert PipelineConfig.from_env().llm.model == "shared-model"
