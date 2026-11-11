"""Pipeline configuration: ``PipelineConfig`` and the variables it reads.

``PipelineConfig`` groups the three sub-configs of a run — ``ChunkConfig``
(how a report is split), ``LLMConfig`` (the Stage 3 provider) and
``ValidationConfig`` (the confidence and evidence gates) — plus the data
and output directories. ``PipelineConfig.from_env()`` is the entry point
that builds one from the environment; it reads exactly these variables:

======================= =========================== =====================
Field                   Environment variable        Default when unset
======================= =========================== =====================
``chunk.max_chars``     ``CHUNK_MAX_CHARS``         3000
``chunk.overlap``       ``CHUNK_OVERLAP``           400
``llm.provider``        ``LLM_PROVIDER``            ``anthropic``
``llm.model``           ``<PROVIDER>_MODEL``,       ``claude-sonnet-5-5``
                        then ``LLM_MODEL``
``llm.timeout_seconds`` ``LLM_TIMEOUT``             120
``llm.max_retries``     ``LLM_MAX_RETRIES``         3
======================= =========================== =====================

``<PROVIDER>_MODEL`` is the model variable of the provider the run uses —
``ANTHROPIC_MODEL``, ``VLLM_MODEL``, ``OLLAMA_MODEL``… (#531) — and
``LLM_MODEL`` is only the fallback when the provider names none. Every
other field (``llm.temperature``, ``llm.circuit_breaker_threshold``, the
whole ``validation`` block, ``data_dir``, ``output_dir``) comes from the
class defaults: ``from_env`` reads no variable for it.

Example: with ``LLM_PROVIDER=ollama`` and ``OLLAMA_MODEL=mistral`` in the
environment, ``PipelineConfig.from_env().llm`` is an ``LLMConfig`` with
provider ``ollama`` and model ``mistral``, and the chunk and validation
blocks keep their defaults apart from any ``CHUNK_*`` variable set.

docs/configuration.md is the operator reference for the variables the
running services read.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


class ChunkConfig(BaseModel):
    max_chars: int = Field(3000, ge=500, le=20_000)
    overlap: int = Field(400, ge=0)


class LLMConfig(BaseModel):
    provider: str = "anthropic"
    model: str = "claude-sonnet-5-5"
    temperature: float = Field(0.0, ge=0.0, le=2.0)
    max_retries: int = Field(3, ge=0, le=10)
    timeout_seconds: int = Field(120, ge=10, le=600)
    # Number of consecutive failures before the circuit opens
    circuit_breaker_threshold: int = Field(5, ge=1)


class ValidationConfig(BaseModel):
    min_confidence: float = Field(0.3, ge=0.0, le=1.0)
    hallucination_min_chars: int = Field(4, ge=1)
    require_evidence: bool = True


class PipelineConfig(BaseModel):
    chunk: ChunkConfig = ChunkConfig()
    llm: LLMConfig = LLMConfig()
    validation: ValidationConfig = ValidationConfig()
    data_dir: Path = Path("pipeline/data")
    output_dir: Path = Path("output")

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        provider = os.getenv("LLM_PROVIDER", "anthropic")
        return cls(
            chunk=ChunkConfig(
                max_chars=int(os.getenv("CHUNK_MAX_CHARS", "3000")),
                overlap=int(os.getenv("CHUNK_OVERLAP", "400")),
            ),
            llm=LLMConfig(
                provider=provider,
                # The model variable of the provider this run uses: ANTHROPIC_MODEL,
                # VLLM_MODEL, OLLAMA_MODEL... (#531), then LLM_MODEL.
                model=os.getenv(f"{provider.upper()}_MODEL", os.getenv("LLM_MODEL", "claude-sonnet-5-5")),
                timeout_seconds=int(os.getenv("LLM_TIMEOUT", "120")),
                max_retries=int(os.getenv("LLM_MAX_RETRIES", "3")),
            ),
        )
