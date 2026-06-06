from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


class ChunkConfig(BaseModel):
    max_chars: int = Field(3000, ge=500, le=20_000)
    overlap: int = Field(400, ge=0)


class LLMConfig(BaseModel):
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-6"
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
        return cls(
            chunk=ChunkConfig(
                max_chars=int(os.getenv("CHUNK_MAX_CHARS", "3000")),
                overlap=int(os.getenv("CHUNK_OVERLAP", "400")),
            ),
            llm=LLMConfig(
                provider=os.getenv("LLM_PROVIDER", "anthropic"),
                model=os.getenv("ANTHROPIC_MODEL", os.getenv("LLM_MODEL", "claude-sonnet-4-6")),
                timeout_seconds=int(os.getenv("LLM_TIMEOUT", "120")),
                max_retries=int(os.getenv("LLM_MAX_RETRIES", "3")),
            ),
        )
