"""Normalized detection-rule model (ADR-0006).

Every rule corpus — whatever its native format — is parsed by a
`RuleCorpusAdapter` into `DetectionRule` records keyed to ATT&CK techniques.
This is the common representation the coverage stage joins against.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class DetectionRule(BaseModel):
    """A detection rule normalized from any corpus and tagged with ATT&CK techniques."""

    id: str                                              # stable: f"{corpus}:{native_id_or_hash}"
    corpus: str                                          # registry name (detection_corpora.yaml)
    format: str = "sigma"                                # source format key
    title: str
    description: str = ""
    technique_ids: list[str] = Field(default_factory=list)       # ["T1059.001", "T1027", ...]
    tactic_shortnames: list[str] = Field(default_factory=list)   # ["execution", ...]
    data_sources: list[str] = Field(default_factory=list)        # logsource-derived telemetry
    severity: Severity = Severity.UNKNOWN
    license: str = "unknown"                             # carried from the corpus registry entry
    source_ref: str = ""                                 # file path / URL (provenance)
    content_hash: str = ""                               # sha256 of raw — byte-identical match
    dedup_key: str = ""                                  # sha256 of normalized detection logic (ADR-0010)
    raw: str = ""                                        # original rule text (lossless, for export)
