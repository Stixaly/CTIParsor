"""Response models of `api/routes/thresholds.py` (ADR-0051, ADR-0058).

`Proposal` is `pipeline.calibration.Proposal.as_dict()`: every field is always
present.  `status` takes one of the five values `propose()` assigns.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from api.response_models import Response


class AutoAcceptAudit(Response):
    """The control sample of one source and entity type, and what an analyst decided on it."""
    source: str
    entity_type: str
    sampled: int = Field(description="Control-sample rows of this kind.")
    decided: int = Field(description="Control-sample rows an analyst decided one at a time.")
    confirmed: int = Field(description="Decided rows the analyst accepted.")
    precision: float | None = Field(description="confirmed / decided, 4 places; None when nothing is decided.")


class ThresholdRow(Response):
    """One stored cutoff for a calibrated source and entity type."""
    source: str
    entity_type: str
    threshold: float
    sample_size: int
    target_precision: float | None
    precision_at: float | None
    recall_retained: float | None
    origin: str
    updated_at: str


class CurvePoint(Response):
    """One score block of a proposal's curve: its score range, its row count and its acceptance rate."""
    lo: float
    hi: float
    n: int
    rate: float = Field(description="Calibrated acceptance rate of the block, rounded to 4 places.")


class Proposal(Response):
    """One proposed cutoff for a calibrated source and entity type (pipeline.calibration.Proposal.as_dict)."""
    source: str
    entity_type: str
    current: float = Field(description="The cutoff in force when the proposal was made.")
    target_precision: float
    sample_size: int
    accepted: int
    rejected: int
    min_score: float | None
    max_score: float | None
    status: Literal["insufficient_samples", "target_unreachable", "above_auto_accept", "unchanged", "ok"]
    proposed: float | None
    unclamped: float | None = Field(
        description="The cutoff before the auto-accept ceiling; equals proposed unless above_auto_accept.",
    )
    precision_at_current: float | None
    recall_at_current: float | None
    precision_at_proposed: float | None
    recall_at_proposed: float | None
    curve: list[CurvePoint]


class ThresholdsOut(Response):
    """GET /api/thresholds: the calibration settings, the control-sample audit, the defaults and the stored cutoffs."""
    enabled: bool = Field(description="THRESHOLD_CALIBRATION_ENABLED.")
    auto_accept_level: float
    control_sample_rate: float
    auto_accept_audit: list[AutoAcceptAudit]
    defaults: dict[str, float] = Field(description="The stage default cutoff, per calibrated source.")
    rows: list[ThresholdRow]


class RecalibrateOut(Response):
    """Result of a recalibration: the proposals, and whether they were written."""
    applied: bool
    written: int
    origins: list[str] = Field(description="The decision origins the proposals were calibrated on.")
    excluded_by_origin: dict[str, int] = Field(description="Decided rows not read, counted per origin.")
    proposals: list[Proposal]


class OverrideOut(Response):
    """A manual cutoff stored for one source and entity type."""
    source: str
    entity_type: str
    threshold: float
    origin: Literal["manual"]


class DeletedKey(Response):
    """The source and entity type of a deleted cutoff."""
    source: str
    entity_type: str


class DeletedOut(Response):
    """Result of deleting a manual cutoff: its key, and the default now in force for the source."""
    deleted: DeletedKey
    default: float = Field(description="The stage default now in force for the source.")
