"""Response models of api/routes/relationships.py."""
from typing import Any

from api.response_models import Response


class RelationshipOut(Response):
    """One relationship row, as `_row_to_dict` and the create route return it."""

    id: str
    job_id: str
    source_value: str
    relationship_type: str
    target_value: str
    confidence: float | None
    accepted: bool | None = None  # NULL: not decided yet
    evidence_text: str | None = None
    evidence_label: str  # observed | reported | assessed | inferred | gap
    start_time: str | None = None  # the bound an analyst view shows (ADR-0063)
    stop_time: str | None = None
    # Free-form on purpose: each item is one TemporalAssertion dumped with
    # exclude_none=True, so its keys vary (value, precision, role, origin, status, ...).
    times: list[dict[str, Any]]
    decision_origin: str | None = None
    held_reason: str | None = None  # ADR-0082
    enrichment_status: str | None = None  # ADR-0090
    baseline_stix_id: str | None = None


class RelationshipBulkResult(Response):
    """Result of POST .../relationships/bulk."""

    updated: int  # rows changed
    action: str  # accept | reject | reset


class RelationshipDeleted(Response):
    """Result of DELETE .../relationships/{rel_id}."""

    deleted: str  # the id that was deleted
