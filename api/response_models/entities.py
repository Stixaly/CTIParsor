"""Response models of api/routes/entities.py."""
from api.response_models import Response


class EntityOut(Response):
    """One entity row, as `_row_to_dict` returns it."""

    id: str
    job_id: str
    value: str
    entity_type: str
    context: str | None = None  # stored as '' by default; NULL is possible
    confidence: float | None
    mitre_id: str | None
    accepted: bool | None = None  # NULL: not decided yet
    source: str | None = None  # 'manual' for a hand-made row, else the extractor
    decision_origin: str | None = None
    control_sample: bool
    held_reason: str | None = None  # ADR-0082: why the pipeline held the row back
    enrichment_status: str | None = None  # ADR-0090: relation to the analyst's STIX bundle
    baseline_stix_id: str | None = None


class EntityAcceptPending(Response):
    """Result of POST .../entities/accept-pending."""

    accepted: int  # rows the call accepted


class EntityBulkResult(Response):
    """Result of POST .../entities/bulk."""

    updated: int  # rows changed
    entity_type: str
    action: str  # accept | reject | reset
    scope: str  # pending | all


class EntityDeleted(Response):
    """Result of DELETE .../entities/{entity_id}."""

    deleted: str  # the id that was deleted
