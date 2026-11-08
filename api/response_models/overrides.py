"""Response models of api/routes/overrides.py."""
from api.response_models import Response


class OverrideRow(Response):
    """One row of entity_overrides, as the store returns it."""

    id: str
    term: str
    entity_type: str
    action: str  # deny | promote
    status: str  # candidate | active | ignored
    display: str | None
    accepted_count: int
    rejected_count: int
    job_count: int
    origin: str  # auto | manual
    note: str | None
    created_at: str
    updated_at: str


class OverrideList(Response):
    """Result of GET /api/overrides."""

    enabled: bool  # the ENTITY_OVERRIDES_ENABLED switch
    rows: list[OverrideRow]


class OverrideCandidate(Response):
    """A candidate rule proposed from the analysts' decisions."""

    term: str
    entity_type: str
    action: str  # deny | promote
    display: str
    accepted_count: int
    rejected_count: int
    job_count: int
    existing_status: str | None  # the status the store already holds, else NULL
    sources: list[str]


class OverridePromotion(Response):
    """Result of POST /api/overrides/promote."""

    applied: bool
    written: int  # candidates written; 0 unless applied
    candidates: list[OverrideCandidate]


class OverrideDeleted(Response):
    """Result of DELETE /api/overrides/{override_id}."""

    deleted: str  # the id that was deleted
