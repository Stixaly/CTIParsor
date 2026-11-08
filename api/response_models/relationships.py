"""Response models of api/routes/relationships.py."""
from api.response_models import Response


class RelationshipDate(Response):
    """One dated bound of a relationship: a TemporalAssertion, as the route dumps it.

    Plain strings, not the pipeline's Literal types: a row stored before a
    value was added must still be read. The values the code writes today are
    in the descriptions.
    """

    id: str | None = None
    role: str | None = None  # start | end
    time_text: str | None = None  # the verbatim text; '' for an analyst entry
    value: str | None = None  # EDTF, as far as it is fixed
    precision: str | None = None  # e.g. year, month, day, instant
    qualifier: str | None = None  # none, or a qualifier the code sets
    first_last: str | None = None  # first | last
    model_value: str | None = None
    alternatives: list[str] | None = None
    anchor: str | None = None  # explicit | document | none
    anchor_source: str | None = None
    anchor_value: str | None = None
    evidence_label: str | None = None
    status: str | None = None  # unresolved, verified, or as the code sets it
    reason: str | None = None
    doc_offset: int | None = None
    origin: str | None = None  # llm | analyst | legacy


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
    # Each item is a TemporalAssertion dumped with exclude_none=True: the keys
    # the route leaves out stay out (response_model_exclude_unset).
    times: list[RelationshipDate]
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
