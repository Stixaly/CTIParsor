"""Response models of api/routes/jobs.py.

The bundle, the ledger's per-object `origin` extras and the intake's report
fields are read through `Response` (extra="allow"): a key a model does not
declare is still returned unchanged.  The routes that serve a model with
optional keys (`get_job`, `get_bundle_ledger`) exclude the unset ones, so a
key absent from the stored data is absent from the response, as it was.
"""
from typing import Literal

from pydantic import Field

from api.response_models import Response as ApiResponse


class JobSummary(ApiResponse):
    """One entry of GET /api/jobs."""

    id: str
    original_filename: str
    status: str = Field(description="uploaded, queued, processing, for_review, reviewing, completed or failed.")
    tlp_level: str | None
    pap_level: str | None
    pipeline_mode: str = Field(description="full, or enrich when the job was created from a baseline (ADR-0090).")
    created_at: str
    updated_at: str


class ExcludedObject(ApiResponse):
    """A baseline object the intake left out, and why."""

    id: str
    type: str
    reason: str
    detail: str


class BaselineReport(ApiResponse):
    """A Report of the baseline bundle, as the intake lists it."""

    id: str
    name: str
    published: str | None
    refs: int = Field(description="How many object references the report holds.")


class BaselineIntake(ApiResponse):
    """What the intake made of a baseline: `Intake` of pipeline/baseline_stix.py,
    stored as job_baselines.intake_json."""

    sha256: str
    bundle_id: str
    counts: dict[str, int] = Field(description="Objects imported, by STIX type; plus out_of_scope and dangling_refs.")
    excluded: list[ExcludedObject]
    warnings: list[str]
    reports: list[BaselineReport]
    scope_report_id: str | None
    needs_report_choice: bool
    min_tlp: str | None
    min_pap: str | None
    excluded_total: int | None = Field(
        default=None, description="Set by the route: how many objects were excluded, before the list is cut.")


class EnrichmentSummary(ApiResponse):
    """The enrich-mode part of GET /api/jobs/{id}."""

    intake: BaselineIntake | None
    validated: bool = Field(description="Whether the worker has checked the baseline against the JSON schemas.")
    counts: dict[str, dict[str, int]] = Field(
        description="Per table (entities, relationships): the number of rows by enrichment_status. "
                    "Empty until Stage 3r writes them.")


class JobDetail(ApiResponse):
    """GET /api/jobs/{id}.  `enrichment` is present only in enrich mode."""

    id: str
    original_filename: str
    status: str
    report_text: str | None
    tlp_level: str | None
    pap_level: str | None
    created_at: str
    updated_at: str
    pipeline_mode: str
    entity_count: int
    relationship_count: int
    enrichment: EnrichmentSummary | None = None


class StatusResult(ApiResponse):
    """PATCH /api/jobs/{id}: the status that was set."""

    status: Literal["for_review", "reviewing", "completed", "failed"]


class FinalizeResult(ApiResponse):
    """POST /api/jobs/{id}/finalize."""

    status: str = Field(description="The job's status after the rebuild.")
    bundle_size: int = Field(description="The length of the rebuilt bundle JSON.")
    validation: str = Field(description="validated, unverified (JSON schemas missing), unknown, or the stored verdict.")


class DeleteResult(ApiResponse):
    """DELETE /api/jobs/{id}."""

    deleted: str = Field(description="The id of the deleted job.")


class LedgerObject(ApiResponse):
    """Why one object or edge of the bundle exists.  `origin` is always present; the other
    keys depend on the origin (status, upsert, changes, ...) and pass through unchanged."""

    origin: str


class LedgerEntity(ApiResponse):
    """What Stage 4 did with one entity row."""

    value: str
    entity_type: str
    outcome: str = Field(description="emitted, merged or dropped.")
    stix_id: str | None = None
    stix_type: str | None = None
    stix_name: str | None = None
    reason: str | None = None


class LedgerRelationship(ApiResponse):
    """What Stage 4 did with one relationship row."""

    source_value: str
    relationship_type: str
    target_value: str
    outcome: str = Field(description="emitted, merged or dropped.")
    changes: list[str] | None = Field(default=None, description="The properties a baseline upsert rewrote.")
    stix_id: str | None = None
    final_type: str | None = None
    source_ref: str | None = None
    target_ref: str | None = None
    reason: str | None = None
    merged_with: str | None = None


class LedgerRemoved(ApiResponse):
    """An object or edge that is not shipped, and why."""

    stix_id: str
    kind: str = Field(description="object or relationship.")
    reason: str
    replaced_by: str | None = None
    name: str | None = None


class LedgerRefused(ApiResponse):
    """An edge Stage 4 would have built and did not, because its triple was rejected or held."""

    source_ref: str
    relationship_type: str
    target_ref: str
    origin: str | None = None
    reason: str | None = None


class BundleLedger(ApiResponse):
    """GET /api/jobs/{id}/bundle/ledger (ADR-0061, pipeline/bundle_ledger.py).  Every key is
    optional: the route returns the stored ledger as it was written, and `refused` is
    present only when something was refused."""

    version: int | None = None
    objects: dict[str, LedgerObject] | None = None
    entities: list[LedgerEntity] | None = None
    relationships: list[LedgerRelationship] | None = None
    removed: list[LedgerRemoved] | None = None
    refused: list[LedgerRefused] | None = None
