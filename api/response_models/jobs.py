"""Response models of api/routes/jobs.py.

The bundle, the ledger's per-object `origin` extras and the intake's report
fields are read through `Response` (extra="allow"): a key a model does not
declare is still returned unchanged.  The routes that serve a model with
optional keys (`get_job`, `get_bundle_ledger`) exclude the unset ones, so a
key absent from the stored data is absent from the response, as it was.
"""
from typing import Literal

from pydantic import Field, JsonValue

from api.response_models import Response as ApiResponse

# Every status a job row holds: the values the code writes to `jobs.status` (set_job_status, _finalize_job,
# the queue loop and the worker). The metrics route emits one series per value (api/routes/metrics.py).
JobStatus = Literal["uploaded", "queued", "processing", "for_review", "reviewing", "completed", "failed"]


class JobSummary(ApiResponse):
    """One entry of GET /api/jobs."""

    id: str
    original_filename: str
    status: JobStatus = Field(description="uploaded, queued, processing, for_review, reviewing, completed or failed.")
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


class StageRecord(ApiResponse):
    """One entry of the stage report the worker stores (ADR-0059): what a stage did.
    Stored values pass through; `label` is added from the stage id."""

    stage: JsonValue = None
    label: JsonValue = Field(default=None, description="The stage's name, from its id.")
    status: JsonValue = Field(default=None, description="ran, skipped or failed.")
    reason: JsonValue = Field(default=None, description="Why a stage was skipped or failed.")
    egress: JsonValue = Field(
        default=None, description="Present when the stage sends the report out (ADR-0097): "
                                  "tlp, provider, host, local and allowed.")


class JobDetail(ApiResponse):
    """GET /api/jobs/{id}.  `enrichment` is present only in enrich mode; `stages` only when
    the worker stored a stage report."""

    id: str
    original_filename: str
    status: JobStatus
    report_text: str | None
    tlp_level: str | None
    pap_level: str | None
    created_at: str
    updated_at: str
    pipeline_mode: str
    entity_count: int
    relationship_count: int
    enrichment: EnrichmentSummary | None = None
    stages: list[StageRecord] | None = None


class StatusResult(ApiResponse):
    """PATCH /api/jobs/{id}: the status that was set."""

    status: Literal["for_review", "reviewing", "completed", "failed"]


class FinalizeResult(ApiResponse):
    """POST /api/jobs/{id}/finalize."""

    status: JobStatus = Field(description="The job's status after the rebuild.")
    bundle_size: int = Field(description="The length of the rebuilt bundle JSON.")
    validation: str = Field(description="validated, unverified (JSON schemas missing), unknown, or the stored verdict.")


class DeleteResult(ApiResponse):
    """DELETE /api/jobs/{id}."""

    deleted: str = Field(description="The id of the deleted job.")


# The ledger is stored inside each bundle, written by every release since
# ADR-0061, and its keys and value shapes changed across ADRs (a `changes`
# entry became an object with from/to/kind/reason).  Every value is any JSON
# value and every key optional, so a GET returns an older ledger as stored.

class LedgerObject(ApiResponse):
    """Why one object or edge of the bundle exists.  `origin` is always present; the other
    keys depend on the origin (status, upsert, changes, ...) and pass through unchanged."""

    origin: JsonValue = None


class LedgerEntity(ApiResponse):
    """What Stage 4 did with one entity row."""

    value: JsonValue = None
    entity_type: JsonValue = None
    outcome: JsonValue = Field(default=None, description="emitted, merged or dropped.")
    stix_id: JsonValue = None
    stix_type: JsonValue = None
    stix_name: JsonValue = None
    reason: JsonValue = None


class LedgerRelationship(ApiResponse):
    """What Stage 4 did with one relationship row."""

    source_value: JsonValue = None
    relationship_type: JsonValue = None
    target_value: JsonValue = None
    outcome: JsonValue = Field(default=None, description="emitted, merged or dropped.")
    changes: JsonValue = Field(
        default=None,
        description="What the mapping rewrote: objects with from, to, kind and reason "
                    "(older ledgers: property names).",
    )
    stix_id: JsonValue = None
    final_type: JsonValue = None
    source_ref: JsonValue = None
    target_ref: JsonValue = None
    reason: JsonValue = None
    merged_with: JsonValue = None


class LedgerRemoved(ApiResponse):
    """An object or edge that is not shipped, and why."""

    stix_id: JsonValue = None
    kind: JsonValue = Field(default=None, description="object or relationship.")
    reason: JsonValue = None
    replaced_by: JsonValue = None
    name: JsonValue = None


class LedgerRefused(ApiResponse):
    """An edge Stage 4 would have built and did not, because its triple was rejected or held."""

    source_ref: JsonValue = None
    relationship_type: JsonValue = None
    target_ref: JsonValue = None
    origin: JsonValue = None
    reason: JsonValue = None


class BundleLedger(ApiResponse):
    """GET /api/jobs/{id}/bundle/ledger (ADR-0061, pipeline/bundle_ledger.py).  Every key is
    optional: the route returns the stored ledger as it was written, and `refused` is
    present only when something was refused."""

    version: JsonValue = None
    objects: dict[str, LedgerObject] | JsonValue = None
    entities: list[LedgerEntity] | JsonValue = None
    relationships: list[LedgerRelationship] | JsonValue = None
    removed: list[LedgerRemoved] | JsonValue = None
    refused: list[LedgerRefused] | JsonValue = None
