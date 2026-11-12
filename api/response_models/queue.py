"""Response models of api/routes/queue.py (GET /api/queue/status)."""
from typing import Literal

from pydantic import Field

from api.response_models import Response as ApiResponse


class QueueInfo(ApiResponse):
    """The job queue: its depth, its limit and the oldest queued job."""
    depth: int = Field(description="Jobs in the queued status.")
    max_depth: int = Field(description="API_QUEUE_MAX_DEPTH: the most queued jobs the API accepts.")
    oldest_queued_job_id: str | None
    oldest_queued_seconds: float | None


class WorkerStatus(ApiResponse):
    """One worker loop, or a worker known only from the jobs it holds."""

    worker_id: str
    state: Literal["stale", "busy", "idle"]
    role: str | None = Field(description="all, api or worker; None when the worker has no heartbeat row.")
    max_concurrent: int | None = Field(description="None when the worker has no heartbeat row; 0 or less is unlimited.")
    app_version: str | None
    started_at: str | None
    running_jobs: int
    heartbeat_seconds_ago: float | None
    oldest_heartbeat_seconds_ago: float | None
    stale: bool


class WorkerSummary(ApiResponse):
    """Counts of the workers in the status, by state, and the capacity they offer."""
    alive: int = Field(description="Workers that are not stale.")
    busy: int
    idle: int
    stale: int
    capacity: int | None = Field(
        description="The sum of the live workers' limits; None when one is unknown or unlimited.")
    idle_slots: int | None = Field(description="Capacity less the running jobs; None when capacity is None.")


class QueueStatus(ApiResponse):
    """GET /api/queue/status."""

    role: str
    backend: str
    counts: dict[str, int] = Field(description="Jobs by status; queued, processing and failed are always present.")
    queue: QueueInfo
    workers: list[WorkerStatus]
    worker_summary: WorkerSummary
