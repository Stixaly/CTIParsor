"""Response models of `api/routes/ingest.py`.

Both routes return what `start_job` returns; the URL route adds three keys about
the capture.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from api.response_models import Response


class IngestJob(Response):
    """Result of a text or file ingest: the job that was queued or started."""
    job_id: str
    filename: str
    status: Literal["processing", "queued"] = Field(
        description="'processing' once the job runs, 'queued' while it waits for a worker.",
    )


class IngestUrlJob(IngestJob):
    """Result of a URL ingest: the IngestJob fields plus what the capture fetched."""
    source_url: str = Field(description="The URL after redirects.")
    blocked_requests: int = Field(description="Subresource requests refused by the route filter.")
    rendered_chars: int = Field(description="Visible DOM text at render time.")
