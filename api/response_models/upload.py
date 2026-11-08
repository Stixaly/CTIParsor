"""Response models of api/routes/upload.py (POST /api/upload)."""
from typing import Literal

from api.response_models import Response as ApiResponse


class UploadResult(ApiResponse):
    """The job the upload created.  `status` is `processing` for a job the worker has taken,
    `queued` for one that waits; the frontend reads `processing` as the start."""

    job_id: str
    filename: str
    status: Literal["queued", "processing"]
