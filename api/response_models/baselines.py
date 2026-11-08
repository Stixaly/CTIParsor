"""Response models of the STIX baseline routes (api/routes/baselines.py).

`POST /api/baselines/inspect` answers with `pipeline.baseline_stix.Intake`,
which the route already declares; this module holds the other operations.
"""
from __future__ import annotations

from pydantic import Field

from api.response_models import Response


class BaselineStatus(Response):
    """Whether this server enriches a bundle, and the limits it applies."""
    enabled: bool = Field(description="False when STIX_ENRICHMENT_ENABLED is off")
    max_bytes: int = Field(description="Largest bundle accepted, in bytes")
    max_objects: int = Field(description="Largest number of STIX objects accepted")
