"""Response models of the API.

They describe what each operation returns today, so the contract snapshot
(`contract/openapi.json`, ADR-0094 item 1) records the response fields, not
only the request ones.  `extra="allow"` on every model: a field a model does
not declare is still returned as is, so declaring a model never changes a
response.  One module per route file (`api/routes/<name>.py` ->
`api/response_models/<name>.py`).
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Response(BaseModel):
    """Base of every response model: undeclared fields pass through."""

    model_config = ConfigDict(extra="allow")
