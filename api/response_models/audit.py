"""Response models of `api/routes/audit.py`."""
from __future__ import annotations

from pydantic import Field

from api.response_models import Response


class AuditEvent(Response):
    id: int = Field(description="The record's number; the cursor orders by it after the time.")
    at: str = Field(description="When the answer was written, UTC, ISO 8601.")
    request_id: str | None = Field(description="The X-Request-ID of the request (or the id the API gave it); "
                                               "None for a command-line change.")
    user_id: str | None = Field(description="The account; None when anonymous or for a command-line change.")
    username: str | None = Field(description="The account's username, or the operating-system user of a "
                                            "command-line change.")
    role: str | None = Field(description="reader, analyst or admin; None when anonymous.")
    auth: str = Field(description="session, token, none (no credentials, or AUTH_MODE=off) or cli.")
    method: str | None = Field(description="POST, PUT, PATCH or DELETE; None for a command-line change.")
    route: str = Field(description="The route template, for example /api/jobs/{job_id}; the raw path when no "
                                   "route matched; the command name for a command-line change.")
    target: dict | None = Field(description="The path parameters of the request, or the account or token id of "
                                            "a command-line change.")
    status: int | None = Field(description="The HTTP status of the answer; None for a command-line change.")
    outcome: str = Field(description="ok (2xx, 3xx), refused (401, 403, 404, 409, 429) or error (anything else).")
    client: str | None = Field(description="The client address as the application sees it.")
    attempted: str | None = Field(description="For a sign-in: the username, only when it is an existing "
                                             "account; never a name that matches none.")
