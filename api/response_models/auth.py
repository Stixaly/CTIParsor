"""Response models of `api/routes/auth.py`."""
from __future__ import annotations

from pydantic import Field

from api.response_models import Response


class Me(Response):
    auth_mode: str = Field(description="AUTH_MODE: off, local, oidc or both.")
    username: str | None = Field(description="None when authentication is off.")
    display_name: str | None
    role: str | None = Field(description="reader, analyst or admin.")
    auth_source: str | None = Field(description="local or oidc.")
    csrf_token: str | None = Field(
        description="Sent back in the X-CSRF-Token header on every state-changing request made with the "
                    "session cookie; None for a bearer token.",
    )


class SignedOut(Response):
    signed_out: bool
