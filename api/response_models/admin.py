"""Response models of `api/routes/admin.py`.  No model has a field for a password,
a password hash, a token hash or a session id."""
from __future__ import annotations

from pydantic import Field

from api.response_models import Response


class UserRecord(Response):
    id: str
    username: str
    display_name: str
    auth_source: str = Field(description="local or oidc.")
    role: str = Field(description="reader, analyst or admin.")
    disabled: bool
    created_at: str
    last_login_at: str | None = None


class TokenRecord(Response):
    id: str
    name: str
    user_id: str
    username: str
    created_at: str
    expires_at: str
    revoked_at: str | None = None
    last_used_at: str | None = None


class TokenCreated(TokenRecord):
    token: str = Field(description="The bearer token. Shown this once; the server keeps only its hash.")


class TokenRevoked(Response):
    revoked: str = Field(description="The id of the token.")


class PasswordChanged(Response):
    id: str
    username: str
    sessions_ended: bool
