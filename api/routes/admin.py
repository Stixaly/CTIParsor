"""Users and API tokens, from the web interface (ADR-0097 items 14 and 15, part D).

The same functions as `python -m api.admin` (api/auth/store.py).  Everything here
answers 404 "Authentication is off" with `AUTH_MODE=off`.  The admin routes are for
an `admin`; `/api/auth/tokens` is for any signed-in user and only ever touches that
user's own tokens (another user's id is a 404, as an id that does not exist).
A password and a token are never logged; an action logs who did it and to whom.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from api.auth import config, store
from api.auth.deps import authenticate, current_user
from api.logging_config import get_logger, one_line
from api.response_models.admin import PasswordChanged, TokenCreated, TokenRecord, TokenRevoked, UserRecord
from api.routes._common import storable_text

logger = get_logger(__name__)

router = APIRouter(prefix="/api", tags=["admin"])

Role = Literal["reader", "analyst", "admin"]
_OFF: dict[int | str, dict[str, Any]] = {404: {"description": "Authentication is off (AUTH_MODE=off)."}}


class NewUser(BaseModel):
    username: str
    role: Role
    display_name: str = Field(default="", max_length=128)
    password: str

    @field_validator("display_name")
    @classmethod
    def _no_nul_or_lone_surrogate(cls, v: str) -> str:
        # PostgreSQL refuses these: a 422 here, a 500 at the INSERT otherwise (#634).
        storable_text(v)
        return v


class UserPatch(BaseModel):
    role: Role | None = None
    disabled: bool | None = None
    display_name: str | None = Field(default=None, max_length=128)

    @field_validator("display_name")
    @classmethod
    def _no_nul_or_lone_surrogate(cls, v: str | None) -> str | None:
        # PostgreSQL refuses these: a 422 here, a 500 at the UPDATE otherwise (#616).
        return storable_text(v)


class NewPassword(BaseModel):
    password: str


class NewToken(BaseModel):
    user_id: str
    name: str
    days: int = Field(default=config.DEFAULT_TOKEN_DAYS, ge=1, le=365)

    @field_validator("user_id", "name")
    @classmethod
    def _no_nul_or_lone_surrogate(cls, v: str) -> str:
        # PostgreSQL refuses these: a 422 here, a 500 otherwise (#616, #633).
        storable_text(v)
        return v


class NewOwnToken(BaseModel):
    name: str
    days: int = Field(default=config.DEFAULT_TOKEN_DAYS, ge=1, le=365)

    @field_validator("name")
    @classmethod
    def _no_nul_or_lone_surrogate(cls, v: str) -> str:
        # PostgreSQL refuses these: a 422 here, a 500 at the INSERT otherwise (#616).
        storable_text(v)
        return v


def _on() -> None:
    if config.auth_mode() == "off":
        raise HTTPException(404, "Authentication is off")


def _actor(user: store.User | None) -> store.User:
    # Not reachable with authentication on: the dependency has refused an anonymous request.
    if user is None:
        raise HTTPException(401, "Authentication required")
    return user


def _signed_in(request: Request) -> None:
    """A token is created from a signed-in session, never with a bearer token: a stolen
    token must not mint others that outlive its revocation (up to 365 days)."""
    _, session = authenticate(request)
    if session is None:
        raise HTTPException(403, "Create tokens from a signed-in session, not with a token")


def _bad(exc: store.AuthError) -> HTTPException:
    return HTTPException(400, str(exc))


def _user(user_id: str) -> dict:
    record = store.user_record(user_id)
    if record is None:
        raise HTTPException(404, "No such user")
    return record


# ── Users (admin) ────────────────────────────────────────────────────────────

@router.get("/admin/users", response_model=list[UserRecord], response_model_exclude_unset=True, responses=_OFF)
def list_users(_user_: store.User | None = Depends(current_user)):
    _on()
    return store.list_users()


@router.post("/admin/users", response_model=UserRecord, response_model_exclude_unset=True, status_code=201,
             responses={**_OFF, 400: {"description": "A bad username or password, or local accounts are off."},
                        409: {"description": "The username is taken."}})
def create_user(body: NewUser, user: store.User | None = Depends(current_user)):
    _on()
    if not config.local_enabled():
        raise HTTPException(400, "Local accounts are not enabled (AUTH_MODE is oidc)")
    try:
        created = store.create_user(body.username, body.role, password=body.password,
                                    display_name=body.display_name)
    except store.UsernameTakenError as exc:
        raise HTTPException(409, str(exc)) from None
    except store.AuthError as exc:
        raise _bad(exc) from None
    logger.info("[admin] %s created the %s account %s", _actor(user).username, created.role, created.username)
    return _user(created.id)


@router.patch("/admin/users/{user_id}", response_model=UserRecord, response_model_exclude_unset=True,
              responses={**_OFF, 404: {"description": "No such user, or authentication is off."},
                         409: {"description": "An admin changing themself, or the last enabled admin."}})
def patch_user(user_id: str, body: UserPatch, user: store.User | None = Depends(current_user)):
    """Change the role, the disabled flag or the display name.  Disabling ends the user's
    sessions and revokes no token (a disabled user's tokens are refused until it is enabled)."""
    _on()
    actor = _actor(user)
    _user(user_id)
    if user_id == actor.id and (body.disabled is True or (body.role is not None and body.role != "admin")):
        raise HTTPException(409, "You cannot disable or demote your own account")
    try:
        updated = store.update_user(user_id, role=body.role, disabled=body.disabled,
                                    display_name=body.display_name)
    except store.LastAdminError as exc:
        raise HTTPException(409, str(exc)) from None
    except store.AuthError as exc:
        raise _bad(exc) from None
    logger.info("[admin] %s changed %s: role=%s disabled=%s", actor.username, updated.username,
                updated.role, updated.disabled)
    return _user(user_id)


@router.post("/admin/users/{user_id}/password", response_model=PasswordChanged, response_model_exclude_unset=True,
             responses={**_OFF, 400: {"description": "The password policy refuses it, or the user is an OIDC one."}})
def set_user_password(user_id: str, body: NewPassword, user: store.User | None = Depends(current_user)):
    """Set a local user's password; it ends that user's sessions and clears their sign-in lock."""
    _on()
    target = _user(user_id)
    try:
        store.set_password(target["username"], body.password)
    except store.AuthError as exc:
        raise _bad(exc) from None
    logger.info("[admin] %s set the password of %s", _actor(user).username, target["username"])
    return {"id": user_id, "username": target["username"], "sessions_ended": True}


# ── Tokens (admin) ───────────────────────────────────────────────────────────

@router.get("/admin/tokens", response_model=list[TokenRecord], response_model_exclude_unset=True, responses=_OFF)
def list_all_tokens(_user_: store.User | None = Depends(current_user)):
    _on()
    return store.list_tokens()


@router.post("/admin/tokens", response_model=TokenCreated, response_model_exclude_unset=True, status_code=201,
             responses={**_OFF, 400: {"description": "A bad name."}, 404: {"description": "No such user."},
                        403: {"description": "Called with a bearer token instead of a signed-in session."}})
def create_token_for(body: NewToken, request: Request, user: store.User | None = Depends(current_user)):
    """A token for any user. The answer holds the token itself, once.  Needs a session."""
    _on()
    _signed_in(request)
    target = _user(body.user_id)
    return _new_token(_actor(user), target["id"], target["username"], body.name, body.days)


@router.delete("/admin/tokens/{token_id}", response_model=TokenRevoked, response_model_exclude_unset=True,
               responses={**_OFF, 404: {"description": "No active token with that id."}})
def revoke_any_token(token_id: str, user: store.User | None = Depends(current_user)):
    _on()
    if not store.revoke_token(token_id):
        raise HTTPException(404, "No active token with that id")
    logger.info("[admin] %s revoked token %s", _actor(user).username, one_line(token_id))
    return {"revoked": token_id}


# ── Own tokens (any signed-in user) ──────────────────────────────────────────

@router.get("/auth/tokens", response_model=list[TokenRecord], response_model_exclude_unset=True, responses=_OFF)
def list_own_tokens(user: store.User | None = Depends(current_user)):
    _on()
    return store.list_tokens(user_id=_actor(user).id)


@router.post("/auth/tokens", response_model=TokenCreated, response_model_exclude_unset=True, status_code=201,
             responses={**_OFF, 400: {"description": "A bad name."},
                        403: {"description": "Called with a bearer token instead of a signed-in session."}})
def create_own_token(body: NewOwnToken, request: Request, user: store.User | None = Depends(current_user)):
    """A token for the signed-in user, with their role. The answer holds the token itself, once.
    Needs a session."""
    _on()
    _signed_in(request)
    actor = _actor(user)
    return _new_token(actor, actor.id, actor.username, body.name, body.days)


@router.delete("/auth/tokens/{token_id}", response_model=TokenRevoked, response_model_exclude_unset=True,
               responses={**_OFF, 404: {"description": "No active token of yours with that id."}})
def revoke_own_token(token_id: str, user: store.User | None = Depends(current_user)):
    _on()
    actor = _actor(user)
    if not store.revoke_token(token_id, user_id=actor.id):
        raise HTTPException(404, "No active token with that id")
    logger.info("[admin] %s revoked their token %s", actor.username, one_line(token_id))
    return {"revoked": token_id}


def _new_token(actor: store.User, user_id: str, username: str, name: str, days: int) -> dict:
    try:
        secret, token_id = store.create_token(user_id, name, days=days)
    except store.AuthError as exc:
        raise _bad(exc) from None
    logger.info("[admin] %s created token %s (%s) for %s", actor.username, token_id, one_line(name, 64),
                one_line(username))
    record = store.get_token(token_id)
    if record is None:
        raise HTTPException(500, "The token was created but cannot be read back")
    return {**record, "token": secret}
