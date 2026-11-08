"""Sign-in, sign-out and "who am I" for the web interface (ADR-0097 item 15).

A local sign-in answers with the session cookie; an unknown username and a wrong
password get the same 401, and five failures for a username lock it for fifteen
minutes (api/auth/store.py).  Nothing here logs a password, a session id or a
token; a failed sign-in logs the username, cut to 64 characters, with `%r`.
"""
from __future__ import annotations

import math
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from api.auth import config, store
from api.auth.deps import SESSION_COOKIE, authenticate, cookie_secure, current_user, set_session_cookie
from api.logging_config import get_logger
from api.main import limiter
from api.response_models.auth import Me, SignedOut

logger = get_logger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


def login_rate_limit() -> str:
    """Sign-in requests per client address, a slowapi limit (LOGIN_RATE_LIMIT, default 10/minute)."""
    return (os.getenv("LOGIN_RATE_LIMIT") or "").strip() or "10/minute"


def _me(user: store.User | None, csrf_token: str | None) -> dict:
    return {
        "auth_mode": config.auth_mode(),
        "username": user.username if user else None,
        "display_name": user.display_name if user else None,
        "role": user.role if user else None,
        "auth_source": user.auth_source if user else None,
        "csrf_token": csrf_token,
    }


@router.post("/login", response_model=Me, responses={
    401: {"description": "Wrong username or password (the same answer for an unknown username)."},
    403: {"description": "Local accounts are not enabled (AUTH_MODE is oidc)."},
    404: {"description": "Authentication is off (AUTH_MODE=off)."},
    429: {"description": "Five failed attempts for this username in 15 minutes, or too many requests from "
                         "this address; try again after Retry-After seconds."},
})
@limiter.limit(login_rate_limit)
def login(body: LoginRequest, request: Request, response: Response):
    mode = config.auth_mode()
    if mode == "off":
        raise HTTPException(404, "Authentication is off")
    if not config.local_enabled():
        raise HTTPException(403, "Local sign-in is not enabled")
    # The attempt is counted before the password is checked, under a lock per username.
    until = store.begin_attempt(body.username)
    if until is not None:
        logger.warning("[auth] sign-in refused, username locked: %s", _label(body.username))
        raise _locked(until)
    user = store.check_credentials(body.username, body.password)
    if user is None:
        logger.warning("[auth] failed sign-in for %s", _label(body.username))
        raise HTTPException(401, "Invalid username or password")
    store.clear_failures(body.username)
    store.mark_login(user.id)
    session_id, session = store.create_session(user.id)
    set_session_cookie(response, session_id, cookie_secure(request))
    return _me(user, session.csrf_token)


def _label(username: str) -> str:
    """What a log line may say about a typed username: the name of an existing account,
    else `<unknown>`.  The field can hold anything, a password included."""
    known = store.find_user(username)
    return known.username if known else "<unknown>"


def _locked(until: datetime) -> HTTPException:
    wait = max(1, math.ceil((until - datetime.now(timezone.utc)).total_seconds()))
    return HTTPException(429, "Too many failed sign-in attempts; try again later",
                         headers={"Retry-After": str(wait)})


@router.post("/logout", response_model=SignedOut)
def logout(request: Request, response: Response, _user: store.User | None = Depends(current_user)):
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        store.delete_session(cookie)
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="strict",
                           secure=cookie_secure(request))
    return {"signed_out": True}


@router.get("/me", response_model=Me)
def me(request: Request, user: store.User | None = Depends(current_user)):
    csrf = None
    if user is not None:
        _, session = authenticate(request)
        csrf = session.csrf_token if session else None
    return _me(user, csrf)

