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

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from api.auth import config, oidc, store
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
    # What the audit record may say about the name typed: the account it names, or nothing (api/audit.py).
    label = _label(body.username)
    request.state.audit_attempted = None if label == _UNKNOWN else label
    # The attempt is counted before the password is checked, under a lock per username.
    until = store.begin_attempt(body.username)
    if until is not None:
        logger.warning("[auth] sign-in refused, username locked: %s", label)
        raise _locked(until)
    user = store.check_credentials(body.username, body.password)
    if user is None:
        logger.warning("[auth] failed sign-in for %s", label)
        raise HTTPException(401, "Invalid username or password")
    store.clear_failures(body.username)
    store.mark_login(user.id)
    session_id, session = store.create_session(user.id)
    set_session_cookie(response, session_id, cookie_secure(request))
    request.state.user = user                       # the audit record names the account that signed in
    return _me(user, session.csrf_token)


_UNKNOWN = "<unknown>"


def _label(username: str) -> str:
    """What a log line may say about a typed username: the name of an existing account,
    else `<unknown>`.  The field can hold anything, a password included."""
    known = store.find_user(username)
    return known.username if known else _UNKNOWN


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



# ── Sign-in with an identity provider (api/auth/oidc.py) ─────────────────────

def _oidc_available() -> None:
    mode = config.auth_mode()
    if mode == "off":
        raise HTTPException(404, "Authentication is off")
    if not config.oidc_enabled():
        raise HTTPException(403, "OIDC sign-in is not enabled")


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store"})


OIDC_COOKIE = "ctiparsor_oidc"
OIDC_COOKIE_PATH = "/api/auth/oidc"


def _clear_binding(answer: RedirectResponse, request: Request) -> RedirectResponse:
    answer.delete_cookie(OIDC_COOKIE, path=OIDC_COOKIE_PATH, httponly=True, samesite="lax",
                         secure=cookie_secure(request))
    return answer


def _refused(code: str, detail: str, request: Request | None = None) -> RedirectResponse:
    """Back to the sign-in page with a fixed code; the log has the reason, never a token.
    With `request` (the callback), the binding cookie is deleted in the same answer."""
    logger.warning("[auth] OIDC sign-in refused (%s): %s", code, detail)
    answer = _redirect(f"/login?error={code}")
    return _clear_binding(answer, request) if request is not None else answer


@router.get("/oidc/login", status_code=302, responses={
    302: {"description": "To the identity provider's authorization endpoint, or to /login?error=<code>."},
    403: {"description": "OIDC sign-in is not enabled (AUTH_MODE is local)."},
    404: {"description": "Authentication is off (AUTH_MODE=off)."},
}, response_class=RedirectResponse)
@limiter.limit(login_rate_limit)
def oidc_login(request: Request, next_path: str = Query("/", alias="next")):
    _oidc_available()
    try:
        url, binding = oidc.begin_login(next_path)
    except oidc.OidcError as exc:
        return _refused(exc.code, str(exc))
    except config.AuthConfigError as exc:
        return _refused("config", str(exc))
    answer = _redirect(url)
    # Lax, not Strict: the identity provider sends the browser back with a cross-site GET.
    answer.set_cookie(OIDC_COOKIE, binding, max_age=int(store.OIDC_LOGIN_TTL.total_seconds()), httponly=True,
                      samesite="lax", secure=cookie_secure(request), path=OIDC_COOKIE_PATH)
    return answer


@router.get("/oidc/callback", status_code=302, responses={
    302: {"description": "To the page asked for, with the session cookie set, or to /login?error=<code>."},
    403: {"description": "OIDC sign-in is not enabled (AUTH_MODE is local)."},
    404: {"description": "Authentication is off (AUTH_MODE=off)."},
}, response_class=RedirectResponse)
@limiter.limit(login_rate_limit)
def oidc_callback(request: Request, code: str | None = None, state: str | None = None,
                  error: str | None = None):
    _oidc_available()
    if error:                                       # the identity provider refused; its text is not passed on
        if state:
            store.consume_oidc_login(state, request.cookies.get(OIDC_COOKIE))
        return _refused("denied", f"the identity provider answered error={error[:64]!r}", request)
    try:
        user, next_path = oidc.complete_login(code, state, request.cookies.get(OIDC_COOKIE))
    except oidc.OidcError as exc:
        return _refused(exc.code, str(exc), request)
    except config.AuthConfigError as exc:
        return _refused("config", str(exc), request)
    session_id, _ = store.create_session(user.id)
    answer = _clear_binding(_redirect(next_path), request)
    set_session_cookie(answer, session_id, cookie_secure(request))
    return answer
