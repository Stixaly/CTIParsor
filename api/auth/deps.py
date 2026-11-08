"""The dependency that turns a request into a user and applies the permission table.

`api/main.py` adds `current_user` to every router at `include_router`.  A route
that needs the user (to record who imported a report, to decide a deletion)
declares it too: FastAPI resolves a dependency once per request, so both see
the same answer.

With AUTH_MODE=off every request passes and there is no user (`None`), as before
authentication existed.  Otherwise a request carries either a session cookie
(`ctiparsor_session`; a state-changing one also sends `X-CSRF-Token`) or an
`Authorization: Bearer ctp_...` token, which needs no CSRF token: a browser does
not attach it by itself.
"""
from __future__ import annotations

from fastapi import HTTPException, Request, Response

from api.auth import store
from api.auth.config import auth_mode, session_ttl_hours
from api.auth.permissions import OPEN, required_role
from api.logging_config import get_logger

logger = get_logger(__name__)

SESSION_COOKIE = "ctiparsor_session"
CSRF_HEADER = "X-CSRF-Token"
AUTH_SCOPE_KEY = "ctiparsor_auth"      # where the middleware leaves its answer for the dependency
_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def route_template(request: Request) -> str | None:
    """The path template of the route that matched, `/api/jobs/{job_id}` for example."""
    route = request.scope.get("route")
    return getattr(route, "path", None)


def cookie_secure(request: Request) -> bool:
    """Did the request arrive over HTTPS, by its scheme or by the proxy's
    `X-Forwarded-Proto`?  Only then is the cookie `Secure`: a browser (Safari) refuses
    a Secure cookie over http://localhost, which is how a published Docker port is reached."""
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return request.url.scheme == "https" or forwarded == "https"


def set_session_cookie(response: Response, session_id: str, secure: bool) -> None:
    response.set_cookie(SESSION_COOKIE, session_id, max_age=int(session_ttl_hours() * 3600),
                        httponly=True, samesite="strict", secure=secure, path="/")


def authenticate(request: Request, fresh: bool = False) -> tuple[store.User | None, store.Session | None]:
    """(user, session) for the credentials on the request: the session is None for a
    bearer token.  (None, None) without credentials, or with ones that do not hold.
    A bearer header that is refused is not retried as a cookie.  The answer the
    middleware already found is reused, unless `fresh` (a stream that checks again)."""
    if not fresh and AUTH_SCOPE_KEY in request.scope:
        return request.scope[AUTH_SCOPE_KEY]
    header = request.headers.get("authorization", "")
    if header:
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer":
            return None, None
        return store.find_token_user(token.strip()), None
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        session = store.find_session(cookie)
        if session is not None:
            return session.user, session
    return None, None


def current_user(request: Request) -> store.User | None:
    """The signed-in user, after the role and CSRF checks of the operation.

    Raises 401 without valid credentials, 403 below the operation's minimum role,
    for a cookie-authenticated state-changing request without the right
    `X-CSRF-Token`, and for an operation the permission table does not list.
    Returns None when AUTH_MODE is `off`, and for an `open` operation without credentials.
    """
    if auth_mode() == "off":
        return None
    template = route_template(request)
    minimum = required_role(request.method, template) if template else None
    if minimum is None:
        logger.error("[auth] no permission is defined for %s %s", request.method, template)
        raise HTTPException(403, "No permission is defined for this operation")
    user, session = authenticate(request)
    if minimum == OPEN:
        return user
    if user is None:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    if session is not None and request.method in _STATE_CHANGING:
        if not store.csrf_matches(session, request.headers.get(CSRF_HEADER)):
            raise HTTPException(403, "CSRF token missing or wrong")
    if not user.has_role(minimum):
        raise HTTPException(403, f"This operation needs the {minimum} role")
    request.state.user = user
    return user



def importing_user_id(request: Request) -> str | None:
    """The id to store as `jobs.imported_by` for a request that creates a report:
    the user `current_user` resolved, or None when authentication is off."""
    user = getattr(request.state, "user", None)
    return user.id if user else None
