"""The first check of an authenticated deployment, before a request body is read.

FastAPI reads a JSON body or spools a multipart form before it solves the
dependencies, so an anonymous `POST /api/upload` would be parsed before the
access check refused it.  This pure ASGI middleware answers 401 first, to every
request for `/api/...` (and the interactive docs) that carries no valid session
cookie and no valid bearer token, except `GET /api/health` and
`POST /api/auth/login`.  Roles and CSRF stay in the dependency
(`api/auth/deps.py`), which reuses the answer found here.

It also hands the browser the new `Max-Age` when a request slid the session's
expiry, on whatever response follows (a stream included).
"""
from __future__ import annotations

import asyncio

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from api.auth import config
from api.auth.deps import AUTH_SCOPE_KEY, SESSION_COOKIE, authenticate, cookie_secure, set_session_cookie

# (method, path) that need no sign-in.
OPEN_REQUESTS = frozenset({("GET", "/api/health"), ("POST", "/api/auth/login")})
# Served by FastAPI itself, outside the routers.
DOC_PATHS = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"})


def is_gated(method: str, path: str) -> bool:
    """Does this request need a signed-in user?"""
    if (method, path) in OPEN_REQUESTS:
        return False
    return path.startswith("/api/") or path in DOC_PATHS


class AuthGateMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not config.enabled():
            await self.app(scope, receive, send)
            return
        path, root = scope["path"], scope.get("root_path", "")
        if root and path.startswith(root + "/"):
            path = path[len(root):]
        if not is_gated(scope["method"], path):
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        user, session = await asyncio.to_thread(authenticate, request)
        if user is None:
            answer = JSONResponse({"detail": "Authentication required"}, status_code=401,
                                  headers={"WWW-Authenticate": "Bearer"})
            await answer(scope, receive, send)
            return
        scope[AUTH_SCOPE_KEY] = (user, session)
        if session is None or not session.refreshed:
            await self.app(scope, receive, send)
            return
        cookie = Response()
        set_session_cookie(cookie, request.cookies[SESSION_COOKIE], cookie_secure(request))
        set_cookie = [(k, v) for k, v in cookie.raw_headers if k == b"set-cookie"]

        async def send_with_cookie(message: Message) -> None:
            if message["type"] == "http.response.start":
                message = {**message, "headers": [*message.get("headers", []), *set_cookie]}
            await send(message)

        await self.app(scope, receive, send_with_cookie)
