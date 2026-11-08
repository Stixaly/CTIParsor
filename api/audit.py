"""The audit trail: who changed what, and whether it was done (ADR-0097 item 17).

One record per state-changing request to `/api/...` (POST, PUT, PATCH, DELETE), written
after the answer, by `AuditMiddleware`, so no route can forget it.  And one per change
made by the admin command line (`api/admin.py`).  A record goes to two places:

  * a JSON line on standard output (standard error for a change made by the command line), through
    the logger `ctiparsor.audit`, always JSON
    whatever `LOG_FORMAT` says, for the log system the organisation already runs;
  * a row of `audit_events` (migration 19), read by `GET /api/audit` (admin).

A record holds what identifies the request and its answer: the time, the request id,
the user (or none), how they signed in, the method, the route template (the raw path
only when no route matched), the path parameters, the status, the outcome, the client
address and, for a sign-in, the account it named.  It never holds a request or response
body, a query string, a header, a cookie, a token or a password: the middleware does not
read any of them, and `tests/test_audit.py` sends each one and searches the output for it.

The retention (`AUDIT_RETENTION_DAYS`, default 365, 0 keeps everything) is applied at most
once an hour, by the process that writes a record.  A database error while writing the
row is logged and does not change the answer to the request.
"""
from __future__ import annotations

import asyncio
import getpass
import json
import logging
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, TextIO

from starlette.types import ASGIApp, Receive, Scope, Send

from api.auth.deps import AUTH_SCOPE_KEY
from api.db import get_conn
from api.logging_config import REQUEST_ID_SCOPE_KEY, get_logger, request_id_for
from pipeline.env_flags import env_int

logger = get_logger(__name__)

AUDIT_LOGGER = "ctiparsor.audit"
DEFAULT_RETENTION_DAYS = 365
_PRUNE_EVERY_S = 3600.0
_RECORDED_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# An answer that refused the request: the user was not allowed, or the thing was not there,
# or it conflicts, or too many came.  Any other failure is an error.
_REFUSED_STATUSES = frozenset({401, 403, 404, 409, 429})
OUTCOMES = ("ok", "refused", "error")
AUTH_KINDS = ("session", "token", "none", "cli")


# ---------------------------------------------------------------------------
# The log line: its own logger, its own handler, JSON only
# ---------------------------------------------------------------------------

_line_stream: TextIO | None = None


@contextmanager
def lines_to(stream: TextIO) -> Iterator[None]:
    """Send the audit lines to `stream` while the block runs.  The command line uses standard error:
    its standard output carries what a script reads (a token, for create-token)."""
    global _line_stream
    previous, _line_stream = _line_stream, stream
    try:
        yield
    finally:
        _line_stream = previous


class _LineHandler(logging.StreamHandler):
    """Standard output (or the stream `lines_to` names) as it is at the time of the record, so a
    redirect or a test's capture sees it."""

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = _line_stream or sys.stdout
        super().emit(record)


_audit_logger = logging.getLogger(AUDIT_LOGGER)
if not any(isinstance(h, _LineHandler) for h in _audit_logger.handlers):
    _handler = _LineHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(message)s"))      # the message is the JSON object itself
    _audit_logger.addHandler(_handler)
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False                                   # not the root's text lines as well


# ---------------------------------------------------------------------------
# Settings and helpers
# ---------------------------------------------------------------------------

def retention_days() -> int:
    """AUDIT_RETENTION_DAYS, read at each call: 0 keeps every row, a negative value is the default."""
    days = env_int("AUDIT_RETENTION_DAYS", default=DEFAULT_RETENTION_DAYS)
    return days if days >= 0 else DEFAULT_RETENTION_DAYS


def outcome_for(status: int) -> str:
    if 200 <= status < 400:
        return "ok"
    if status in _REFUSED_STATUSES:
        return "refused"
    return "error"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(moment: datetime) -> str:
    """The stored form of a time: UTC, fixed width, so the text compares as the time does."""
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def _insert(record: dict[str, Any]) -> None:
    target = record.get("target")
    get_conn().execute(
        "INSERT INTO audit_events (at, request_id, user_id, username, role, auth, method, route, target, "
        "status, outcome, client, attempted) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (record["at"], record["request_id"], record["user_id"], record["username"], record["role"],
         record["auth"], record["method"], record["route"],
         None if target is None else json.dumps(target, sort_keys=True),
         record["status"], record["outcome"], record["client"], record["attempted"]),
    )


_last_pruned = float("-inf")


def prune_if_due() -> None:
    """Apply the retention at most once an hour, on the write of a record: no thread of its own."""
    global _last_pruned
    now = time.monotonic()
    if now - _last_pruned < _PRUNE_EVERY_S:
        return
    _last_pruned = now
    prune()


def prune(now: datetime | None = None) -> None:
    """Delete the rows older than AUDIT_RETENTION_DAYS (nothing when that is 0)."""
    days = retention_days()
    if days == 0:
        return
    cutoff = timestamp((now or _now()) - timedelta(days=days))
    get_conn().execute("DELETE FROM audit_events WHERE at < ?", (cutoff,))


def write(record: dict[str, Any], *, row: bool = True) -> None:
    """Write one record: the JSON line, then the row (unless `row` is False).  Never raises: the
    answer to the request is decided before this runs, and a failed write is logged by its type
    only (the message of a database error can repeat the values it refused)."""
    _audit_logger.info(json.dumps({"audit": True, **record}, default=str))
    if not row:
        return
    try:
        _insert(record)
    except Exception as exc:
        logger.error("[audit] could not write an audit row (%s); the answer to the request is not changed",
                     type(exc).__name__)
        return
    try:
        prune_if_due()
    except Exception as exc:
        logger.error("[audit] could not apply the retention (%s)", type(exc).__name__)


def record_cli(command: str, target: dict[str, Any]) -> None:
    """A change made by `python -m api.admin`: the OS user who ran it, no request, no client."""
    try:
        username: str | None = getpass.getuser()
    except Exception:
        username = None
    write({
        "at": timestamp(_now()),
        "request_id": None,
        "user_id": None,
        "username": username,
        "role": None,
        "auth": "cli",
        "method": None,
        "route": command,
        "target": target,
        "status": None,
        "outcome": "ok",
        "client": None,
        "attempted": None,
    })


# ---------------------------------------------------------------------------
# The middleware
# ---------------------------------------------------------------------------

def _api_path(scope: Scope) -> str:
    path, root = scope["path"], scope.get("root_path", "")
    if root and path.startswith(root + "/"):
        path = path[len(root):]
    return path


def _actor(scope: Scope) -> tuple[Any, str]:
    """(user or None, how they signed in).  The gate's answer when it ran; else the user a route
    recorded in the request state (a sign-in, which is open, and creates a session)."""
    pair = scope.get(AUTH_SCOPE_KEY)
    if pair is not None and pair[0] is not None:
        user, session = pair
        return user, "session" if session is not None else "token"
    user = (scope.get("state") or {}).get("user")
    if user is not None:
        return user, "session"
    return None, "none"


#: An unmatched path is the caller's text: keep its start only.
_MAX_RAW_PATH = 256
#: The one open write whose anonymous refusals are kept as rows: failed sign-ins (rate-limited).
_SIGN_IN = "/api/auth/login"


def _keeps_row(record: dict[str, Any]) -> bool:
    """An anonymous request the gate refused (401, no user) is a JSON line only, not a row: an
    unauthenticated client must not be able to fill the table.  A failed sign-in is kept."""
    return not (record["user_id"] is None and record["status"] == 401 and record["route"] != _SIGN_IN)


def _record(scope: Scope, status: int) -> dict[str, Any]:
    user, auth = _actor(scope)
    route = scope.get("route")
    template = getattr(route, "path", None)
    if not template:
        # No route matched (an unknown path, or the gate's 401 before routing): the path itself,
        # with a NUL byte written out, since PostgreSQL refuses it in text.
        template = _api_path(scope).replace("\x00", "\\x00")[:_MAX_RAW_PATH]
    client = scope.get("client")
    return {
        "at": timestamp(_now()),
        "request_id": scope.get(REQUEST_ID_SCOPE_KEY),
        "user_id": user.id if user is not None else None,
        "username": user.username if user is not None else None,
        "role": user.role if user is not None else None,
        "auth": auth,
        "method": scope["method"],
        "route": template,
        "target": dict(scope.get("path_params") or {}),
        "status": status,
        "outcome": outcome_for(status),
        "client": client[0] if client else None,
        "attempted": (scope.get("state") or {}).get("audit_attempted"),
    }


class AuditMiddleware:
    """Pure ASGI, so the body is never read and the status is taken from the response start.

    It also assigns the request id (`api.logging_config.request_id_for`) that the request's log
    lines and its record share: `add_request_id` in `api/main.py` reuses it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        raw = ""
        for name, value in scope.get("headers", []):
            if name == b"x-request-id":
                raw = value.decode("latin-1")
                break
        scope[REQUEST_ID_SCOPE_KEY] = request_id_for(raw)
        if scope["method"] not in _RECORDED_METHODS or not _api_path(scope).startswith("/api/"):
            await self.app(scope, receive, send)
            return

        answer: dict[str, int] = {}

        async def send_and_see(message: Any) -> None:
            if message["type"] == "http.response.start":
                answer["status"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_and_see)
        finally:
            # An unhandled error sends no answer from the app: the server answers 500, so 500 is recorded.
            record = _record(scope, answer.get("status", 500))
            await asyncio.to_thread(write, record, row=_keeps_row(record))


# ---------------------------------------------------------------------------
# Reading (the route) and its filters
# ---------------------------------------------------------------------------

def stored_moment(value: str) -> str:
    """An ISO 8601 time from a query parameter, as the stored text.  A naive one is UTC."""
    moment = datetime.fromisoformat(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return timestamp(moment)
