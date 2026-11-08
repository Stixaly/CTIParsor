"""The audit trail, read (ADR-0097 item 17): `GET /api/audit`, admin only.

Newest first.  Filters: `user` (a username), `route` (a route template, as recorded), `outcome`
(`ok`, `refused`, `error`), `since` and `until` (ISO 8601).  Keyset pagination like `GET /api/jobs`:
when more records follow, `X-Next-Cursor` holds the cursor of the next page.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Response

from api.audit import stored_moment
from api.db import get_conn
from api.response_models.audit import AuditEvent

router = APIRouter(prefix="/api/audit", tags=["audit"])

_CURSOR_MALFORMED = "malformed cursor"
_TIME_MALFORMED = "since and until are ISO 8601 times"
_COLUMNS = ("SELECT id, at, request_id, user_id, username, role, auth, method, route, target, status, "
            "outcome, client, attempted FROM audit_events")


def _encode_cursor(at: str, event_id: int) -> str:
    raw = json.dumps([at, event_id], separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> tuple[str, int]:
    """(at, id) of a cursor; 400 when this endpoint did not write it."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = json.loads(base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True))
    except (ValueError, TypeError):
        raise HTTPException(400, _CURSOR_MALFORMED) from None
    if not (isinstance(value, list) and len(value) == 2 and isinstance(value[0], str)
            and isinstance(value[1], int) and not isinstance(value[1], bool)):
        raise HTTPException(400, _CURSOR_MALFORMED)
    return value[0], value[1]


def _event(row: Any) -> dict:
    target = row["target"]
    return {
        "id": row["id"],
        "at": row["at"],
        "request_id": row["request_id"],
        "user_id": row["user_id"],
        "username": row["username"],
        "role": row["role"],
        "auth": row["auth"],
        "method": row["method"],
        "route": row["route"],
        "target": json.loads(target) if target is not None else None,
        "status": row["status"],
        "outcome": row["outcome"],
        "client": row["client"],
        "attempted": row["attempted"],
    }


@router.get("", response_model=list[AuditEvent], response_model_exclude_unset=True)
def list_audit(
    response: Response,
    user: str | None = Query(None, max_length=64, description="The username of the records."),
    route: str | None = Query(None, max_length=512, description="The route template, as recorded."),
    outcome: Literal["ok", "refused", "error"] | None = Query(None, description="ok, refused or error."),
    since: str | None = Query(None, max_length=64, description="Records at or after this ISO 8601 time."),
    until: str | None = Query(None, max_length=64, description="Records before this ISO 8601 time."),
    limit: int = Query(100, ge=1, le=500, description="Most records in this page (1-500)."),
    cursor: str | None = Query(None, description="The X-Next-Cursor of the previous page."),
):
    """The audit records, newest first (`at` DESC, then `id` DESC).  A page holds at most `limit`;
    when more follow, the header X-Next-Cursor holds the cursor of the next page."""
    clauses: list[str] = []
    params: list[Any] = []
    if user is not None:
        clauses.append("username = ?")
        params.append(user.strip().lower())
    if route is not None:
        clauses.append("route = ?")
        params.append(route)
    if outcome is not None:
        clauses.append("outcome = ?")
        params.append(outcome)
    try:
        if since is not None:
            clauses.append("at >= ?")
            params.append(stored_moment(since))
        if until is not None:
            clauses.append("at < ?")
            params.append(stored_moment(until))
    except ValueError:
        raise HTTPException(400, _TIME_MALFORMED) from None
    if cursor is not None:
        at, last_id = _decode_cursor(cursor)
        clauses.append("(at < ? OR (at = ? AND id < ?))")
        params += [at, at, last_id]
    sql = _COLUMNS + (" WHERE " + " AND ".join(clauses) if clauses else "")
    # One row more than the page: its presence says whether another page follows.
    sql += " ORDER BY at DESC, id DESC LIMIT ?"
    params.append(limit + 1)
    rows = get_conn().execute(sql, tuple(params)).fetchall()
    page = rows[:limit]
    if len(rows) > limit:
        last = page[-1]
        response.headers["X-Next-Cursor"] = _encode_cursor(last["at"], last["id"])
    return [_event(row) for row in page]
