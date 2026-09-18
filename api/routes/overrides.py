"""
GET    /api/overrides?status=&action=   — the deny / promote rows
POST   /api/overrides/promote           — candidates from analyst decisions
                                          (stored as `candidate` only with apply)
POST   /api/overrides                   — a hand-written rule, active at once
PATCH  /api/overrides/{id}              — candidate | active | ignored
DELETE /api/overrides/{id}

ADR-0052.  A `deny` row drops an exact (value, entity_type) from every NER
stage; a `promote` row adds a term to the Stage 2b gazetteer.  Only `active`
rows act.  The promotion job never activates: a candidate is a suggestion the
analysts' decisions make, activating it is a person's decision.
"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

import pipeline.overrides as overrides
from api.db import _lock, get_conn, now_iso
from pipeline.overrides import ACTIONS, GAZETTEER_TYPES, NAMED_TYPES, STATUSES
from pipeline.promotion import (
    DEFAULT_MIN_ACCEPTS,
    DEFAULT_MIN_JOBS,
    DEFAULT_MIN_REJECTIONS,
    DEFAULT_SHARE,
    add_manual,
    apply_candidates,
    delete_override,
    list_overrides,
    propose,
    set_status,
)

router = APIRouter(prefix="/api/overrides", tags=["overrides"])


class PromoteIn(BaseModel):
    min_rejections: int = DEFAULT_MIN_REJECTIONS
    min_accepts: int = DEFAULT_MIN_ACCEPTS
    min_jobs: int = DEFAULT_MIN_JOBS
    share: float = DEFAULT_SHARE
    apply: bool = False


class OverrideIn(BaseModel):
    term: str
    entity_type: str
    action: str
    display: str | None = None
    note: str | None = None


class StatusIn(BaseModel):
    status: str


def _check_rule(entity_type: str, action: str) -> None:
    if action not in ACTIONS:
        raise HTTPException(400, f"action must be one of: {', '.join(ACTIONS)}")
    allowed = GAZETTEER_TYPES if action == "promote" else NAMED_TYPES
    if entity_type not in allowed:
        raise HTTPException(400, f"entity_type for '{action}' must be one of: {', '.join(sorted(allowed))}")


@router.get("")
def get_overrides(status: str | None = Query(None), action: str | None = Query(None)) -> dict:
    if status is not None and status not in STATUSES:
        raise HTTPException(400, f"status must be one of: {', '.join(STATUSES)}")
    if action is not None and action not in ACTIONS:
        raise HTTPException(400, f"action must be one of: {', '.join(ACTIONS)}")
    with get_conn() as conn:
        rows = list_overrides(conn, status=status, action=action)
    return {"enabled": overrides.overrides_enabled(), "rows": rows}


@router.post("/promote")
def promote(body: PromoteIn) -> dict:
    if min(body.min_rejections, body.min_accepts, body.min_jobs) < 1:
        raise HTTPException(400, "'min_rejections', 'min_accepts' and 'min_jobs' must be positive integers")
    if not 0.0 < body.share <= 1.0:
        raise HTTPException(400, "'share' must be in (0, 1]")
    with _lock:
        with get_conn() as conn:
            candidates = propose(
                conn, min_rejections=body.min_rejections, min_accepts=body.min_accepts,
                min_jobs=body.min_jobs, share=body.share,
            )
            written = apply_candidates(conn, candidates, now_iso()) if body.apply else 0
    return {"applied": body.apply, "written": written, "candidates": [c.as_dict() for c in candidates]}


@router.post("")
def create_override(body: OverrideIn) -> dict:
    _check_rule(body.entity_type, body.action)
    if not body.term.strip():
        raise HTTPException(400, "'term' must not be empty")
    with _lock:
        with get_conn() as conn:
            row = add_manual(conn, body.term, body.entity_type, body.action, now_iso(),
                             display=body.display, note=body.note)
    overrides.reload()
    return row


@router.patch("/{override_id}")
def patch_override(override_id: str, body: StatusIn) -> dict:
    if body.status not in STATUSES:
        raise HTTPException(400, f"status must be one of: {', '.join(STATUSES)}")
    with _lock:
        with get_conn() as conn:
            row = set_status(conn, override_id, body.status, now_iso())
    if row is None:
        raise HTTPException(404, "Override not found")
    overrides.reload()
    return row


@router.delete("/{override_id}")
def remove_override(override_id: str) -> dict:
    with _lock:
        with get_conn() as conn:
            removed = delete_override(conn, override_id)
    if not removed:
        raise HTTPException(404, "Override not found")
    overrides.reload()
    return {"deleted": override_id}
