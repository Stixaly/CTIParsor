from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.db import _lock, get_conn, now_iso, transaction
from api.routes._common import require_job
from models.schemas import EntityType
from pipeline import decisions

router = APIRouter(prefix="/api/jobs/{job_id}/entities", tags=["entities"])

# Derived from the EntityType enum so it's always in sync — no need to
# maintain this list manually as new types are added to the pipeline.
VALID_TYPES = {e.value for e in EntityType}


class EntityPatch(BaseModel):
    accepted: bool | None = None
    entity_type: str | None = None
    value: str | None = None
    mitre_id: str | None = None
    # ADR-0058 — 'human' (one card) or 'human_bulk' (a group or selection
    # decided in one click).  Automatic origins are the server's to write.
    decision_origin: str = decisions.HUMAN


class EntityCreate(BaseModel):
    value: str
    entity_type: str
    context: str = ""
    confidence: float = 1.0
    mitre_id: str | None = None


class BulkPatch(BaseModel):
    entity_type: str               # e.g. "malware"
    action: str                    # "accept" | "reject" | "reset"
    scope: str = "pending"         # "pending" → only NULL rows | "all" → every row of that type


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "job_id": row["job_id"],
        "value": row["value"],
        "entity_type": row["entity_type"],
        "context": row["context"],
        "confidence": row["confidence"],
        "mitre_id": row["mitre_id"],
        "accepted": None if row["accepted"] is None else bool(row["accepted"]),
        "source": row["source"],
        "decision_origin": row["decision_origin"],
        "control_sample": bool(row["control_sample"]),
        # ADR-0082: why the pipeline held this row back; it ships once accepted.
        "held_reason": row["held_reason"],
    }


def _check_origin(origin: str) -> None:
    if origin not in decisions.CLIENT_ORIGINS:
        raise HTTPException(
            400, f"decision_origin must be one of: {', '.join(sorted(decisions.CLIENT_ORIGINS))}",
        )


@router.get("")
def list_entities(job_id: str):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM entities WHERE job_id=? ORDER BY entity_type, value",
            (job_id,),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


@router.post("")
def create_entity(job_id: str, body: EntityCreate):
    if body.entity_type not in VALID_TYPES:
        raise HTTPException(400, f"Unknown entity_type '{body.entity_type}'")
    with get_conn() as conn:
        require_job(conn, job_id)

    eid = str(uuid4())
    with _lock:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO entities (id,job_id,value,entity_type,context,confidence,mitre_id,source) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (eid, job_id, body.value, body.entity_type, body.context, body.confidence, body.mitre_id, "manual"),
            )
            conn.commit()
    return {"id": eid, "job_id": job_id, "value": body.value, "entity_type": body.entity_type,
            "context": body.context, "confidence": body.confidence, "mitre_id": body.mitre_id,
            "accepted": None, "source": "manual", "decision_origin": None, "control_sample": False,
            "held_reason": None}


@router.patch("/{entity_id}")
def update_entity(job_id: str, entity_id: str, patch: EntityPatch):
    _check_origin(patch.decision_origin)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM entities WHERE id=? AND job_id=?", (entity_id, job_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Entity not found")
    if decisions.held_from_bulk_accept(row, patch.accepted, patch.decision_origin):
        raise HTTPException(409, f"held for review ({row['held_reason']}): accept it on its own card")

    updates: list[str] = []
    # SQL parameter values are heterogeneous (strings, None for NULL-clearing).
    values: list[Any] = []

    # `accepted` is a decision (ADR-0058): written through decisions.record so
    # the row carries its origin and the journal gets a line.  An explicit
    # null resets to pending, and still counts as the analyst's decision —
    # which is what keeps auto-accept from re-accepting it.
    decide = "accepted" in patch.model_fields_set

    if patch.entity_type is not None:
        if patch.entity_type not in VALID_TYPES:
            raise HTTPException(400, f"Unknown entity_type '{patch.entity_type}'")
        updates.append("entity_type=?")
        values.append(patch.entity_type)

    if patch.value is not None:
        updates.append("value=?")
        values.append(patch.value)

    if "mitre_id" in patch.model_fields_set:
        updates.append("mitre_id=?")
        values.append(patch.mitre_id)  # can be None to clear it

    if not updates and not decide:
        return _row_to_dict(row)

    values.extend([entity_id, job_id])
    with _lock:
        with get_conn() as conn:
            with transaction(conn):
                if updates:
                    result = conn.execute(
                        f"UPDATE entities SET {', '.join(updates)} WHERE id=? AND job_id=?",
                        values,
                    )
                    if result.rowcount == 0:
                        raise HTTPException(404, "Entity not found or was deleted")
                if decide:
                    decided = decisions.record(
                        conn, "entity", "id=? AND job_id=?", (entity_id, job_id),
                        accepted=patch.accepted, origin=patch.decision_origin, decided_at=now_iso(),
                    )
                    if decided == 0:
                        raise HTTPException(404, "Entity not found or was deleted")
            updated = conn.execute(
                "SELECT * FROM entities WHERE id=? AND job_id=?", (entity_id, job_id)
            ).fetchone()
    if updated is None:
        raise HTTPException(404, "Entity not found")
    return _row_to_dict(updated)


@router.post("/accept-pending")
def accept_all_pending(job_id: str):
    """Accept all entities whose accepted field is NULL (unreviewed) in one query."""
    with _lock:
        with get_conn() as conn:
            accepted = decisions.record(
                conn, "entity", "job_id=? AND accepted IS NULL AND held_reason IS NULL", (job_id,),
                accepted=True, origin=decisions.HUMAN_BULK, decided_at=now_iso(),
            )
    return {"accepted": accepted}


@router.post("/bulk")
def bulk_update_entities(job_id: str, body: BulkPatch):
    """
    Bulk accept / reject / reset all entities of a given type in one SQL query.

    action:
      "accept" → set accepted=1
      "reject" → set accepted=0
      "reset"  → set accepted=NULL  (back to pending)

    scope:
      "pending" (default) → only rows where accepted IS NULL
      "all"               → every row of that entity_type regardless of current state

    Returns { updated: N, entity_type, action } where N is the row count changed.
    """
    if body.action not in ("accept", "reject", "reset"):
        raise HTTPException(400, "action must be one of: accept | reject | reset")
    if body.scope not in ("pending", "all"):
        raise HTTPException(400, "scope must be one of: pending | all")
    if body.action == "reset" and body.scope == "pending":
        raise HTTPException(
            400,
            "action 'reset' with scope 'pending' is a no-op: "
            "pending entities are already in the reset state",
        )
    if body.entity_type not in VALID_TYPES:
        raise HTTPException(400, f"Unknown entity_type '{body.entity_type}'")

    # Verify the job exists
    with get_conn() as conn:
        require_job(conn, job_id)

    accepted_val = (
        True  if body.action == "accept" else
        False if body.action == "reject" else
        None      # reset
    )

    # Only touch pending rows unless the caller explicitly asked for "all"
    scope_clause = "AND accepted IS NULL" if body.scope == "pending" else ""
    # A row the pipeline held back (ADR-0082) is accepted one card at a time,
    # by someone who read why: never by a click over a whole type.
    if body.action == "accept":
        scope_clause += " AND (held_reason IS NULL OR accepted IS NOT NULL)"

    with _lock:
        with get_conn() as conn:
            updated = decisions.record(
                conn, "entity", f"job_id=? AND entity_type=? {scope_clause}",
                (job_id, body.entity_type),
                accepted=accepted_val, origin=decisions.HUMAN_BULK, decided_at=now_iso(),
            )

    return {
        "updated":     updated,
        "entity_type": body.entity_type,
        "action":      body.action,
        "scope":       body.scope,
    }


@router.delete("/{entity_id}")
def delete_entity(job_id: str, entity_id: str):
    with _lock:
        with get_conn() as conn:
            result = conn.execute(
                "DELETE FROM entities WHERE id=? AND job_id=?", (entity_id, job_id)
            )
            conn.commit()
            if result.rowcount == 0:
                raise HTTPException(404, "Entity not found")
    return {"deleted": entity_id}
