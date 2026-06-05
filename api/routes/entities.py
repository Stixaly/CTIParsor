from uuid import uuid4
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from api.db import get_conn, now_iso, _lock

from models.schemas import EntityType

router = APIRouter(prefix="/api/jobs/{job_id}/entities", tags=["entities"])

# Derived from the EntityType enum so it's always in sync — no need to
# maintain this list manually as new types are added to the pipeline.
VALID_TYPES = {e.value for e in EntityType}


class EntityPatch(BaseModel):
    accepted: bool | None = None
    entity_type: str | None = None
    value: str | None = None
    mitre_id: str | None = None


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
    }


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
        job = conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(404, "Job not found")

    eid = str(uuid4())
    with _lock:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO entities (id,job_id,value,entity_type,context,confidence,mitre_id,source) VALUES (?,?,?,?,?,?,?,?)",
                (eid, job_id, body.value, body.entity_type, body.context, body.confidence, body.mitre_id, "manual"),
            )
            conn.commit()
    return {"id": eid, "job_id": job_id, "value": body.value, "entity_type": body.entity_type,
            "context": body.context, "confidence": body.confidence, "mitre_id": body.mitre_id,
            "accepted": None, "source": "manual"}


@router.patch("/{entity_id}")
def update_entity(job_id: str, entity_id: str, patch: EntityPatch):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM entities WHERE id=? AND job_id=?", (entity_id, job_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Entity not found")

    updates = []
    values = []

    if patch.accepted is not None:
        updates.append("accepted=?")
        values.append(1 if patch.accepted else 0)
    elif patch.accepted is None and "accepted" in patch.model_fields_set:
        # explicitly set to null (reset to pending) — use parameterized value
        updates.append("accepted=?")
        values.append(None)

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

    if not updates:
        return _row_to_dict(row)

    values.extend([entity_id, job_id])
    with _lock:
        with get_conn() as conn:
            result = conn.execute(
                f"UPDATE entities SET {', '.join(updates)} WHERE id=? AND job_id=?",
                values,
            )
            conn.commit()
            if result.rowcount == 0:
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
            result = conn.execute(
                "UPDATE entities SET accepted=1 WHERE job_id=? AND accepted IS NULL",
                (job_id,),
            )
            conn.commit()
    return {"accepted": result.rowcount}


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
        raise HTTPException(400, "action 'reset' with scope 'pending' is a no-op: pending entities are already in the reset state")
    if body.entity_type not in VALID_TYPES:
        raise HTTPException(400, f"Unknown entity_type '{body.entity_type}'")

    # Verify the job exists
    with get_conn() as conn:
        if not conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, "Job not found")

    accepted_val = (
        1    if body.action == "accept" else
        0    if body.action == "reject" else
        None     # reset
    )

    # Only touch pending rows unless the caller explicitly asked for "all"
    scope_clause = "AND accepted IS NULL" if body.scope == "pending" else ""

    with _lock:
        with get_conn() as conn:
            result = conn.execute(
                f"UPDATE entities SET accepted=? "
                f"WHERE job_id=? AND entity_type=? {scope_clause}",
                (accepted_val, job_id, body.entity_type),
            )
            conn.commit()

    return {
        "updated":     result.rowcount,
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
