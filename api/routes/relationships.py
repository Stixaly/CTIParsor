from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.db import _lock, get_conn

router = APIRouter(prefix="/api/jobs/{job_id}/relationships", tags=["relationships"])

VALID_REL_TYPES = [
    "uses", "attributed-to", "targets", "indicates", "mitigates",
    "related-to", "delivers", "drops", "exploits", "originates-from", "compromises",
]


class RelPatch(BaseModel):
    accepted: bool | None = None
    source_value: str | None = None
    relationship_type: str | None = None
    target_value: str | None = None
    evidence_text: str | None = None


class RelCreate(BaseModel):
    source_value: str
    relationship_type: str
    target_value: str
    confidence: float = 0.8
    evidence_text: str | None = None


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "job_id": row["job_id"],
        "source_value": row["source_value"],
        "relationship_type": row["relationship_type"],
        "target_value": row["target_value"],
        "confidence": row["confidence"],
        "accepted": None if row["accepted"] is None else bool(row["accepted"]),
        # evidence_text was added via migration; use .get() for safety on old rows
        "evidence_text": row["evidence_text"] if "evidence_text" in row.keys() else None,
    }


@router.get("")
def list_relationships(job_id: str):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM relationships WHERE job_id=? ORDER BY relationship_type",
            (job_id,),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


@router.get("/valid-types")
def get_valid_types():
    return VALID_REL_TYPES


@router.post("")
def create_relationship(job_id: str, body: RelCreate):
    if body.relationship_type not in VALID_REL_TYPES:
        raise HTTPException(400, f"Unknown relationship_type '{body.relationship_type}'. "
                                 f"Valid types: {', '.join(VALID_REL_TYPES)}")
    with get_conn() as conn:
        if not conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, "Job not found")
    rid = str(uuid4())
    with _lock:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO relationships "
                "(id,job_id,source_value,relationship_type,target_value,confidence,accepted,evidence_text) "
                "VALUES (?,?,?,?,?,?,1,?)",
                (rid, job_id, body.source_value.strip(), body.relationship_type,
                 body.target_value.strip(), body.confidence, body.evidence_text),
            )
            conn.commit()
    return {"id": rid, "job_id": job_id, **body.model_dump(), "accepted": True}


@router.patch("/{rel_id}")
def update_relationship(job_id: str, rel_id: str, patch: RelPatch):
    if patch.relationship_type and patch.relationship_type not in VALID_REL_TYPES:
        raise HTTPException(400, f"Unknown relationship_type '{patch.relationship_type}'")

    # Build dynamic SET clause from whichever fields were sent
    updates: list[str] = []
    values: list = []

    if "source_value" in patch.model_fields_set and patch.source_value is not None:
        updates.append("source_value=?")
        values.append(patch.source_value.strip())
    if "relationship_type" in patch.model_fields_set and patch.relationship_type is not None:
        updates.append("relationship_type=?")
        values.append(patch.relationship_type)
    if "target_value" in patch.model_fields_set and patch.target_value is not None:
        updates.append("target_value=?")
        values.append(patch.target_value.strip())
    if "accepted" in patch.model_fields_set:
        accepted_val = 1 if patch.accepted is True else (0 if patch.accepted is False else None)
        updates.append("accepted=?")
        values.append(accepted_val)
    if "evidence_text" in patch.model_fields_set:
        updates.append("evidence_text=?")
        values.append(patch.evidence_text)

    if not updates:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM relationships WHERE id=? AND job_id=?", (rel_id, job_id)
            ).fetchone()
            if not row:
                raise HTTPException(404, "Relationship not found")
        return _row_to_dict(row)

    values.extend([rel_id, job_id])
    with _lock:
        with get_conn() as conn:
            result = conn.execute(
                f"UPDATE relationships SET {', '.join(updates)} WHERE id=? AND job_id=?",
                values,
            )
            conn.commit()
            if result.rowcount == 0:
                raise HTTPException(404, "Relationship not found")
            updated = conn.execute(
                "SELECT * FROM relationships WHERE id=?", (rel_id,)
            ).fetchone()
    return _row_to_dict(updated)


@router.delete("/{rel_id}")
def delete_relationship(job_id: str, rel_id: str):
    with _lock:
        with get_conn() as conn:
            result = conn.execute(
                "DELETE FROM relationships WHERE id=? AND job_id=?", (rel_id, job_id)
            )
            conn.commit()
            if result.rowcount == 0:
                raise HTTPException(404, "Relationship not found")
    return {"deleted": rel_id}
