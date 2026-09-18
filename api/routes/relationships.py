from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.db import _lock, get_conn
from api.routes._common import require_job
from models.schemas import STIX_RELATIONSHIP_TYPES
from pipeline.stage3_llm import _parse_flexible_date

router = APIRouter(prefix="/api/jobs/{job_id}/relationships", tags=["relationships"])

# Sorted list of every STIX 2.1 relationship type the pipeline can emit, so the
# manual add/edit API accepts the same verbs the builder produces (previously a
# hardcoded 11-type subset rejected valid edges like "communicates-with").
VALID_REL_TYPES = sorted(STIX_RELATIONSHIP_TYPES)


_VALID_LABELS = {"observed", "reported", "assessed", "inferred", "gap"}


class RelPatch(BaseModel):
    accepted: bool | None = None
    source_value: str | None = None
    relationship_type: str | None = None
    target_value: str | None = None
    evidence_text: str | None = None
    evidence_label: str | None = None
    # STIX 2.1 SRO optional properties (spec Sec 5.1.2) — ISO 8601 date string,
    # or '' / null to clear.  Validated by _parse_date_field below.
    start_time: str | None = None
    stop_time: str | None = None


class RelCreate(BaseModel):
    source_value: str
    relationship_type: str
    target_value: str
    confidence: float = 0.8
    evidence_text: str | None = None
    evidence_label: str = "reported"
    start_time: str | None = None
    stop_time: str | None = None


def _parse_date_field(raw: str | None, field: str) -> str | None:
    """Parse one start_time/stop_time value for storage.

    None or an empty string clears the bound. Raises HTTPException(400) on an
    unparseable date — this is a direct analyst edit, so it gets an immediate,
    actionable error instead of the silent-drop behaviour LLM extraction uses
    (stage3_llm._normalize_llm_json, which can't ask a human to retry).
    """
    if raw is None or raw.strip() == "":
        return None
    dt = _parse_flexible_date(raw)
    if dt is None:
        raise HTTPException(400, f"Invalid {field}: '{raw}' is not a parseable date")
    return dt.isoformat()


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "job_id": row["job_id"],
        "source_value": row["source_value"],
        "relationship_type": row["relationship_type"],
        "target_value": row["target_value"],
        "confidence": row["confidence"],
        "accepted": None if row["accepted"] is None else bool(row["accepted"]),
        # evidence_text / evidence_label were added via migration; guard old rows
        "evidence_text": row["evidence_text"] if "evidence_text" in row.keys() else None,
        "evidence_label": (
            row["evidence_label"]
            if "evidence_label" in row.keys() and row["evidence_label"]
            else "reported"
        ),
        # start_time / stop_time were added via migration; guard old rows
        "start_time": row["start_time"] if "start_time" in row.keys() else None,
        "stop_time": row["stop_time"] if "stop_time" in row.keys() else None,
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
        require_job(conn, job_id)
    _label = body.evidence_label if body.evidence_label in _VALID_LABELS else "reported"
    _start = _parse_date_field(body.start_time, "start_time")
    _stop = _parse_date_field(body.stop_time, "stop_time")
    if _start and _stop and _stop <= _start:
        raise HTTPException(400, "stop_time must be later than start_time")
    rid = str(uuid4())
    with _lock:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO relationships "
                "(id,job_id,source_value,relationship_type,target_value,"
                "confidence,accepted,evidence_text,evidence_label,start_time,stop_time) "
                "VALUES (?,?,?,?,?,?,1,?,?,?,?)",
                (rid, job_id, body.source_value.strip(), body.relationship_type,
                 body.target_value.strip(), body.confidence, body.evidence_text, _label,
                 _start, _stop),
            )
            conn.commit()
    return {
        "id": rid, "job_id": job_id, **body.model_dump(), "evidence_label": _label,
        "start_time": _start, "stop_time": _stop, "accepted": True,
    }


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
    if "evidence_label" in patch.model_fields_set and patch.evidence_label is not None:
        if patch.evidence_label not in _VALID_LABELS:
            raise HTTPException(400, f"Unknown evidence_label '{patch.evidence_label}'. "
                                     f"Valid: {', '.join(sorted(_VALID_LABELS))}")
        updates.append("evidence_label=?")
        values.append(patch.evidence_label)
    if "start_time" in patch.model_fields_set or "stop_time" in patch.model_fields_set:
        # Only one bound may be patched at a time — fetch the other so the
        # STIX 2.1 stop_time > start_time constraint is checked against the
        # value that will actually be stored, not just the one in this PATCH.
        with get_conn() as conn:
            existing = conn.execute(
                "SELECT start_time, stop_time FROM relationships WHERE id=? AND job_id=?",
                (rel_id, job_id),
            ).fetchone()
        if not existing:
            raise HTTPException(404, "Relationship not found")
        existing_start = existing["start_time"] if "start_time" in existing.keys() else None
        existing_stop = existing["stop_time"] if "stop_time" in existing.keys() else None
        new_start = (
            _parse_date_field(patch.start_time, "start_time")
            if "start_time" in patch.model_fields_set else existing_start
        )
        new_stop = (
            _parse_date_field(patch.stop_time, "stop_time")
            if "stop_time" in patch.model_fields_set else existing_stop
        )
        if new_start and new_stop and new_stop <= new_start:
            raise HTTPException(400, "stop_time must be later than start_time")
        updates.append("start_time=?")
        values.append(new_start)
        updates.append("stop_time=?")
        values.append(new_stop)

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
