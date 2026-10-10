from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.db import _lock, get_conn, now_iso, transaction
from api.routes._common import require_job
from models.schemas import STIX_RELATIONSHIP_TYPES
from pipeline import decisions
from pipeline.temporal import (
    TemporalAssertion,
    analyst_assertion,
    display_bounds,
    legacy_assertions,
    mark_conflicts,
    times_from_json,
    times_to_json,
    window,
)

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
    # The analyst's start / end of the relationship (ADR-0063 §9), at the
    # precision they typed: "2023", "2023-03", "2023-03-12", "March 2023", a
    # timestamp with its offset — or '' / null to clear that bound.
    start_time: str | None = None
    stop_time: str | None = None
    # ADR-0058 — see EntityPatch.decision_origin.
    decision_origin: str = decisions.HUMAN


class RelBulk(BaseModel):
    ids: list[str]
    action: str                    # "accept" | "reject" | "reset"


# A review group is every row that shares a target; the largest measured on
# the 7 real reports was 6.  The cap keeps one call to one bounded statement.
_BULK_MAX = 500


class RelCreate(BaseModel):
    source_value: str
    relationship_type: str
    target_value: str
    confidence: float = 0.8
    evidence_text: str | None = None
    evidence_label: str = "reported"
    start_time: str | None = None
    stop_time: str | None = None


def _parse_date_field(raw: str | None, field: str) -> TemporalAssertion | None:
    """One analyst bound, at the precision typed (ADR-0063 §9).

    None or an empty string clears the bound. Raises HTTPException(400) on an
    entry that is not a date, or is ambiguous ("03/04/2023") -- this is a
    direct analyst edit, so it gets an immediate, actionable error instead of
    a date nobody can export.
    """
    if raw is None or raw.strip() == "":
        return None
    role = "start" if field == "start_time" else "end"
    try:
        return analyst_assertion(role, raw)
    except ValueError as exc:
        raise HTTPException(400, f"Invalid {field}: {exc}") from exc


def _out_of_order(start: TemporalAssertion | None, stop: TemporalAssertion | None) -> bool:
    """True when the end cannot come after the start.

    Compared as windows, not strings: a start in June 2023 and an end in March
    2023 contradict each other; a start and an end both in 2023 do not.  Two
    equal instants do (STIX requires stop_time > start_time).  Offsets are
    honoured -- 2023-06-02T20:00:00+00:00 is after 2023-06-02T23:00:00+05:00.
    """
    if start is None or stop is None:
        return False
    ws, we = window(start.value), window(stop.value)
    if ws is None or we is None:
        return False
    if start.precision == "instant" and stop.precision == "instant":
        return we[0] <= ws[0]
    return ws[0] >= we[1]


def _stored_times(row) -> list[TemporalAssertion]:
    """The row's dates: its assertions, or -- for a row written before
    ADR-0063 -- its start/stop timestamps as legacy dates."""
    keys = row.keys()
    times = times_from_json(row["times_json"] if "times_json" in keys else None)
    if times:
        return times
    return legacy_assertions(row["start_time"] if "start_time" in keys else None,
                             row["stop_time"] if "stop_time" in keys else None)


def _with_bound(times: list[TemporalAssertion], role: str,
                new: TemporalAssertion | None) -> list[TemporalAssertion]:
    """An analyst setting a bound replaces every assertion of that role; an
    analyst clearing it removes them (the old columns' semantics).  Dates of
    other roles are kept."""
    kept = [a for a in times if a.role != role]
    return mark_conflicts(kept + ([new] if new is not None else []))


def _row_to_dict(row) -> dict:
    times = _stored_times(row)
    start, stop = display_bounds(times)
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
        # ADR-0063: the value an analyst view shows for each bound (the
        # analyst's own first, then a verified one), and every date as stored.
        "start_time": start,
        "stop_time": stop,
        "times": [a.model_dump(mode="json", exclude_none=True) for a in times],
        "decision_origin": row["decision_origin"],
        # ADR-0082: why the pipeline held this claim back; it ships once accepted.
        "held_reason": row["held_reason"],
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
    if _out_of_order(_start, _stop):
        raise HTTPException(400, "stop_time must be later than start_time")
    _times = [a for a in (_start, _stop) if a is not None]
    rid = str(uuid4())
    now = now_iso()
    with _lock:
        with get_conn() as conn:
            with transaction(conn):
                # An analyst drew this edge: accepted, and their decision.
                conn.execute(
                    "INSERT INTO relationships "
                    "(id,job_id,source_value,relationship_type,target_value,"
                    "confidence,accepted,evidence_text,evidence_label,times_json,"
                    "decision_origin,decided_at) "
                    "VALUES (?,?,?,?,?,?,1,?,?,?,?,?)",
                    (rid, job_id, body.source_value.strip(), body.relationship_type,
                     body.target_value.strip(), body.confidence, body.evidence_text, _label,
                     times_to_json(_times), decisions.HUMAN, now),
                )
                conn.execute(
                    "INSERT INTO review_decisions "
                    "(job_id, target_kind, target_id, previous, accepted, origin, created_at) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (job_id, "relationship", rid, None, 1, decisions.HUMAN, now),
                )
    _shown_start, _shown_stop = display_bounds(_times)
    return {
        "id": rid, "job_id": job_id, **body.model_dump(), "evidence_label": _label,
        "start_time": _shown_start, "stop_time": _shown_stop,
        "times": [a.model_dump(mode="json", exclude_none=True) for a in _times],
        "accepted": True, "decision_origin": decisions.HUMAN, "held_reason": None,
    }


@router.post("/bulk")
def bulk_update_relationships(job_id: str, body: RelBulk):
    """Accept, reject or reset the given relationships in one statement.

    The review page groups the relationships that share a target and decides a
    group in one click.  Every row is journaled as `human_bulk` (ADR-0058),
    which calibration does not read.  Ids that belong to another job are not
    touched.  Returns { updated: N, action }.
    """
    if body.action not in ("accept", "reject", "reset"):
        raise HTTPException(400, "action must be one of: accept | reject | reset")
    ids = list(dict.fromkeys(i for i in body.ids if i))
    if not ids:
        raise HTTPException(400, "ids must not be empty")
    if len(ids) > _BULK_MAX:
        raise HTTPException(400, f"at most {_BULK_MAX} ids per call")

    with get_conn() as conn:
        require_job(conn, job_id)

    accepted = {"accept": True, "reject": False, "reset": None}[body.action]
    placeholders = ",".join("?" * len(ids))
    # A claim the pipeline held back (ADR-0082) is accepted one at a time, by
    # someone who read why: a group accept leaves it pending.
    held = " AND (held_reason IS NULL OR accepted IS NOT NULL)" if body.action == "accept" else ""
    with _lock:
        with get_conn() as conn:
            updated = decisions.record(
                conn, "relationship", f"job_id=? AND id IN ({placeholders}){held}", (job_id, *ids),
                accepted=accepted, origin=decisions.HUMAN_BULK, decided_at=now_iso(),
            )
    return {"updated": updated, "action": body.action}


@router.patch("/{rel_id}")
def update_relationship(job_id: str, rel_id: str, patch: RelPatch):
    if patch.relationship_type and patch.relationship_type not in VALID_REL_TYPES:
        raise HTTPException(400, f"Unknown relationship_type '{patch.relationship_type}'")
    if patch.decision_origin not in decisions.CLIENT_ORIGINS:
        raise HTTPException(
            400, f"decision_origin must be one of: {', '.join(sorted(decisions.CLIENT_ORIGINS))}",
        )

    if patch.accepted is True and patch.decision_origin == decisions.HUMAN_BULK:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT accepted, held_reason FROM relationships WHERE id=? AND job_id=?", (rel_id, job_id)
            ).fetchone()
        if row and decisions.held_from_bulk_accept(row, patch.accepted, patch.decision_origin):
            raise HTTPException(409, f"held for review ({row['held_reason']}): accept it on its own card")

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
    # `accepted` is a decision (ADR-0058), written through decisions.record below.
    decide = "accepted" in patch.model_fields_set
    if "evidence_text" in patch.model_fields_set:
        updates.append("evidence_text=?")
        values.append(patch.evidence_text)
    if "evidence_label" in patch.model_fields_set and patch.evidence_label is not None:
        if patch.evidence_label not in _VALID_LABELS:
            raise HTTPException(400, f"Unknown evidence_label '{patch.evidence_label}'. "
                                     f"Valid: {', '.join(sorted(_VALID_LABELS))}")
        updates.append("evidence_label=?")
        values.append(patch.evidence_label)
    _wants_date_update = (
        "start_time" in patch.model_fields_set or "stop_time" in patch.model_fields_set
    )

    if not updates and not _wants_date_update and not decide:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM relationships WHERE id=? AND job_id=?", (rel_id, job_id)
            ).fetchone()
            if not row:
                raise HTTPException(404, "Relationship not found")
        return _row_to_dict(row)

    with _lock:
        with get_conn() as conn:
            if _wants_date_update:
                # Only one bound may be patched at a time -- fetch the other so
                # the STIX 2.1 stop_time > start_time constraint is checked
                # against the value that will actually be stored, not just
                # the one in this PATCH. Read and validated inside the same
                # lock as the write below, not before acquiring it: two
                # concurrent single-field PATCHes on the same relationship
                # could otherwise each read the same pre-write row, each
                # validate cleanly against now-stale data, and jointly commit
                # an invalid stored range that neither request alone would
                # have been allowed to write.
                existing = conn.execute(
                    "SELECT * FROM relationships WHERE id=? AND job_id=?",
                    (rel_id, job_id),
                ).fetchone()
                if not existing:
                    raise HTTPException(404, "Relationship not found")
                times = _stored_times(existing)
                if "start_time" in patch.model_fields_set:
                    times = _with_bound(times, "start",
                                        _parse_date_field(patch.start_time, "start_time"))
                if "stop_time" in patch.model_fields_set:
                    times = _with_bound(times, "end",
                                        _parse_date_field(patch.stop_time, "stop_time"))
                # The pair the export would see: the analyst's own bound when
                # there is one, else a verified one.
                def _effective(role: str) -> TemporalAssertion | None:
                    mine = [a for a in times if a.role == role and a.origin == "analyst"]
                    ok = [a for a in times if a.role == role and a.status == "verified"]
                    pool = mine or ok
                    return pool[0] if pool else None
                if _out_of_order(_effective("start"), _effective("end")):
                    raise HTTPException(400, "stop_time must be later than start_time")
                # The legacy columns are folded into the assertions above and
                # cleared, so a row has one source of dates.
                updates += ["times_json=?", "start_time=?", "stop_time=?"]
                values += [times_to_json(times), None, None]

            values.extend([rel_id, job_id])
            with transaction(conn):
                if updates:
                    result = conn.execute(
                        f"UPDATE relationships SET {', '.join(updates)} WHERE id=? AND job_id=?",
                        values,
                    )
                    if result.rowcount == 0:
                        raise HTTPException(404, "Relationship not found")
                if decide:
                    decided = decisions.record(
                        conn, "relationship", "id=? AND job_id=?", (rel_id, job_id),
                        accepted=patch.accepted, origin=patch.decision_origin,
                        decided_at=now_iso(),
                    )
                    if decided == 0:
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
