"""
GET    /api/thresholds                          — the cutoffs in force, per stage
POST   /api/thresholds/recalibrate              — propose (and optionally apply)
                                                  cutoffs from analyst decisions
PUT    /api/thresholds/{source}/{entity_type}   — hand-set one cutoff
DELETE /api/thresholds/{source}/{entity_type}   — back to the stage default

ADR-0051.  A cutoff is a number in [0, 1] on the raw confidence Stage 2d
(CyNER) or 2e (GLiNER) attaches to a prediction; below it the entity is never
shown.  `recalibrate` never applies unless asked: the report is the product,
the write is the analyst's call.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import pipeline.thresholds as thresholds
from api.db import _lock, get_conn, now_iso
from models.schemas import EntityType
from pipeline.calibration import (
    AUTO_ACCEPT_LEVEL,
    CALIBRATED_SOURCES,
    DEFAULT_MIN_SAMPLES,
    DEFAULT_TARGET_PRECISION,
    apply_proposals,
    calibrate,
    clear_override,
    list_overrides,
    set_override,
    stage_default,
)

router = APIRouter(prefix="/api/thresholds", tags=["thresholds"])

_VALID_TYPES = {e.value for e in EntityType}


class RecalibrateIn(BaseModel):
    target_precision: float = DEFAULT_TARGET_PRECISION
    min_samples: int = DEFAULT_MIN_SAMPLES
    apply: bool = False


class OverrideIn(BaseModel):
    threshold: float


def _check_key(source: str, entity_type: str) -> None:
    if source not in CALIBRATED_SOURCES:
        raise HTTPException(400, f"source must be one of: {', '.join(CALIBRATED_SOURCES)}")
    if entity_type not in _VALID_TYPES:
        raise HTTPException(400, f"Unknown entity_type '{entity_type}'")


@router.get("")
def get_thresholds() -> dict:
    with get_conn() as conn:
        rows = list_overrides(conn)
    return {
        "enabled": thresholds.calibration_enabled(),
        "auto_accept_level": AUTO_ACCEPT_LEVEL,
        "defaults": {source: stage_default(source) for source in CALIBRATED_SOURCES},
        "rows": rows,
    }


@router.post("/recalibrate")
def recalibrate(body: RecalibrateIn) -> dict:
    if not 0.0 < body.target_precision <= 1.0:
        raise HTTPException(400, "'target_precision' must be in (0, 1]")
    if body.min_samples < 1:
        raise HTTPException(400, "'min_samples' must be a positive integer")

    # _lock only needs to guard the actual write below: calibrate() is a
    # read-only, unindexed full scan of `entities` whose cost grows with the
    # whole analyst corpus, and holding the process-wide write lock for its
    # duration would block every job-status update/progress-emit in this
    # process for that long. Readers don't need this lock on either backend
    # (SQLite's WAL mode and Postgres both support concurrent reads).
    with get_conn() as conn:
        proposals = calibrate(
            conn, target_precision=body.target_precision, min_samples=body.min_samples,
        )
        written = 0
        if body.apply:
            with _lock:
                written = apply_proposals(conn, proposals, now_iso())
    if written:
        thresholds.reload()
    return {
        "applied": body.apply,
        "written": written,
        "proposals": [p.as_dict() for p in proposals],
    }


@router.put("/{source}/{entity_type}")
def put_threshold(source: str, entity_type: str, body: OverrideIn) -> dict:
    _check_key(source, entity_type)
    if not 0.0 <= body.threshold <= 1.0:
        raise HTTPException(400, "'threshold' must be in [0, 1]")
    with _lock:
        with get_conn() as conn:
            set_override(conn, source, entity_type, body.threshold, now_iso())
    thresholds.reload()
    return {"source": source, "entity_type": entity_type, "threshold": body.threshold, "origin": "manual"}


@router.delete("/{source}/{entity_type}")
def delete_threshold(source: str, entity_type: str) -> dict:
    _check_key(source, entity_type)
    with _lock:
        with get_conn() as conn:
            removed = clear_override(conn, source, entity_type)
    if not removed:
        raise HTTPException(404, "No override stored for that source and entity_type")
    thresholds.reload()
    return {"deleted": {"source": source, "entity_type": entity_type}, "default": stage_default(source)}
