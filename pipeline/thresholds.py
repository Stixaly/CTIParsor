"""Per-(source, entity_type) NER confidence cutoffs — runtime side (ADR-0051).

Stage 2d (CyNER) and Stage 2e (GLiNER) discard a prediction below a single
constant per stage.  This module lets a `model_thresholds` row override that
constant for one source+type, so a label that analysts reject at 0.45 can be
cut at 0.55 while another that they accept at 0.40 keeps its floor.

Rows are written by `pipeline.calibration` (from analyst decisions) or by hand
through `PUT /api/thresholds/...`; nothing here ever writes.

Read once per process: the pipeline runs in a `spawn`ed subprocess per job
(api/worker.py), so every job sees the table as it stood when it started and
no cross-process invalidation is needed.  The API process calls `reload()`
after it writes so `GET /api/thresholds` reflects the write.

Fails soft in every direction: no database, no table, a driver error, or
`THRESHOLD_CALIBRATION_ENABLED=false` all mean "use the stage's default".  A
CLI run (`main.py`) must never create an empty job store as a side effect of
asking for a threshold, hence the existence check before connecting.
"""
from __future__ import annotations

import functools

from api.logging_config import get_logger
from pipeline.env_flags import env_bool

logger = get_logger(__name__)


def calibration_enabled() -> bool:
    return env_bool("THRESHOLD_CALIBRATION_ENABLED", default=True)


@functools.lru_cache(maxsize=1)
def _load_all() -> dict[tuple[str, str], float]:
    """Every stored override, keyed by (source, entity_type).  Empty on any failure."""
    if not calibration_enabled():
        return {}
    try:
        import api.db as db

        conn = db.get_conn()
        rows = conn.execute(
            "SELECT source, entity_type, threshold FROM model_thresholds"
        ).fetchall()
    except Exception as exc:  # a missing table or store is the normal CLI case
        logger.debug(f"[thresholds] no overrides loaded ({type(exc).__name__}: {exc})")
        return {}
    loaded = {(r["source"], r["entity_type"]): float(r["threshold"]) for r in rows}
    if loaded:
        logger.info(f"[thresholds] {len(loaded)} calibrated cutoff(s) loaded")
    return loaded


def get_threshold(source: str, entity_type: str, default: float) -> float:
    """The cutoff for *source*+*entity_type*: the stored override, else *default*."""
    return _load_all().get((source, entity_type), default)


def overrides_for(source: str) -> dict[str, float]:
    """Every stored override for one source, keyed by entity_type."""
    return {t: v for (s, t), v in _load_all().items() if s == source}


def reload() -> None:
    _load_all.cache_clear()
