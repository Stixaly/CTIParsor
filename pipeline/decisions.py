"""Who decided an entity or relationship was right (ADR-0058).

`accepted` = 1/0 used to be all the store knew, and three very different
events wrote it: an analyst clicking accept on one card, an analyst accepting
a whole type at once, and the review page itself, which on first load wrote
`accepted = 1` for every entity at or above 90 % confidence.  Calibration
(ADR-0051) and the promote list (ADR-0052) then read every `accepted = 1` back
as an analyst's verdict — including the LLM's own name lists, stored at 0.9
and so accepted by the page before anyone looked at them.

Every write of `accepted` now goes through `record()`, which stamps the row
with a `decision_origin` and appends one row per change to `review_decisions`,
a journal that is only ever inserted into:

* `human`       — one decision on one card
* `human_bulk`  — one click that decided many rows (a type, a group, a selection)
* `auto_policy` — `apply_auto_accept()` at the end of a job; `policy_version`
                  records the level and control-sample rate it ran with
* `default`     — accepted at insertion (relationships the pipeline emits)
* `propagated`  — copied from an analyst decision (the lexicon rescan)
* `legacy`      — decided before this column existed; cannot be told apart

Readers that learn from decisions ask for `HUMAN_ORIGINS` (or only `human`).
"""
from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from pipeline.env_flags import env_float

HUMAN = "human"
HUMAN_BULK = "human_bulk"
AUTO_POLICY = "auto_policy"
DEFAULT = "default"
PROPAGATED = "propagated"
LEGACY = "legacy"

# The origins an API client may claim.  Anything automatic is written by the
# server itself, so a client can never label its own write as policy.
CLIENT_ORIGINS: frozenset[str] = frozenset({HUMAN, HUMAN_BULK})

# Decisions an analyst actually made.
HUMAN_ORIGINS: tuple[str, ...] = (HUMAN, HUMAN_BULK)

# The review UI's auto-accept tier, moved server-side.  Also the ceiling
# calibration puts on a proposed cutoff (pipeline.calibration).
AUTO_ACCEPT_LEVEL = 0.90

_TABLES = {"entity": "entities", "relationship": "relationships"}


def control_sample_rate() -> float:
    """Share of would-be auto-accepts left pending for an analyst to confirm.

    Those confirmations are the only unbiased labels above AUTO_ACCEPT_LEVEL,
    so they measure what auto-accept actually lets through.  0 disables.
    """
    rate = env_float("REVIEW_CONTROL_SAMPLE_RATE", default=0.10)
    return min(max(rate, 0.0), 1.0)


def policy_version(level: float = AUTO_ACCEPT_LEVEL, rate: float | None = None) -> str:
    """The parameters an auto-accept ran with, stored on every row it decided."""
    rate = control_sample_rate() if rate is None else rate
    return f"auto-accept/1 level={level:.2f} control={rate:.2f}"


def in_control_sample(row_id: str, rate: float) -> bool:
    """Deterministic draw on the row id — the same row always lands the same way,
    so a re-run of the policy never flips a row in or out of the sample."""
    if rate <= 0.0:
        return False
    if rate >= 1.0:
        return True
    digest = hashlib.sha256(row_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / 2**64 < rate


def record(
    conn,
    kind: str,
    where: str,
    params: Sequence[Any],
    *,
    accepted: bool | None,
    origin: str,
    decided_at: str,
    policy: str | None = None,
    actor: str | None = None,
) -> int:
    """Set `accepted` on every `kind` row matching `where`, and journal each one.

    One statement, so the journal and the rows cannot disagree: the rows are
    locked and read (for the previous value), updated, and the journal is
    written from what the UPDATE returned.  `where` must only reference the
    target table's columns.  Returns the number of rows decided.
    """
    table = _TABLES[kind]
    value = None if accepted is None else (1 if accepted else 0)
    sql = (
        f"WITH old AS (SELECT id, accepted AS prev FROM {table} WHERE {where} FOR UPDATE), "
        f"upd AS (UPDATE {table} t SET accepted=?, decision_origin=?, decided_at=?, policy_version=? "
        "FROM old WHERE t.id = old.id RETURNING t.id, t.job_id, old.prev) "
        "INSERT INTO review_decisions "
        "(job_id, target_kind, target_id, previous, accepted, origin, actor, policy_version, created_at) "
        "SELECT job_id, ?, id, prev, ?, ?, ?, ?, ? FROM upd"
    )
    cur = conn.execute(sql, (
        *params,
        value, origin, decided_at, policy,
        kind, value, origin, actor, policy, decided_at,
    ))
    return cur.rowcount


def apply_auto_accept(
    conn,
    job_id: str,
    decided_at: str,
    *,
    level: float = AUTO_ACCEPT_LEVEL,
    rate: float | None = None,
) -> dict[str, int]:
    """Accept a finished job's high-confidence entities, minus a control sample.

    Only rows nobody has decided yet (`decision_origin IS NULL`): a row an
    analyst reset to pending keeps `human` and is never re-accepted.  The
    control sample is drawn from the same eligible rows and left pending with
    `control_sample = 1`, for the review page to flag.

    Relationships are not touched: the pipeline already stores them accepted
    (`default`), so the page's old relationship rule never had a pending row
    to act on.
    """
    rate = control_sample_rate() if rate is None else rate
    eligible = conn.execute(
        "SELECT id FROM entities WHERE job_id=? AND accepted IS NULL "
        "AND decision_origin IS NULL AND control_sample=0 AND confidence >= ?",
        (job_id, level),
    ).fetchall()
    control = [r["id"] for r in eligible if in_control_sample(r["id"], rate)]
    for i in range(0, len(control), 500):
        batch = control[i:i + 500]
        marks = ",".join("?" for _ in batch)
        conn.execute(
            f"UPDATE entities SET control_sample=1 WHERE id IN ({marks})", tuple(batch),
        )
    accepted = record(
        conn, "entity",
        "job_id=? AND accepted IS NULL AND decision_origin IS NULL "
        "AND control_sample=0 AND confidence >= ?",
        (job_id, level),
        accepted=True, origin=AUTO_POLICY, decided_at=decided_at,
        policy=policy_version(level, rate),
    )
    return {"accepted": accepted, "control_sample": len(control)}


def auto_accept_audit(conn) -> list[dict]:
    """What the control sample says about auto-accept, per (source, entity_type).

    `precision` is the share of control-sample rows an analyst accepted, among
    those an analyst has decided one at a time — the estimate of how often an
    auto-accepted row of that kind is right.
    """
    rows = conn.execute(
        "SELECT source, entity_type, "
        "COUNT(*) AS sampled, "
        "SUM(CASE WHEN decision_origin=? THEN 1 ELSE 0 END) AS decided, "
        "SUM(CASE WHEN decision_origin=? AND accepted=1 THEN 1 ELSE 0 END) AS confirmed "
        "FROM entities WHERE control_sample=1 GROUP BY source, entity_type "
        "ORDER BY source, entity_type",
        (HUMAN, HUMAN),
    ).fetchall()
    out = []
    for r in rows:
        decided = int(r["decided"] or 0)
        confirmed = int(r["confirmed"] or 0)
        out.append({
            "source": r["source"],
            "entity_type": r["entity_type"],
            "sampled": int(r["sampled"]),
            "decided": decided,
            "confirmed": confirmed,
            "precision": round(confirmed / decided, 4) if decided else None,
        })
    return out
