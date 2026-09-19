"""Calibrate NER confidence cutoffs from analyst decisions (ADR-0051).

Every CyNER/GLiNER entity the review UI shows is stored with the model's raw
`confidence` and, once an analyst rules on it, `accepted` = 1/0.  Those pairs
are a labelled sample of P(correct | score) for each (source, entity_type),
which is exactly what a discard threshold should be chosen from — instead of
the one constant per stage that ships today (GLiNER 0.40, CyNER 0.70).

Method
------
Raw scores from a neural tagger are not probabilities (they are typically
over-confident), so the sample is first passed through **isotonic regression**
— the pool-adjacent-violators algorithm, which fits the closest non-decreasing
step function to the observed accept rate.  The proposed cutoff is then the
lowest score at which the *calibrated* acceptance probability reaches the
target precision.  Because every step boundary is an observed score, the
proposal can never go below what analysts have actually seen: nothing is
extrapolated into the region the current cutoff already hides.

Three guards, each reported as a status rather than silently applied:

* `insufficient_samples` — fewer decisions than `min_samples`; the estimate
  would be noise (the rarer GLiNER labels get here first).
* `target_unreachable` — no score band reaches the target: raising the cutoff
  would not fix the label, it needs a content filter (as ADR-0050 found for
  CyNER's generic-language spans) or a better label wording.
* `above_auto_accept` — the only band that reaches the target starts at or
  above the tier the review UI accepts on its own (`Review.tsx`,
  AUTO_ACCEPT_THRESHOLD = 90 %).  Accepts up there are mostly implicit — the
  analyst had to *undo* them to reject — so the sample is biased in the
  model's favour and a cutoff resting on it is not the analyst's verdict.
  Left to a human, via the `unclamped` value the report carries.

Nothing here touches the model: it is a threshold on scores the stages already
compute, read back by `pipeline.thresholds` in the next worker subprocess.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from api.logging_config import get_logger

logger = get_logger(__name__)

# Sources whose scores are calibrated.  Gazetteer/IoC/LLM rows carry fixed
# nominal confidences (0.92, 1.0, 0.9), not a model score to threshold.
CALIBRATED_SOURCES: tuple[str, ...] = ("cyner", "gliner")

# The review UI accepts anything at or above this on load (Review.tsx,
# AUTO_ACCEPT_THRESHOLD = 90 %).  Kept as the ceiling for a proposed cutoff.
AUTO_ACCEPT_LEVEL = 0.90

DEFAULT_TARGET_PRECISION = 0.90
DEFAULT_MIN_SAMPLES = 200

# Floor on a SINGLE isotonic block's own sample count before its rate is
# trusted as the cutoff. min_samples above only gates the pair's aggregate
# decision count; PAVA can still isolate one lucky (or unlucky) decision into
# its own tiny block that happens to already be locally non-decreasing, which
# min_samples alone does not catch. The blocks' rates are non-decreasing by
# construction, so skipping an under-sized block and continuing to the next
# one never picks a worse cutoff than the aggregate check already allowed.
DEFAULT_MIN_BLOCK_SAMPLES = 20


@dataclass(frozen=True)
class Block:
    """One step of the isotonic fit: scores in [lo, hi] share one calibrated rate."""
    lo: float
    hi: float
    n: int
    accepted: int

    @property
    def rate(self) -> float:
        return self.accepted / self.n


def isotonic_blocks(points: list[tuple[float, bool]]) -> list[Block]:
    """Pool-adjacent-violators over (score, accepted) pairs.

    Returns the non-decreasing step function closest (least squares) to the
    observed accept rate, as blocks ordered by score.  Empty input → no blocks.
    """
    # [lo, hi, n, accepted]; means compared by cross-multiplication so the
    # merge test never divides.
    blocks: list[list] = []
    for score, ok in sorted(points, key=lambda p: p[0]):
        blocks.append([score, score, 1, 1 if ok else 0])
        while len(blocks) >= 2:
            prev, last = blocks[-2], blocks[-1]
            if prev[3] * last[2] <= last[3] * prev[2]:
                break
            blocks[-2:] = [[prev[0], last[1], prev[2] + last[2], prev[3] + last[3]]]
    return [Block(lo, hi, n, acc) for lo, hi, n, acc in blocks]


def calibrated_rate(blocks: list[Block], score: float) -> float | None:
    """P(accepted | score) from the fit; None when the fit is empty."""
    if not blocks:
        return None
    for b in blocks:
        if score <= b.hi:
            return b.rate
    return blocks[-1].rate


@dataclass
class Proposal:
    source: str
    entity_type: str
    current: float
    target_precision: float
    sample_size: int = 0
    accepted: int = 0
    rejected: int = 0
    min_score: float | None = None
    max_score: float | None = None
    status: str = "insufficient_samples"
    proposed: float | None = None
    # The data-supported cutoff before the auto-accept ceiling was applied;
    # equals `proposed` unless status is `above_auto_accept`.
    unclamped: float | None = None
    precision_at_current: float | None = None
    recall_at_current: float | None = None
    precision_at_proposed: float | None = None
    recall_at_proposed: float | None = None
    curve: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def _precision_recall(points: list[tuple[float, bool]], cutoff: float) -> tuple[float | None, float | None]:
    """Empirical precision among score >= cutoff, and the share of all
    accepted entities that survive it."""
    kept = [ok for s, ok in points if s >= cutoff]
    total_ok = sum(1 for _, ok in points if ok)
    if not kept:
        return None, (0.0 if total_ok else None)
    kept_ok = sum(1 for ok in kept if ok)
    precision = kept_ok / len(kept)
    recall = kept_ok / total_ok if total_ok else None
    return precision, recall


def propose(
    source: str,
    entity_type: str,
    current: float,
    points: list[tuple[float, bool]],
    *,
    target_precision: float = DEFAULT_TARGET_PRECISION,
    min_samples: int = DEFAULT_MIN_SAMPLES,
    min_block_samples: int = DEFAULT_MIN_BLOCK_SAMPLES,
    auto_accept_level: float = AUTO_ACCEPT_LEVEL,
) -> Proposal:
    """One (source, entity_type)'s proposal from its decided (score, accepted) pairs."""
    p = Proposal(source=source, entity_type=entity_type, current=current, target_precision=target_precision)
    p.sample_size = len(points)
    p.accepted = sum(1 for _, ok in points if ok)
    p.rejected = p.sample_size - p.accepted
    if not points:
        return p
    scores = [s for s, _ in points]
    p.min_score, p.max_score = min(scores), max(scores)
    p.precision_at_current, p.recall_at_current = _precision_recall(points, current)

    blocks = isotonic_blocks(points)
    p.curve = [{"lo": b.lo, "hi": b.hi, "n": b.n, "rate": round(b.rate, 4)} for b in blocks]

    if p.sample_size < min_samples:
        p.status = "insufficient_samples"
        return p

    # Monotone fit: once a block reaches the target every higher block does
    # too, so the first such block's lower edge is the lowest safe cutoff.
    first_ok = next((b for b in blocks if b.rate >= target_precision), None)
    if first_ok is None:
        p.status = "target_unreachable"
        return p

    # min_samples above only gates the pair's AGGREGATE decision count, not
    # how much of it actually falls at or above this specific cutoff. PAVA
    # can isolate a single lucky decision into its own already-monotone block
    # (no violation to pool it with a neighbour), so first_ok.n alone is not
    # a reliable guard -- a legitimate, well-supported cutoff is routinely
    # made of many such small blocks in a row. What has to be large enough is
    # the SAME support _precision_recall(points, cutoff) below counts: every
    # decision at or above the proposed cutoff, which is the population this
    # cutoff's precision actually rests on going forward.
    support = sum(1 for s, _ in points if s >= first_ok.lo)
    if support < min_block_samples:
        p.status = "target_unreachable"
        return p

    p.unclamped = first_ok.lo
    if first_ok.lo >= auto_accept_level:
        p.status = "above_auto_accept"
        return p

    p.proposed = first_ok.lo
    p.precision_at_proposed, p.recall_at_proposed = _precision_recall(points, p.proposed)
    p.status = "unchanged" if abs(p.proposed - current) < 1e-9 else "ok"
    return p


# ── Database side ────────────────────────────────────────────────────────────


def stage_default(source: str) -> float:
    """The cutoff a stage applies when no override exists."""
    if source == "gliner":
        from pipeline.stage2e_gliner import _GLINER_THRESHOLD
        return _GLINER_THRESHOLD
    if source == "cyner":
        from pipeline.stage2d_cyner import _MEDIUM_THRESH
        return _MEDIUM_THRESH
    raise ValueError(f"no calibrated stage for source {source!r}")


def load_decisions(
    conn, sources: tuple[str, ...] = CALIBRATED_SOURCES,
) -> dict[tuple[str, str], list[tuple[float, bool]]]:
    """Every analyst-decided row of the calibrated sources, grouped by (source, entity_type)."""
    marks = ",".join("?" for _ in sources)
    rows = conn.execute(
        "SELECT source, entity_type, confidence, accepted FROM entities "
        f"WHERE accepted IS NOT NULL AND confidence IS NOT NULL AND source IN ({marks})",
        tuple(sources),
    ).fetchall()
    grouped: dict[tuple[str, str], list[tuple[float, bool]]] = {}
    for r in rows:
        grouped.setdefault((r["source"], r["entity_type"]), []).append(
            (float(r["confidence"]), bool(r["accepted"]))
        )
    return grouped


def list_overrides(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT source, entity_type, threshold, sample_size, target_precision, precision_at, "
        "recall_retained, origin, updated_at FROM model_thresholds ORDER BY source, entity_type"
    ).fetchall()
    return [dict(zip(r.keys(), tuple(r))) for r in rows]


def calibrate(
    conn,
    *,
    target_precision: float = DEFAULT_TARGET_PRECISION,
    min_samples: int = DEFAULT_MIN_SAMPLES,
    sources: tuple[str, ...] = CALIBRATED_SOURCES,
) -> list[Proposal]:
    """A proposal per (source, entity_type) that has any decided rows.

    `current` is the cutoff in force today — the stored override if there is
    one, else the stage default — so the before/after in the report is real.
    """
    overrides = {(o["source"], o["entity_type"]): float(o["threshold"]) for o in list_overrides(conn)}
    decisions = load_decisions(conn, sources)
    proposals = []
    for (source, entity_type), points in sorted(decisions.items()):
        current = overrides.get((source, entity_type), stage_default(source))
        proposals.append(propose(
            source, entity_type, current, points,
            target_precision=target_precision, min_samples=min_samples,
        ))
    return proposals


_UPSERT = (
    "INSERT INTO model_thresholds (source, entity_type, threshold, sample_size, target_precision, "
    "precision_at, recall_retained, origin, updated_at) VALUES (?,?,?,?,?,?,?,?,?) "
    "ON CONFLICT (source, entity_type) DO UPDATE SET threshold=excluded.threshold, "
    "sample_size=excluded.sample_size, target_precision=excluded.target_precision, "
    "precision_at=excluded.precision_at, recall_retained=excluded.recall_retained, "
    "origin=excluded.origin, updated_at=excluded.updated_at"
)


def apply_proposals(conn, proposals: list[Proposal], now: str) -> int:
    """Store every proposal that carries a cutoff; the guarded statuses leave
    whatever row exists untouched.  Returns the number of rows written.

    p.proposed is a raw score off entities.confidence -- a column with no
    CHECK constraint and no clamp in either NER stage -- so it is range-
    checked here the same way api/routes/thresholds.py's manual PUT already
    validates a hand-set threshold. Persisting a value outside [0, 1] would
    make get_threshold's `score < cutoff` comparison silently always-reject
    (or always-accept) every future prediction for that (source, entity_type),
    with no error anywhere in the write path to catch it.
    """
    written = 0
    for p in proposals:
        if p.proposed is None:
            continue
        if not 0.0 <= p.proposed <= 1.0:
            logger.warning(
                f"[calibration] skipping out-of-range proposed threshold "
                f"{p.proposed!r} for ({p.source}, {p.entity_type})"
            )
            continue
        conn.execute(_UPSERT, (
            p.source, p.entity_type, p.proposed, p.sample_size, p.target_precision,
            p.precision_at_proposed, p.recall_at_proposed, "calibrated", now,
        ))
        written += 1
    conn.commit()
    return written


def set_override(conn, source: str, entity_type: str, threshold: float, now: str) -> None:
    """A hand-set cutoff (origin 'manual'); the next calibration run overwrites it
    only if it has enough decisions to propose one."""
    conn.execute(_UPSERT, (source, entity_type, threshold, 0, None, None, None, "manual", now))
    conn.commit()


def clear_override(conn, source: str, entity_type: str) -> bool:
    cur = conn.execute(
        "DELETE FROM model_thresholds WHERE source=? AND entity_type=?", (source, entity_type)
    )
    conn.commit()
    return cur.rowcount > 0
