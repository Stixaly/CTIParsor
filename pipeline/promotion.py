"""Grow the deny / promote lists from analyst decisions (ADR-0052).

Every review is a vote on a `(value, entity_type)`.  Aggregated across
reports, a value the analysts keep rejecting under one type is noise the
stages should stop proposing, and a value they keep accepting — or typed in
by hand — that no gazetteer knows is a name the gazetteer should learn.

Rules, each one number the operator can move:

* **deny** — rejected at least `min_rejections` times, in at least `min_jobs`
  distinct reports, and rejected in at least `share` of its reviews.  The
  report count is what stops one analyst's bad afternoon from becoming a
  rule; the share is what keeps a contested name (accepted as often as
  rejected) out of the list.
* **promote** — a gazetteer type (malware / threat_actor / tool), accepted at
  least `min_accepts` times (a hand-created `manual` entity counts as an
  accept — the analyst typed it), in at least `min_jobs` reports, accepted in
  at least `share` of its reviews, not already a gazetteer surface form, at
  least four characters (the gazetteer's own floor), and not made entirely
  of the generic vocabulary ADR-0050 enumerated — "accept all pending" is
  one click, and this is what keeps `"the malware"` out of a dictionary.

The output is a list of candidates.  `apply_candidates` stores them with
`status = 'candidate'` and refreshes the counts of rows that already exist
without touching their status: a candidate a human set to `ignored` stays
ignored, an `active` row stays active.  Activation is a separate, human
call.  Nothing here reads the pipeline; `pipeline/overrides.py` does.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from uuid import uuid4

from api.db import transaction
from pipeline.overrides import GAZETTEER_TYPES, NAMED_TYPES, normalise

DEFAULT_MIN_REJECTIONS = 3
DEFAULT_MIN_ACCEPTS = 3
DEFAULT_MIN_JOBS = 2
DEFAULT_SHARE = 0.8

# The gazetteer skips shorter keys (stage2b_gazetteer._MIN_NAME_LEN).
_MIN_TERM_LEN = 4


@dataclass
class Candidate:
    term: str
    entity_type: str
    action: str
    display: str
    accepted_count: int
    rejected_count: int
    job_count: int
    # What the store already holds for this (term, type, action): None when
    # new, else the existing row's status.
    existing_status: str | None = None
    sources: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class _Tally:
    accepted: int = 0
    rejected: int = 0
    accepted_jobs: set = field(default_factory=set)
    rejected_jobs: set = field(default_factory=set)
    surface: Counter = field(default_factory=Counter)
    sources: set = field(default_factory=set)


def load_decisions(conn) -> list[tuple[str, str, str, int | None, str]]:
    """(value, entity_type, source, accepted, job_id) for every reviewed row of a
    named type, plus every hand-created one (reviewed or not)."""
    marks = ",".join("?" for _ in NAMED_TYPES)
    rows = conn.execute(
        "SELECT value, entity_type, source, accepted, job_id FROM entities "
        f"WHERE entity_type IN ({marks}) AND (accepted IS NOT NULL OR source = 'manual')",
        tuple(sorted(NAMED_TYPES)),
    ).fetchall()
    return [(r["value"], r["entity_type"], r["source"], r["accepted"], r["job_id"]) for r in rows]


def compute_candidates(
    decisions: list[tuple[str, str, str, int | None, str]],
    *,
    known_terms: frozenset[str] | set[str] = frozenset(),
    min_rejections: int = DEFAULT_MIN_REJECTIONS,
    min_accepts: int = DEFAULT_MIN_ACCEPTS,
    min_jobs: int = DEFAULT_MIN_JOBS,
    share: float = DEFAULT_SHARE,
) -> list[Candidate]:
    from pipeline.stage2d_cyner import _is_generic_fragment

    tallies: dict[tuple[str, str], _Tally] = {}
    for value, entity_type, source, accepted, job_id in decisions:
        term = normalise(value)
        if not term or entity_type not in NAMED_TYPES:
            continue
        t = tallies.setdefault((term, entity_type), _Tally())
        t.sources.add(source)
        if accepted == 0:
            t.rejected += 1
            t.rejected_jobs.add(job_id)
            continue
        # accepted == 1, or a manual row the analyst never had to accept
        if accepted == 1 or source == "manual":
            t.accepted += 1
            t.accepted_jobs.add(job_id)
            t.surface[value.strip()] += 1

    out: list[Candidate] = []
    for (term, entity_type), t in sorted(tallies.items()):
        total = t.accepted + t.rejected
        if not total:
            continue
        display = t.surface.most_common(1)[0][0] if t.surface else term

        def _candidate(action: str, job_count: int) -> Candidate:
            return Candidate(
                term=term, entity_type=entity_type, action=action, display=display,
                accepted_count=t.accepted, rejected_count=t.rejected, job_count=job_count,
                sources=sorted(t.sources),
            )

        if (t.rejected >= min_rejections and len(t.rejected_jobs) >= min_jobs
                and t.rejected / total >= share):
            out.append(_candidate("deny", len(t.rejected_jobs)))
        if (entity_type in GAZETTEER_TYPES and t.accepted >= min_accepts
                and len(t.accepted_jobs) >= min_jobs and t.accepted / total >= share
                and term not in known_terms and len(term) >= _MIN_TERM_LEN
                and not _is_generic_fragment(term)):
            out.append(_candidate("promote", len(t.accepted_jobs)))
    return out


# ── Store ────────────────────────────────────────────────────────────────────


def _row(r) -> dict:
    return dict(zip(r.keys(), tuple(r)))


def list_overrides(conn, *, status: str | None = None, action: str | None = None) -> list[dict]:
    clauses, params = [], []
    if status:
        clauses.append("status=?")
        params.append(status)
    if action:
        clauses.append("action=?")
        params.append(action)
    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    rows = conn.execute(
        "SELECT id, term, entity_type, action, status, display, accepted_count, rejected_count, "
        f"job_count, origin, note, created_at, updated_at FROM entity_overrides {where}"
        "ORDER BY action, entity_type, term",
        tuple(params),
    ).fetchall()
    return [_row(r) for r in rows]


def gazetteer_terms() -> frozenset[str]:
    """Every surface form the gazetteer already matches (base index + active promotions)."""
    try:
        from pipeline.stage2b_gazetteer import _load
        return frozenset(e["name"] for e in _load())
    except Exception:
        return frozenset()


def propose(
    conn,
    *,
    min_rejections: int = DEFAULT_MIN_REJECTIONS,
    min_accepts: int = DEFAULT_MIN_ACCEPTS,
    min_jobs: int = DEFAULT_MIN_JOBS,
    share: float = DEFAULT_SHARE,
) -> list[Candidate]:
    """Candidates from the store's decisions, each annotated with the status
    the store already holds for it (so the report can say "already active")."""
    candidates = compute_candidates(
        load_decisions(conn), known_terms=gazetteer_terms(),
        min_rejections=min_rejections, min_accepts=min_accepts, min_jobs=min_jobs, share=share,
    )
    existing = {(o["term"], o["entity_type"], o["action"]): o["status"] for o in list_overrides(conn)}
    for c in candidates:
        c.existing_status = existing.get((c.term, c.entity_type, c.action))
    return candidates


_UPSERT_CANDIDATE = (
    "INSERT INTO entity_overrides (id, term, entity_type, action, status, display, accepted_count, "
    "rejected_count, job_count, origin, created_at, updated_at) "
    "VALUES (?,?,?,?,'candidate',?,?,?,?,'auto',?,?) "
    "ON CONFLICT (term, entity_type, action) DO UPDATE SET "
    "accepted_count=excluded.accepted_count, rejected_count=excluded.rejected_count, "
    "job_count=excluded.job_count, display=excluded.display, updated_at=excluded.updated_at"
)


def apply_candidates(conn, candidates: list[Candidate], now: str) -> int:
    """Store every candidate as `candidate`; an existing row of the same key
    keeps its status (active stays active, ignored stays ignored) and only its
    counts are refreshed.  Returns the number of rows written.

    Wrapped in one transaction: `conn` runs in autocommit mode on both
    backends (see api.db.transaction's docstring), so without this a process
    killed partway through the loop would leave earlier candidates durably
    committed and later ones silently dropped, with no rollback."""
    with transaction(conn):
        for c in candidates:
            conn.execute(_UPSERT_CANDIDATE, (
                str(uuid4()), c.term, c.entity_type, c.action, c.display,
                c.accepted_count, c.rejected_count, c.job_count, now, now,
            ))
    return len(candidates)


def set_status(conn, override_id: str, status: str, now: str) -> dict | None:
    cur = conn.execute(
        "UPDATE entity_overrides SET status=?, updated_at=? WHERE id=?", (status, now, override_id)
    )
    conn.commit()
    if cur.rowcount == 0:
        return None
    return _row(conn.execute("SELECT * FROM entity_overrides WHERE id=?", (override_id,)).fetchone())


def activate_all_candidates(conn, now: str) -> int:
    cur = conn.execute(
        "UPDATE entity_overrides SET status='active', updated_at=? WHERE status='candidate'", (now,)
    )
    conn.commit()
    return cur.rowcount


def validate_promote_term(term: str) -> str | None:
    """None if `term` is safe to promote to the Stage 2b gazetteer; otherwise
    the reason it isn't.

    Applies the same bar compute_candidates holds auto-generated candidates
    to (ADR-0052, see the `promote` branch above): a manually created
    'promote' override has exactly the same power to pollute every future
    report with a false-positive gazetteer match -- there is no analyst
    review step for a manual override the way there is for a candidate --
    so it must clear the same length / not-generic-vocabulary bar.
    """
    from pipeline.stage2d_cyner import _is_generic_fragment

    stripped = normalise(term)
    if len(stripped) < _MIN_TERM_LEN:
        return f"'term' must be at least {_MIN_TERM_LEN} characters for a 'promote' rule"
    if _is_generic_fragment(stripped):
        return "'term' reads as generic CTI vocabulary, not a specific name, and would match too broadly if promoted"
    return None


def add_manual(conn, term: str, entity_type: str, action: str, now: str, *,
               display: str | None = None, note: str | None = None) -> dict:
    """A hand-written rule, active at once.  An existing row of the same key is
    switched to active and marked manual rather than duplicated.

    Raises ValueError for a 'promote' term that fails validate_promote_term --
    a 'deny' rule carries no equivalent risk (it can only suppress a match,
    never manufacture one), so the gate applies to 'promote' only.
    """
    if action == "promote":
        reason = validate_promote_term(term)
        if reason:
            raise ValueError(reason)
    key = normalise(term)
    conn.execute(
        "INSERT INTO entity_overrides (id, term, entity_type, action, status, display, origin, note, "
        "created_at, updated_at) VALUES (?,?,?,?,'active',?,'manual',?,?,?) "
        "ON CONFLICT (term, entity_type, action) DO UPDATE SET status='active', origin='manual', "
        "display=COALESCE(excluded.display, entity_overrides.display), note=excluded.note, "
        "updated_at=excluded.updated_at",
        (str(uuid4()), key, entity_type, action, (display or term).strip(), note, now, now),
    )
    conn.commit()
    return _row(conn.execute(
        "SELECT * FROM entity_overrides WHERE term=? AND entity_type=? AND action=?",
        (key, entity_type, action),
    ).fetchone())


def delete_override(conn, override_id: str) -> bool:
    cur = conn.execute("DELETE FROM entity_overrides WHERE id=?", (override_id,))
    conn.commit()
    return cur.rowcount > 0
