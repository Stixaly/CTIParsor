"""Analyst-grown deny / promote lists — runtime side (ADR-0052).

`pipeline/stage2d_cyner.py` carries hand-kept lists of things the model gets
wrong (`_ORG_BLOCKLIST`, `_KNOWN_NON_MALWARE`, `_KNOWN_NON_ACTORS`), each
enumerated after someone read a real report's noise.  The `entity_overrides`
table is the same idea fed by the review UI instead of by hand:

* a `deny` row drops an exact `(value, entity_type)` from every NER stage's
  output — the gazetteer, CyNER, GLiNER, and the LLM's name lists;
* a `promote` row adds a term the analysts keep accepting (or created by
  hand) to the Stage 2b gazetteer, so the next report finds it
  deterministically at gazetteer confidence, before any model runs.

Only rows with `status = 'active'` act.  `pipeline/promotion.py` writes
`candidate` rows from the decisions and never touches a status; turning a
candidate active is a human's call (API or CLI).

Read once per process, like `pipeline/thresholds.py`: the pipeline runs in
a `spawn`ed subprocess per job, so each job sees the table as it stood when
it started.  Fails soft — no store, no table, a driver error, or
`ENTITY_OVERRIDES_ENABLED=false` all mean "no overrides" — and never creates
a store as a side effect of being asked.
"""
from __future__ import annotations

import functools

from api.logging_config import get_logger
from models.schemas import RawEntity
from pipeline.env_flags import env_bool

logger = get_logger(__name__)

# Types a deny row may name: the named SDOs a stage can mislabel.  IoC types
# are per-report facts (an address rejected in one report says nothing about
# the next), and TTPs are keyed by ATT&CK id, not by surface form.
NAMED_TYPES: frozenset[str] = frozenset({
    "malware", "threat_actor", "intrusion_set", "tool",
    "campaign", "infrastructure", "identity", "location",
})

# Types the Stage 2b gazetteer emits — the only ones a promote row can carry.
GAZETTEER_TYPES: frozenset[str] = frozenset({"malware", "threat_actor", "tool"})

ACTIONS: tuple[str, ...] = ("deny", "promote")
STATUSES: tuple[str, ...] = ("candidate", "active", "ignored")


def overrides_enabled() -> bool:
    return env_bool("ENTITY_OVERRIDES_ENABLED", default=True)


def normalise(value: str) -> str:
    """The match key: exact whole value, case-folded, outer whitespace dropped."""
    return value.strip().lower()


@functools.lru_cache(maxsize=1)
def _load_active() -> tuple[frozenset[tuple[str, str]], tuple[dict, ...]]:
    """(denied keys, promoted gazetteer entries) from the active rows.  Empty on any failure."""
    if not overrides_enabled():
        return frozenset(), ()
    try:
        import api.db as db

        rows = db.get_conn().execute(
            "SELECT term, entity_type, action, display FROM entity_overrides WHERE status='active'"
        ).fetchall()
    except Exception as exc:  # a missing table or store is the normal CLI case
        logger.debug(f"[overrides] none loaded ({type(exc).__name__}: {exc})")
        return frozenset(), ()

    denied: set[tuple[str, str]] = set()
    promoted: list[dict] = []
    for r in rows:
        term = normalise(r["term"])
        if r["action"] == "deny":
            denied.add((term, r["entity_type"]))
        elif r["action"] == "promote" and r["entity_type"] in GAZETTEER_TYPES:
            promoted.append({
                "name": term,
                "canonical": (r["display"] or "").strip() or r["term"],
                "entity_type": r["entity_type"],
                "mitre_id": None,
                "domain": "override",
            })
    if denied or promoted:
        logger.info(f"[overrides] {len(denied)} deny / {len(promoted)} promote row(s) active")
    return frozenset(denied), tuple(promoted)


def denied_keys() -> frozenset[tuple[str, str]]:
    return _load_active()[0]


def promoted_entries() -> list[dict]:
    """Gazetteer entries (the shape `pipeline/data/gazetteer.json` uses) for every active promote row."""
    return [dict(e) for e in _load_active()[1]]


def is_denied(value: str, entity_type: str) -> bool:
    return (normalise(value), entity_type) in denied_keys()


def drop_denied(entities: list[RawEntity]) -> list[RawEntity]:
    """*entities* without the ones an active deny row names.  A no-op list
    pass-through when nothing is denied, so a stage pays nothing by default."""
    keys = denied_keys()
    if not keys:
        return entities
    kept = [e for e in entities if (normalise(e.value), e.entity_type.value) not in keys]
    if len(kept) != len(entities):
        logger.info(f"[overrides] deny rows dropped {len(entities) - len(kept)} of {len(entities)} entities")
    return kept


def reload() -> None:
    """Forget the cached rows — and the gazetteer automaton built on them."""
    _load_active.cache_clear()
    try:
        from pipeline import stage2b_gazetteer
        stage2b_gazetteer._load.cache_clear()
        stage2b_gazetteer._build_automaton.cache_clear()
    except Exception:  # pragma: no cover - the gazetteer module is always importable here
        pass
