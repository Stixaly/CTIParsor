"""The detectors' named entities reach the bundle on every path (audit B 8.1.2).

Stage 4 builds its malware, threat-actor and tool SDOs from the LLM's lists
only; a gazetteer, CyNER, GLiNER or alias-list entity the LLM did not echo is
recorded `dropped / not_in_llm_lists` (ADR-0061).  The API worker's
finalisation rebuilt those lists from the job store, so the UI shipped them;
the CLI and `run_document` passed `llm_result` as it came out of Stage 3 and
shipped bundles with no actor and no malware — silently, and contrary to
ADR-0059 ("one pipeline").  One helper now does it for both.

The same helper keeps one type per name (ADR-0092).  A name typed as more than
one of malware, threat actor, tool and campaign keeps the type or types of its
best-ranked source (`pipeline.base.TYPE_PRECEDENCE`, extended to the LLM and the
analyst; a campaign ranks after every source but the analyst's), leaves the
lists of the others and is recorded in the ledger.  Equal ranks all stay.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING, Any

from models.schemas import EntityType, RawEntity
from pipeline import decisions
from pipeline.base import DEFAULT_PRECEDENCE, TYPE_PRECEDENCE
from pipeline.stage3_llm import LLMEnrichmentResult

if TYPE_CHECKING:
    from pipeline.bundle_ledger import MappingLedger

#: The entity types Stage 4 maps through the LLM's named lists.
NAMED_LISTS: dict[EntityType, str] = {
    EntityType.MALWARE: "malware_families",
    EntityType.THREAT_ACTOR: "threat_actors",
    EntityType.TOOL: "tools",
}

#: The types compared by name: the three lists, and the campaign.
_COMPARED: frozenset[EntityType] = frozenset({*NAMED_LISTS, EntityType.CAMPAIGN})
#: The analyst's rank: nothing outranks it, and a campaign of it is not demoted.
ANALYST_RANK: int = TYPE_PRECEDENCE["analyst"]
#: A campaign ranks after every source but the analyst's: the LLM's `campaign_name`
#: is the one field where it re-types a name the others already found.
CAMPAIGN_RANK: int = DEFAULT_PRECEDENCE + 1


def stored_row_source(source: str | None, accepted: int | None, decision_origin: str | None) -> str:
    """The source a stored row counts as in the ranking: `analyst` for a row the
    analyst accepted on its own, `baseline_stix` for a row the analyst's baseline
    holds (Stage 3r accepted it, ADR-0090), the row's `source` otherwise.  A bulk
    accept, the auto-accept policy and a default do not make a row the analyst's."""
    if accepted == 1 and decision_origin == decisions.HUMAN:
        return "analyst"
    if accepted == 1 and decision_origin == decisions.BASELINE_STIX:
        return decisions.BASELINE_STIX
    return source or ""


def _key(value: str | None) -> str:
    return (value or "").lower().strip()


def _rank(source: str, entity_type: EntityType) -> int:
    rank = TYPE_PRECEDENCE.get(source, DEFAULT_PRECEDENCE)
    if entity_type == EntityType.CAMPAIGN and rank > ANALYST_RANK:
        return CAMPAIGN_RANK
    return rank


@dataclass(frozen=True)
class OutrankedType:
    """A (name, type) another type of the same name outranks (ADR-0092).
    `value` is the first spelling seen; `entity_type` an `EntityType` value;
    `kept_sources` every source of the kept types."""
    value: str
    entity_type: str
    sources: tuple[str, ...]
    kept_types: tuple[str, ...]
    kept_sources: tuple[str, ...]


@dataclass(frozen=True)
class NamedEntities:
    """`llm_result` with the named lists completed and the outranked types left
    out, and the types that were left out."""
    llm_result: LLMEnrichmentResult
    outranked: tuple[OutrankedType, ...] = ()

    def keeps(self, entity: RawEntity) -> bool:
        """False for a raw entity of an outranked (name, type), which Stage 4's
        input must not hold; True for every other, IoCs included."""
        return (_key(entity.value), entity.entity_type.value) not in self._gone

    @cached_property
    def _gone(self) -> frozenset[tuple[str, str]]:
        return frozenset((_key(o.value), o.entity_type) for o in self.outranked)

    def record(self, ledger: MappingLedger) -> None:
        """One `dropped / outranked_type` entry per outranked type (ADR-0061)."""
        for o in self.outranked:
            ledger.entity(o.value, o.entity_type, "dropped", reason="outranked_type",
                          sources=list(o.sources), kept_types=list(o.kept_types),
                          kept_sources=list(o.kept_sources))


def with_named_entities(
    llm_result: LLMEnrichmentResult,
    entities: Iterable[RawEntity | tuple[str, str] | tuple[str, str, str]],
    baseline_holds: Callable[[str, str], bool] | None = None,
) -> NamedEntities:
    """Every malware, threat-actor and tool in `entities` joins the matching
    list of `llm_result`, deduplicated case-insensitively; a name both have
    keeps the list's spelling.  `entities` are RawEntity objects (a pipeline
    run), or `(entity_type, value)` pairs or `(entity_type, value, source)`
    triples (the job store's rows; a pair has no source).  A name typed several
    ways leaves the lists of the outranked types, and `campaign_name` goes when
    its campaign is outranked (ADR-0092).  The result holds `llm_result` itself
    when nothing is added and nothing is outranked.

    `baseline_holds(entity_type, value)` is a run's Stage 3r answer (enrich
    mode): a (name, type) the analyst's baseline holds counts as `baseline_stix`,
    whatever found it, as its stored row does on a finalize (`stored_row_source`)."""
    lists: dict[str, list[str]] = {f: list(getattr(llm_result, f)) for f in NAMED_LISTS.values()}
    seen: dict[str, set[str]] = {f: {_key(n) for n in v} for f, v in lists.items()}
    # (name key, type) -> the first spelling, and every source that typed it so
    typed: dict[tuple[str, EntityType], tuple[str, set[str]]] = {}

    def note(value: str, etype: EntityType, source: str) -> None:
        key = _key(value)
        if key:
            if baseline_holds is not None and baseline_holds(etype.value, value):
                source = decisions.BASELINE_STIX
            typed.setdefault((key, etype), (value.strip(), set()))[1].add(source)

    for etype, field in NAMED_LISTS.items():
        for name in lists[field]:
            note(name, etype, "llm")
    if llm_result.campaign_name:
        note(llm_result.campaign_name, EntityType.CAMPAIGN, "llm")

    added = False
    for e in entities:
        raw_type: str | EntityType
        source: str
        if isinstance(e, RawEntity):
            raw_type, value, source = e.entity_type, e.value, e.source
        else:
            raw_type, value, *rest = e
            source = rest[0] if rest else ""
        try:
            etype = EntityType(raw_type)
        except ValueError:
            continue
        if etype not in _COMPARED:
            continue
        key = _key(value)
        if not key:
            continue
        note(value, etype, source)
        target = NAMED_LISTS.get(etype)
        if target is None or key in seen[target]:
            continue
        lists[target].append(value.strip())
        seen[target].add(key)
        added = True

    types_of: dict[str, list[EntityType]] = {}
    for key, etype in typed:
        types_of.setdefault(key, []).append(etype)
    outranked: list[OutrankedType] = []
    for key, etypes in types_of.items():
        if len(etypes) < 2:
            continue
        ranks = {t: min(_rank(s, t) for s in typed[(key, t)][1]) for t in etypes}
        best = min(ranks.values())
        kept = [t for t in etypes if ranks[t] == best]
        kept_types = tuple(sorted(t.value for t in kept))
        kept_sources = tuple(sorted({s for t in kept for s in typed[(key, t)][1]}))
        outranked.extend(
            OutrankedType(value=typed[(key, t)][0], entity_type=t.value,
                          sources=tuple(sorted(typed[(key, t)][1])),
                          kept_types=kept_types, kept_sources=kept_sources)
            for t in etypes if ranks[t] != best
        )

    if not outranked:
        return NamedEntities(llm_result if not added else llm_result.model_copy(update=lists))
    outranked.sort(key=lambda o: (_key(o.value), o.entity_type))
    gone = {(_key(o.value), o.entity_type) for o in outranked}
    update: dict[str, Any] = {
        field: [n for n in lists[field] if (_key(n), etype.value) not in gone]
        for etype, field in NAMED_LISTS.items()
    }
    if llm_result.campaign_name and (_key(llm_result.campaign_name), EntityType.CAMPAIGN.value) in gone:
        update["campaign_name"] = None
    return NamedEntities(llm_result.model_copy(update=update), tuple(outranked))
