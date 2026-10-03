"""The detectors' named entities reach the bundle on every path (audit B 8.1.2).

Stage 4 builds its malware, threat-actor and tool SDOs from the LLM's lists
only; a gazetteer, CyNER, GLiNER or alias-list entity the LLM did not echo is
recorded `dropped / not_in_llm_lists` (ADR-0061).  The API worker's
finalisation rebuilt those lists from the job store, so the UI shipped them;
the CLI and `run_document` passed `llm_result` as it came out of Stage 3 and
shipped bundles with no actor and no malware — silently, and contrary to
ADR-0059 ("one pipeline").  One helper now does it for both.
"""
from __future__ import annotations

from collections.abc import Iterable

from models.schemas import EntityType, RawEntity
from pipeline.stage3_llm import LLMEnrichmentResult

#: The entity types Stage 4 maps through the LLM's named lists.
NAMED_LISTS: dict[EntityType, str] = {
    EntityType.MALWARE: "malware_families",
    EntityType.THREAT_ACTOR: "threat_actors",
    EntityType.TOOL: "tools",
}


def with_named_entities(
    llm_result: LLMEnrichmentResult,
    entities: Iterable[RawEntity | tuple[str, str]],
) -> LLMEnrichmentResult:
    """Every malware, threat-actor and tool in `entities` joins the matching
    list of `llm_result`, deduplicated case-insensitively; a name both have
    keeps the list's spelling.  `entities` are RawEntity objects (a pipeline
    run) or `(entity_type, value)` pairs (the job store's rows).  Returns
    `llm_result` itself when nothing is added."""
    lists: dict[str, list[str]] = {f: list(getattr(llm_result, f)) for f in NAMED_LISTS.values()}
    seen: dict[str, set[str]] = {f: {n.lower().strip() for n in v} for f, v in lists.items()}
    added = False
    for e in entities:
        etype, value = (e.entity_type, e.value) if isinstance(e, RawEntity) else e
        try:
            etype = EntityType(etype)
        except ValueError:
            continue
        field = NAMED_LISTS.get(etype)
        if field is None:
            continue
        key = (value or "").lower().strip()
        if not key or key in seen[field]:
            continue
        lists[field].append(value.strip())
        seen[field].add(key)
        added = True
    if not added:
        return llm_result
    return llm_result.model_copy(update=lists)
