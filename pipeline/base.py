from __future__ import annotations

from abc import abstractmethod
from typing import Protocol, runtime_checkable

from models.schemas import RawEntity


@runtime_checkable
class ExtractionStage(Protocol):
    """
    Common protocol for all Stage-2 extractors.

    Stages whose model cannot be loaded must return available()=False and
    return [] from extract() without raising — the registry skips them silently.
    """

    @property
    def name(self) -> str: ...

    def available(self) -> bool: ...

    def extract(self, text: str) -> list[RawEntity]: ...


class BaseExtractionStage:
    """
    Mixin that concrete Stage-2 extractors can inherit from.

    Provides the shared merge helper so each stage does not need to
    reimplement the (value.lower(), entity_type) deduplication logic.
    """

    name: str = "base"

    def available(self) -> bool:
        return True

    @abstractmethod
    def extract(self, text: str) -> list[RawEntity]: ...

    @staticmethod
    def merge_into(
        existing: list[RawEntity],
        new_entities: list[RawEntity],
    ) -> list[RawEntity]:
        """
        Merge new_entities into existing, deduplicating by (value.lower(), entity_type).
        First-writer policy: the existing entry wins on conflict.

        Deduplication also applies *within* new_entities — `seen` is updated as
        each entry is accepted, so two equal entries in new_entities don't both
        land in the result (the previous version seeded `seen` only from
        `existing`, letting intra-batch duplicates through).
        """
        seen = {(e.value.lower(), e.entity_type) for e in existing}
        result = list(existing)
        for e in new_entities:
            key = (e.value.lower(), e.entity_type)
            if key not in seen:
                seen.add(key)
                result.append(e)
        return result


# ---------------------------------------------------------------------------
# Cross-source type-conflict resolution
# ---------------------------------------------------------------------------

# How much to trust a source's entity_type label, when two sources agree a
# string names *something* but disagree on *what*. Lower rank wins.
#
# Motivation (found on a real report, 2026-09-20): the MITRE gazetteer
# correctly matches "PsExec" and "Rubeus" as `tool` (S0029 / S1071 — whole-word
# dictionary hits against MITRE's own Software list). CyNER 2.0 has no
# dedicated Tool label at all — it can only emit Malware or Threat_group — so
# whenever it *also* recognises one of these names it tags it `malware`.
# merge_into()'s dedup key is (value, entity_type), so the two rows do not
# collide there and both used to reach the review queue, contradicting each
# other on the same string. This is a second, deliberately separate pass: it
# only resolves a genuine type disagreement on the same value, never touches
# a value only one source reported, and never drops a value outright.
_TYPE_PRECEDENCE: dict[str, int] = {
    "ioc": 0, "gazetteer": 0,   # deterministic, whole-word/regex matched
    "semantic": 1,
    "cyner": 2, "gliner": 2,
    "spacy": 3, "alias_list": 3,
}
_DEFAULT_PRECEDENCE = 99


def resolve_type_conflicts(entities: list[RawEntity]) -> list[RawEntity]:
    """
    When the same value (case-insensitive) was typed differently by different
    sources, keep only the type(s) from the highest-precision source and drop
    the rest. A value every source agreed on (or that only one source found)
    passes through untouched.
    """
    by_value: dict[str, list[RawEntity]] = {}
    order: list[str] = []
    for e in entities:
        key = e.value.lower()
        if key not in by_value:
            by_value[key] = []
            order.append(key)
        by_value[key].append(e)

    result: list[RawEntity] = []
    for key in order:
        group = by_value[key]
        if len({e.entity_type for e in group}) <= 1:
            result.extend(group)
            continue
        best_rank = min(_TYPE_PRECEDENCE.get(e.source, _DEFAULT_PRECEDENCE) for e in group)
        winning_types = {
            e.entity_type for e in group
            if _TYPE_PRECEDENCE.get(e.source, _DEFAULT_PRECEDENCE) == best_rank
        }
        result.extend(e for e in group if e.entity_type in winning_types)
    return result
