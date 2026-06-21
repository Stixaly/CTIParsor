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
