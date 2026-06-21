"""Tests for the Stage-2 extractor registry helpers (pipeline/base, registry)."""
from models.schemas import EntityType, RawEntity
from pipeline.base import BaseExtractionStage


def _e(value: str, etype: EntityType = EntityType.IPV4) -> RawEntity:
    return RawEntity(value=value, entity_type=etype)


def test_merge_into_dedups_against_existing():
    existing = [_e("1.2.3.4")]
    merged = BaseExtractionStage.merge_into(existing, [_e("1.2.3.4"), _e("5.6.7.8")])
    values = sorted(e.value for e in merged)
    assert values == ["1.2.3.4", "5.6.7.8"]


def test_merge_into_dedups_within_new_batch():
    """Two equal entries in new_entities must collapse to one — regression for
    the version that seeded `seen` only from `existing`."""
    merged = BaseExtractionStage.merge_into([], [_e("9.9.9.9"), _e("9.9.9.9")])
    assert len(merged) == 1
    assert merged[0].value == "9.9.9.9"


def test_merge_into_is_case_insensitive_on_value():
    merged = BaseExtractionStage.merge_into(
        [_e("Evil.COM", EntityType.DOMAIN)],
        [_e("evil.com", EntityType.DOMAIN)],
    )
    assert len(merged) == 1


def test_merge_into_keeps_same_value_different_type():
    merged = BaseExtractionStage.merge_into(
        [],
        [_e("1.2.3.4", EntityType.IPV4), _e("1.2.3.4", EntityType.DOMAIN)],
    )
    assert len(merged) == 2
