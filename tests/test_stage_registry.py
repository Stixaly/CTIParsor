"""Tests for the Stage-2 extractor registry helpers (pipeline/base, registry)."""
from models.schemas import EntityType, RawEntity
from pipeline.base import BaseExtractionStage, resolve_type_conflicts


def _e(value: str, etype: EntityType = EntityType.IPV4, source: str = "ioc") -> RawEntity:
    return RawEntity(value=value, entity_type=etype, source=source)


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


# ── resolve_type_conflicts ──────────────────────────────────────────────────
# Real case (2026-09-20): the gazetteer correctly types "PsExec" `tool`
# (whole-word dictionary match against MITRE's own Software list); CyNER has
# no dedicated Tool label at all, so whenever it also recognises the same
# string it tags it `malware`. merge_into's (value, type) key does not
# consider these a collision, so both used to reach the review queue.

def test_gazetteer_tool_wins_over_cyners_conflicting_malware_type():
    entities = [
        _e("PsExec", EntityType.TOOL, source="gazetteer"),
        _e("PsExec", EntityType.MALWARE, source="cyner"),
    ]
    resolved = resolve_type_conflicts(entities)
    assert [(r.value, r.entity_type) for r in resolved] == [("PsExec", EntityType.TOOL)]


def test_resolve_type_conflicts_is_case_insensitive_on_value():
    entities = [
        _e("Rubeus", EntityType.TOOL, source="gazetteer"),
        _e("rubeus", EntityType.MALWARE, source="cyner"),
    ]
    resolved = resolve_type_conflicts(entities)
    assert len(resolved) == 1
    assert resolved[0].entity_type == EntityType.TOOL


def test_resolve_type_conflicts_leaves_agreement_untouched():
    """A value only one source found, or that every source agrees on, is not touched."""
    entities = [
        _e("Emotet", EntityType.MALWARE, source="gazetteer"),
        _e("Emotet", EntityType.MALWARE, source="cyner"),
        _e("1.2.3.4", EntityType.IPV4, source="ioc"),
    ]
    resolved = resolve_type_conflicts(entities)
    assert len(resolved) == 3


def test_resolve_type_conflicts_falls_back_to_first_seen_when_sources_are_unranked():
    """Two unknown/equal-precedence sources disagreeing: both types are kept
    rather than silently dropping information neither side is more trusted on."""
    entities = [
        _e("Foo", EntityType.MALWARE, source="unknown_a"),
        _e("Foo", EntityType.THREAT_ACTOR, source="unknown_b"),
    ]
    resolved = resolve_type_conflicts(entities)
    assert {r.entity_type for r in resolved} == {EntityType.MALWARE, EntityType.THREAT_ACTOR}


def test_resolve_type_conflicts_real_report_scenario_apt44():
    """apt44-unearthing-sandworm.pdf, 2026-09-20: 'PsExec' and 'Rubeus' both
    reached review as malware+tool duplicates. End-to-end shape check."""
    entities = [
        _e("PsExec", EntityType.TOOL, source="gazetteer"),
        _e("PsExec", EntityType.MALWARE, source="cyner"),
        _e("Rubeus", EntityType.TOOL, source="gazetteer"),
        _e("Rubeus", EntityType.MALWARE, source="cyner"),
        _e("CHISEL", EntityType.MALWARE, source="cyner"),  # only CyNER found this one
    ]
    resolved = resolve_type_conflicts(entities)
    by_value = {r.value: r.entity_type for r in resolved}
    assert by_value == {
        "PsExec": EntityType.TOOL,
        "Rubeus": EntityType.TOOL,
        "CHISEL": EntityType.MALWARE,
    }
