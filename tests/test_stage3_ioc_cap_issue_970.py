"""
Issue #970 — the Stage 3 IoC cap spreads the kept entries across types.

Sorting by type and cutting at 30 gave all the places to the first types
(40 domains + 20 IPs showed only domains).  `_sample_iocs_by_type` takes them
in turns across types; the prompt builder counts what it leaves out.
"""
from __future__ import annotations

from unittest.mock import patch

from models.schemas import EntityType, RawEntity
from pipeline import llm_stats
from pipeline.stage3_llm import _sample_iocs_by_type, enrich_chunk


def _iocs(kind: EntityType, n: int, prefix: str) -> list[RawEntity]:
    return [RawEntity(value=f"{prefix}{i}", entity_type=kind) for i in range(n)]


def _mixed() -> list[RawEntity]:
    # 40 domains, then 20 IPv4, then 20 sha256 — the order of the text.
    return (
        _iocs(EntityType.DOMAIN, 40, "d")
        + _iocs(EntityType.IPV4, 20, "ip")
        + _iocs(EntityType.SHA256, 20, "h")
    )


class TestSampleIocsByType:
    def test_cap_is_filled_with_every_type_evenly(self):
        shown = _sample_iocs_by_type(_mixed(), 30)
        assert len(shown) == 30
        by_type: dict[str, list[str]] = {}
        for e in shown:
            by_type.setdefault(e.entity_type.value, []).append(e.value)
        assert set(by_type) == {"domain", "ipv4", "sha256"}
        assert all(len(v) == 10 for v in by_type.values())

    def test_order_inside_each_type_is_kept(self):
        shown = _sample_iocs_by_type(_mixed(), 30)
        for kind, prefix in (("domain", "d"), ("ipv4", "ip"), ("sha256", "h")):
            values = [e.value for e in shown if e.entity_type.value == kind]
            assert values == [f"{prefix}{i}" for i in range(10)]

    def test_is_deterministic(self):
        assert _sample_iocs_by_type(_mixed(), 30) == _sample_iocs_by_type(_mixed(), 30)

    def test_list_under_the_cap_is_returned_unchanged(self):
        entities = _iocs(EntityType.DOMAIN, 15, "d") + _iocs(EntityType.IPV4, 10, "ip")
        assert _sample_iocs_by_type(entities, 30) == entities

    def test_single_type_takes_the_first_cap_entries(self):
        entities = _iocs(EntityType.DOMAIN, 50, "d")
        shown = _sample_iocs_by_type(entities, 30)
        assert [e.value for e in shown] == [f"d{i}" for i in range(30)]

    def test_types_are_ordered_by_first_appearance(self):
        # IPs come first in the text, so they are the first round's pick.
        entities = _iocs(EntityType.IPV4, 3, "ip") + _iocs(EntityType.DOMAIN, 3, "d")
        shown = _sample_iocs_by_type(entities + _iocs(EntityType.SHA256, 3, "h"), 3)
        assert [e.value for e in shown] == ["ip0", "d0", "h0"]


class TestPromptCountsOmittedIocs:
    def test_prompt_lists_every_type_and_counts_the_rest(self, sample_cti_text):
        seen = {}

        def fake(system, user, provider=None):
            seen["user"] = user
            return "{}"

        before = llm_stats.snapshot()
        with patch("pipeline.stage3_llm._call_llm", side_effect=fake), \
             patch("pipeline.stage3_llm._provider_ready", return_value=True):
            enrich_chunk(sample_cti_text, _mixed())
        delta = llm_stats.delta(before, llm_stats.snapshot())

        user = seen["user"]
        assert "- [domain] d0" in user
        assert "- [ipv4] ip0" in user
        assert "- [sha256] h0" in user
        assert "... and 50 more IoCs" in user
        assert delta["ioc_omitted"] == 50

    def test_nothing_counted_when_everything_fits(self, sample_cti_text):
        before = llm_stats.snapshot()
        with patch("pipeline.stage3_llm._call_llm", return_value="{}"), \
             patch("pipeline.stage3_llm._provider_ready", return_value=True):
            enrich_chunk(sample_cti_text, _iocs(EntityType.DOMAIN, 25, "d"))
        delta = llm_stats.delta(before, llm_stats.snapshot())
        assert "ioc_omitted" not in delta
