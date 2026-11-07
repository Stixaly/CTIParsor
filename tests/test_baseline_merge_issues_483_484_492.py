"""The baseline merge matches URLs by their path's case, and indicators by their whole
pattern (issues #483, #484), and folds what a new relationship adds (its dates and
its description) into the baseline relationship it duplicates (#492).

Each baseline is built from a small synthetic bundle, through `intake` and the same
`BaselineBuild` the pipeline uses.
"""
from __future__ import annotations

from datetime import UTC, datetime

import stix2

from pipeline import baseline_stix as bs


def _build(*objects) -> bs.BaselineBuild:
    index, _intake, bundle = bs.intake(stix2.Bundle(objects=list(objects)).serialize().encode(), validate=False)
    assert index is not None
    return bs.BaselineBuild(index=index, objects={o["id"]: o for o in bundle["objects"]})


def _ids(objects: list) -> list[str]:
    return [o.id for o in objects]


# ── #483: URLs ─────────────────────────────────────────────────────────────

def test_urls_that_differ_only_by_the_case_of_the_path_are_not_merged_issue_483():
    base = stix2.URL(value="https://example.org/A")
    new = stix2.URL(value="https://example.org/a")
    objects = [new]

    result = bs.merge_baseline(objects, _build(base))

    assert result.remap == {}
    assert new.id in _ids(objects)


def test_identical_urls_are_still_one_object_issue_483():
    base = stix2.URL(value="https://example.org/A")
    new = stix2.URL(value="https://example.org/A")
    objects = [new]

    result = bs.merge_baseline(objects, _build(base))

    assert [o.id for o in objects if o.type == "url"] == [base.id]
    assert result.remap == {}


def test_scheme_and_host_case_still_match_issue_483():
    base = stix2.URL(value="https://example.org/A")
    new = stix2.URL(value="HTTPS://EXAMPLE.ORG/A")
    objects = [new]

    result = bs.merge_baseline(objects, _build(base))

    assert result.remap == {new.id: base.id}
    assert new.id not in _ids(objects)


# ── #484: indicators ───────────────────────────────────────────────────────

def test_a_simple_indicator_is_not_merged_into_a_compound_baseline_one_issue_484():
    base = stix2.Indicator(name="complex", pattern_type="stix",
                           pattern="[ipv4-addr:value = '198.18.1.1' AND network-traffic:dst_port = 443]")
    new = stix2.Indicator(name="simple", pattern_type="stix", pattern="[ipv4-addr:value = '198.18.1.1']")
    objects = [new]

    result = bs.merge_baseline(objects, _build(base))

    assert result.remap == {}
    assert new.id in _ids(objects)
    assert base.id in result.kept


def test_an_indicator_with_the_same_single_pattern_is_still_merged_issue_484():
    base = stix2.Indicator(name="simple", pattern_type="stix", pattern="[ipv4-addr:value = '198.18.1.1']")
    new = stix2.Indicator(name="simple again", pattern_type="stix", pattern="[ipv4-addr:value = '198.18.1.1']")
    objects = [new]

    result = bs.merge_baseline(objects, _build(base))

    assert result.remap == {new.id: base.id}
    assert new.id not in _ids(objects)


def test_an_indicator_with_a_different_compound_pattern_is_not_merged_issue_484():
    base = stix2.Indicator(name="or", pattern_type="stix",
                           pattern="[ipv4-addr:value = '198.18.1.1' OR ipv4-addr:value = '198.18.1.2']")
    new = stix2.Indicator(name="simple", pattern_type="stix", pattern="[ipv4-addr:value = '198.18.1.1']")
    objects = [new]

    result = bs.merge_baseline(objects, _build(base))

    assert result.remap == {}
    assert new.id in _ids(objects)


# ── #492: what a duplicate relationship adds joins the baseline one ────────

ACTOR = stix2.ThreatActor(name="Actor One")
MALWARE = stix2.Malware(name="Sample One", is_family=True)


def _merge(base_rel, new_rel):
    build = _build(ACTOR, MALWARE, base_rel)
    objects = [new_rel]
    result = bs.merge_baseline(objects, build)
    shipped = [o for o in objects if o.type == "relationship"]
    return build, result, shipped


def test_the_date_of_a_new_relationship_joins_the_baseline_one_issue_492():
    """The issue's case: the new edge's start_time is not lost, it is carried by
    the baseline edge, re-issued under its own id (an OpenCTI upsert)."""
    base_rel = stix2.Relationship(source_ref=ACTOR.id, relationship_type="uses", target_ref=MALWARE.id)
    new_rel = stix2.Relationship(source_ref=ACTOR.id, relationship_type="uses", target_ref=MALWARE.id,
                                 start_time=datetime(2024, 1, 1, tzinfo=UTC), description="Seen in January.")
    build, result, shipped = _merge(base_rel, new_rel)

    assert [o.id for o in shipped] == [base_rel.id]            # one edge, the baseline's id
    assert str(shipped[0].start_time).startswith("2024-01-01")
    assert shipped[0].description == "Seen in January."
    reissued, gained = result.upserted[base_rel.id]
    assert gained == ("start_time", "description")
    assert reissued["created"] == build.objects[base_rel.id]["created"]
    assert reissued["modified"] > build.objects[base_rel.id]["modified"]
    assert {"id": new_rel.id, "reason": "duplicate_after_baseline_merge", "kept": base_rel.id} \
        in result.removed_relationships


def test_dates_widen_and_descriptions_add_up_issue_492():
    """The earlier start and the later stop win, as in OpenCTI's upsert; the new
    description follows the baseline's, which stays."""
    base_rel = stix2.Relationship(source_ref=ACTOR.id, relationship_type="uses", target_ref=MALWARE.id,
                                  start_time=datetime(2024, 3, 1, tzinfo=UTC),
                                  stop_time=datetime(2024, 6, 1, tzinfo=UTC), description="From the vendor.")
    new_rel = stix2.Relationship(source_ref=ACTOR.id, relationship_type="uses", target_ref=MALWARE.id,
                                 start_time=datetime(2024, 1, 1, tzinfo=UTC),
                                 stop_time=datetime(2024, 4, 1, tzinfo=UTC), description="From the report.")
    _, result, shipped = _merge(base_rel, new_rel)

    edge = shipped[0]
    assert str(edge.start_time).startswith("2024-01-01")       # earlier: taken
    assert str(edge.stop_time).startswith("2024-06-01")        # the baseline's is later: kept
    assert edge.description == "From the vendor.\n\nFrom the report."
    assert result.upserted[base_rel.id][1] == ("start_time", "description")


def test_a_duplicate_that_adds_nothing_leaves_the_baseline_edge_as_received_issue_492():
    base_rel = stix2.Relationship(source_ref=ACTOR.id, relationship_type="uses", target_ref=MALWARE.id,
                                  start_time=datetime(2024, 1, 1, tzinfo=UTC), description="Known.")
    new_rel = stix2.Relationship(source_ref=ACTOR.id, relationship_type="uses", target_ref=MALWARE.id,
                                 start_time=datetime(2024, 5, 1, tzinfo=UTC), description="Known.")
    _, result, _ = _merge(base_rel, new_rel)
    assert result.upserted == {}


def test_dates_that_would_end_the_edge_before_it_starts_are_not_merged_issue_492():
    """STIX requires stop_time later than start_time: a merge that breaks it is not made."""
    base_rel = stix2.Relationship(source_ref=ACTOR.id, relationship_type="uses", target_ref=MALWARE.id,
                                  start_time=datetime(2024, 6, 1, tzinfo=UTC))
    new_rel = stix2.Relationship(source_ref=ACTOR.id, relationship_type="uses", target_ref=MALWARE.id,
                                 stop_time=datetime(2024, 1, 1, tzinfo=UTC))
    _, result, shipped = _merge(base_rel, new_rel)
    assert result.upserted == {}
    assert not hasattr(shipped[0], "stop_time") or shipped[0].stop_time is None


def test_stage4_ships_the_reissued_edge_and_the_ledger_says_so_issue_492():
    """Stage 4 writes the re-issued dict (not the one received) and drops it from
    the objects Stage 5 trusts; the ledger names the properties that changed."""
    from pipeline.bundle_ledger import MappingLedger

    base_rel = stix2.Relationship(source_ref=ACTOR.id, relationship_type="uses", target_ref=MALWARE.id)
    new_rel = stix2.Relationship(source_ref=ACTOR.id, relationship_type="uses", target_ref=MALWARE.id,
                                 start_time=datetime(2024, 1, 1, tzinfo=UTC))
    build, result, _ = _merge(base_rel, new_rel)
    led = MappingLedger()
    for oid, (_, gained) in result.upserted.items():
        led.baseline_upsert(oid, gained)
    assert led.objects[base_rel.id]["changes"] == ["start_time"]
    assert led.objects[base_rel.id]["upsert"] == "baseline_relationship_upsert"
