"""Remap of a CTIParsor object whose id a baseline object holds (#414, ADR-0090 lot 4).

SCO ids are deterministic: a CTIParsor observable can carry the id of a baseline
observable the analyst rejected.  The rejection must hold, so such an object is not
shipped when no kept twin takes its place, and the relationships that name it go with it.
When a kept baseline observable of the same value exists, the lookup must not be
ambiguous because of the rejected one: the CTIParsor copy merges onto the kept twin.

A reference closure is not a rejection: an object it drops comes back as CTIParsor's own
copy, as before.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import stix2

from pipeline import baseline_stix as bs
from pipeline.bundle_ledger import MappingLedger
from tests import test_baseline_merge as t

# A kept baseline address with the same value as the IPV4 of the fixture, under another id.
KEPT_TWIN = "ipv4-addr--11111111-2222-4333-8444-555555555555"
# A directory the analyst rejects, and a file whose parent it is: the file is out of closure.
DIRECTORY = "directory--66666666-7777-4888-8999-aaaaaaaaaaaa"
FILE_IN_DIRECTORY = "file--77777777-8888-4999-8aaa-bbbbbbbbbbbb"


def _build_with(extra: list[dict], excluded: frozenset[str] = frozenset()) -> bs.BaselineBuild:
    """The OpenCTI fixture plus `extra` objects, all in the scope of its report."""
    bundle = json.loads((t.FIX / "opencti_report.json").read_bytes())
    bundle["objects"] += extra
    for o in bundle["objects"]:
        if o["type"] == "report":
            o["object_refs"] += [x["id"] for x in extra]
    index, _intake, bundle = bs.intake(json.dumps(bundle).encode(), validate=False)
    assert index is not None
    return bs.BaselineBuild(index=index, objects={o["id"]: o for o in bundle["objects"]}, excluded=excluded)


def _kept_twin() -> dict:
    return {"type": "ipv4-addr", "spec_version": "2.1", "id": KEPT_TWIN, "value": t.IP_VALUE}


def test_rejected_baseline_observable_does_not_come_back_issue_414():
    build = _build_with([], excluded=frozenset({t.IPV4}))
    sco = stix2.IPv4Address(value=t.IP_VALUE)           # the id stix2 computes: the rejected baseline's
    assert sco.id == t.IPV4
    objects = [sco]

    result = bs.merge_baseline(objects, build)

    assert t.IPV4 in result.dropped
    assert result.rejected == frozenset({t.IPV4})
    assert t.IPV4 not in t._ids(objects) and t.IPV4 not in result.stated and t.IPV4 not in result.kept


def test_kept_twin_absorbs_the_copy_of_a_rejected_observable_issue_414():
    build = _build_with([_kept_twin()], excluded=frozenset({t.IPV4}))
    sco = stix2.IPv4Address(value=t.IP_VALUE)
    objects = [sco]

    result = bs.merge_baseline(objects, build)

    assert KEPT_TWIN in result.kept
    assert result.remap == {t.IPV4: KEPT_TWIN}
    assert [o.id for o in objects if getattr(o, "value", None) == t.IP_VALUE] == [KEPT_TWIN]
    assert result.rejected == frozenset()


def test_relationship_citing_a_rejected_observable_is_removed_and_ledgered_issue_414():
    build = _build_with([], excluded=frozenset({t.IPV4}))
    sco = stix2.IPv4Address(value=t.IP_VALUE)
    indicator = stix2.Indicator(name=t.IP_VALUE, pattern=f"[ipv4-addr:value = '{t.IP_VALUE}']", pattern_type="stix")
    based_on = stix2.Relationship(source_ref=indicator.id, relationship_type="based-on", target_ref=sco.id)
    objects = [sco, indicator, based_on]

    result = bs.merge_baseline(objects, build)

    assert result.remap == {indicator.id: t.INDICATOR}           # the Indicator still merges onto its kept one
    assert result.rejected == frozenset({t.IPV4})
    assert result.removed_relationships == [{"id": based_on.id, "reason": "baseline_rejected"}]
    assert based_on.id not in t._ids(objects) and sco.id not in t._ids(objects)
    assert t.IPV4 not in result.stated

    led = MappingLedger()
    led.object(sco, "entity")
    led.entity(t.IP_VALUE, "ipv4", "emitted", obj=sco)
    led.relationship(SimpleNamespace(source_value=t.IP_VALUE, relationship_type="based-on",
                                     target_value=t.IP_VALUE),
                     "emitted", stix_id=based_on.id, source_ref=indicator.id, target_ref=sco.id)
    led.apply_baseline_merge(result)
    ledgered = led.to_dict()

    assert sco.id not in ledgered["objects"]
    (entity,) = ledgered["entities"]
    assert entity["outcome"] == "dropped" and entity["reason"] == "baseline_rejected" and "stix_id" not in entity
    (edge,) = ledgered["relationships"]
    assert edge["outcome"] == "dropped" and edge["reason"] == "baseline_rejected" and "stix_id" not in edge
    assert [r["stix_id"] for r in ledgered["removed"] if r.get("stix_id") == t.IPV4] == [t.IPV4]


def test_observable_out_of_closure_still_comes_back_issue_414():
    build = _build_with([
        {"type": "directory", "spec_version": "2.1", "id": DIRECTORY, "path": "C:/x"},
        {"type": "file", "spec_version": "2.1", "id": FILE_IN_DIRECTORY, "name": "a.dll",
         "parent_directory_ref": DIRECTORY},
    ], excluded=frozenset({DIRECTORY}))
    dropped_file = stix2.File(name="a.dll", id=FILE_IN_DIRECTORY)
    objects = [dropped_file]

    result = bs.merge_baseline(objects, build)

    assert result.dropped[FILE_IN_DIRECTORY] == f"baseline_refs_closure:{DIRECTORY}"
    assert dropped_file.id in t._ids(objects) and result.rejected == frozenset()


def test_ambiguous_lookup_between_kept_observables_is_not_merged_issue_414():
    build = _build_with([_kept_twin()])
    sco = stix2.IPv4Address(value=t.IP_VALUE, id="ipv4-addr--00000005-0000-4000-8000-000000000000")
    objects = [sco]

    result = bs.merge_baseline(objects, build)

    assert {t.IPV4, KEPT_TWIN} <= result.kept
    assert result.remap == {}
    assert sco.id in t._ids(objects)


def test_kept_observable_with_its_own_id_is_written_once_issue_414():
    build = _build_with([_kept_twin()])
    sco = stix2.IPv4Address(value=t.IP_VALUE)           # the baseline's own id, kept
    objects = [sco]

    result = bs.merge_baseline(objects, build)

    assert t.IPV4 in result.kept and KEPT_TWIN in result.kept
    assert t._ids(objects).count(t.IPV4) == 1
    assert sco.id not in result.remap


def test_rejection_leaves_unrelated_ctiparsor_observable_in_place_issue_414():
    build = _build_with([], excluded=frozenset({t.IPV4}))
    sco = stix2.IPv4Address(value="198.18.99.1", id="ipv4-addr--00000004-0000-4000-8000-000000000000")
    objects = [sco]

    result = bs.merge_baseline(objects, build)

    assert result.dropped[t.IPV4] == "baseline_rejected"
    assert sco.id in t._ids(objects) and result.remap == {} and result.rejected == frozenset()
