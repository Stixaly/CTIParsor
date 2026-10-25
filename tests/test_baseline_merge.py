"""The merge of CTIParsor's STIX objects into the analyst's baseline (ADR-0090, lot 4).

Stage 4 folds its objects into the chosen baseline (`merge_baseline`), re-issues
the chosen Report (`reissue_report`), writes the baseline objects back as they
were received (`serialize_bundle`, invariant I2), and gives Stage 5 the rest to
validate (`validation_json`).  The baseline is the lot-0 OpenCTI export: an
intrusion-set APT29 (alias Cozy Bear) that uses the malware WellMess, an IPv4
address with its Indicator, a file, a technique and the report that names them.
"""
from __future__ import annotations

import copy
import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path

import stix2

from models.schemas import EntityType, RawEntity
from pipeline import baseline_stix as bs

FIX = Path(__file__).parent / "fixtures" / "baselines"

# ids of tests/fixtures/baselines/opencti_report.json
APT29 = "intrusion-set--4f4f0eaf-960c-43f3-9319-4fb9a8d3ae7c"
WELLMESS = "malware--ce12e6b1-5ad7-4fc6-a2ed-2a3ca268a445"
ATTACK = "attack-pattern--7d05d478-43c5-4a43-8e80-ca34d16324f6"
INDICATOR = "indicator--f838c643-e36c-4c0b-9389-1386738617b6"
IPV4 = "ipv4-addr--dac4ca46-8fa0-52fb-94df-2a9acd2636bf"
FILE = "file--c7abdbaa-36f3-531e-8ce2-78743f8252dd"
IDENTITY = "identity--7b24b13f-17ba-4194-b6ae-4b1d3423bf15"
REPORT = "report--8bfd99f1-1304-415f-9ea8-597445d831da"
SRO_BASED_ON = "relationship--fa5f98bc-0a81-4516-a4d7-cdf4bb46be3f"
SRO_USES = "relationship--fd3e7a73-f3b2-485d-a28b-111fadd6bea1"
SRO_INDICATES = "relationship--75b18d1d-5f66-4989-a19f-33ebd8c660f6"
IP_VALUE = "198.18.12.77"
NOW = datetime(2026, 10, 25, 10, 0, tzinfo=UTC)


def _build(name: str = "opencti_report.json", **kwargs) -> bs.BaselineBuild:
    index, _intake, bundle = bs.intake((FIX / name).read_bytes(), validate=False)
    assert index is not None
    return bs.BaselineBuild(index=index, objects={o["id"]: o for o in bundle["objects"]}, **kwargs)


def _ids(objects: list) -> list[str]:
    return [o.id for o in objects]


def test_threat_actor_is_replaced_by_the_baseline_intrusion_set():
    build = _build()
    actor = stix2.ThreatActor(name="APT29")
    malware = stix2.Malware(name="SUNBURST", is_family=True)
    other = stix2.Malware(name="GoldenSpy", is_family=True)
    uses = stix2.Relationship(source_ref=actor.id, relationship_type="uses", target_ref=malware.id)
    link = stix2.Relationship(source_ref=malware.id, relationship_type="variant-of", target_ref=other.id)
    sighting = stix2.Sighting(sighting_of_ref=actor.id, count=1)
    objects = [actor, malware, other, uses, link, sighting]

    result = bs.merge_baseline(objects, build)

    assert result.remap == {actor.id: APT29}
    assert actor.id not in _ids(objects) and APT29 in _ids(objects)
    assert malware.id in _ids(objects)                                    # SUNBURST is not in the baseline
    assert result.remapped_relationships == {uses.id: (APT29, malware.id)}
    rewired = next(o for o in objects if o.id == uses.id)
    assert (rewired.source_ref, rewired.target_ref) == (APT29, malware.id)
    assert link.id in _ids(objects) and link.id not in result.remapped_relationships   # both ends untouched
    moved = next(o for o in objects if o.id == sighting.id)
    assert moved.sighting_of_ref == APT29                                 # a CTIParsor *_ref, not only SROs
    assert APT29 in result.stated and malware.id not in result.stated


def test_observable_and_indicator_are_remapped_onto_the_baseline_ones():
    build = _build()
    # stix2 computes the same id for this address as the baseline does: a different id stands
    # for a CTIParsor object the baseline holds under another one
    sco = stix2.IPv4Address(value=IP_VALUE, id="ipv4-addr--00000001-0000-4000-8000-000000000000")
    indicator = stix2.Indicator(name=IP_VALUE, pattern=f"[ipv4-addr:value = '{IP_VALUE}']", pattern_type="stix")
    objects = [sco, indicator]

    result = bs.merge_baseline(objects, build)

    assert result.remap == {sco.id: IPV4, indicator.id: INDICATOR}
    assert _ids(objects).count(IPV4) == 1 and _ids(objects).count(INDICATOR) == 1
    assert sco.id not in _ids(objects) and indicator.id not in _ids(objects)


def test_observable_with_its_own_baseline_id_is_the_baseline_object_once():
    build = _build()
    sco = stix2.IPv4Address(value=IP_VALUE)                 # the id stix2 computes: the baseline's
    assert sco.id == IPV4
    objects = [sco]

    result = bs.merge_baseline(objects, build)

    assert result.remap == {}
    assert _ids(objects).count(IPV4) == 1
    # The document states it: it goes into the Report, it is not "STIX only".
    assert IPV4 in result.stated
    written = json.loads(bs.serialize_bundle(stix2.Bundle(objects=objects, allow_custom=True),
                                             {IPV4: build.objects[IPV4]}))["objects"]
    assert next(o for o in written if o["id"] == IPV4) == build.objects[IPV4]


def test_observable_the_baseline_only_holds_through_an_indicator_is_not_remapped():
    build = _build("misp_indicators_only.json")            # an address with an Indicator and no SCO
    sco = stix2.IPv4Address(value="198.18.45.100")
    objects = [sco]

    result = bs.merge_baseline(objects, build)

    assert result.remap == {}
    assert sco.id in _ids(objects)


def test_a_rejected_indicator_is_not_remapped_but_its_observable_still_is():
    build = _build(excluded=frozenset({INDICATOR}))
    sco = stix2.IPv4Address(value=IP_VALUE, id="ipv4-addr--00000002-0000-4000-8000-000000000000")
    indicator = stix2.Indicator(name=IP_VALUE, pattern=f"[ipv4-addr:value = '{IP_VALUE}']", pattern_type="stix")
    objects = [sco, indicator]

    result = bs.merge_baseline(objects, build)

    assert result.remap == {sco.id: IPV4}
    assert indicator.id in _ids(objects) and INDICATOR not in result.kept


def test_relationship_identical_to_a_baseline_one_is_dropped_and_the_baseline_kept():
    build = _build()
    actor = stix2.ThreatActor(name="APT29")
    wellmess = stix2.Malware(name="WellMess", is_family=True)
    uses = stix2.Relationship(source_ref=actor.id, relationship_type="uses", target_ref=wellmess.id)
    objects = [actor, wellmess, uses]

    result = bs.merge_baseline(objects, build)

    assert result.removed_relationships == [
        {"id": uses.id, "reason": "duplicate_after_baseline_merge", "kept": SRO_USES}]
    assert uses.id not in _ids(objects) and SRO_USES in _ids(objects)
    assert uses.id not in result.remapped_relationships
    assert {APT29, WELLMESS, SRO_USES} <= result.stated


def test_two_ctiparsor_relationships_that_become_one_keep_the_first():
    build = _build()
    actor = stix2.ThreatActor(name="APT29")
    cozy = stix2.ThreatActor(name="Cozy Bear")               # an alias of the baseline intrusion-set
    sunburst = stix2.Malware(name="SUNBURST", is_family=True)
    first = stix2.Relationship(source_ref=actor.id, relationship_type="uses", target_ref=sunburst.id)
    second = stix2.Relationship(source_ref=cozy.id, relationship_type="uses", target_ref=sunburst.id)
    objects = [actor, cozy, sunburst, first, second]

    result = bs.merge_baseline(objects, build)

    assert result.removed_relationships == [
        {"id": second.id, "reason": "duplicate_after_baseline_merge", "kept": first.id}]
    assert result.remapped_relationships == {first.id: (APT29, sunburst.id)}
    assert result.remap == {actor.id: APT29, cozy.id: APT29}


def test_relationship_whose_two_ends_become_one_baseline_object_is_a_self_loop():
    build = _build()
    actor = stix2.ThreatActor(name="APT29")
    cozy = stix2.ThreatActor(name="Cozy Bear")
    rel = stix2.Relationship(source_ref=actor.id, relationship_type="related-to", target_ref=cozy.id)
    objects = [actor, cozy, rel]

    result = bs.merge_baseline(objects, build)

    assert result.removed_relationships == [{"id": rel.id, "reason": "self_loop_after_baseline_merge"}]
    assert rel.id not in _ids(objects)


def test_rejected_baseline_object_and_what_refers_to_it_leave_the_bundle():
    build = _build(excluded=frozenset({WELLMESS, "malware--00000003-0000-4000-8000-000000000000"}))
    wellmess = stix2.Malware(name="WellMess", is_family=True)
    objects = [wellmess]

    result = bs.merge_baseline(objects, build)

    assert WELLMESS not in result.kept and WELLMESS not in _ids(objects)
    assert result.dropped[WELLMESS] == "baseline_rejected"
    assert result.dropped[SRO_USES] == f"baseline_refs_closure:{WELLMESS}"
    assert result.dropped[SRO_INDICATES] == f"baseline_refs_closure:{WELLMESS}"
    assert "malware--00000003-0000-4000-8000-000000000000" not in result.dropped
    assert wellmess.id in _ids(objects) and result.remap == {}   # no baseline object to become


def test_baseline_object_the_bundle_does_not_hold_is_not_kept():
    full = _build()
    build = dataclasses.replace(full, objects={oid: o for oid, o in full.objects.items() if oid != IDENTITY})
    objects: list = []

    result = bs.merge_baseline(objects, build)

    assert IDENTITY not in result.kept and IDENTITY not in _ids(objects)
    assert result.kept == full.index.imported_ids - {REPORT, IDENTITY}


def test_chosen_report_is_never_added_nor_kept():
    build = _build()
    objects: list = []

    result = bs.merge_baseline(objects, build)

    assert build.index.scope_report_id == REPORT
    assert REPORT not in _ids(objects) and REPORT not in result.kept


def test_without_a_chosen_report_the_baseline_report_is_kept():
    build = _build()
    build = dataclasses.replace(build, index=dataclasses.replace(build.index, scope_report_id=None))
    objects: list = []

    result = bs.merge_baseline(objects, build)

    assert REPORT in result.kept and REPORT in _ids(objects)


def test_every_kept_baseline_object_is_written_back_as_received():
    build = _build()
    objects = [stix2.ThreatActor(name="APT29")]

    result = bs.merge_baseline(objects, build)
    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    verbatim = {oid: build.objects[oid] for oid in result.kept}
    written = json.loads(bs.serialize_bundle(bundle, verbatim))["objects"]

    assert len(written) == len(objects)
    for obj in written:
        if obj["id"] in result.kept:
            assert obj == build.objects[obj["id"]]
    assert bs.serialize_bundle(bundle) == bundle.serialize(pretty=True)


def test_references_of_ctiparsor_objects_are_rewritten_and_others_are_left_alone():
    build = _build()
    actor = stix2.ThreatActor(name="APT29")
    malware = stix2.Malware(name="SUNBURST", is_family=True)
    note = stix2.Note(content="weekly note", object_refs=[actor.id, malware.id])
    untouched = stix2.Note(content="other", object_refs=[malware.id])
    objects = [actor, malware, note, untouched]

    bs.merge_baseline(objects, build)

    assert next(o for o in objects if o.id == note.id).object_refs == [APT29, malware.id]
    assert any(o is untouched for o in objects)


def test_reissued_report_keeps_what_the_upsert_must_keep():
    build = _build(excluded=frozenset({WELLMESS}))
    result = bs.merge_baseline([], build)
    original = build.objects[REPORT]
    before = copy.deepcopy(original)
    new_sro = "relationship--00000001-0000-4000-8000-000000000000"
    source_ref = {"source_name": "CTIParsor", "url": "https://example.test/original-document"}
    enrichment = {"baseline_sha256": "9f2b6c1d4a7e3085b1d6f4e2a9c37d58e0b4a1f6c2d93e7a5b80c4d1f6e3a972"}

    d = bs.reissue_report(original, result.kept, [APT29, new_sro], enrichment, source_ref, NOW)

    for key in ("id", "created", "created_by_ref", "confidence", "object_marking_refs", "name", "description"):
        assert d[key] == original[key]
    assert WELLMESS in original["object_refs"] and WELLMESS not in d["object_refs"]
    assert d["object_refs"] == [r for r in before["object_refs"] if r in result.kept] + [new_sro]
    assert d["modified"] == "2026-10-25T10:00:00.000Z" and d["modified"] > original["modified"]
    assert d["external_references"] == [*original["external_references"], source_ref]
    assert d["x_ctiparsor_enrichment"] == enrichment
    assert original == before                                                 # the original is not changed


def test_reissued_report_is_one_millisecond_past_an_original_modified_in_the_future():
    build = _build()
    original = copy.deepcopy(build.objects[REPORT])
    original["modified"] = "2026-12-01T00:00:00.000Z"

    d = bs.reissue_report(original, set(build.objects), [], {}, None, NOW)

    assert d["modified"] == "2026-12-01T00:00:00.001Z"
    assert d["external_references"] == original["external_references"]        # no source_ref: nothing appended


def test_reissued_report_with_an_unreadable_modified_takes_now():
    build = _build()
    original = copy.deepcopy(build.objects[REPORT])
    original["modified"] = "not a date"

    d = bs.reissue_report(original, set(build.objects), [], {}, None, NOW)

    assert d["modified"] == "2026-10-25T10:00:00.000Z"


def test_validation_json_drops_exactly_the_trusted_objects():
    build = _build()
    bundle_json = json.dumps({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000001",
                              "objects": list(build.objects.values())})
    trusted = {APT29, WELLMESS}

    out = json.loads(bs.validation_json(bundle_json, frozenset(trusted)))

    assert {o["id"] for o in out["objects"]} == set(build.objects) - trusted
    assert bs.validation_json(bundle_json, frozenset()) == bundle_json


def test_in_text_entities_are_the_baseline_in_text_rows_as_raw_entities():
    rec = bs.Reconciliation(imported_entities=[
        bs.ImportedEntity(value="Cozy Bear", entity_type="threat_actor", mitre_id="G0016",
                          status=bs.BASELINE_IN_TEXT, baseline_stix_id=APT29),
        bs.ImportedEntity(value="WellMess", entity_type="malware", mitre_id=None,
                          status=bs.BASELINE_ONLY, baseline_stix_id=WELLMESS),
        bs.ImportedEntity(value="sample", entity_type="not_a_type", mitre_id=None,
                          status=bs.BASELINE_IN_TEXT, baseline_stix_id=FILE),
        bs.ImportedEntity(value=IP_VALUE, entity_type="ipv4", mitre_id=None,
                          status=bs.BASELINE_IN_TEXT, baseline_stix_id=IPV4),
    ])

    out = rec.in_text_entities()

    assert all(isinstance(e, RawEntity) for e in out)
    assert [(e.value, e.entity_type, e.mitre_id, e.source, e.confidence) for e in out] == [
        ("Cozy Bear", EntityType.THREAT_ACTOR, "G0016", bs.SOURCE, 1.0),
        (IP_VALUE, EntityType.IPV4, None, bs.SOURCE, 1.0),
    ]


def test_merge_into_an_empty_list_gives_exactly_the_kept_baseline_objects():
    build = _build()
    objects: list = []

    result = bs.merge_baseline(objects, build)

    assert _ids(objects) == sorted(result.kept)
    assert result.kept == build.index.imported_ids - {REPORT}
    assert result.remap == {} and result.stated == frozenset()
    assert result.dropped == {} and result.removed_relationships == [] and result.remapped_relationships == {}


def test_newest_versions_keeps_the_latest_modified_of_an_id_and_the_first_of_a_tie():
    older = {"type": "malware", "id": WELLMESS, "modified": "2026-03-01T00:00:00.000Z", "name": "older"}
    newer = {"type": "malware", "id": WELLMESS, "modified": "2026-03-10T00:00:00.000Z", "name": "newer"}
    first = {"type": "intrusion-set", "id": APT29, "modified": "2026-03-10T00:00:00.000Z", "name": "first"}
    second = {"type": "intrusion-set", "id": APT29, "modified": "2026-03-10T00:00:00.000Z", "name": "second"}

    assert bs.newest_versions([newer, older])[WELLMESS] is newer          # the newer one first in the file
    assert bs.newest_versions([older, newer])[WELLMESS] is newer          # and later in it
    assert bs.newest_versions([first, second])[APT29] is first            # a tie: the first one


def test_newest_versions_skips_what_is_not_an_object_with_a_string_id():
    valid = {"type": "malware", "id": WELLMESS, "modified": "2026-03-01T00:00:00.000Z"}
    items = ["malware", 7, None, {"type": "malware"}, {"type": "malware", "id": 7}, valid]

    assert bs.newest_versions(items) == {WELLMESS: valid}
    assert bs.newest_versions([]) == {}


def test_a_verbatim_object_with_a_lone_surrogate_is_written_and_read_back_with_it():
    lone = chr(0xD800)
    actor = stix2.ThreatActor(name="APT29")
    bundle = stix2.Bundle(objects=[actor], allow_custom=True)
    forged = {**json.loads(actor.serialize()), "name": f"APT29 {lone}"}

    text = bs.serialize_bundle(bundle, {actor.id: forged})

    text.encode("utf-8")                                                  # a lone surrogate would raise here
    assert text.isascii()                                                 # the fallback escapes it
    (written,) = json.loads(text)["objects"]
    assert written["name"] == f"APT29 {lone}"


def test_a_bundle_with_no_surrogate_keeps_its_non_ascii_text_unescaped():
    actor = stix2.ThreatActor(name="Café")
    bundle = stix2.Bundle(objects=[actor], allow_custom=True)

    text = bs.serialize_bundle(bundle, {actor.id: json.loads(actor.serialize())})

    assert '"name": "Café"' in text
    assert json.loads(text)["objects"][0]["name"] == "Café"


# ── A file known by its name alone (lot 7, A4: one file in OpenCTI) ─────────

def test_a_name_only_file_becomes_the_one_baseline_file_of_that_name():
    build = _build()
    named = stix2.File(name="svchost_update.dll")
    indicator = stix2.Indicator(pattern="[file:name = 'svchost_update.dll']", pattern_type="stix")
    based_on = stix2.Relationship(source_ref=indicator.id, relationship_type="based-on", target_ref=named.id)
    objects = [named, indicator, based_on]

    result = bs.merge_baseline(objects, build)

    assert result.remap == {named.id: FILE}                               # the name-only Indicator stays CTIParsor's
    assert named.id not in _ids(objects) and FILE in result.stated
    rewired = next(o for o in objects if o.id == based_on.id)
    assert rewired.target_ref == FILE


def test_a_file_with_a_hash_of_its_own_is_never_merged_on_its_name():
    build = _build()
    other = stix2.File(name="svchost_update.dll", hashes={"SHA-256": "a" * 64})
    objects = [other]
    assert bs.merge_baseline(objects, build).remap == {}
    assert other.id in _ids(objects)


def test_a_name_only_indicator_becomes_the_baseline_one_of_the_same_file_and_pattern():
    raw = {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000001", "objects": [
        {"type": "file", "spec_version": "2.1", "id": "file--00000000-0000-4000-8000-000000000002",
         "name": "cmd.exe"},
        {"type": "indicator", "spec_version": "2.1", "id": "indicator--00000000-0000-4000-8000-000000000003",
         "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
         "pattern": "[file:name = 'cmd.exe']", "pattern_type": "stix", "valid_from": "2026-01-01T00:00:00Z"},
        {"type": "relationship", "spec_version": "2.1", "id": "relationship--00000000-0000-4000-8000-000000000004",
         "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
         "relationship_type": "based-on", "source_ref": "indicator--00000000-0000-4000-8000-000000000003",
         "target_ref": "file--00000000-0000-4000-8000-000000000002"},
    ]}
    index, _intake, bundle = bs.intake(json.dumps(raw).encode(), validate=False)
    build = bs.BaselineBuild(index=index, objects={o["id"]: o for o in bundle["objects"]})
    named = stix2.File(name="cmd.exe")
    indicator = stix2.Indicator(pattern="[file:name = 'cmd.exe']", pattern_type="stix")
    objects = [named, indicator]

    result = bs.merge_baseline(objects, build)

    assert result.remap == {named.id: "file--00000000-0000-4000-8000-000000000002",
                            indicator.id: "indicator--00000000-0000-4000-8000-000000000003"}


def test_a_name_only_indicator_is_not_merged_into_a_hash_indicator():
    build = _build()                                  # the fixture's file has no name-only Indicator
    indicator = stix2.Indicator(pattern="[file:name = 'svchost_update.dll']", pattern_type="stix")
    objects = [indicator]
    assert bs.merge_baseline(objects, build).remap == {}
    assert indicator.id in _ids(objects)


# ── Objects no index entry holds (lot 7, the A2 round trip on real reports) ──

def _passthrough_build(*objects: dict) -> bs.BaselineBuild:
    raw = {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-0000000000aa", "objects": list(objects)}
    index, _intake, bundle = bs.intake(json.dumps(raw).encode(), validate=False)
    return bs.BaselineBuild(index=index, objects={o["id"]: o for o in bundle["objects"]})


def _sdo(stix_type: str, n: int, **props) -> dict:
    return {"type": stix_type, "spec_version": "2.1", "id": f"{stix_type}--00000000-0000-4000-8000-{n:012d}",
            "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z", **props}


RULE = "rule FrostSvc {\n  strings:\n    $a = \"FrostSvc\"\n  condition:\n    $a\n}"


def test_a_course_of_action_or_a_rule_of_the_same_content_becomes_the_baseline_one():
    coa = _sdo("course-of-action", 1, name="Block the C2 domain")
    yara = _sdo("indicator", 2, name="Yara rule: FrostSvc", pattern=RULE, pattern_type="yara",
                valid_from="2026-01-01T00:00:00Z")
    build = _passthrough_build(coa, yara)
    mine_coa = stix2.CourseOfAction(name="block the  C2 domain")
    mine_yara = stix2.Indicator(name="Yara rule: FrostSvc", pattern=RULE.replace("\n", "\n\n"), pattern_type="yara")
    objects = [mine_coa, mine_yara]

    result = bs.merge_baseline(objects, build)

    assert result.remap == {mine_coa.id: coa["id"], mine_yara.id: yara["id"]}


def test_two_baseline_twins_or_another_rule_type_merge_nothing():
    one = _sdo("course-of-action", 1, name="Patch")
    two = _sdo("course-of-action", 2, name="patch")
    sigma = _sdo("indicator", 3, pattern=RULE, pattern_type="sigma", valid_from="2026-01-01T00:00:00Z")
    build = _passthrough_build(one, two, sigma)
    objects = [stix2.CourseOfAction(name="Patch"), stix2.Indicator(pattern=RULE, pattern_type="yara")]
    assert bs.merge_baseline(objects, build).remap == {}
