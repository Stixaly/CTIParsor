"""scripts/opencti_expectations.py: what the OpenCTI check expects of what OpenCTI kept (ADR-0094 item 8).

The platform is built here the way scripts/opencti_import_check.py reads it
back: each node with its standard id, the ids OpenCTI stored, its entity type
and OpenCTI's STIX export (toStix).  No pycti, no OpenCTI.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import opencti_expectations as x

ROOT = Path(__file__).resolve().parent.parent
OCTI = x.OPENCTI_EXTENSION
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
PAP_GREEN = "marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1"
ANALYST = "identity--7b24b13f-17ba-4194-b6ae-4b1d3423bf15"          # a random id, as an analyst's export has
ANALYST_STD = "identity--690878fa-00d5-58dc-b022-1cd15b4165dc"      # the one OpenCTI gives it
MALWARE = "malware--1bf57b7d-3541-5b44-a0c9-7664b2636ca4"
ACTOR = "intrusion-set--1d4a1c5b-2a0e-4f43-9d8a-6a3b1f1c2d3e"
ACTOR_STD = "intrusion-set--55e9a5c1-73c5-5a3f-9a3c-2b5d4f6e7a8b"
USES = "relationship--0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
REPORT = "report--8bfd99f1-1304-415f-9ea8-597445d831da"
REPORT_STD = "report--9d8557a2-12f8-5315-b645-2b2ccef3aa34"
FILE = {"name": "report.txt", "data": "aGVsbG8=", "mime_type": "text/plain", "no_trigger_import": True}


def bundle() -> dict:
    """An analyst's Report on an intrusion set that uses a malware, TLP:AMBER and PAP:GREEN."""
    marks = [TLP_AMBER, PAP_GREEN]
    return {"type": "bundle", "id": "bundle--5d0a3b1e-6c2f-4b8a-9e1d-7f3c2a1b0e9d", "objects": [
        {"type": "marking-definition", "id": TLP_AMBER, "definition_type": "tlp", "definition": {"tlp": "amber"}},
        {"type": "marking-definition", "id": PAP_GREEN, "definition_type": "statement",
         "definition": {"statement": "PAP:GREEN"}},
        {"type": "identity", "id": ANALYST, "name": "ACME", "identity_class": "organization"},
        {"type": "intrusion-set", "id": ACTOR, "name": "APT29", "aliases": ["Cozy Bear"],
         "created_by_ref": ANALYST, "object_marking_refs": marks, "created": "2026-03-02T08:14:55.213456Z"},
        {"type": "malware", "id": MALWARE, "name": "WellMess", "is_family": True,
         "created_by_ref": ANALYST, "object_marking_refs": marks},
        {"type": "relationship", "id": USES, "relationship_type": "uses", "source_ref": ACTOR,
         "target_ref": MALWARE, "created_by_ref": ANALYST, "object_marking_refs": marks},
        {"type": "report", "id": REPORT, "name": "APT29 and WellMess", "confidence": 85,
         "description": "## Source\r\n\r\nThe text.  ", "object_refs": [ACTOR, MALWARE, USES],
         "created_by_ref": ANALYST, "object_marking_refs": marks, "x_opencti_files": [FILE]},
    ]}


def raw(stix: dict, std: str | None = None, entity_type: str | None = None, files: tuple = ()) -> dict:
    """A node as the check reads it: OpenCTI's export of `stix`, under OpenCTI's standard id."""
    std = std or stix["id"]
    exported = {**stix, "id": std,
                "extensions": {OCTI: {"stix_ids": [stix["id"]] if std != stix["id"] else [],
                                      "files": [dict(f) for f in files]}}}
    return {"standard_id": std, "x_opencti_stix_ids": [stix["id"]] if std != stix["id"] else [],
            "entity_type": entity_type or stix["type"], "toStix": json.dumps(exported)}


MARKINGS = [{"standard_id": TLP_AMBER, "x_opencti_stix_ids": [], "definition_type": "TLP", "definition": "TLP:AMBER"},
            {"standard_id": PAP_GREEN, "x_opencti_stix_ids": [], "definition_type": "PAP", "definition": "PAP:GREEN"}]


def faithful(b: dict, **change) -> x.Platform:
    """The platform after a faithful import of `b`; `change` replaces the export of one object by id."""
    by_id = {o["id"]: o for o in b["objects"]}
    std = {ANALYST: ANALYST_STD, ACTOR: ACTOR_STD, REPORT: REPORT_STD}

    def mapped(o: dict) -> dict:
        o = {k: v for k, v in o.items() if k != "x_opencti_files"}
        for field in ("created_by_ref", "source_ref", "target_ref"):
            if field in o:
                o[field] = std.get(o[field], o[field])
        if "object_refs" in o:
            o["object_refs"] = [std.get(i, i) for i in o["object_refs"]]
        o["created"] = "2026-03-02T08:14:55.213Z" if "created" in o else o.get("created")
        return {k: v for k, v in o.items() if v is not None}

    objects, rels = [], []
    for oid in (ANALYST, ACTOR, MALWARE, REPORT):
        stix = change.get(oid, mapped(by_id[oid]))
        files = ({"name": FILE["name"], "mime_type": FILE["mime_type"]},) if oid == REPORT else ()
        objects.append(raw({**stix, "id": oid}, std=std.get(oid), files=files))
    rels.append(raw({**change.get(USES, mapped(by_id[USES])), "id": USES}))
    return x.Platform(objects, rels, MARKINGS)


def results(checks: list[dict]) -> dict[str, bool]:
    return {c["check"].split(": ", 1)[1]: c["pass"] for c in checks}


def test_names_of_reads_names_values_and_aliases_and_a_nameless_observables_hashes():
    assert x.names_of({"name": " WellMess ", "aliases": ["WellMail"]}) == {"wellmess", "wellmail"}
    assert x.names_of({"value": "198.18.12.77"}) == {"198.18.12.77"}
    assert x.names_of({"type": "file", "hashes": {"SHA-256": "AB12"}}) == {"ab12"}
    assert x.names_of({"type": "file", "name": "a.dll", "hashes": {"SHA-256": "AB12"}}) == {"a.dll"}


def test_an_object_is_found_by_any_id_it_answers_to():
    platform = faithful(bundle())
    for stix_id in (ACTOR, ACTOR_STD):
        found, how = platform.resolve({"type": "intrusion-set", "id": stix_id, "name": "APT29"})
        assert (found["standard_id"], how) == (ACTOR_STD, "id")


def test_an_object_opencti_renamed_is_found_by_its_name_or_aliases():
    # A later object named it by an alias: OpenCTI renamed it, and its standard id followed the name.
    renamed = {"type": "malware", "id": "malware--60058a4e-69c5-5653-89f0-eaad41b09793", "name": "WellMail",
               "aliases": ["WellMess"], "is_family": True}
    platform = x.Platform([raw(renamed)], [], MARKINGS)

    found, how = platform.resolve({"type": "malware", "id": MALWARE, "name": "WellMess"})

    assert (found["stix"]["name"], how) == ("WellMail", "name")
    assert platform.resolve({"type": "malware", "id": MALWARE, "name": "Other"}) == (None, "absent")
    assert platform.resolve({"type": "relationship", "id": USES}) == (None, "absent")


def test_two_objects_of_the_name_are_ambiguous():
    twins = [raw({"type": "malware", "id": f"malware--{i}", "name": "WellMess"}) for i in ("a", "b")]
    assert x.Platform(twins, [], []).resolve({"type": "malware", "id": MALWARE, "name": "WellMess"}) == (
        None, "ambiguous")


def test_a_faithful_import_passes_every_check():
    b = bundle()

    checks = x.bundle_checks("3", "enriched", b, [b], faithful(b))

    assert all(c["pass"] for c in checks), [c for c in checks if not c["pass"]]
    assert set(results(checks)) == {
        "every object in OpenCTI, once",
        "each object on an OpenCTI object of its own",
        "each relationship on an OpenCTI relationship of its own",
        "no second object of the same type and name, value or alias",
        "no second relationship of the same type between the same objects",
        "each relationship joins the objects the bundle names",
        "each object's author (created_by_ref) attached",
        "each object's markings (TLP, PAP) as the bundles set them",
        "no description emptied (objects and relationships)",
        "the Report holds the bundle's references",
        "the Report's description kept",
        "the Report's file attached once (x_opencti_files)",
        "the Report's confidence kept",
    }


def test_a_missing_object_fails():
    b = bundle()
    platform = faithful(b)
    platform = x.Platform([raw(n["stix"] | {"id": next(iter(n["ids"] - {n["standard_id"]}), n["standard_id"])},
                               std=n["standard_id"]) for n in platform.objects if n["stix"]["type"] != "malware"],
                          [raw(n["stix"]) for n in platform.relationships], MARKINGS)

    checks = results(x.bundle_checks("3", "enriched", b, [b], platform))

    assert checks["every object in OpenCTI, once"] is False


def test_a_second_object_with_the_name_or_an_alias_is_a_duplicate():
    b = bundle()
    platform = faithful(b)
    second = raw({"type": "intrusion-set", "id": "intrusion-set--99999999-9999-4999-8999-999999999999",
                  "name": "The Dukes", "aliases": ["cozy bear"]})
    platform = x.Platform([*(raw_of(n) for n in platform.objects), second],
                          [raw_of(n) for n in platform.relationships], MARKINGS)

    checks = x.bundle_checks("3", "enriched", b, [b], platform)

    dup = next(c for c in checks if "no second object" in c["check"])
    assert dup["pass"] is False and set(dup["detail"]) == {ACTOR}


def raw_of(n: dict) -> dict:
    """A node back to the raw form the Platform reads."""
    return {"standard_id": n["standard_id"], "x_opencti_stix_ids": sorted(n["ids"] - {n["standard_id"]}),
            "entity_type": n["entity_type"], "toStix": n["stix"]}


def test_a_second_relationship_between_the_same_objects_is_a_duplicate():
    b = bundle()
    platform = faithful(b)
    rel = dict(platform.relationships[0]["stix"], id="relationship--11111111-1111-4111-8111-111111111111")
    platform = x.Platform([raw_of(n) for n in platform.objects],
                          [raw_of(n) for n in platform.relationships] + [raw(rel)], MARKINGS)

    checks = results(x.bundle_checks("3", "enriched", b, [b], platform))

    assert checks["no second relationship of the same type between the same objects"] is False


def test_a_relationship_joined_to_another_object_fails():
    b = bundle()
    moved = {"type": "relationship", "relationship_type": "uses", "source_ref": ACTOR_STD,
             "target_ref": "malware--22222222-2222-4222-8222-222222222222", "created_by_ref": ANALYST_STD,
             "object_marking_refs": [TLP_AMBER, PAP_GREEN]}

    checks = results(x.bundle_checks("3", "enriched", b, [b], faithful(b, **{USES: moved})))

    assert checks["each relationship joins the objects the bundle names"] is False


def test_an_author_another_bundle_set_is_accepted_and_an_unknown_one_is_not():
    b = bundle()
    other_author = "identity--df314057-d669-5e4d-aa9c-5257582a7ecd"
    exported = {"type": "malware", "name": "WellMess", "is_family": True, "created_by_ref": other_author,
                "object_marking_refs": [TLP_AMBER, PAP_GREEN]}
    platform = faithful(b, **{MALWARE: exported})
    later = {"type": "bundle", "objects": [{"type": "identity", "id": other_author, "name": "CTIParsor",
                                            "identity_class": "system"},
                                           {"type": "malware", "id": MALWARE, "name": "WellMess",
                                            "created_by_ref": other_author}]}
    platform = x.Platform([*(raw_of(n) for n in platform.objects),
                           raw({"type": "identity", "id": other_author, "name": "CTIParsor"})],
                          [raw_of(n) for n in platform.relationships], MARKINGS)

    alone = results(x.bundle_checks("3", "enriched", b, [b], platform))
    both = results(x.bundle_checks("5", "full", b, [b, later], platform))

    assert alone["each object's author (created_by_ref) attached"] is False
    assert both["each object's author (created_by_ref) attached"] is True


def test_markings_must_be_those_the_bundles_set_no_fewer_no_more():
    b = bundle()
    fewer = {"type": "malware", "name": "WellMess", "is_family": True, "created_by_ref": ANALYST_STD,
             "object_marking_refs": [TLP_AMBER]}
    tlp_red = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
    more = dict(fewer, object_marking_refs=[TLP_AMBER, PAP_GREEN, tlp_red])

    for exported in (fewer, more):
        checks = results(x.bundle_checks("3", "enriched", b, [b], faithful(b, **{MALWARE: exported})))
        assert checks["each object's markings (TLP, PAP) as the bundles set them"] is False


def report_export(**change) -> dict:
    report = {"type": "report", "name": "APT29 and WellMess", "confidence": 85,
              "description": "## Source\n\nThe text.", "object_refs": [ACTOR_STD, MALWARE, USES],
              "created_by_ref": ANALYST_STD, "object_marking_refs": [TLP_AMBER, PAP_GREEN]}
    return {**report, **change}


def test_the_reports_description_confidence_and_references_are_compared():
    b = bundle()

    def report_checks(**change):
        return results(x.bundle_checks("3", "enriched", b, [b], faithful(b, **{REPORT: report_export(**change)})))

    assert report_checks()["the Report's description kept"] is True        # line ends and trailing blanks aside
    assert report_checks(description="## Source\n\nAnother text.")["the Report's description kept"] is False
    assert report_checks(confidence=100)["the Report's confidence kept"] is False
    assert report_checks(object_refs=[ACTOR_STD, USES])["the Report holds the bundle's references"] is False


def test_the_reports_file_must_be_attached_once_with_its_mime_type():
    b = bundle()
    std = faithful(b)

    def with_files(*files):
        objects = [raw_of(n) for n in std.objects]
        report = next(n for n in std.objects if n["standard_id"] == REPORT_STD)
        stix = dict(report["stix"])
        stix["extensions"] = {OCTI: {"stix_ids": [REPORT], "files": list(files)}}
        objects = [o for o in objects if o["standard_id"] != REPORT_STD] + [
            {"standard_id": REPORT_STD, "x_opencti_stix_ids": [REPORT], "entity_type": "Report", "toStix": stix}]
        platform = x.Platform(objects, [raw_of(n) for n in std.relationships], MARKINGS)
        checks = results(x.bundle_checks("3", "enriched", b, [b], platform))
        return checks["the Report's file attached once (x_opencti_files)"]

    plain = {"name": "report.txt", "mime_type": "text/plain"}
    assert with_files(plain) is True
    assert with_files() is False
    assert with_files(plain, plain) is False
    assert with_files({"name": "report.txt", "mime_type": "application/octet-stream"}) is False


def test_a_second_import_must_refuse_nothing_and_add_nothing():
    second = {"objects": 7, "imported": ["x"] * 7, "refused": []}
    counts = {"Malware": 1, "relationship:uses": 1, "files": 1}

    assert [c["pass"] for c in x.reimport_checks("1", "baseline", second, counts, counts)] == [True, True]
    refused = dict(second, refused=[{"id": USES, "type": "relationship", "error": "MISSING_REFERENCE_ERROR"}])
    grown = dict(counts, Malware=2)
    checks = x.reimport_checks("1", "baseline", refused, counts, grown)
    assert [c["pass"] for c in checks] == [False, False]
    assert checks[1]["detail"] == {"Malware": [1, 2]}


def test_counts_are_by_type_relationship_type_and_attached_file():
    # The fake platform's entity types are the STIX types; OpenCTI's are its own ("Intrusion-Set").
    assert faithful(bundle()).counts() == {"files": 1, "identity": 1, "intrusion-set": 1, "malware": 1,
                                           "relationship:uses": 1, "report": 1}


def test_transformations_leave_out_defaults_precision_and_mapped_references():
    b = bundle()
    exported = {"type": "malware", "name": "WellMail", "is_family": True, "created_by_ref": ANALYST_STD,
                "object_marking_refs": [PAP_GREEN, TLP_AMBER], "confidence": 100, "lang": "en", "revoked": False}

    found = x.transformations(b, faithful(b, **{MALWARE: exported}))

    assert {(t["id"], t["field"], t["change"]) for t in found} == {
        (MALWARE, "name", "changed"), (MALWARE, "confidence", "added")}
    assert x.summarize(found) == [
        {"type": "malware", "field": "confidence", "change": "added", "objects": 1,
         "example": {"id": MALWARE, "bundle": None, "opencti": 100}},
        {"type": "malware", "field": "name", "change": "changed", "objects": 1,
         "example": {"id": MALWARE, "bundle": "WellMess", "opencti": "WellMail"}},
    ]


def test_an_object_found_by_name_is_listed_and_later_changes_are_what_the_import_did_not_show():
    b = bundle()
    after = x.transformations(b, faithful(b))
    renamed = {"type": "malware", "id": "malware--60058a4e-69c5-5653-89f0-eaad41b09793", "name": "WellMail",
               "aliases": ["WellMess"], "is_family": True, "created_by_ref": ANALYST_STD,
               "object_marking_refs": [TLP_AMBER, PAP_GREEN]}
    platform = faithful(b)
    # OpenCTI's export of the relationship follows the renamed object's new standard id.
    rel = dict(platform.relationships[0]["stix"], target_ref=renamed["id"])
    platform = x.Platform([raw_of(n) for n in platform.objects if n["entity_type"] != "malware"] + [raw(renamed)],
                          [raw(rel)], MARKINGS)

    final = x.transformations(b, platform)
    later = x.later_changes(after, final)

    assert after == []
    assert {(t["field"], t["change"]) for t in later} == {
        ("(found by name or alias)", "renamed"), ("name", "changed"), ("aliases", "added")}


def run_record(**change) -> dict:
    run = {"date": "2026-11-01T13:00:00Z",
           "candidate": {"image": "ghcr.io/stixaly/ctiparsor:sha-4df5", "commit": "4df5" * 10,
                         "digest_ref": "ghcr.io/stixaly/ctiparsor@sha256:3301", "job_git_revs": ["4df5" * 10]},
           "bundles": {"full": {"sha256": "aa" * 32, "validation": "validated", "objects": 47,
                                "source": "tests/fixtures/sample_report.txt"}},
           "opencti": {"images": {"opencti/platform:7.260930.0": "opencti/platform@sha256:f0b5"}},
           "durations_s": {"total": 200}, "memory_mb": {"peak_used": 6000}}
    return {**run, **change}


def check_record(passed: bool = True) -> dict:
    return {"versions": {"opencti": "7.260930.0", "pycti": "7.260930.0"},
            "bundles": {"full": {"sha256": "aa" * 32}},
            "checks": [{"step": "5", "check": "nothing refused: full as admin", "expected": "0 refused",
                        "observed": "0 refused of 47" if passed else "1 refused of 47", "pass": passed}],
            "imports": [{"label": "full (admin)", "refused": [] if passed else [{"id": USES, "type": "relationship",
                                                                                  "error": "MISSING_REFERENCE"}]}],
            "transformations": {"full": {"after_import": [], "later": []}}}


def test_step_0_ties_the_bundles_to_the_candidate():
    assert all(c["pass"] for c in x.candidate_checks(run_record(), check_record()))
    other_rev = run_record(candidate={**run_record()["candidate"], "job_git_revs": ["beef" * 10]})
    unverified = run_record(bundles={"full": {**run_record()["bundles"]["full"], "validation": "unverified"}})
    edited = check_record()
    edited["bundles"]["full"]["sha256"] = "bb" * 32
    assert [c["pass"] for c in x.candidate_checks(other_rev, check_record())] == [False, True, True]
    assert [c["pass"] for c in x.candidate_checks(unverified, check_record())] == [True, False, True]
    assert [c["pass"] for c in x.candidate_checks(run_record(), edited)] == [True, True, False]


def test_the_report_command_writes_the_report_and_exits_on_the_result(tmp_path):
    (tmp_path / "run.json").write_text(json.dumps(run_record()), encoding="utf-8")
    for passed, code in ((True, 0), (False, 1)):
        (tmp_path / "check.json").write_text(json.dumps(check_record(passed)), encoding="utf-8")

        assert x.main(["report", "--run", str(tmp_path / "run.json"), "--check", str(tmp_path / "check.json"),
                       "--out-dir", str(tmp_path)]) == code

        report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        markdown = (tmp_path / "report.md").read_text(encoding="utf-8")
        assert report["passed"] is passed
        assert "ghcr.io/stixaly/ctiparsor@sha256:3301" in markdown and "4df5" * 10 in markdown
        assert ("**PASS**" if passed else "**FAIL**") in markdown
        assert ("Nothing, in 1 imports." in markdown) is passed
    assert x.main(["report", "--run", str(tmp_path / "missing.json"), "--check", str(tmp_path / "check.json"),
                   "--out-dir", str(tmp_path)]) == 2


def test_the_entry_point_refuses_a_run_without_a_candidate():
    script = ROOT / "scripts" / "check_opencti_candidate.sh"
    usage = subprocess.run(["bash", str(script), "--help"], capture_output=True, text=True, check=False)
    none = subprocess.run(["bash", str(script)], capture_output=True, text=True, check=False)
    both = subprocess.run(["bash", str(script), "--image", "x", "--bundles", "y"], capture_output=True, text=True,
                          check=False)

    assert usage.returncode == 0 and "--image REF" in usage.stdout
    assert none.returncode == 2 and "give --image REF, or --bundles DIR" in none.stderr
    assert both.returncode == 2


WELLMAIL = "malware--60058a4e-69c5-5653-89f0-eaad41b09793"
USES_WELLMAIL = "relationship--5c2f1e0a-7b3d-4c9e-8a1f-2d6b4e8c0a13"


def two_malware_bundle() -> dict:
    """APT29 uses WellMess and WellMail: two families (ATT&CK S0514, S0515), two relationships."""
    b = bundle()
    b["objects"] += [
        {"type": "malware", "id": WELLMAIL, "name": "WellMail", "is_family": True},
        {"type": "relationship", "id": USES_WELLMAIL, "relationship_type": "uses", "source_ref": ACTOR,
         "target_ref": WELLMAIL},
    ]
    report = next(o for o in b["objects"] if o["type"] == "report")
    report["object_refs"] = [ACTOR, MALWARE, WELLMAIL, USES, USES_WELLMAIL]
    return b


def test_two_objects_of_a_bundle_on_one_opencti_object_fail():
    # OpenCTI found WellMail by an alias of WellMess and merged them, relationships included.
    b = two_malware_bundle()
    platform = faithful(b)
    merged = {"type": "malware", "name": "WellMail", "aliases": ["WellMess"], "is_family": True,
              "created_by_ref": ANALYST_STD, "object_marking_refs": [TLP_AMBER, PAP_GREEN]}
    rel = dict(platform.relationships[0]["stix"])
    objects = [raw_of(n) for n in platform.objects if n["entity_type"] != "malware"]
    objects.append({"standard_id": MALWARE, "x_opencti_stix_ids": [WELLMAIL], "entity_type": "malware",
                    "toStix": {**merged, "id": MALWARE}})
    report = next(o for o in objects if o["standard_id"] == REPORT_STD)
    report["toStix"] = dict(report["toStix"], object_refs=[ACTOR_STD, MALWARE, USES])
    platform = x.Platform(objects, [{"standard_id": USES, "x_opencti_stix_ids": [USES_WELLMAIL],
                                     "entity_type": "uses", "toStix": rel}], MARKINGS)

    checks = {c["check"].split(": ", 1)[1]: c for c in x.bundle_checks("5", "full", b, [b], platform)}

    assert checks["every object in OpenCTI, once"]["pass"] is True        # each found: not enough
    assert checks["each object on an OpenCTI object of its own"]["pass"] is False
    assert checks["each object on an OpenCTI object of its own"]["detail"] == {MALWARE: sorted([MALWARE, WELLMAIL])}
    assert checks["each relationship on an OpenCTI relationship of its own"]["pass"] is False
    refs = checks["the Report holds the bundle's references"]
    assert (refs["pass"], refs["expected"], refs["observed"]) == (False, "5 references", "3 held (4 merged into 2)")
    final = x.final_checks("6", {"full": b}, platform)
    assert [c["pass"] for c in final] == [False]


def test_a_later_disappearance_fails_and_is_listed():
    b = bundle()
    after = x.transformations(b, faithful(b))
    platform = faithful(b)
    gone = x.Platform([raw_of(n) for n in platform.objects if n["entity_type"] != "malware"],
                      [raw_of(n) for n in platform.relationships], MARKINGS)

    final = x.final_checks("6", {"baseline": b}, gone)
    later = x.later_changes(after, x.transformations(b, gone))

    assert final[0]["pass"] is False and final[0]["detail"]["absent_or_ambiguous"] == {MALWARE: "absent"}
    assert {(t["id"], t["field"], t["change"]) for t in later} >= {(MALWARE, "(object)", "absent")}
    assert x.final_checks("6", {"baseline": b}, platform)[0]["pass"] is True


def test_markings_another_bundle_set_on_the_same_object_are_expected():
    b = bundle()
    tlp_red = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
    exported = {"type": "malware", "name": "WellMess", "is_family": True, "created_by_ref": ANALYST_STD,
                "object_marking_refs": [TLP_AMBER, PAP_GREEN, tlp_red]}
    platform = faithful(b, **{MALWARE: exported})
    later = {"type": "bundle", "objects": [{"type": "malware", "id": MALWARE, "name": "WellMess",
                                            "object_marking_refs": [tlp_red]}]}

    alone = results(x.bundle_checks("3", "enriched", b, [b], platform))
    both = results(x.bundle_checks("5", "full", b, [b, later], platform))

    assert alone["each object's markings (TLP, PAP) as the bundles set them"] is False
    assert both["each object's markings (TLP, PAP) as the bundles set them"] is True


def test_a_job_that_recorded_no_commit_fails_step_0():
    commit = run_record()["candidate"]["commit"]
    for revs in ([], ["(none)"], ["(none)", commit]):
        run = run_record(candidate={**run_record()["candidate"], "job_git_revs": revs})
        assert x.candidate_checks(run, check_record())[0]["pass"] is False, revs


def test_one_name_under_two_types_is_a_warning_not_a_failure(tmp_path):
    actor = {"type": "threat-actor", "id": "threat-actor--7f47ce54-16c8-5fb1-b905-8006861f4884", "name": "APT29"}
    platform = faithful(bundle())
    platform = x.Platform([*(raw_of(n) for n in platform.objects), raw(actor, entity_type="Threat-Actor-Group")],
                          [raw_of(n) for n in platform.relationships], MARKINGS)

    warnings = x.cross_type_warnings({"baseline": bundle(), "full": {"objects": [actor]}}, platform)

    assert len(warnings) == 1 and warnings[0]["names"] == ["apt29"]
    assert {(m["type"], m["entity_type"], tuple(m["bundles"])) for m in warnings[0]["objects"]} == {
        ("intrusion-set", "intrusion-set", ("baseline",)), ("threat-actor", "Threat-Actor-Group", ("full",))}
    (tmp_path / "run.json").write_text(json.dumps(run_record()), encoding="utf-8")
    (tmp_path / "check.json").write_text(json.dumps({**check_record(), "warnings": warnings}), encoding="utf-8")
    assert x.main(["report", "--run", str(tmp_path / "run.json"), "--check", str(tmp_path / "check.json"),
                   "--out-dir", str(tmp_path)]) == 0
    markdown = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "**PASS**" in markdown and "**1 WARN**" in markdown
    assert "| WARN | apt29 |" in markdown and "Threat-Actor-Group" in markdown


def test_settle_says_whether_two_readings_agreed():
    now = [0.0]

    def clock() -> float:
        return now[0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    counter = iter(range(1000))
    assert x.settle(lambda: next(counter), 10, 2, clock=clock, sleep=sleep) == (5, False)
    assert x.settle(lambda: {"a": 1}, 10, 2, clock=clock, sleep=sleep) == ({"a": 1}, True)
    assert x.reading_checks("6", [{"label": "final", "settled": True}])[0]["pass"] is True
    assert x.reading_checks("6", [{"label": "final", "settled": False}])[0]["pass"] is False
    assert x.reading_checks("6", [])[0]["pass"] is False


def test_a_description_emptied_fails_and_a_changed_one_is_recorded():
    b = bundle()
    next(o for o in b["objects"] if o["id"] == MALWARE)["description"] = "Backdoor written in Go and .NET."
    base = {"type": "malware", "name": "WellMess", "is_family": True, "created_by_ref": ANALYST_STD,
            "object_marking_refs": [TLP_AMBER, PAP_GREEN]}

    emptied = results(x.bundle_checks("3", "enriched", b, [b], faithful(b, **{MALWARE: base})))
    rewritten = faithful(b, **{MALWARE: dict(base, description="Mentioned in the report.")})

    assert emptied["no description emptied (objects and relationships)"] is False
    assert results(x.bundle_checks("3", "enriched", b, [b], rewritten))[
        "no description emptied (objects and relationships)"] is True
    assert (MALWARE, "description", "changed") in {(t["id"], t["field"], t["change"])
                                                   for t in x.transformations(b, rewritten)}


def test_transformations_keep_whole_values_and_what_a_list_lost(tmp_path):
    b = bundle()
    acme = {"source_name": "ACME blog", "url": "https://intel.acme.example/apt29"}
    original = {"source_name": "original_document", "description": "Original CTI report: " + "r" * 200,
                "hashes": {"SHA-256": "e1" * 32}}
    report = next(o for o in b["objects"] if o["type"] == "report")
    report["external_references"] = [acme, original]

    found = x.transformations(b, faithful(b, **{REPORT: report_export(external_references=[acme])}))

    entry = next(t for t in found if t["field"] == "external_references")
    assert entry["bundle"] == [acme, original] and entry["diff"] == {"removed": [original], "added": []}
    (tmp_path / "run.json").write_text(json.dumps(run_record()), encoding="utf-8")
    check = {**check_record(), "transformations": {"full": {"after_import": found, "later": []}}}
    (tmp_path / "check.json").write_text(json.dumps(check), encoding="utf-8")
    x.main(["report", "--run", str(tmp_path / "run.json"), "--check", str(tmp_path / "check.json"),
            "--out-dir", str(tmp_path)])
    report_json = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    kept = report_json["check"]["transformations"]["full"]["after_import"]
    assert next(t for t in kept if t["field"] == "external_references")["diff"]["removed"] == [original]
    assert '- [{"description": "Original CTI report: rrr' in (tmp_path / "report.md").read_text(encoding="utf-8")


def test_the_report_says_where_the_bundles_and_the_checkout_come_from():
    def markdown(run: dict) -> str:
        return x.summary_markdown(x.build_report(run, check_record()))

    reused = run_record(bundles_from={"dir": "/runs/earlier", "earlier_run": {
        "date": "2026-11-01T13:43:08Z", "digest_ref": "ghcr.io/stixaly/ctiparsor@sha256:3301", "commit": "4df5" * 10}},
        checkout={"commit": "beef" * 10, "dirty": True, "files": {}})
    assert "**not produced by this run**" in markdown(reused) and "/runs/earlier" in markdown(reused)
    assert f"`{'beef' * 10}`, tracked files modified" in markdown(reused)
    assert "produced by this run, through the candidate's API" in markdown(run_record())
    assert "Checkout that ran the check: unknown" in markdown(run_record())


def _port_in_use(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


FAKE_DOCKER = """#!/usr/bin/env bash
# Records each call, the CTI_ variables it sees and the env files it is given; refuses compose up.
{
  echo "ARGS $*"
  if [ "$1" = compose ] && [ "$2" != version ]; then
    token="${OPENCTI_ADMIN_TOKEN-unset}"
    echo "ENV CTI_IMAGE=${CTI_IMAGE-unset} CTI_ENV_FILE=${CTI_ENV_FILE-unset} OPENCTI_ADMIN_TOKEN=$token"
    prev=""
    for a in "$@"; do
      if [ "$prev" = --env-file ]; then sed 's/^/ENVFILE /' "$a"; fi
      prev="$a"
    done
  fi
} >> LOG
if [ "$1" = compose ]; then
  for a in "$@"; do [ "$a" = up ] && exit 1; done
  exit 0
fi
if [ "$1" = image ]; then
  case "$*" in
    *RepoDigests*) echo "ghcr.io/example/ctiparsor@sha256:$(printf 'b%.0s' $(seq 64))" ;;
    *revision*) printf 'c%.0s' $(seq 40); echo ;;
  esac
fi
exit 0
"""


@pytest.mark.skipif(sys.platform != "linux" or not all(shutil.which(t) for t in ("curl", "free", "getent")),
                    reason="the entry point runs on Linux, with curl, free and getent")
def test_compose_runs_without_the_callers_environment_and_a_digest_is_used_as_given(tmp_path):
    if _port_in_use(4000):
        pytest.skip("port 4000 is in use (an OpenCTI is running)")
    log = tmp_path / "docker.log"
    docker = tmp_path / "bin" / "docker"
    docker.parent.mkdir()
    docker.write_text(FAKE_DOCKER.replace("LOG", str(log)), encoding="utf-8")
    venv_python = tmp_path / "venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text("#!/bin/sh" + chr(10) + "echo 7.260930.0" + chr(10), encoding="utf-8")
    for path in (docker, venv_python):
        path.chmod(0o755)
    (tmp_path / "tmp").mkdir()
    digest = "ghcr.io/example/ctiparsor@sha256:" + "a" * 64
    env = {**os.environ, "DOCKER_BIN": str(docker), "PYCTI_VENV": str(tmp_path / "venv"),
           "CANDIDATE_PORT": str(_free_port()), "TMPDIR": str(tmp_path / "tmp"),
           "CTI_IMAGE": "leaked:tag", "CTI_ENV_FILE": "/leaked/.env", "OPENCTI_ADMIN_TOKEN": "leaked"}

    run = subprocess.run(["bash", str(ROOT / "scripts" / "check_opencti_candidate.sh"), "--image", digest,
                          "--out", str(tmp_path / "out")], capture_output=True, text=True, env=env, check=False)

    calls = log.read_text(encoding="utf-8").splitlines()
    assert run.returncode == 2 and "the candidate did not start" in run.stderr, run.stderr
    seen = [line for line in calls if line.startswith("ENV ")]
    assert seen and set(seen) == {"ENV CTI_IMAGE=unset CTI_ENV_FILE=unset OPENCTI_ADMIN_TOKEN=unset"}
    assert f"ENVFILE CTI_IMAGE={digest}" in calls
    assert not any("RepoDigests" in line for line in calls)            # the digest given, not looked up
    assert any(line.startswith("ARGS compose -p ctiparsor-opencti-candidate") and " down -v" in line
               for line in calls)
    assert not list((tmp_path / "tmp").iterdir())                      # the run's secrets are gone
