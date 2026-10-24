"""The baseline STIX fixtures (ADR-0090) are what tests/fixtures/baselines/README.md says.

Later lots parse these bundles; each one is checked here for the property it
is kept for, so a fixture edited by hand cannot quietly stop being that case.
The bundles meant to be valid pass the stix2 library and Stage 5's JSON
schemas (skipped, as Stage 5 itself reports it, when the schemas are not
installed); the invalid ones fail for the intended objects and only them.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import stix2

from pipeline.detection.pattern_check import REFUSED, check_pattern
from pipeline.detection.yara_check import COMPILES, prepare_embedded_rule
from pipeline.stage5_validation import INVALID, UNVERIFIED, VALIDATED, validate_bundle

BASELINES = Path(__file__).parent / "fixtures" / "baselines"
FIXTURES = sorted(p.name for p in BASELINES.glob("*.json"))
VALID = ["opencti_report.json", "misp_indicators_only.json", "two_reports.json",
         "report_with_confidence.json", "refs_outside.json"]
SCO_TYPES = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "email-addr", "mutex",
             "windows-registry-key", "network-traffic", "autonomous-system", "mac-addr", "user-account"}


def _load(name: str) -> dict:
    return json.loads((BASELINES / name).read_text(encoding="utf-8"))


def _objects(name: str, type_: str | None = None) -> list[dict]:
    return [o for o in _load(name)["objects"] if type_ is None or o["type"] == type_]


def _by_name(name: str, type_: str, object_name: str) -> dict:
    (found,) = [o for o in _objects(name, type_) if o.get("name") == object_name]
    return found


def _parse_failures(name: str) -> list[str]:
    failed = []
    for obj in _load(name)["objects"]:
        try:
            stix2.parse(obj, allow_custom=True)
        except Exception:
            failed.append(obj["id"])
    return failed


def test_every_fixture_is_listed_in_the_readme():
    readme = (BASELINES / "README.md").read_text(encoding="utf-8")
    assert all(f"`{name}`" in readme for name in [*FIXTURES, "opencti_report.txt"])


@pytest.mark.parametrize("name", FIXTURES)
def test_fixture_is_a_bundle_with_objects(name):
    bundle = _load(name)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert bundle["objects"]


@pytest.mark.parametrize("name", VALID)
def test_valid_fixture_parses_with_stix2(name):
    assert _parse_failures(name) == []


@pytest.mark.parametrize("name", VALID)
def test_valid_fixture_passes_stage_5(name):
    result = validate_bundle((BASELINES / name).read_text(encoding="utf-8"))
    if result.status == UNVERIFIED:
        pytest.skip("the STIX JSON schemas are not installed")
    assert result.status == VALIDATED, result.errors


# ── opencti_report ───────────────────────────────────────────────────────────

def test_opencti_report_has_the_shapes_it_is_kept_for():
    types = {o["type"] for o in _objects("opencti_report.json")}
    assert {"report", "identity", "intrusion-set", "malware", "indicator", "ipv4-addr", "file",
            "attack-pattern", "relationship", "marking-definition"} == types
    apt = _by_name("opencti_report.json", "intrusion-set", "APT29")
    assert "Cozy Bear" in apt["aliases"]
    assert {"source_name": "mitre-attack", "url": "https://attack.mitre.org/groups/G0016",
            "external_id": "G0016"} in apt["external_references"]
    technique = _by_name("opencti_report.json", "attack-pattern", "PowerShell")
    assert technique["external_references"][0]["external_id"] == "T1059.001"

    marking = _objects("opencti_report.json", "marking-definition")[0]
    assert marking["id"] == stix2.TLP_AMBER.id
    assert (marking["definition_type"], marking["name"]) == ("TLP", "TLP:AMBER")
    assert "definition" not in marking                      # OpenCTI's convertMarkingToStix

    (indicator,) = _objects("opencti_report.json", "indicator")
    assert indicator["pattern_type"] == "stix"
    assert indicator["pattern"] == "[ipv4-addr:value = '198.18.12.77']"
    rels = {(r["relationship_type"], r["source_ref"].split("--")[0], r["target_ref"].split("--")[0])
            for r in _objects("opencti_report.json", "relationship")}
    assert rels == {("based-on", "indicator", "ipv4-addr"), ("uses", "intrusion-set", "malware"),
                    ("indicates", "indicator", "malware")}
    for obj in _objects("opencti_report.json"):
        assert obj.get("extensions"), obj["id"]

    (report,) = _objects("opencti_report.json", "report")
    assert report["confidence"] == 85 and report["labels"] and report["created_by_ref"]
    assert report["object_marking_refs"] == [marking["id"]] and report["external_references"]
    ids = {o["id"] for o in _objects("opencti_report.json")}
    assert set(report["object_refs"]) <= ids


def test_opencti_report_text_names_what_the_lots_expect():
    text = (BASELINES / "opencti_report.txt").read_text(encoding="utf-8")
    (file_sco,) = _objects("opencti_report.json", "file")
    assert "Cozy Bear" in text                              # matched: an alias of APT29
    assert file_sco["hashes"]["SHA-256"] in text            # matched: the file
    assert "SUNBURST" in text                               # new: a malware the bundle lacks
    assert "T1566.001" in text                              # new: a technique the bundle lacks
    (ip,) = _objects("opencti_report.json", "ipv4-addr")
    assert ip["value"] not in text                          # baseline only
    assert "WellMess" not in text and "T1059" not in text and "PowerShell" not in text   # baseline only too
    assert not {o["name"] for o in _objects("opencti_report.json", "malware")} & {"SUNBURST"}
    assert not {o["external_references"][0]["external_id"]
                for o in _objects("opencti_report.json", "attack-pattern")} & {"T1566.001"}
    assert re.fullmatch(r"[0-9a-f]{64}", file_sco["hashes"]["SHA-256"])


# ── misp_indicators_only ─────────────────────────────────────────────────────

def test_misp_fixture_is_indicators_without_observables():
    objects = _objects("misp_indicators_only.json")
    assert not {o["type"] for o in objects} & SCO_TYPES
    indicators = _objects("misp_indicators_only.json", "indicator")
    assert len(indicators) == 3 and all(i["pattern_type"] == "stix" for i in indicators)
    assert all(any(label.startswith("misp:") for label in i["labels"]) for i in indicators)
    assert all(any(k.startswith("x_misp_") for k in i) for i in indicators)
    patterns = [i["pattern"] for i in indicators]
    assert any(" OR file:hashes.'SHA-256' = " in p and p.startswith("[file:hashes.MD5 = ") for p in patterns)
    assert any(re.fullmatch(r"\[domain-name:value = '[^']+'\] AND \[url:value = '[^']+'\]", p) for p in patterns)


# ── rules ────────────────────────────────────────────────────────────────────

def test_rules_fixture_has_one_refused_sigma_rule_and_accepted_others():
    by_type: dict[str, list[dict]] = {}
    for indicator in _objects("rules.json", "indicator"):
        by_type.setdefault(indicator["pattern_type"], []).append(indicator)
    assert {t: len(v) for t, v in by_type.items()} == {"yara": 1, "sigma": 2, "suricata": 1}

    # importorskip: a missing parser skips on a laptop and fails in CI (tests/conftest.py)
    pytest.importorskip("sigma")
    pytest.importorskip("parsuricata")
    pytest.importorskip("yara")
    verdicts = {i["name"]: check_pattern(i["pattern_type"], i["pattern"])[0]
                for t in ("sigma", "suricata") for i in by_type[t]}
    assert {n for n, v in verdicts.items() if v == REFUSED} == {"Sigma rule: MidnightFrost Broken Rule"}
    assert prepare_embedded_rule(by_type["yara"][0]["pattern"]).status == COMPILES


# ── invalid_objects ──────────────────────────────────────────────────────────

def test_invalid_objects_fail_for_the_intended_objects_only():
    no_family = _by_name("invalid_objects.json", "malware", "NoFamilyFlag")["id"]
    assert sorted(_parse_failures("invalid_objects.json")) == sorted([no_family, "indicator--not-a-uuid"])

    result = validate_bundle((BASELINES / "invalid_objects.json").read_text(encoding="utf-8"))
    if result.status == UNVERIFIED:
        pytest.skip("the STIX JSON schemas are not installed")
    assert result.status == INVALID
    assert any(no_family in e and "is_family" in e for e in result.errors)
    assert any("indicator--not-a-uuid" in e for e in result.errors)


def test_invalid_objects_carry_two_versions_of_one_object():
    versions = [o for o in _objects("invalid_objects.json", "threat-actor")]
    assert len(versions) == 2 and versions[0]["id"] == versions[1]["id"]
    assert versions[0]["modified"] < versions[1]["modified"] and versions[0]["created"] == versions[1]["created"]


# ── stix20, two_reports, report_with_confidence, refs_outside ────────────────

def test_stix20_is_a_2_0_bundle():
    bundle = _load("stix20.json")
    assert bundle["spec_version"] == "2.0"
    assert all("spec_version" not in o for o in bundle["objects"])


def test_two_reports_share_one_object_and_own_one_each():
    reports = _objects("two_reports.json", "report")
    assert len(reports) == 2
    a, b = (set(r["object_refs"]) for r in reports)
    assert len(a & b) == 1 and len(a - b) == 1 and len(b - a) == 1
    ids = {o["id"] for o in _objects("two_reports.json")}
    assert (a | b) <= ids
    (shared,) = a & b
    assert shared.startswith("intrusion-set--")


def test_report_with_confidence_keeps_its_rating_and_opencti_properties():
    (report,) = _objects("report_with_confidence.json", "report")
    assert report["confidence"] == 85
    assert any(k.startswith("x_opencti_") for k in report)
    assert any(k.startswith("extension-definition--") for k in report["extensions"])


def test_refs_outside_points_at_ids_the_bundle_does_not_have():
    objects = _objects("refs_outside.json")
    ids = {o["id"] for o in objects}
    refs = {o["created_by_ref"] for o in objects} | {m for o in objects for m in o["object_marking_refs"]}
    assert len(refs) >= 3 and not refs & ids
