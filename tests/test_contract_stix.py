"""The STIX extractor of scripts/contract.py (ADR-0094 item 1).

It reads the Stage 4 reference bundles (tests/fixtures/stage4_reference/
expected/, pinned to the code by tests/test_stage4_reference.py): the custom
properties CTIParsor writes, with their JSON types, and the id of every
object whose id is deterministic (docs/support-policy.md, STIX output, "The
identity rules").  The real surface is compared with contract/stix.json by
tests/test_contract.py.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import stix2

from scripts import contract as c


def _bundle(path: Path, objects: list[dict]) -> Path:
    path.write_text(json.dumps({"objects": objects, "ledger": {}}), encoding="utf-8")
    return path


_MALWARE = {"type": "malware", "id": "malware--4b1e4ff0-2b3c-5d2e-9f43-000000000001", "name": "SUNBURST"}


def test_ids_and_custom_properties(tmp_path):
    files = [
        _bundle(tmp_path / "minimal.json", [
            _MALWARE,
            {"type": "ipv4-addr", "id": "ipv4-addr--00000000-0000-5000-8000-000000000002", "value": "1.2.3.4"},
            {"type": "file", "id": "file--00000000-0000-5000-8000-000000000003",
             "hashes": {"SHA-256": "ab", "MD5": "cd"}},
            {"type": "relationship", "id": "relationship--R1", "x_evidence_text": "quoted"},
            {"type": "report", "id": "report--R1", "name": "Report", "x_synthesis_stats": {"n": 1}},
            {"type": "attack-pattern", "id": "attack-pattern--R2", "name": "No standard id"},
        ]),
        _bundle(tmp_path / "other.json", [
            {"type": "relationship", "id": "relationship--R1", "x_evidence_text": None},
            {"type": "vulnerability", "id": "vulnerability--00000000-0000-5000-8000-000000000004",
             "name": "CVE-2023-23397", "x_cvss_v3_score": 9.8},
        ]),
    ]
    entries, unkeyed = c.stix_entries(files)
    assert unkeyed == 0
    assert entries == {
        'id minimal malware name="SUNBURST"': {"id": _MALWARE["id"]},
        'id minimal ipv4-addr value="1.2.3.4"': {"id": "ipv4-addr--00000000-0000-5000-8000-000000000002"},
        'id minimal file hashes={"MD5": "cd", "SHA-256": "ab"}': {
            "id": "file--00000000-0000-5000-8000-000000000003"},
        'id minimal report name="Report"': {"id": "random"},                  # a random id, recorded as such
        'id minimal attack-pattern name="No standard id"': {"id": "random"},
        'id other vulnerability name="CVE-2023-23397"': {
            "id": "vulnerability--00000000-0000-5000-8000-000000000004"},
        "property relationship x_evidence_text": {"types": ["null", "string"]},
        "property report x_synthesis_stats": {"types": ["object"]},
        "property vulnerability x_cvss_v3_score": {"types": ["number"]},
    }


def test_the_first_natural_key_names_the_object(tmp_path):
    obj = {"type": "file", "id": "file--00000000-0000-5000-8000-000000000005", "name": "a.dll",
           "hashes": {"MD5": "cd"}}
    entries, _ = c.stix_entries([_bundle(tmp_path / "s.json", [obj])])
    assert list(entries) == ['id s file name="a.dll"']


def test_an_object_without_a_natural_key_is_counted_not_recorded(tmp_path):
    obj = {"type": "x-thing", "id": "x-thing--00000000-0000-5000-8000-000000000006"}
    assert c.stix_entries([_bundle(tmp_path / "s.json", [obj])]) == ({}, 1)


def test_two_objects_with_one_key_fail(tmp_path):
    twin = {**_MALWARE, "id": "malware--00000000-0000-5000-8000-000000000007"}
    with pytest.raises(c.ExtractError, match="have the key"):
        c.stix_entries([_bundle(tmp_path / "s.json", [_MALWARE, twin])])


def test_a_random_and_a_standard_object_with_one_key_fail(tmp_path):
    standard = {"type": "attack-pattern", "id": "attack-pattern--00000000-0000-5000-8000-000000000008",
                "name": "Phishing"}
    random = {"type": "attack-pattern", "id": "attack-pattern--R1", "name": "Phishing"}
    with pytest.raises(c.ExtractError, match="have the key"):
        c.stix_entries([_bundle(tmp_path / "s.json", [standard, random])])


@pytest.mark.parametrize(("value", "kind"), [
    (None, "null"), (True, "boolean"), (3, "number"), (9.8, "number"), ("x", "string"), ([], "array"),
    ({}, "object")])
def test_json_types(value, kind):
    assert c._json_type(value) == kind


def test_no_reference_bundle_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "ROOT", tmp_path)
    with pytest.raises(c.ExtractError, match="no object"):
        c.extract_stix()


def test_the_real_reference_bundles():
    entries = c.extract_stix()
    properties = {k for k in entries if k.startswith("property ")}
    assert properties == {
        "property relationship x_evidence_label", "property relationship x_evidence_text",
        "property relationship x_inference_rule", "property relationship x_inferred_from",
        "property relationship x_policy_rule", "property relationship x_pin_evidence",
        "property relationship x_temporal_assertions", "property report x_source_published",
        "property report x_synthesis_stats", "property report x_opencti_files",
        "property vulnerability x_cvss_v3_score", "property vulnerability x_cvss_v3_vector",
    }
    # A relationship has no natural key: no id entry.  The Report of each scenario has a random id.
    assert not [k for k in entries if k.startswith("id ") and k.split(" ")[2] == "relationship"]
    reports = [v for k, v in entries.items() if k.startswith("id ") and k.split(" ")[2] == "report"]
    assert reports == [{"id": "random"}] * 5
    # The TLP markings carry the standard ids.
    assert entries['id minimal marking-definition name="TLP:RED"'] == {"id": stix2.TLP_RED.id}
    assert entries['id apt_report marking-definition name="TLP:AMBER"'] == {"id": stix2.TLP_AMBER.id}
