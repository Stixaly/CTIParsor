"""The baseline module (ADR-0090, lot 1): keys, patterns, resolution, references, then intake and the index.

Review (Stage 3r) and Stage 4 match through these functions, so a baseline
value, a job-store row and an object CTIParsor built must reach the same keys.
The tests below pin that, one normalisation at a time and then through Stage 4
itself, plus the matching rule and the reference closure.  The second half reads
the lot-0 fixtures (tests/fixtures/baselines/) through `intake`: every refusal
and exclusion, the scope, the markings, the entries and relations of the index,
its lookup and its JSON, and the contract the fuzz target relies on.
"""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import logging
import random
import re
from collections import Counter, namedtuple
from pathlib import Path

import pytest
import stix2

from models.schemas import EntityType, RawEntity
from pipeline import aliases
from pipeline import baseline_stix as bs
from pipeline import stage4_stix_mapping as s4
from pipeline.stage3_llm import LLMEnrichmentResult, TTPExtracted

BASELINES = Path(__file__).parent / "fixtures" / "baselines"
SHA256 = "9f2b6c1d4a7e3085b1d6f4e2a9c37d58e0b4a1f6c2d93e7a5b80c4d1f6e3a972"
MD5 = "5d41402abc4b2a76b9719d911017c592"
SHA1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"


def _objects(name: str) -> dict[str, dict]:
    bundle = json.loads((BASELINES / name).read_text(encoding="utf-8"))
    return {o["id"]: o for o in bundle["objects"]}


def _of_type(name: str, stix_type: str) -> list[dict]:
    return [o for o in _objects(name).values() if o["type"] == stix_type]


def _id(stix_type: str, n: int) -> str:
    return f"{stix_type}--{n:08x}-0000-4000-8000-000000000000"


# ── Entity types: the table and Stage 4 cannot drift ───────────────────────

# One value per observable type that `_entity_to_sco` accepts.
OBSERVABLE_VALUES = {
    "ipv4": "198.18.0.1", "ipv6": "2001:db8::1", "domain": "evil.test", "url": "http://evil.test/a",
    "email": "a@evil.test", "mac_addr": "00:11:22:33:44:55", "asn": "AS64500",
    "md5": MD5, "sha1": SHA1, "sha256": SHA256, "file": "svchost.exe",
    "registry_key": r"HKLM\Software\Run", "mutex": "Global\\FrostMtx", "user_account": "svc_frost",
}


def test_every_entity_type_has_a_stix_type():
    assert {e.value for e in EntityType} == set(bs.ENTITY_TO_STIX)


@pytest.mark.parametrize("entity_type", sorted(OBSERVABLE_VALUES))
def test_an_observable_type_is_the_one_stage_4_builds(entity_type):
    sco = s4._entity_to_sco(RawEntity(value=OBSERVABLE_VALUES[entity_type],
                                      entity_type=EntityType(entity_type)))
    assert sco is not None
    assert sco["type"] == bs.ENTITY_TO_STIX[entity_type]


def test_network_traffic_is_the_one_stage_4_builds():
    sco = s4._network_traffic_sco("beacons to 198.18.0.1:443 over https", [], {}, {}, None)
    assert sco["type"] == bs.ENTITY_TO_STIX["network_traffic"]


def test_the_observable_types_are_the_ones_stage_4_builds_as_scos():
    assert bs.OBSERVABLE_ENTITY_TYPES == set(OBSERVABLE_VALUES) | {"network_traffic"}


@pytest.mark.parametrize("entity_type, value", [
    ("infrastructure", "FrostInfra"), ("intrusion_set", "FrostSet"), ("location", "France"),
    ("identity", "Frost Bank"), ("campaign", "FrostCampaign"), ("incident", "FrostIncident"),
    ("cve", "CVE-2024-12345"), ("technique", "Frost technique"), ("tactic", "Frost tactic"),
    ("procedure", "Frost procedure"), ("ttp", "Frost ttp"),
])
def test_a_named_type_is_the_one_stage_4_builds_from_a_row(entity_type, value):
    bundle = s4.build_stix_bundle([RawEntity(value=value, entity_type=EntityType(entity_type))],
                                  LLMEnrichmentResult(), "r", report_text=value)
    [obj] = [o for o in bundle.objects if o.get("name") == value]
    assert obj["type"] == bs.ENTITY_TO_STIX[entity_type]


@pytest.mark.parametrize("entity_type, llm", [
    ("threat_actor", LLMEnrichmentResult(threat_actors=["ZzActor"])),
    ("malware", LLMEnrichmentResult(malware_families=["ZzMalware"])),
    ("tool", LLMEnrichmentResult(tools=["ZzTool"])),
    ("ttp", LLMEnrichmentResult(ttps=[TTPExtracted(technique_name="ZzTechnique")])),
])
def test_a_named_type_is_the_one_stage_4_builds_from_the_llm_lists(entity_type, llm):
    bundle = s4.build_stix_bundle([], llm, "r", report_text="ZzActor ZzMalware ZzTool ZzTechnique")
    [obj] = [o for o in bundle.objects if str(o.get("name", "")).startswith("Zz")]
    assert obj["type"] == bs.ENTITY_TO_STIX[entity_type]


# ── Families ────────────────────────────────────────────────────────────────

def test_actors_share_a_family_and_so_does_software():
    assert bs.family("threat-actor") == bs.family("intrusion-set") == "actor"
    assert bs.family("malware") == bs.family("tool") == "software"


def test_every_other_type_is_its_own_family():
    assert bs.family("campaign") == "campaign"
    assert bs.family("identity") == "identity"
    assert bs.family("threat-actor") != bs.family("malware")


# ── Normalisation ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("entity_type, spellings", [
    ("ipv6", ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1")),
    ("ipv4", ("198.18.0.1", " 198.18.0.1\n")),
    ("ipv4", ("198.18.0[.]1", "198.18.0.1")),
    ("ipv4", ("198.18.0.0/24", "198.18.0.0/24")),
    ("ipv6", ("2001:DB8:0:0:0:0:0:0/32", "2001:db8::/32")),
    ("domain", ("Evil[.]TEST", "evil.test")),
    ("email", ("Bob(at)Evil[.]test", "bob@evil.test")),
    ("url", ("hxxps://Evil[.]test/A", "https://evil.test/a")),
    ("mac_addr", ("00:1A:2B:3C:4D:5E", "00:1a:2b:3c:4d:5e")),
    ("sha256", (SHA256.upper(), SHA256)),
    ("file", ("SVCHost.EXE ", "svchost.exe")),
    ("registry_key", (r"HKLM\Software\Run", r"HKEY_LOCAL_MACHINE\SOFTWARE\Run")),
    ("registry_key", (r"hkcu\Software\Run", r"HKEY_CURRENT_USER\Software\Run")),
    ("asn", ("AS64500", "64500")),
    ("asn", ("as 64500", "64500")),
    ("asn", ("AS0064500", "64500")),
    ("cve", ("cve-2024-12345", "CVE-2024-12345")),
    ("threat_actor", ("  Cozy   BEAR ", "cozy bear")),
    ("malware", ("Wicked\tRAT", "wicked rat")),
])
def test_both_spellings_normalise_alike(entity_type, spellings):
    first, second = spellings
    assert bs.normalize_value(entity_type, first) == bs.normalize_value(entity_type, second)


def test_a_normal_form_is_the_expected_one():
    assert bs.normalize_value("ipv6", "2001:0DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert bs.normalize_value("asn", "AS64500") == "64500"
    assert bs.normalize_value("registry_key", r"HKLM\Software\Run") == r"hkey_local_machine\software\run"
    assert bs.normalize_value("cve", "cve-2024-1") == "CVE-2024-1"
    assert bs.normalize_value("threat_actor", "  Cozy   BEAR ") == "cozy bear"


def test_an_asn_that_is_no_number_keeps_its_text():
    assert bs.normalize_value("asn", "AS-FROST") == "as-frost"
    assert bs.normalize_value("asn", "") == ""


def test_a_value_that_is_no_address_is_lowercased():
    assert bs.normalize_value("ipv4", "Not-An-Address") == "not-an-address"
    assert bs.normalize_value("ipv4", "300.1.1.1/24") == "300.1.1.1/24"


def test_a_name_is_not_refanged():
    assert bs.normalize_value("malware", "Wicked[.]RAT") == "wicked[.]rat"


def test_an_entity_type_may_be_the_enum():
    assert bs.normalize_value(EntityType.IPV6, "2001:0DB8::1") == "2001:db8::1"


# ── Keys of a row ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("entity_type, value, key", [
    ("ipv4", "198.18.0.1", ("obs", "ipv4-addr", "198.18.0.1")),
    ("ipv6", "2001:0DB8::1", ("obs", "ipv6-addr", "2001:db8::1")),
    ("domain", "Evil[.]test", ("obs", "domain-name", "evil.test")),
    ("url", "hxxp://evil.test/a", ("obs", "url", "http://evil.test/a")),
    ("email", "A@Evil.test", ("obs", "email-addr", "a@evil.test")),
    ("mac_addr", "00:11:22:33:44:AA", ("obs", "mac-addr", "00:11:22:33:44:aa")),
    ("asn", "AS64500", ("obs", "autonomous-system", "64500")),
    ("registry_key", r"HKLM\Software\Run", ("obs", "windows-registry-key", r"hkey_local_machine\software\run")),
    ("mutex", "Global\\FrostMtx", ("obs", "mutex", "global\\frostmtx")),
    ("user_account", "SVC_Frost", ("obs", "user-account", "svc_frost")),
    ("network_traffic", "beacons to 198.18.0.1", ("obs", "network-traffic", "beacons to 198.18.0.1")),
    ("md5", MD5.upper(), ("hash", "MD5", MD5)),
    ("sha1", SHA1, ("hash", "SHA-1", SHA1)),
    ("sha256", SHA256, ("hash", "SHA-256", SHA256)),
    ("cve", "cve-2024-12345", ("cve", "CVE-2024-12345")),
])
def test_a_row_gives_its_strong_key(entity_type, value, key):
    assert bs.keys_for_row(entity_type, value) == ({key}, set())


def test_a_file_row_gives_a_weak_key_only():
    assert bs.keys_for_row("file", r"C:\Users\Public\SVCHost.exe") == \
        (set(), {("file_name", r"c:\users\public\svchost.exe")})


def test_a_row_of_a_type_without_keys_or_without_a_value_gives_none():
    assert bs.keys_for_row("something_else", "x") == (set(), set())
    assert bs.keys_for_row("ipv4", "   ") == (set(), set())


def test_a_row_may_carry_the_enum():
    assert bs.keys_for_row(EntityType.CVE, "CVE-2024-1") == ({("cve", "CVE-2024-1")}, set())


def test_a_row_named_with_a_mitre_alias_reaches_the_group_id_and_its_forms():
    strong, weak = bs.keys_for_row("threat_actor", "Cozy Bear")
    assert ("mitre", "G0016") in strong
    assert {("named", "actor", "apt29"), ("named", "actor", "cozy bear")} <= strong
    assert weak == set()


def test_the_stix_type_decides_a_name_two_mitre_objects_share():
    # "snake" is both the Turla group and the Uroburos malware (ADR-0021)
    assert ("mitre", "G0010") in bs.keys_for_row("threat_actor", "Snake")[0]
    assert ("mitre", "S0022") in bs.keys_for_row("malware", "Snake")[0]


def test_a_mitre_id_on_the_row_is_a_key_of_any_named_type():
    strong, _ = bs.keys_for_row("campaign", "Frost run", mitre_id=" c0001 ")
    assert strong == {("named", "campaign", "frost run"), ("mitre", "C0001")}


def test_a_blank_mitre_id_is_no_mitre_id():
    strong, _ = bs.keys_for_row("campaign", "Frost run", mitre_id="  ")
    assert strong == {("named", "campaign", "frost run")}


def test_a_ttp_row_has_its_id_or_the_one_its_name_gives():
    assert ("mitre", "T1059.001") in bs.keys_for_row("ttp", "PowerShell", mitre_id="T1059.001")[0]
    assert ("mitre", "T1059.001") in bs.keys_for_row("ttp", "powershell")[0]
    strong, _ = bs.keys_for_row("ttp", "Frost technique")
    assert strong == {("named", "attack-pattern", "frost technique")}


def test_a_name_in_no_gazetteer_keeps_its_own_form_only():
    assert bs.keys_for_row("malware", "ZzMalware")[0] == {("named", "software", "zzmalware")}


def test_a_country_row_has_its_iso_code_and_its_name():
    assert bs.keys_for_row("location", "France")[0] == {("loc", "FR"), ("named", "location", "france")}
    assert bs.keys_for_row("location", "Atlantis")[0] == {("named", "location", "atlantis")}


# ── Keys of an object ───────────────────────────────────────────────────────

def test_a_file_with_three_hashes_has_a_key_for_each_and_a_weak_name():
    obj = {"type": "file", "id": _id("file", 1), "name": "Loader.DLL",
           "hashes": {"MD5": MD5.upper(), "SHA-1": SHA1, "SHA-256": SHA256}}
    strong, weak = bs.keys_for_object(obj)
    assert strong == {("id", obj["id"]), ("hash", "MD5", MD5), ("hash", "SHA-1", SHA1),
                      ("hash", "SHA-256", SHA256)}
    assert weak == {("file_name", "loader.dll")}


def test_a_hash_spelled_another_way_is_in_the_stix_vocabulary():
    strong, _ = bs.keys_for_object({"type": "file", "hashes": {"SHA256": SHA256, "sha_1": SHA1, "SSDEEP": "3:a:b"}})
    assert strong == {("hash", "SHA-256", SHA256), ("hash", "SHA-1", SHA1)}


def test_a_file_with_nothing_to_key_gives_nothing():
    assert bs.keys_for_object({"type": "file", "hashes": "oops", "name": ""}) == (set(), set())


@pytest.mark.parametrize("obj, key", [
    ({"type": "ipv4-addr", "value": "198.18.0.1"}, ("obs", "ipv4-addr", "198.18.0.1")),
    ({"type": "ipv6-addr", "value": "2001:0db8:0:0:0:0:0:1"}, ("obs", "ipv6-addr", "2001:db8::1")),
    ({"type": "domain-name", "value": "Evil.TEST"}, ("obs", "domain-name", "evil.test")),
    ({"type": "url", "value": "http://Evil.test/a"}, ("obs", "url", "http://evil.test/a")),
    ({"type": "email-addr", "value": "A@evil.test"}, ("obs", "email-addr", "a@evil.test")),
    ({"type": "mac-addr", "value": "00:11:22:33:44:AA"}, ("obs", "mac-addr", "00:11:22:33:44:aa")),
    ({"type": "autonomous-system", "number": 64500, "name": "FrostNet"}, ("obs", "autonomous-system", "64500")),
    ({"type": "windows-registry-key", "key": r"HKEY_LOCAL_MACHINE\Software\Run"},
     ("obs", "windows-registry-key", r"hkey_local_machine\software\run")),
    ({"type": "mutex", "name": "FrostMtx"}, ("obs", "mutex", "frostmtx")),
    ({"type": "user-account", "user_id": "svc_frost"}, ("obs", "user-account", "svc_frost")),
])
def test_an_sco_gives_its_obs_key(obj, key):
    assert bs.keys_for_object(obj) == ({key}, set())


def test_a_defanged_sco_value_is_refanged():
    strong, _ = bs.keys_for_object({"type": "domain-name", "value": "evil[.]test", "defanged": True})
    assert strong == {("obs", "domain-name", "evil.test")}
    strong, _ = bs.keys_for_object({"type": "url", "value": "hxxp://evil[.]test/a", "defanged": True})
    assert strong == {("obs", "url", "http://evil.test/a")}


def test_an_sco_without_a_value_or_a_known_type_has_its_id_only():
    assert bs.keys_for_object({"type": "ipv4-addr", "id": _id("ipv4-addr", 1)}) == \
        ({("id", _id("ipv4-addr", 1))}, set())
    assert bs.keys_for_object({"type": "network-traffic", "id": _id("network-traffic", 1), "dst_port": 443}) == \
        ({("id", _id("network-traffic", 1))}, set())
    assert bs.keys_for_object({"type": "note", "id": _id("note", 1), "name": "Cozy Bear"}) == \
        ({("id", _id("note", 1))}, set())
    assert bs.keys_for_object({"type": "domain-name", "value": ""}) == (set(), set())


def test_an_object_without_a_type_or_an_id_gives_nothing():
    assert bs.keys_for_object({}) == (set(), set())
    assert bs.keys_for_object({"id": 7, "type": 7}) == (set(), set())


def test_a_stix2_instance_and_its_dict_give_the_same_keys():
    sco = stix2.IPv4Address(value="198.18.0.1")
    assert bs.keys_for_object(sco) == bs.keys_for_object(json.loads(sco.serialize()))
    file_sco = stix2.File(hashes={"SHA-256": SHA256}, name="a.dll")
    assert bs.keys_for_object(file_sco) == bs.keys_for_object(json.loads(file_sco.serialize()))
    actor = stix2.IntrusionSet(name="APT29", aliases=["Cozy Bear"])
    assert bs.keys_for_object(actor) == bs.keys_for_object(json.loads(actor.serialize()))


def test_a_stix_indicator_gives_the_keys_of_its_pattern():
    obj = {"type": "indicator", "id": _id("indicator", 1), "pattern_type": "stix",
           "pattern": "[file:hashes.MD5 = 'AA' OR file:hashes.'SHA-256' = 'bb'] AND [file:name = 'X.exe']"}
    assert bs.keys_for_object(obj) == (
        {("id", obj["id"]), ("hash", "MD5", "aa"), ("hash", "SHA-256", "bb")},
        {("file_name", "x.exe")})


@pytest.mark.parametrize("extra", [{"pattern_type": "yara"}, {"pattern_type": "sigma"}, {},
                                   {"pattern_type": "stix", "pattern": 7}])
def test_any_other_indicator_has_its_id_only(extra):
    obj = {"type": "indicator", "id": _id("indicator", 2), "pattern": "[ipv4-addr:value = '198.18.0.1']", **extra}
    assert bs.keys_for_object(obj) == ({("id", obj["id"])}, set())


def test_apt29_and_a_cozy_bear_row_share_a_named_actor_key_and_the_mitre_key():
    apt29 = _of_type("opencti_report.json", "intrusion-set")[0]
    strong, weak = bs.keys_for_object(apt29)
    row, _ = bs.keys_for_row("threat_actor", "Cozy Bear")
    shared = strong & row
    assert ("mitre", "G0016") in shared
    assert ("named", "actor", "cozy bear") in shared
    assert ("named", "actor", "apt29") in shared
    assert ("id", apt29["id"]) in strong
    assert weak == set()


def test_a_threat_actor_and_an_intrusion_set_of_one_name_share_their_keys():
    actor = bs.keys_for_object({"type": "threat-actor", "name": "APT29"})[0]
    group = bs.keys_for_object({"type": "intrusion-set", "name": "APT29"})[0]
    assert actor == group
    assert ("named", "actor", "apt29") in actor


def test_malware_and_tool_share_the_software_family_and_nothing_else():
    malware = bs.keys_for_object({"type": "malware", "name": "Cobalt Strike", "is_family": True})[0]
    tool = bs.keys_for_object({"type": "tool", "name": "Cobalt Strike"})[0]
    assert malware == tool
    assert ("named", "software", "cobalt strike") in malware
    assert ("mitre", "S0154") in malware
    actor = bs.keys_for_object({"type": "threat-actor", "name": "Cobalt Strike"})[0]
    assert not {k for k in actor if k[0] == "named"} & {k for k in malware if k[0] == "named"}


def test_the_external_reference_of_a_mitre_source_wins_over_the_gazetteer():
    for source in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
        obj = {"type": "intrusion-set", "name": "APT29",
               "external_references": [{"source_name": source, "external_id": "g9999"}]}
        mitre = {k for k in bs.keys_for_object(obj)[0] if k[0] == "mitre"}
        assert mitre == {("mitre", "G9999")}
    other = {"type": "intrusion-set", "name": "APT29",
             "external_references": [{"source_name": "other", "external_id": "G9999"},
                                     {"source_name": "mitre-attack"}]}
    assert {k for k in bs.keys_for_object(other)[0] if k[0] == "mitre"} == {("mitre", "G0016")}


def test_an_attack_pattern_without_an_external_id_gets_its_id_from_its_name():
    obj = {"type": "attack-pattern", "name": "PowerShell"}
    strong, _ = bs.keys_for_object(obj)
    assert ("mitre", "T1059.001") in strong
    assert ("named", "attack-pattern", "powershell") in strong
    assert bs.keys_for_object({"type": "attack-pattern", "name": "Frost technique"})[0] == \
        {("named", "attack-pattern", "frost technique")}


def test_a_name_missing_or_not_text_gives_no_name_key():
    assert bs.keys_for_object({"type": "campaign", "id": _id("campaign", 1)}) == \
        ({("id", _id("campaign", 1))}, set())
    obj = {"type": "campaign", "name": 7, "aliases": ["Frost", 7, " ", "  Run  "], "x_mitre_aliases": "no"}
    assert bs.keys_for_object(obj)[0] == {("named", "campaign", "frost"), ("named", "campaign", "run")}


def test_the_aliases_are_forms_of_the_name():
    obj = {"type": "malware", "name": "ZzMalware", "aliases": ["Zz Alias"], "x_mitre_aliases": ["ZZ Mitre"]}
    assert bs.keys_for_object(obj)[0] == {("named", "software", "zzmalware"), ("named", "software", "zz alias"),
                                          ("named", "software", "zz mitre")}


def test_a_vulnerability_has_its_cve_from_its_name_or_its_reference():
    named = bs.keys_for_object({"type": "vulnerability", "name": "cve-2024-12345"})[0]
    assert ("cve", "CVE-2024-12345") in named
    referenced = bs.keys_for_object({"type": "vulnerability", "name": "Frost bug", "external_references": [
        {"source_name": "cve", "external_id": "CVE-2024-99999"}, {"source_name": "other", "external_id": "x"}]})[0]
    assert referenced == {("cve", "CVE-2024-99999"), ("named", "vulnerability", "frost bug")}


def test_a_row_cve_meets_the_object_cve():
    row = bs.keys_for_row("cve", "CVE-2024-12345")[0]
    assert row <= bs.keys_for_object({"type": "vulnerability", "name": "CVE-2024-12345"})[0]


def test_a_location_has_its_country_or_the_one_its_name_gives():
    assert ("loc", "FR") in bs.keys_for_object({"type": "location", "name": "France", "country": "fr"})[0]
    assert ("loc", "DE") in bs.keys_for_object({"type": "location", "name": "Germany"})[0]
    assert bs.keys_for_object({"type": "location", "name": "Paris", "region": "europe"})[0] == \
        {("named", "location", "paris")}


def test_a_sector_identity_has_a_named_key_in_its_own_family():
    sector = {"type": "identity", "name": "Financial Services", "identity_class": "class"}
    assert bs.keys_for_object(sector)[0] == {("named", "identity", "financial services")}
    assert bs.keys_for_row("identity", "financial  services")[0] == {("named", "identity", "financial services")}


def test_the_opencti_fixture_objects_give_what_the_row_of_their_value_gives():
    objects = _objects("opencti_report.json")
    by_type = {o["type"]: o for o in objects.values()}
    file_keys = bs.keys_for_object(by_type["file"])[0]
    assert bs.keys_for_row("sha256", SHA256)[0] <= file_keys
    assert bs.keys_for_row("md5", MD5)[0] <= file_keys
    ip = bs.keys_for_row("ipv4", "198.18.12.77")[0]
    assert ip <= bs.keys_for_object(by_type["ipv4-addr"])[0]
    assert ip <= bs.keys_for_object(by_type["indicator"])[0]           # [ipv4-addr:value = …]
    assert bs.keys_for_row("ttp", "PowerShell", "T1059.001")[0] <= bs.keys_for_object(by_type["attack-pattern"])[0]
    assert bs.keys_for_row("malware", "WellMess")[0] & bs.keys_for_object(by_type["malware"])[0]
    assert bs.keys_for_object(by_type["identity"])[0] >= {("named", "identity", "acme threat intelligence")}


def test_a_report_a_marking_and_a_relationship_have_their_id_only():
    for obj in _objects("opencti_report.json").values():
        if obj["type"] in ("report", "marking-definition", "relationship"):
            assert bs.keys_for_object(obj) == ({("id", obj["id"])}, set())


def test_the_misp_indicators_without_an_sco_are_keyed_by_their_pattern():
    by_pattern = {o["pattern"]: bs.keys_for_object(o) for o in _of_type("misp_indicators_only.json", "indicator")}
    keys = {tuple(sorted(k for k in strong if k[0] != "id")): weak for strong, weak in by_pattern.values()}
    assert (("hash", "MD5", MD5), ("hash", "SHA-256", SHA256)) in keys
    assert (("obs", "domain-name", "frostmail-cdn.test"),
            ("obs", "url", "http://frostmail-cdn.test/stage/payload.bin")) in keys
    assert (("obs", "ipv4-addr", "198.18.45.100"),) in keys


def test_a_rule_indicator_has_its_id_only():
    for obj in _of_type("rules.json", "indicator"):
        assert bs.keys_for_object(obj) == ({("id", obj["id"])}, set())


# ── What CTIParsor builds is found by the rows it was built from (A2, module level) ──

def _index(objects):
    by_key: dict = {}
    for obj in objects:
        for key in bs.keys_for_object(obj)[0]:
            by_key.setdefault(key, []).append(obj)
    return by_key


def test_every_row_resolves_to_the_object_stage_4_built_for_it():
    values = {**OBSERVABLE_VALUES, "cve": "CVE-2024-12345", "location": "France",
              "campaign": "FrostCampaign", "infrastructure": "FrostInfra", "intrusion_set": "FrostSet",
              "identity": "Frost Bank", "incident": "FrostIncident"}
    del values["file"]                                   # a hashless file is a weak key: no merge
    rows = [RawEntity(value=v, entity_type=EntityType(t)) for t, v in values.items()]
    rows.append(RawEntity(value="PowerShell", entity_type=EntityType.TTP, mitre_id="T1059.001"))
    llm = LLMEnrichmentResult(threat_actors=["Cozy Bear"], malware_families=["ZzMalware"], tools=["Cobalt Strike"],
                              ttps=[TTPExtracted(technique_name="Frost technique")])
    bundle = s4.build_stix_bundle(rows, llm, "r", report_text=" ".join(values.values()))
    objects = [json.loads(o.serialize()) for o in bundle.objects]
    by_key = _index(objects)
    wanted = [(r.entity_type.value, r.value, r.mitre_id) for r in rows]
    wanted += [("threat_actor", "Cozy Bear", None), ("malware", "ZzMalware", None), ("tool", "Cobalt Strike", None),
               ("ttp", "Frost technique", None)]
    for entity_type, value, mitre_id in wanted:
        strong, _ = bs.keys_for_row(entity_type, value, mitre_id)
        found = bs.resolve(strong, bs.ENTITY_TO_STIX[entity_type], by_key, lambda o: o["type"])
        assert isinstance(found, dict), (entity_type, value, found)
        expected = bs.ENTITY_TO_STIX[entity_type]
        assert found["type"] == expected, (entity_type, value)


def test_a_hashless_file_row_meets_its_object_by_the_weak_key_only():
    bundle = s4.build_stix_bundle([RawEntity(value="svchost.exe", entity_type=EntityType.FILE)],
                                  LLMEnrichmentResult(), "r", report_text="svchost.exe")
    [file_obj] = [json.loads(o.serialize()) for o in bundle.objects if o["type"] == "file"]
    row_strong, row_weak = bs.keys_for_row("file", "svchost.exe")
    obj_strong, obj_weak = bs.keys_for_object(file_obj)
    assert row_strong == set() and row_weak == obj_weak
    assert row_weak.isdisjoint(obj_strong)


# ── Patterns ────────────────────────────────────────────────────────────────

def test_a_single_ipv4_pattern():
    assert bs.pattern_keys("[ipv4-addr:value = '198.18.0.1']") == ({("obs", "ipv4-addr", "198.18.0.1")}, set())


def test_an_or_of_two_hashes_gives_two_keys():
    strong, weak = bs.pattern_keys("[file:hashes.MD5 = '5D41402ABC4B2A76B9719D911017C592' "
                                   "OR file:hashes.'SHA-256' = '" + SHA256 + "']")
    assert strong == {("hash", "MD5", MD5), ("hash", "SHA-256", SHA256)}
    assert weak == set()


def test_an_and_of_two_observations_gives_one_key_each():
    strong, _ = bs.pattern_keys("[domain-name:value = 'Frostmail-CDN.test'] AND [url:value = 'http://x.test/a']")
    assert strong == {("obs", "domain-name", "frostmail-cdn.test"), ("obs", "url", "http://x.test/a")}


def test_matches_gives_no_key():
    assert bs.pattern_keys("[file:name MATCHES '^evil.*']") == (set(), set())
    assert bs.pattern_keys("[domain-name:value MATCHES 'evil']") == (set(), set())


@pytest.mark.parametrize("pattern", [
    "[ipv4-addr:value NOT = '198.18.0.1']",
    "[ipv4-addr:value IN ('198.18.0.1', '198.18.0.2')]",
    "[ipv4-addr:value ISSUBSET '198.18.0.0/16']",
    "[domain-name:value LIKE 'evil%']",
    "[autonomous-system:number > 64500]",
])
def test_an_operator_other_than_equals_gives_no_key(pattern):
    assert bs.pattern_keys(pattern) == (set(), set())


def test_a_file_name_is_a_weak_key():
    assert bs.pattern_keys(r"[file:name = 'C:\\Users\\Public\\SVCHost.exe']") == \
        (set(), {("file_name", r"c:\users\public\svchost.exe")})


def test_an_autonomous_system_number_is_bare():
    assert bs.pattern_keys("[autonomous-system:number = 64500]") == ({("obs", "autonomous-system", "64500")}, set())


def test_a_registry_key_with_escaped_backslashes_meets_the_expanded_row():
    strong, _ = bs.pattern_keys(r"[windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\Software\\Run']")
    assert strong == bs.keys_for_row("registry_key", r"HKLM\Software\Run")[0]


def test_an_escaped_quote_and_an_escaped_backslash_are_undone():
    strong, _ = bs.pattern_keys(r"[mutex:name = 'it\'s a\\mutex']")
    assert strong == {("obs", "mutex", "it's a\\mutex")}


def test_a_hash_spelled_sha256_is_a_sha_256_key():
    assert bs.pattern_keys("[file:hashes.SHA256 = 'BB']")[0] == {("hash", "SHA-256", "bb")}
    assert bs.pattern_keys("[file:hashes.'SHA-1' = 'cc']")[0] == {("hash", "SHA-1", "cc")}


def test_a_hash_without_an_entity_type_gives_no_key():
    assert bs.pattern_keys("[file:hashes.'SSDEEP' = '3:a:b']") == (set(), set())
    assert bs.pattern_keys("[file:hashes.TLSH = 'T1abc']") == (set(), set())


def test_a_path_that_is_no_key_gives_none():
    assert bs.pattern_keys("[network-traffic:dst_ref.value = '198.18.0.1' AND network-traffic:dst_port = 443]") \
        == (set(), set())
    assert bs.pattern_keys("[file:extensions.'windows-pebinary-ext'.sections[*].name = 'x']") == (set(), set())
    assert bs.pattern_keys("[file:size = 12]") == (set(), set())
    assert bs.pattern_keys("[domain-name:value = '']") == (set(), set())
    assert bs.pattern_keys("[file:hashes.MD5 = '']") == (set(), set())
    assert bs.pattern_keys("[file:name = '']") == (set(), set())
    assert bs.pattern_keys("[autonomous-system:number = 0]") == ({("obs", "autonomous-system", "0")}, set())


def _or_of(n: int) -> str:
    return "[" + " OR ".join(f"ipv4-addr:value = '198.18.{i // 250}.{i % 250}'" for i in range(n)) + "]"


def _nested(depth: int) -> str:
    return "[" + "(" * (depth - 1) + "file:name = 'x'" + ")" * (depth - 1) + "]"


@pytest.mark.parametrize("pattern", ["garbage", "", "[ipv4-addr:value = '1", None, 7])
def test_a_pattern_that_does_not_parse_gives_no_key_and_never_raises(pattern):
    assert bs.pattern_keys(pattern) == (set(), set())


@pytest.mark.parametrize("pattern", [_nested(3000), _or_of(4000), _or_of(258), _nested(65),
                                     "[file:name = '" + "x" * 70_000 + "']"])
def test_a_pattern_too_complex_gives_no_key_and_reaches_no_parser(pattern, monkeypatch):
    def no_parser(*args, **kwargs):
        raise AssertionError("the parser was called")
    monkeypatch.setattr(bs, "Pattern", no_parser)
    assert bs.pattern_too_complex(pattern)
    assert bs.pattern_keys(pattern) == (set(), set())


def test_the_complexity_bounds_are_inclusive():
    assert not bs.pattern_too_complex(_or_of(bs._MAX_PATTERN_JOINERS + 1))  # 256 joiners
    assert bs.pattern_too_complex(_or_of(bs._MAX_PATTERN_JOINERS + 2))      # 257 joiners
    assert not bs.pattern_too_complex(_nested(bs._MAX_PATTERN_DEPTH))
    assert bs.pattern_too_complex(_nested(bs._MAX_PATTERN_DEPTH + 1))
    assert not bs.pattern_too_complex("[file:name = '" + "x" * (bs._MAX_PATTERN_CHARS - 16) + "']")


def test_what_is_quoted_counts_neither_as_a_term_nor_as_a_bracket():
    literal = "'" + " OR ".join(["(["] * 300) + " \\' OR AND ((" + "'"
    assert not bs.pattern_too_complex(f"[file:name = {literal}]")
    assert not bs.pattern_too_complex("[file:name = 'a\\\\'] OR [file:name = 'b']")


@pytest.mark.parametrize("entity_type", ["ipv4", "domain", "url", "registry_key", "asn", "malware", "cve"])
def test_a_value_with_a_lone_surrogate_has_no_key(entity_type):
    assert bs.normalize_value(entity_type, "evil\ud800.test") == ""
    assert bs.keys_for_row(entity_type, "evil\ud800.test") == (set(), set())


def test_a_hundred_term_or_is_still_read():
    strong, _ = bs.pattern_keys(_or_of(100))
    assert len(strong) == 100


def test_a_pattern_and_the_row_of_its_value_meet():
    for entity_type, value in [("ipv4", "198.18.0.1"), ("domain", "Evil.test"), ("url", "http://evil.test/a?b='c'"),
                               ("email", "a@evil.test"), ("asn", "AS64500"), ("mutex", "Global\\x"),
                               ("registry_key", r"HKCU\Software\Run"), ("md5", MD5), ("sha256", SHA256),
                               ("ipv6", "2001:db8:0:0:0:0:0:1")]:
        sco = s4._entity_to_sco(RawEntity(value=value, entity_type=EntityType(entity_type)))
        pattern = s4._build_stix_pattern(value, sco)
        assert bs.pattern_keys(pattern)[0] == bs.keys_for_row(entity_type, value)[0], (entity_type, pattern)
        assert bs.keys_for_row(entity_type, value)[0] <= bs.keys_for_object(sco)[0], entity_type


# ── Resolution ──────────────────────────────────────────────────────────────

Cand = namedtuple("Cand", "name stix_type")


def _resolve(keys, stix_type, *cands_by_key):
    by_key: dict = {}
    for key, cand in cands_by_key:
        by_key.setdefault(key, []).append(cand)
    return bs.resolve(keys, stix_type, by_key, lambda c: c.stix_type)


def test_resolve_with_no_candidate_is_none():
    assert _resolve({("obs", "ipv4-addr", "1")}, "ipv4-addr") is None
    assert _resolve(set(), "malware") is None


def test_resolve_with_one_candidate_returns_it():
    cand = Cand("a", "ipv4-addr")
    key = ("obs", "ipv4-addr", "198.18.0.1")
    assert _resolve({key}, "ipv4-addr", (key, cand)) is cand
    # the same entry under several keys is one candidate
    other = ("hash", "MD5", "aa")
    assert _resolve({key, other}, "ipv4-addr", (key, cand), (other, cand)) is cand


def test_resolve_prefers_the_candidate_of_the_exact_type():
    group = Cand("APT29", "intrusion-set")
    actor = Cand("APT29", "threat-actor")
    key = ("named", "actor", "apt29")
    assert _resolve({key}, "intrusion-set", (key, group), (key, actor)) is group
    assert _resolve({key}, "threat-actor", (key, group), (key, actor)) is actor


def test_resolve_with_several_candidates_and_none_of_the_exact_type_is_ambiguous():
    group = Cand("APT29", "intrusion-set")
    actor = Cand("APT29", "threat-actor")
    key = ("named", "actor", "apt29")
    assert _resolve({key}, "campaign", (key, group), (key, actor)) is None      # another family: no candidate
    mitre = ("mitre", "G0016")
    assert _resolve({mitre}, "malware", (mitre, group), (mitre, actor)) is bs.AMBIGUOUS


def test_resolve_with_two_candidates_of_the_exact_type_is_ambiguous():
    first, second = Cand("a", "malware"), Cand("b", "malware")
    key = ("hash", "MD5", "aa")
    assert _resolve({key}, "malware", (key, first), (key, second)) is bs.AMBIGUOUS


def test_a_weak_key_is_never_considered():
    cand = Cand("svchost.exe", "file")
    weak = ("file_name", "svchost.exe")
    assert _resolve({weak}, "file", (weak, cand)) is None


def test_a_name_key_of_another_family_is_not_considered():
    tool = Cand("Mimikatz", "tool")
    assert _resolve({("named", "software", "mimikatz")}, "threat-actor",
                    (("named", "software", "mimikatz"), tool)) is None
    assert _resolve({("named", "software", "mimikatz")}, "malware",
                    (("named", "software", "mimikatz"), tool)) is tool


def test_a_strong_key_matches_across_families():
    tool = Cand("Cobalt Strike", "tool")
    key = ("mitre", "S0154")
    assert _resolve({key}, "malware", (key, tool)) is tool


def test_without_a_type_any_name_family_counts_and_several_candidates_are_ambiguous():
    actor, malware = Cand("Snake", "threat-actor"), Cand("Snake", "malware")
    a, m = ("named", "actor", "snake"), ("named", "software", "snake")
    assert _resolve({a, m}, None, (a, actor)) is actor
    assert _resolve({a, m}, None, (a, actor), (m, malware)) is bs.AMBIGUOUS


# ── References ──────────────────────────────────────────────────────────────

def test_iter_refs_finds_every_reference_at_any_depth():
    obj = {
        "type": "network-traffic", "id": _id("network-traffic", 1),
        "created_by_ref": _id("identity", 1),
        "object_marking_refs": [_id("marking-definition", 1), _id("marking-definition", 2)],
        "granular_markings": [{"marking_ref": _id("marking-definition", 3), "selectors": ["description"]}],
        "src_ref": _id("ipv4-addr", 1), "dst_ref": _id("ipv4-addr", 2),
        "extensions": {"extension-definition--x": {"creator_refs": [_id("identity", 2)],
                                                   "deep": [{"deeper": {"x_ref": _id("malware", 1)}}]}},
        "protocols": ["tcp"], "external_references": [{"source_name": "x", "external_id": _id("malware", 9)}],
        "description": _id("malware", 8),
    }
    assert sorted(bs.iter_refs(obj)) == sorted([
        _id("identity", 1), _id("marking-definition", 1), _id("marking-definition", 2),
        _id("marking-definition", 3), _id("ipv4-addr", 1), _id("ipv4-addr", 2), _id("identity", 2),
        _id("malware", 1)])


def test_iter_refs_yields_ids_only():
    obj = {"source_ref": "not an id", "target_ref": 7, "sample_refs": ["", None, _id("file", 1), "a--"],
           "child_ref": ["indicator--not-a-uuid"], "x_ref": {"nested": 1}, "y_refs": 3}
    assert sorted(bs.iter_refs(obj)) == sorted([_id("file", 1), "indicator--not-a-uuid"])


def test_iter_refs_reads_a_stix2_instance():
    rel = stix2.Relationship(relationship_type="uses", source_ref=_id("malware", 1), target_ref=_id("tool", 1),
                             created_by_ref=_id("identity", 1))
    assert sorted(bs.iter_refs(rel)) == sorted([_id("malware", 1), _id("tool", 1), _id("identity", 1)])


def test_iter_refs_does_not_recurse_on_a_deep_object():
    node: dict = {"leaf_ref": _id("malware", 1)}
    for _ in range(5000):
        node = {"child": node}
    assert list(bs.iter_refs(node)) == [_id("malware", 1)]


def test_iter_refs_of_something_that_is_no_container():
    assert list(bs.iter_refs("text")) == []
    assert list(bs.iter_refs(None)) == []


def _graph() -> dict[str, dict]:
    bad, rel, sight, note, report, plain = (_id(t, i) for t, i in [
        ("malware", 1), ("relationship", 1), ("sighting", 1), ("note", 1), ("report", 1), ("tool", 1)])
    return {
        bad: {"id": bad, "type": "malware"},
        rel: {"id": rel, "type": "relationship", "source_ref": bad, "target_ref": plain},
        sight: {"id": sight, "type": "sighting", "sighting_of_ref": plain, "extensions": {"e": {"x_refs": [rel]}}},
        note: {"id": note, "type": "note", "object_refs": [sight, plain]},
        report: {"id": report, "type": "report", "object_refs": [bad, rel, plain]},
        plain: {"id": plain, "type": "tool", "created_by_ref": _id("identity", 99)},   # absent from the bundle
    }


def test_the_closure_cascades_over_two_levels_and_more():
    objects = _graph()
    bad, rel, sight, note, report, plain = (_id(t, i) for t, i in [
        ("malware", 1), ("relationship", 1), ("sighting", 1), ("note", 1), ("report", 1), ("tool", 1)])
    kept, dropped = bs.ref_closure(objects, set(objects), {bad})
    assert dropped == {
        rel: f"baseline_refs_closure:{bad}",
        report: f"baseline_refs_closure:{bad}",
        sight: f"baseline_refs_closure:{rel}",        # level 2: through the relationship
        note: f"baseline_refs_closure:{sight}",       # level 3
    }
    assert kept == {plain}


def test_the_excluded_are_not_reported_as_dropped_and_not_kept():
    objects = _graph()
    bad = _id("malware", 1)
    kept, dropped = bs.ref_closure(objects, set(objects), {bad})
    assert bad not in kept and bad not in dropped


def test_a_protected_object_is_never_dropped_and_its_referrers_are_not_followed_through_it():
    objects = _graph()
    bad, rel, sight, note, report = (_id(t, i) for t, i in [
        ("malware", 1), ("relationship", 1), ("sighting", 1), ("note", 1), ("report", 1)])
    kept, dropped = bs.ref_closure(objects, set(objects), {bad}, protected={report})
    assert report in kept and report not in dropped
    assert {rel, sight, note} == set(dropped)


def test_a_reference_to_an_id_absent_from_the_bundle_drops_nothing():
    objects = _graph()
    plain = _id("tool", 1)
    kept, dropped = bs.ref_closure(objects, {plain}, set())
    assert kept == {plain} and dropped == {}


def test_excluding_an_id_that_is_not_in_the_bundle_still_drops_its_referrers():
    objects = _graph()
    plain = _id("tool", 1)
    kept, dropped = bs.ref_closure(objects, set(objects), {_id("identity", 99)})
    assert dropped == {plain: f"baseline_refs_closure:{_id('identity', 99)}",
                       _id("relationship", 1): f"baseline_refs_closure:{plain}",
                       _id("report", 1): f"baseline_refs_closure:{plain}",
                       _id("sighting", 1): f"baseline_refs_closure:{plain}",
                       _id("note", 1): f"baseline_refs_closure:{plain}"}
    assert kept == {_id("malware", 1)}


def test_the_closure_only_works_on_the_candidates():
    objects = _graph()
    bad, rel = _id("malware", 1), _id("relationship", 1)
    kept, dropped = bs.ref_closure(objects, {rel, _id("tool", 1)}, {bad})
    assert dropped == {rel: f"baseline_refs_closure:{bad}"}
    assert kept == {_id("tool", 1)}


def test_a_candidate_without_an_object_is_kept():
    ghost = _id("note", 7)
    kept, dropped = bs.ref_closure({}, {ghost}, set())
    assert kept == {ghost} and dropped == {}


def test_a_reference_cycle_is_closed_once():
    a, b, c = _id("note", 1), _id("note", 2), _id("malware", 1)
    objects = {a: {"object_refs": [b, c]}, b: {"object_refs": [a]}, c: {}}
    kept, dropped = bs.ref_closure(objects, set(objects), {c})
    assert kept == set() and set(dropped) == {a, b}


def test_the_closure_on_the_fixture_follows_a_rejected_malware():
    objects = _objects("opencti_report.json")
    [malware] = [i for i, o in objects.items() if o["type"] == "malware"]
    reports = [i for i, o in objects.items() if o["type"] == "report"]
    kept, dropped = bs.ref_closure(objects, set(objects), {malware}, protected=set(reports))
    assert malware not in kept
    assert all(objects[i]["type"] == "relationship" for i in dropped)
    assert dropped and all(r.endswith(malware) for r in dropped.values())
    refs_malware = {i for i, o in objects.items() if malware in set(bs.iter_refs(o)) and i not in reports}
    assert set(dropped) == refs_malware


def test_the_fixture_with_references_outside_loses_nothing():
    objects = _objects("refs_outside.json")
    kept, dropped = bs.ref_closure(objects, set(objects), set())
    assert kept == set(objects) and dropped == {}


# ── Changes to the pure half ────────────────────────────────────────────────

def test_a_capec_reference_gives_a_mitre_key_that_a_row_with_a_capec_id_meets():
    obj = {"type": "attack-pattern", "name": "Frost injection",
           "external_references": [{"source_name": "capec", "external_id": "CAPEC-123"}]}
    assert ("mitre", "CAPEC-123") in bs.keys_for_object(obj)[0]
    assert ("mitre", "CAPEC-123") in bs.keys_for_row("ttp", "Anything else", mitre_id="capec-123")[0]


def test_the_family_table_is_the_one_aliases_uses():
    assert bs._FAMILY == aliases._STIX_FAMILY


def test_the_pap_levels_are_the_ones_stage_4_accepts():
    assert set(bs._PAP_ORDER) == s4._PAP_LEVELS
    assert bs._PAP_ORDER == ("WHITE", "GREEN", "AMBER", "RED")


def test_an_sdo_entry_gets_the_entity_type_whose_stix_type_it_is():
    assert set(bs._ENTITY_OF_SDO) == bs._NAMED_STIX_TYPES
    assert all(bs.ENTITY_TO_STIX[entity] == stix for stix, entity in bs._ENTITY_OF_SDO.items())


# ── Intake: helpers ─────────────────────────────────────────────────────────

TS = "2026-03-02T08:14:55.213Z"
BUNDLE_ID = "bundle--00000000-0000-4000-8000-0000000000aa"
OPENCTI_EXT = s4.OPENCTI_EXTENSION_ID


def _obj(stix_type: str, n: int, **props) -> dict:
    """A STIX 2.1 SDO or SRO of the type, with the id `_id` gives it."""
    return {"type": stix_type, "spec_version": "2.1", "id": _id(stix_type, n), "created": TS, "modified": TS, **props}


def _sco(stix_type: str, n: int, **props) -> dict:
    return {"type": stix_type, "id": _id(stix_type, n), **props}


def _malware(n: int, name: str = "WellMess", **props) -> dict:
    return _obj("malware", n, name=name, is_family=True, **props)


def _rel(n: int, verb: str, source: dict, target: dict, **props) -> dict:
    return _obj("relationship", n, relationship_type=verb, source_ref=source["id"], target_ref=target["id"], **props)


def _indicator(n: int, pattern: str, pattern_type: str = "stix", **props) -> dict:
    return _obj("indicator", n, pattern=pattern, pattern_type=pattern_type, valid_from=TS, name=f"ind {n}", **props)


def _report(n: int, *members: dict, **props) -> dict:
    return _obj("report", n, name=f"Report {n}", published=TS, report_types=["threat-report"],
                object_refs=[m["id"] for m in members], **props)


def _bundle(*objects: dict, **top) -> bytes:
    return json.dumps({"type": "bundle", "id": BUNDLE_ID, "objects": list(objects), **top}).encode()


def _read(*objects: dict, **kwargs):
    return bs.intake(_bundle(*objects), **kwargs)


def _fixture(name: str) -> bytes:
    return (BASELINES / name).read_bytes()


def _baseline(name: str, **kwargs) -> bs.BaselineIndex:
    index, _, _ = bs.intake(_fixture(name), **kwargs)
    assert index is not None
    return index


def _entry(index: bs.BaselineIndex, stix_type: str) -> bs.Entry:
    [entry] = [e for e in index.entries if e.stix_type == stix_type]
    return entry


def _reasons(summary: bs.Intake) -> dict[str, str]:
    return {e["id"]: e["reason"] for e in summary.excluded}


# ── Intake: global refusals ─────────────────────────────────────────────────

def test_a_baseline_over_the_size_limit_is_refused_and_says_so():
    with pytest.raises(bs.BaselineError, match="20 MB"):
        bs.intake(b" " * (bs.MAX_BASELINE_BYTES + 1))


@pytest.mark.parametrize("raw", [b"", b"nope", b"\xff\xfe\x00", b'{"a": "\xff"}', b"[1, 2", b"[" * 200_000,
                                 b'{"a":' * 100_000, b'{"type": "bundle", "objects": [NaN]}',
                                 b'{"type": "bundle", "objects": [{"n": ' + b"9" * 5000 + b"}]}"])
def test_what_is_no_json_is_refused(raw):
    with pytest.raises(bs.BaselineError):
        bs.intake(raw)


@pytest.mark.parametrize("document", [
    [], "bundle", {"type": "report"}, {"type": "bundle"}, {"type": "bundle", "objects": []},
    {"type": "bundle", "objects": {"a": 1}}, {"type": "bundle", "objects": [1]},
    {"type": "bundle", "objects": [{"type": "malware"}, "x"]},
])
def test_what_is_no_bundle_is_refused(document):
    with pytest.raises(bs.BaselineError):
        bs.intake(json.dumps(document).encode())


def test_more_objects_than_the_limit_are_refused():
    objects = [{"type": "malware", "spec_version": "2.1"}] * (bs.MAX_BASELINE_OBJECTS + 1)
    with pytest.raises(bs.BaselineError, match=str(bs.MAX_BASELINE_OBJECTS)):
        bs.intake(json.dumps({"type": "bundle", "objects": objects}).encode())


def test_the_stix_20_fixture_is_refused():
    with pytest.raises(bs.BaselineError, match="STIX 2.0"):
        bs.intake(_fixture("stix20.json"))
    with pytest.raises(bs.BaselineError, match="STIX 2.0"):
        bs.intake(_fixture("stix20.json"), preview=True)


def test_an_object_without_spec_version_is_a_stix_20_object():
    old = _malware(1)
    del old["spec_version"]
    with pytest.raises(bs.BaselineError, match="STIX 2.0 objects"):
        _read(old, _malware(2, "Other"))
    old["spec_version"] = "2.0"
    with pytest.raises(bs.BaselineError, match="STIX 2.0 objects"):
        _read(old)


def test_an_sco_may_lack_spec_version_and_so_may_a_bundle():
    index, summary, _ = _read(_sco("ipv4-addr", 1, value="198.18.0.1"))
    assert summary.counts["ipv4-addr"] == 1 and [e.entity_type for e in index.entries] == ["ipv4"]


def test_a_bundle_level_spec_version_21_is_tolerated_and_20_is_not():
    assert bs.intake(_bundle(_malware(1), spec_version="2.1"))[0] is not None
    with pytest.raises(bs.BaselineError, match="STIX 2.0"):
        bs.intake(_bundle(_malware(1), spec_version="2.0"))


def test_the_parsed_bundle_is_returned_with_its_hash_and_id():
    raw = _bundle(_malware(1))
    index, summary, parsed = bs.intake(raw)
    assert parsed["objects"][0]["name"] == "WellMess"
    assert summary.sha256 == index.sha256 == hashlib.sha256(raw).hexdigest()
    assert summary.bundle_id == index.bundle_id == BUNDLE_ID
    assert bs.intake(json.dumps({"type": "bundle", "id": 7, "objects": [_malware(1)]}).encode())[1].bundle_id == ""


# ── Intake: ids and versions ────────────────────────────────────────────────

def test_an_object_whose_id_is_no_uuid_is_excluded_with_a_reason():
    _, summary, _ = _read(_malware(1), {**_malware(2), "id": "malware--nope"},
                          {**_malware(3), "id": 7}, {**_malware(4), "type": 7},
                          {**_malware(5), "id": "Malware--" + "0" * 36})
    assert [(e["reason"], e["type"]) for e in summary.excluded] == [(bs.INVALID, "malware")] * 2 + \
        [(bs.INVALID, ""), (bs.INVALID, "malware")]
    assert summary.excluded[0]["id"] == "malware--nope" and "not <type>--<uuid>" in summary.excluded[0]["detail"]
    assert summary.excluded[1]["id"] == "" and "not a string" in summary.excluded[1]["detail"]
    assert summary.counts["malware"] == 1


def test_an_invalid_copy_of_an_id_leaves_out_only_itself_and_the_valid_copy_stays():
    valid, invalid = _malware(1, "Valid"), {**_malware(1), "type": 7}
    other = _malware(2, "Other")
    link = _rel(3, "related-to", valid, other)
    for copies in ([valid, invalid], [invalid, valid]):
        index, summary, _ = _read(*copies, other, link)
        assert _reasons(summary) == {valid["id"]: bs.INVALID}
        assert index.imported_ids == {valid["id"], other["id"], link["id"]}


def test_the_greatest_modified_of_two_versions_is_kept():
    older, newer = _malware(1, "Old name"), _malware(1, "New name", modified="2026-03-09T16:40:02.981Z")
    for pair in ([older, newer], [newer, older]):
        index, summary, _ = _read(*pair)
        assert [e.value for e in index.entries] == ["New name"]
        [gone] = summary.excluded
        assert gone["reason"] == bs.OLDER_VERSION and gone["id"] == older["id"]


def test_versions_that_cannot_be_ordered_keep_the_first():
    first, second = _malware(1, "First"), _malware(1, "Second")
    assert [e.value for e in _read(first, second)[0].entries] == ["First"]
    for modified in ("not a date", 7, None):
        second["modified"] = modified
        assert [e.value for e in _read(first, second)[0].entries] == ["First"]
    # the epoch is the oldest: a version with a readable date wins over one without
    first["modified"] = "garbage"
    second["modified"] = TS
    assert [e.value for e in _read(first, second)[0].entries] == ["Second"]


def test_dates_in_other_zones_and_out_of_range_are_compared_without_error():
    base = _malware(1, "Zone")
    for modified in ("2026-03-09T16:40:02+02:00", "2026-03-09T16:40:02", "0001-01-01T00:00:00+05:00",
                     "9999-12-31T23:59:59-05:00"):
        _read(base, {**base, "name": "Other", "modified": modified})


def test_the_invalid_objects_fixture_loses_exactly_the_malware_the_bad_id_and_the_old_version():
    index, summary, _ = bs.intake(_fixture("invalid_objects.json"))
    assert _reasons(summary) == {
        "indicator--not-a-uuid": bs.INVALID,
        "threat-actor--0c97ffd8-353d-4bba-a64f-649161105b6e": bs.OLDER_VERSION,
        "malware--70a37c2b-7744-47d8-aa16-709466f8fa9a": bs.INVALID,
    }
    for excluded in summary.excluded:
        assert set(excluded) == {"id", "type", "reason", "detail"}
        assert all(isinstance(v, str) for v in excluded.values()) and len(excluded["detail"]) <= 300
    by_id = {e["id"]: e for e in summary.excluded}
    assert "is_family" in by_id["malware--70a37c2b-7744-47d8-aa16-709466f8fa9a"]["detail"]
    assert summary.counts == {"identity": 1, "malware": 1, "threat-actor": 1, "out_of_scope": 0, "dangling_refs": 0}
    assert {e.value for e in index.entries} == {"Fixture Author", "GoodWare", "TwiceSeen"}
    assert "seen twice" in _entry(index, "threat-actor").surface_forms          # the newer version


def test_what_refers_to_an_excluded_object_is_dropped_whole_and_so_is_what_refers_to_that():
    good, bad = _malware(1, "GoodWare"), {k: v for k, v in _malware(2, "Bad").items() if k != "is_family"}
    link = _rel(3, "related-to", good, bad)
    note = _obj("note", 4, content="about the link", object_refs=[link["id"]])
    index, summary, _ = _read(good, bad, link, note)
    assert _reasons(summary) == {bad["id"]: bs.INVALID, link["id"]: bs.REFS_CLOSURE, note["id"]: bs.REFS_CLOSURE}
    details = {e["id"]: e["detail"] for e in summary.excluded}
    assert details[link["id"]] == bad["id"] and details[note["id"]] == link["id"]
    assert index.imported_ids == {good["id"]}
    assert summary.counts["malware"] == 1 and "relationship" not in summary.counts


def test_an_invalid_object_goes_whatever_its_kind():
    # stix2 accepts these, the JSON schemas do not: no millisecond, an invalid language tag
    no_millis = _malware(1, "Seconds", created="2026-03-02T08:14:55Z")
    bad_lang = _malware(2, "Lang", lang="not a lang!")
    index, summary, _ = _read(no_millis, bad_lang, _malware(3, "Fine"))
    assert _reasons(summary) == {no_millis["id"]: bs.INVALID, bad_lang["id"]: bs.INVALID}
    assert {e["id"]: e["detail"] for e in summary.excluded}[bad_lang["id"]].count("RFC 5646") == 1
    assert [e.value for e in index.entries] == ["Fine"]


def test_an_object_stix2_cannot_parse_is_excluded_with_its_message():
    nameless = {k: v for k, v in _obj("campaign", 1, name="x").items() if k != "name"}
    _, summary, _ = _read(nameless, _malware(2))
    [gone] = summary.excluded
    assert gone["reason"] == bs.INVALID and gone["detail"].startswith("MissingPropertiesError")


def test_the_detail_of_an_exclusion_is_cut_to_300_characters():
    assert len(bs._exclusion({"id": "a", "type": "b"}, "r", "x" * 1000)["detail"]) == 300
    assert bs._exclusion({"id": 1}, "r") == {"id": "", "type": "", "reason": "r", "detail": ""}


def test_intake_says_nothing_of_what_it_refuses_not_to_stdout_and_not_to_any_logger(capsys, caplog):
    caplog.set_level(logging.DEBUG)
    bs.intake(_fixture("invalid_objects.json"))
    bs.intake(_fixture("rules.json"))
    _read(_malware(1, lang="not a lang!"), _malware(2, "Fine"), _indicator(3, "rule X { condition: nope }", "yara"))
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    assert caplog.records == []


def test_validate_bundle_quiet_gives_the_same_verdict_without_printing_or_logging(capsys, caplog):
    caplog.set_level(logging.DEBUG)
    text = json.dumps({"type": "bundle", "id": BUNDLE_ID, "objects": [_malware(1, lang="not a lang!")]})
    loud = bs.stage5_validation.validate_bundle(text)
    assert loud.status == bs.stage5_validation.INVALID and caplog.records
    caplog.clear()
    capsys.readouterr()
    assert bs.stage5_validation.validate_bundle(text, quiet=True) == loud
    captured = capsys.readouterr()
    assert caplog.records == [] and captured.out == "" and captured.err == ""
    ok = json.dumps({"type": "bundle", "id": BUNDLE_ID, "objects": [_malware(1)]})
    assert bs.stage5_validation.validate_bundle(ok, quiet=True).status == bs.stage5_validation.VALIDATED
    assert caplog.records == []


def test_a_validator_that_falls_over_refuses_the_objects_it_fell_over_on(monkeypatch):
    def boom(text, quiet=False):
        raise RuntimeError("validator down " + "!" * 400)
    monkeypatch.setattr(bs.stage5_validation, "validate_bundle", boom)
    index, summary, _ = _read(_malware(1))
    [gone] = summary.excluded
    assert gone["reason"] == bs.INVALID and gone["detail"].startswith("RuntimeError: validator down !")
    assert len(summary.excluded[0]["detail"]) == 300 and index.entries == []


def test_without_the_json_schemas_stix2_alone_checks_and_a_warning_says_so(monkeypatch):
    monkeypatch.setattr(bs.stage5_validation, "validate_bundle",
                        lambda text, quiet=False: bs.stage5_validation.ValidationResult(
                            bs.stage5_validation.UNVERIFIED))
    index, summary, _ = _read(_malware(1, lang="not a lang!"), {k: v for k, v in _malware(2).items() if k != "name"})
    assert len(summary.excluded) == 1 and "'name' is a required property" in summary.excluded[0]["detail"]
    assert [e.value for e in index.entries] == ["WellMess"]
    assert len(summary.warnings) == 1 and "schemas are not installed" in summary.warnings[0]


def test_a_bundle_that_fails_as_a_whole_but_not_object_by_object_is_kept_with_a_warning(monkeypatch):
    real = bs.stage5_validation.validate_bundle

    def only_whole(text, quiet=False):
        if len(json.loads(text)["objects"]) > 1:
            return bs.stage5_validation.ValidationResult(bs.stage5_validation.INVALID, ["objects clash"])
        return real(text, quiet=quiet)
    monkeypatch.setattr(bs.stage5_validation, "validate_bundle", only_whole)
    index, summary, _ = _read(_malware(1), _malware(2, "Other"))
    assert summary.excluded == [] and len(index.entries) == 2
    assert summary.warnings == [
        "the bundle as a whole fails the STIX schemas although each object passes: objects clash"]


def _count_validations(monkeypatch) -> list[int]:
    calls: list[int] = []
    real = bs.stage5_validation.validate_bundle

    def counting(text, quiet=False):
        calls.append(len(json.loads(text)["objects"]))
        return real(text, quiet=quiet)
    monkeypatch.setattr(bs.stage5_validation, "validate_bundle", counting)
    return calls


def _crashing(n: int, name: str = "Crash") -> dict:
    """An object stix2 and the JSON schemas accept, on which the validator itself raises."""
    return _malware(n, name, kill_chain_phases=[{"kill_chain_name": "x", "phase_name": 5}])


def test_every_object_the_schemas_refuse_is_found_without_a_search(monkeypatch):
    objects = [_malware(n, f"Fine {n}") for n in range(1, 65)]
    bad = {2, 9, 10, 16, 33, 34, 50, 51, 52, 64}
    for n in bad:
        objects[n - 1] = _malware(n, f"Bad {n}", lang="not a lang!")
    calls = _count_validations(monkeypatch)
    index, summary, _ = _read(*objects)
    assert _reasons(summary) == {_id("malware", n): bs.INVALID for n in sorted(bad)}
    # the bundle, then each named object alone (the validator may name one by mistake): every error is
    # explained by a solo run, so nothing is validated again
    assert len(index.entries) == 54 and calls == [64] + [1] * 10
    assert all("RFC 5646" in e["detail"] and not e["detail"].startswith("malware--") for e in summary.excluded)


def test_what_the_validator_names_no_object_for_is_searched_by_halves(monkeypatch):
    monkeypatch.setattr(bs, "_VALIDATION_BUDGET_FACTOR", 10)          # two culprits cost more than the default
    objects = [_malware(n, f"Fine {n}") for n in range(1, 17)]
    objects[2] = _malware(3, "Lang", lang="not a lang!")
    objects[11] = _crashing(12)
    calls = _count_validations(monkeypatch)
    index, summary, _ = _read(*objects)
    assert _reasons(summary) == {_id("malware", 3): bs.INVALID, _id("malware", 12): bs.INVALID}
    assert calls[0] == 16 and max(calls[1:]) <= 9 and len(index.entries) == 14      # halves of about equal weight


class _Verdicts:
    """A validator that answers by the ids of the bundle it is given."""
    def __init__(self, monkeypatch, answer):
        self.calls: list[list[str]] = []
        self.answer = answer
        monkeypatch.setattr(bs.stage5_validation, "validate_bundle", self)

    def __call__(self, text, quiet=False):
        ids = [o["id"] for o in json.loads(text)["objects"]]
        self.calls.append(ids)
        errors = self.answer(ids)
        status = bs.stage5_validation.INVALID if errors else bs.stage5_validation.VALIDATED
        return bs.stage5_validation.ValidationResult(status, errors)


def test_the_errors_the_validator_attributes_are_kept_and_only_the_rest_is_searched(monkeypatch):
    one, two, three = (_id("malware", n) for n in (1, 2, 3))

    def answer(ids):
        errors = []
        if one in ids:
            errors += ["something at the bundle level", "unknown--x: about no object", f"{one}: boom", f"{one}: again"]
        if two in ids:
            errors.append("a fault that names nobody")
        return errors
    verdicts = _Verdicts(monkeypatch, answer)
    _, summary, _ = _read(_malware(1), _malware(2, "Two"), _malware(3, "Three"))
    assert {e["id"]: e["detail"] for e in summary.excluded} == {one: "boom; again", two: "a fault that names nobody"}
    assert verdicts.calls == [[one, two, three], [one], [two, three], [two], [three]]


def test_when_every_object_is_attributed_nothing_more_is_validated(monkeypatch):
    one = _id("malware", 1)
    verdicts = _Verdicts(monkeypatch, lambda ids: ["something at the bundle level", f"{one}: boom"])
    index, summary, _ = _read(_malware(1))
    assert [(e["id"], e["detail"]) for e in summary.excluded] == [(one, "boom")]
    assert verdicts.calls == [[one], [one]]                                  # the bundle, then the object alone
    assert index.entries == [] and summary.warnings == []


def test_an_invalid_verdict_with_no_error_is_searched_like_one_with_errors(monkeypatch):
    two = _id("malware", 2)
    result = bs.stage5_validation.ValidationResult
    monkeypatch.setattr(bs.stage5_validation, "validate_bundle", lambda text, quiet=False: result(
        bs.stage5_validation.INVALID if two in text else bs.stage5_validation.VALIDATED))
    _, summary, _ = _read(_malware(1), _malware(2, "Two"))
    assert [(e["id"], e["detail"]) for e in summary.excluded] == [(two, "")]


def test_one_refused_object_among_many_costs_about_two_validations_per_level(monkeypatch):
    objects = [_malware(n, f"Fine {n}") for n in range(1, 65)]
    objects[40] = _crashing(41)
    calls = _count_validations(monkeypatch)
    _, summary, _ = _read(*objects)
    assert list(_reasons(summary)) == [_id("malware", 41)]
    assert summary.excluded[0]["detail"].startswith("AttributeError")
    assert len(calls) <= 1 + 2 * 7                                # the bundle, then both halves at each level


def test_a_single_object_bundle_that_is_refused_is_the_culprit_without_a_search(monkeypatch):
    calls = _count_validations(monkeypatch)
    _, summary, _ = _read(_malware(1, lang="not a lang!"))
    assert list(_reasons(summary)) == [_id("malware", 1)] and calls == [1, 1]     # the bundle, then the object alone


def test_a_validator_is_called_once_on_a_valid_bundle(monkeypatch):
    calls = []
    real = bs.stage5_validation.validate_bundle
    monkeypatch.setattr(bs.stage5_validation, "validate_bundle",
                        lambda text, quiet=False: calls.append(text) or real(text, quiet=quiet))
    _read(_malware(1), _malware(2, "Other"), _malware(3, "Third"))
    assert len(calls) == 1


def test_without_validation_stix2_alone_parses_and_a_warning_says_the_schemas_were_not_checked(monkeypatch):
    monkeypatch.setattr(bs.stage5_validation, "validate_bundle",
                        lambda text, quiet=False: pytest.fail("no validation asked"))
    nameless = {k: v for k, v in _malware(3).items() if k != "name"}
    index, summary, _ = _read(_malware(1, lang="not a lang!"), _malware(2, "Fine"), nameless, validate=False)
    assert _reasons(summary) == {nameless["id"]: bs.INVALID}
    assert len(index.entries) == 2
    assert summary.warnings == [
        "the STIX schemas were not checked (validate=False): the objects were checked by the stix2 library only"]


def test_with_validation_asked_for_nothing_changes_and_the_schemas_run():
    _, summary, _ = _read(_malware(1, lang="not a lang!"), validate=True)
    assert list(_reasons(summary)) == [_id("malware", 1)] and summary.warnings == []


def test_the_fixtures_read_without_validation_give_the_same_index_as_with_it():
    for name in ("opencti_report.json", "misp_indicators_only.json", "rules.json", "refs_outside.json"):
        with_schemas = bs.intake(_fixture(name))
        without = bs.intake(_fixture(name), validate=False)
        assert without[0] == with_schemas[0]
        assert without[1].excluded == with_schemas[1].excluded
        assert without[1].warnings == [
            "the STIX schemas were not checked (validate=False): the objects were checked by the stix2 library only",
            *with_schemas[1].warnings]


# ── Intake: scope ───────────────────────────────────────────────────────────

def test_two_reports_without_a_choice_ask_for_one_in_a_preview():
    index, summary, parsed = bs.intake(_fixture("two_reports.json"), preview=True)
    assert index is None and summary.needs_report_choice and summary.scope_report_id is None
    assert [(r["name"], r["published"], r["refs"]) for r in summary.reports] == [
        ("Report A: APT29 and WellMess", "2026-03-01T00:00:00.000Z", 2),
        ("Report B: APT29 and SUNBURST", "2026-03-08T00:00:00.000Z", 2)]
    assert summary.counts["report"] == 2 and parsed["type"] == "bundle"


def test_two_reports_without_a_choice_are_an_error_at_job_creation():
    with pytest.raises(bs.BaselineError) as caught:
        bs.intake(_fixture("two_reports.json"))
    assert "report--daaf07ee-a8da-4ace-ae5b-0dde5deeb9ef" in str(caught.value)
    assert "report--bee50ac0-42cd-4813-98b3-02d6d948b618" in str(caught.value)


def test_a_long_list_of_reports_is_cut_in_the_message():
    reports = [_report(100 + i) for i in range(12)]
    with pytest.raises(bs.BaselineError, match="12 reports.*and 2 more"):
        _read(*reports)


def test_with_a_report_id_the_other_reports_own_object_is_out_of_scope_and_the_shared_one_is_in():
    report_a = "report--daaf07ee-a8da-4ace-ae5b-0dde5deeb9ef"
    index, summary, _ = bs.intake(_fixture("two_reports.json"), report_id=report_a)
    assert summary.scope_report_id == index.scope_report_id == "report--daaf07ee-a8da-4ace-ae5b-0dde5deeb9ef"
    values = {e.value for e in index.entries}
    assert values == {"APT29", "WellMess"}                     # SUNBURST belongs to report B only
    assert summary.counts == {"identity": 1, "intrusion-set": 1, "malware": 1, "report": 1,
                              "out_of_scope": 2, "dangling_refs": 0}
    assert not summary.needs_report_choice and summary.excluded == []
    assert [r["id"] for r in summary.reports] == [
        "report--daaf07ee-a8da-4ace-ae5b-0dde5deeb9ef", "report--bee50ac0-42cd-4813-98b3-02d6d948b618"]
    other = bs.intake(_fixture("two_reports.json"), report_id="report--bee50ac0-42cd-4813-98b3-02d6d948b618")[0]
    assert {e.value for e in other.entries} == {"APT29", "SUNBURST"}
    assert index.report_ids == ("report--daaf07ee-a8da-4ace-ae5b-0dde5deeb9ef",)


def test_a_report_id_that_is_no_report_of_the_bundle_is_refused():
    for kwargs in ({"report_id": "report--ffffffff-0000-4000-8000-000000000000"},
                   {"report_id": "malware--8af0aaa0-20fb-4ea7-ae68-7623644daae8"}):
        for preview in (False, True):
            with pytest.raises(bs.BaselineError, match="not a report"):
                bs.intake(_fixture("two_reports.json"), preview=preview, **kwargs)
    with pytest.raises(bs.BaselineError, match="not a report"):          # no report at all
        _read(_malware(1), report_id=_id("report", 1))
    with pytest.raises(bs.BaselineError, match="not a report"):          # one report, another id
        _read(_report(1), report_id=_id("report", 2))


def test_a_single_report_is_chosen_without_asking_and_with_its_own_id():
    for kwargs in ({}, {"report_id": _id("report", 1)}):
        _, summary, _ = _read(_report(1, _malware(1)), _malware(1), _malware(2, "Elsewhere"), **kwargs)
        assert summary.scope_report_id == _id("report", 1) and summary.counts["malware"] == 1
        assert summary.counts["out_of_scope"] == 1


def test_a_bundle_without_a_report_is_taken_whole():
    index, summary, _ = _read(_malware(1), _malware(2, "Other"))
    assert summary.scope_report_id is None and summary.reports == [] and index.scope_report_id is None
    assert index.report_ids == () and summary.counts["out_of_scope"] == 0


def test_the_scope_follows_references_at_any_depth():
    author = _obj("identity", 1, name="Author", identity_class="organization")
    a, b = _malware(1, "A", created_by_ref=author["id"]), _malware(2, "B")
    link = _rel(3, "related-to", a, b)
    note = _obj("note", 4, content="c", object_refs=[link["id"]])
    stray = _malware(5, "Stray")
    index, summary, _ = _read(_report(1, note), note, link, a, b, author, stray)
    assert index.imported_ids == {_id("report", 1), note["id"], link["id"], a["id"], b["id"], author["id"]}
    assert summary.counts["out_of_scope"] == 1


def test_a_relationship_between_two_objects_in_scope_is_in_scope_though_the_report_omits_it():
    """CTIParsor keeps ATT&CK and composed edges out of its Report: out of scope, a
    round trip rebuilt them under new ids (ADR-0090 lot 4)."""
    a, b, stray = _malware(1, "A"), _malware(2, "B"), _malware(3, "Stray")
    inside, outside = _rel(4, "related-to", a, b), _rel(5, "related-to", a, stray)
    index, summary, _ = _read(_report(1, a, b), a, b, stray, inside, outside)
    assert inside["id"] in index.imported_ids
    assert outside["id"] not in index.imported_ids and stray["id"] not in index.imported_ids
    assert summary.counts["out_of_scope"] == 2


def test_a_chosen_report_that_fails_validation_stops_the_intake():
    broken = {k: v for k, v in _report(1, _malware(1)).items() if k != "published"}
    with pytest.raises(bs.BaselineError, match="report--00000001.*MissingPropertiesError"):
        _read(broken, _malware(1))


def test_the_chosen_report_stays_when_what_it_lists_is_dropped():
    good, bad = _malware(1, "Good"), {k: v for k, v in _malware(2, "Bad").items() if k != "is_family"}
    report = _report(1, good, bad)
    index, summary, _ = _read(report, good, bad)
    assert _reasons(summary) == {bad["id"]: bs.INVALID}
    assert report["id"] in index.imported_ids and index.passthrough_ids == {report["id"]}
    assert summary.warnings == ["the chosen report references 1 excluded object(s), which will be left out"]


# ── Intake: rules ───────────────────────────────────────────────────────────

def test_the_refused_sigma_rule_is_excluded_and_the_other_rules_stay():
    index, summary, _ = bs.intake(_fixture("rules.json"))
    assert _reasons(summary) == {"indicator--0a2e05f8-31f1-48e7-badd-4106c485a811": bs.RULE_REFUSED}
    assert "condition" in summary.excluded[0]["detail"]
    assert len(index.imported_ids) == 3 and index.entries == [] and index.passthrough_ids == index.imported_ids


def test_a_yara_rule_that_does_not_compile_is_refused_as_it_is():
    broken = _indicator(1, "rule Broken { condition: unknown_identifier }", "yara")
    good = _indicator(2, 'rule Fine { strings: $a = "x" condition: $a }', "yara")
    _, summary, _ = _read(broken, good)
    assert _reasons(summary) == {broken["id"]: bs.RULE_REFUSED} and summary.warnings == []


def test_a_rule_whose_parser_is_missing_is_kept_with_a_warning_naming_the_library(monkeypatch):
    monkeypatch.setattr(bs.yara_check, "compile_status", lambda source: (bs.yara_check.UNVERIFIED, None))
    monkeypatch.setattr(bs.pattern_check, "check_pattern", lambda kind, rule: (bs.pattern_check.UNVERIFIED, None))
    rules = [_indicator(1, "r1", "yara"), _indicator(2, "r2", "yara"), _indicator(3, "r3", "sigma"),
             _indicator(4, "r4", "snort"), _indicator(5, "r5", "suricata")]
    index, summary, _ = _read(*rules)
    assert summary.excluded == [] and len(index.imported_ids) == 5
    assert summary.warnings == [
        "pysigma is not installed: 1 sigma rule(s) kept without a check, and OpenCTI may refuse them",
        "OpenCTI's Snort parser is not installed: 1 snort rule(s) kept without a check, and OpenCTI may refuse them",
        "parsuricata is not installed: 1 suricata rule(s) kept without a check, and OpenCTI may refuse them",
        "yara-python is not installed: 2 yara rule(s) kept without a check, and OpenCTI may refuse them"]


def test_a_stix_indicator_is_not_checked_as_a_rule(monkeypatch):
    monkeypatch.setattr(bs.pattern_check, "check_pattern", lambda *a: pytest.fail("a STIX pattern is no rule"))
    monkeypatch.setattr(bs.yara_check, "compile_status", lambda *a: pytest.fail("a STIX pattern is no rule"))
    assert _read(_indicator(1, "[ipv4-addr:value = '198.18.0.1']"))[1].excluded == []


# ── Intake: ids CTIParsor emits ─────────────────────────────────────────────

def test_an_identity_with_the_authors_id_and_another_name_is_a_collision_and_takes_its_referrers():
    author = json.loads(s4._authoring_identity().serialize())
    impostor = {**author, "name": "Somebody else", "identity_class": "organization"}
    victim = _malware(1, created_by_ref=author["id"])
    index, summary, _ = _read(impostor, victim)
    assert _reasons(summary) == {author["id"]: bs.ID_COLLISION, victim["id"]: bs.REFS_CLOSURE}
    assert index.imported_ids == frozenset()


def test_an_identity_with_the_authors_id_and_the_same_name_and_class_is_no_collision():
    author = json.loads(s4._authoring_identity().serialize())
    older_cti_parsor = {**author, "created": "2020-01-01T00:00:00.000Z", "modified": "2020-01-01T00:00:00.000Z",
                        "description": "Written by an earlier version."}
    index, summary, _ = _read(older_cti_parsor, _malware(1, created_by_ref=author["id"]))
    assert summary.excluded == [] and author["id"] in index.passthrough_ids
    assert [e.value for e in index.entries] == ["WellMess"]          # the author is no entry


def test_a_marking_with_a_known_id_and_another_level_is_a_collision():
    amber = json.loads(stix2.TLP_AMBER.serialize())
    red_at_amber = {**_named_marking(1, "TLP:RED"), "id": amber["id"]}
    pap = json.loads(s4._pap_marking("AMBER").serialize())
    red_pap = {**pap, "definition": {"statement": "PAP:RED"}}
    unreadable = {**pap, "id": s4._pap_marking("GREEN").id, "definition": {"statement": "something"}}
    _, summary, _ = _read(red_at_amber, red_pap, unreadable)
    assert _reasons(summary) == {amber["id"]: bs.ID_COLLISION, pap["id"]: bs.ID_COLLISION,
                                 unreadable["id"]: bs.ID_COLLISION}


def test_the_markings_ctiparsor_emits_come_back_unchanged():
    markings = [json.loads(m.serialize()) for m in (stix2.TLP_WHITE, stix2.TLP_GREEN, stix2.TLP_AMBER, stix2.TLP_RED,
                                                    s4.TLP_AMBER_STRICT, s4._pap_marking("AMBER"),
                                                    s4._pap_marking("WHITE"))]
    index, summary, _ = _read(*markings)
    assert summary.excluded == [] and len(index.imported_ids) == 7


# ── Intake: references the bundle does not hold ────────────────────────────

def test_the_references_outside_the_bundle_are_counted_and_warned_about_and_nothing_goes():
    index, summary, _ = bs.intake(_fixture("refs_outside.json"))
    assert summary.excluded == [] and len(index.imported_ids) == 3
    assert summary.counts["dangling_refs"] == 3
    dangling, marking = summary.warnings
    assert dangling.startswith("3 reference(s) point at ids the bundle does not hold, e.g. identity--162f1952")
    assert marking == ("marking marking-definition--59e2cafc-8007-4757-810f-73dc7a06c8b7 cannot be read: "
                       "not counted in the TLP/PAP minimum")


# ── Markings ────────────────────────────────────────────────────────────────

def _marked(*refs: str, n: int = 1) -> dict:
    return _malware(n, f"Marked {n}", object_marking_refs=list(refs))


def _named_marking(n: int, name: str, definition_type: str = "TLP") -> dict:
    """A marking the way OpenCTI exports it: definition_type, a name, no definition, its extension."""
    return _obj("marking-definition", n, name=name, definition_type=definition_type,
                extensions={OPENCTI_EXT: {"extension_type": "property-extension", "order": 1}})


def test_opencti_marks_tlp_by_name_and_the_minimum_reads_it():
    _, summary, _ = bs.intake(_fixture("opencti_report.json"))
    assert summary.min_tlp == "AMBER" and summary.min_pap is None


def test_the_misp_fixture_carries_the_standard_green_id():
    assert bs.intake(_fixture("misp_indicators_only.json"))[1].min_tlp == "GREEN"


def test_a_bundle_without_markings_has_no_minimum():
    _, summary, _ = bs.intake(_fixture("report_with_confidence.json"))
    assert (summary.min_tlp, summary.min_pap) == (None, None)


@pytest.mark.parametrize("marking, expected", [
    (stix2.TLP_WHITE, "CLEAR"), (stix2.TLP_GREEN, "GREEN"), (stix2.TLP_AMBER, "AMBER"), (stix2.TLP_RED, "RED"),
    (s4.TLP_AMBER_STRICT, "AMBER+STRICT"),
])
def test_the_three_forms_of_tlp_give_levels_in_the_vocabulary_of_stage_4(marking, expected):
    dicts = [json.loads(marking.serialize())]
    assert bs.intake(_bundle(*dicts, _marked(marking.id)))[1].min_tlp == expected
    assert s4.normalise_tlp(expected) == expected


@pytest.mark.parametrize("name, expected", [
    ("TLP:CLEAR", "CLEAR"), ("tlp:white", "CLEAR"), ("TLP:GREEN", "GREEN"), ("TLP:AMBER", "AMBER"),
    ("TLP:AMBER+STRICT", "AMBER+STRICT"), ("TLP:RED", "RED")])
def test_a_tlp_marking_known_by_its_name_only_is_read(name, expected):
    marking = _named_marking(7, name)
    assert bs.intake(_bundle(marking, _marked(marking["id"])))[1].min_tlp == expected


def test_the_minimum_is_the_most_restrictive_of_the_markings_the_imported_objects_carry():
    ids = [stix2.TLP_GREEN.id, stix2.TLP_WHITE.id, s4.TLP_AMBER_STRICT.id, stix2.TLP_AMBER.id]
    amber_strict = json.loads(s4.TLP_AMBER_STRICT.serialize())
    objects = [_marked(i, n=n) for n, i in enumerate(ids, 1)]
    assert bs.intake(_bundle(amber_strict, *objects))[1].min_tlp == "AMBER+STRICT"
    assert bs.intake(_bundle(_marked(stix2.TLP_WHITE.id), _marked(stix2.TLP_GREEN.id, n=2)))[1].min_tlp == "GREEN"
    assert bs.intake(_bundle(_marked(stix2.TLP_RED.id), _marked(s4.TLP_AMBER_STRICT.id, n=2),
                             json.loads(s4.TLP_AMBER_STRICT.serialize())))[1].min_tlp == "RED"


def test_an_object_that_is_not_imported_sets_no_minimum():
    red = _malware(2, "Red", object_marking_refs=[stix2.TLP_RED.id], **{"spec_version": "2.1"})
    _, summary, _ = _read(_report(1, _marked(stix2.TLP_GREEN.id)), _marked(stix2.TLP_GREEN.id), red)
    assert summary.min_tlp == "GREEN" and summary.counts["out_of_scope"] == 1


def test_pap_is_read_from_the_statement_and_from_the_name_in_the_vocabulary_of_stage_4():
    assert s4._pap_marking("WHITE") is not None
    for level in ("WHITE", "GREEN", "AMBER", "RED"):
        pap = json.loads(s4._pap_marking(level).serialize())
        assert bs.intake(_bundle(pap, _marked(pap["id"])))[1].min_pap == level
    named = _named_marking(8, "PAP:CLEAR", definition_type="PAP")
    assert bs.intake(_bundle(named, _marked(named["id"])))[1].min_pap == "WHITE"
    red = _named_marking(9, "pap:red", definition_type="PAP")
    green = json.loads(s4._pap_marking("GREEN").serialize())
    assert bs.intake(_bundle(red, green, _marked(green["id"], red["id"])))[1].min_pap == "RED"
    assert bs.intake(_bundle(red, _marked(red["id"], stix2.TLP_AMBER.id)))[1].min_tlp == "AMBER"


@pytest.mark.parametrize("marking", [
    {"definition_type": "statement", "definition": {"statement": "Copyright 2026"}},
    {"definition_type": "statement", "definition": {"statement": 7}},
    {"definition_type": "tlp", "definition": {"tlp": 7}},
    {"name": "TLP:PURPLE"}, {"name": 7}, {},
])
def test_a_marking_that_states_no_level_gives_none(marking):
    assert bs._marking_states(marking) == set()


def test_a_marking_states_its_level_by_its_definition():
    assert bs._marking_states({"definition_type": "tlp", "definition": {"tlp": "amber"}}) == {("tlp", "AMBER")}
    assert bs._marking_states({"definition": {"statement": " PAP:amber "}}) == {("pap", "AMBER")}
    assert bs._marking_states({"name": "PAP:CLEAR"}) == {("pap", "WHITE")}


def test_a_marking_the_bundle_does_not_define_and_a_ref_that_is_no_id_are_no_level():
    unknown = _marked(_id("marking-definition", 99), n=1)
    assert bs._most_restrictive([unknown], {}, []) == (None, None)
    assert bs._marking_refs({"object_marking_refs": "not a list"}) == []
    assert bs._marking_refs({"object_marking_refs": ["a", 7, None]}) == ["a"]
    assert bs._marking_refs({}) == []


# ── The index: entries ──────────────────────────────────────────────────────

def test_an_sco_with_its_indicator_and_based_on_is_one_entry():
    index = _baseline("opencti_report.json")
    ip = _entry(index, "ipv4-addr")
    assert (ip.entity_type, ip.value, ip.surface_forms) == ("ipv4", "198.18.12.77", ("198.18.12.77",))
    assert ip.sco_id == ip.entry_id == "ipv4-addr--dac4ca46-8fa0-52fb-94df-2a9acd2636bf"
    assert ip.indicator_ids == ("indicator--f838c643-e36c-4c0b-9389-1386738617b6",)
    assert ip.object_ids == (ip.sco_id, ip.indicator_ids[0], "relationship--fa5f98bc-0a81-4516-a4d7-cdf4bb46be3f")
    assert ip.keys == {("id", ip.sco_id), ("id", ip.indicator_ids[0]), ("obs", "ipv4-addr", "198.18.12.77")}
    assert [e.entity_type for e in index.entries] == ["ipv4", "sha256", "intrusion_set", "malware", "ttp"]


def test_the_based_on_inside_an_entry_is_no_relation():
    index = _baseline("opencti_report.json")
    assert [r.relationship_type for r in index.relations] == ["uses", "indicates"]
    assert "relationship--fa5f98bc-0a81-4516-a4d7-cdf4bb46be3f" not in {r.stix_id for r in index.relations}
    assert "relationship--fa5f98bc-0a81-4516-a4d7-cdf4bb46be3f" not in index.passthrough_ids


def test_a_relation_of_an_indicator_is_routed_to_its_iocs_entry():
    index = _baseline("opencti_report.json")
    ip, malware, actor = _entry(index, "ipv4-addr"), _entry(index, "malware"), _entry(index, "intrusion-set")
    indicates = [r for r in index.relations if r.relationship_type == "indicates"][0]
    assert indicates.source_ref == ip.indicator_ids[0] and indicates.source_entry == ip.entry_id
    assert indicates.target_entry == malware.entry_id
    uses = [r for r in index.relations if r.relationship_type == "uses"][0]
    assert (uses.source_entry, uses.target_entry) == (actor.entry_id, malware.entry_id)


def test_a_file_with_three_hashes_is_one_entry_found_by_each_of_them_and_its_name_is_weak():
    sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    loader = _sco("file", 1, name="Loader.DLL", hashes={"MD5": MD5, "SHA-1": sha1, "SHA-256": SHA256})
    index, _, _ = _read(loader)
    [entry] = index.entries
    assert (entry.entity_type, entry.value, entry.weak_keys) == ("sha256", SHA256, {("file_name", "loader.dll")})
    assert entry.surface_forms == (MD5, sha1, SHA256)
    for entity_type, value in (("md5", MD5), ("sha1", sha1), ("sha256", SHA256.upper())):
        assert index.lookup(bs.keys_for_row(entity_type, value)[0], "file") is entry
    assert index.lookup(bs.keys_for_row("sha256", "ab" * 32)[0], "file") is None


def test_a_file_known_by_a_weaker_hash_or_by_a_name_only():
    sha1_only = _sco("file", 1, hashes={"SHA-1": SHA1}, name="x")
    md5_only = _sco("file", 2, hashes={"MD5": MD5})
    named = _sco("file", 3, name="payload.bin")
    short = _sco("file", 4, name="ab")
    index, _, _ = _read(sha1_only, md5_only, named, short)
    assert [(e.entity_type, e.value) for e in index.entries] == [
        ("sha1", SHA1), ("md5", MD5), ("file", "payload.bin"), ("file", "ab")]
    assert [e.surface_forms for e in index.entries] == [(SHA1,), (MD5,), ("payload.bin",), ()]
    assert index.entries[2].keys == {("id", named["id"])}
    assert index.entries[2].weak_keys == {("file_name", "payload.bin")}


@pytest.mark.parametrize("sco, entity_type, value", [
    (_sco("ipv6-addr", 1, value="2001:0DB8::1"), "ipv6", "2001:0DB8::1"),
    (_sco("domain-name", 1, value="Evil.TEST"), "domain", "Evil.TEST"),
    (_sco("url", 1, value="http://evil.test/A"), "url", "http://evil.test/A"),
    (_sco("email-addr", 1, value="a@evil.test"), "email", "a@evil.test"),
    (_sco("mac-addr", 1, value="00:11:22:33:44:aa"), "mac_addr", "00:11:22:33:44:aa"),
    (_sco("autonomous-system", 1, number=64500), "asn", "AS64500"),
    (_sco("windows-registry-key", 1, key=r"HKEY_LOCAL_MACHINE\Software\Run"), "registry_key",
     r"HKEY_LOCAL_MACHINE\Software\Run"),
    (_sco("mutex", 1, name="FrostMtx"), "mutex", "FrostMtx"),
    (_sco("user-account", 1, user_id="svc_frost"), "user_account", "svc_frost"),
])
def test_every_recognised_sco_is_an_entry_of_the_entity_type_that_names_it(sco, entity_type, value):
    index, _, _ = _read(sco)
    [entry] = index.entries
    assert (entry.stix_type, entry.entity_type, entry.value) == (sco["type"], entity_type, value)
    expected = ("as64500", "as 64500") if entity_type == "asn" else (bs.normalize_value(entity_type, value),)
    assert entry.surface_forms == expected
    row_value = value if entity_type != "asn" else "64500"
    assert index.lookup(bs.keys_for_row(entity_type, row_value)[0], sco["type"]) is entry


def test_an_sco_without_a_value_or_that_is_not_modelled_is_copied():
    nameless, ip = _sco("mutex", 1, name=""), _sco("ipv4-addr", 3, value="198.18.0.1")
    traffic = _sco("network-traffic", 2, protocols=["tcp"], dst_ref=ip["id"])
    index, _, _ = _read(nameless, traffic, ip)
    assert [e.entry_id for e in index.entries] == [ip["id"]]
    assert index.passthrough_ids == {nameless["id"], traffic["id"]}


def test_an_indicator_alone_is_an_entry_of_the_type_it_states():
    index = _baseline("misp_indicators_only.json")
    hashes = [e for e in index.entries if e.entity_type == "sha256"][0]
    assert hashes.sco_id is None and hashes.entry_id == hashes.indicator_ids[0] == hashes.object_ids[0]
    assert (hashes.stix_type, hashes.value) == ("file", SHA256)
    assert hashes.keys >= {("hash", "MD5", MD5), ("hash", "SHA-256", SHA256), ("id", hashes.entry_id)}
    domain, url = [e for e in index.entries if e.stix_type in ("domain-name", "url")]
    assert (domain.entity_type, domain.value) == ("domain", "frostmail-cdn.test")
    assert (url.entity_type, url.value) == ("url", "http://frostmail-cdn.test/stage/payload.bin")
    assert domain.indicator_ids == url.indicator_ids == (domain.entry_id,)          # one Indicator, two entries
    assert url.entry_id == f"{domain.entry_id}#url"
    assert domain.keys.isdisjoint({k for k in url.keys if k[0] == "obs"})
    assert [e.entity_type for e in index.entries] == ["sha256", "domain", "url", "ipv4"]


def test_the_entries_of_one_indicator_follow_the_order_of_its_pattern():
    pattern = "[url:value = 'http://x.test/a' OR domain-name:value = 'x.test']"
    url, domain = _read(_indicator(1, pattern))[0].entries
    assert (url.stix_type, url.entity_type, url.value) == ("url", "url", "http://x.test/a")
    assert url.entry_id == _id("indicator", 1)
    assert (domain.stix_type, domain.entry_id) == ("domain-name", _id("indicator", 1) + "#domain-name")
    only = _read(_indicator(1, "[network-traffic:dst_port = 443 AND ipv4-addr:value = '198.18.0.1']"))[0].entries
    assert [(e.stix_type, e.value) for e in only] == [("ipv4-addr", "198.18.0.1")]
    asn = _read(_indicator(1, "[autonomous-system:number = 64500]"))[0].entries[0]
    assert (asn.entity_type, asn.value, asn.surface_forms) == ("asn", "AS64500", ("as64500", "as 64500"))


def test_an_indicator_of_a_file_name_alone_is_an_entry_with_a_weak_key_only():
    [entry] = _read(_indicator(1, "[file:name = 'Payload.EXE']"))[0].entries
    assert (entry.stix_type, entry.entity_type, entry.value) == ("file", "file", "payload.exe")
    assert entry.weak_keys == {("file_name", "payload.exe")} and entry.keys == {("id", _id("indicator", 1))}
    assert entry.surface_forms == ("payload.exe",)
    [short] = _read(_indicator(1, "[file:name = 'ab']"))[0].entries
    assert short.surface_forms == ()


def test_an_indicator_without_a_key_is_copied_as_it_is():
    index, _, _ = _read(_indicator(1, "[file:name MATCHES '^evil.*']"),
                        _indicator(2, "[ipv4-addr:value ISSUBSET '198.18.0.0/16']"),
                        _indicator(3, "[network-traffic:dst_port = 443]"), _indicator(4, "anything", "pcre"))
    assert index.entries == [] and len(index.passthrough_ids) == 4


def test_indicators_that_share_a_key_join_the_entry_of_that_key_and_bring_the_keys_of_its_type():
    ip = _sco("ipv4-addr", 1, value="198.18.0.1")
    first = _indicator(1, "[ipv4-addr:value = '198.18.0.1' OR domain-name:value = 'a.test']")
    second = _indicator(2, "[domain-name:value = 'a.test']")
    third = _indicator(3, "[domain-name:value = 'a.test' AND file:name = 'x.exe']")
    index, _, _ = _read(ip, first, second, third)
    address, domain, file_entry = index.entries
    assert address.entry_id == ip["id"] and address.indicator_ids == (first["id"],)
    assert address.keys == {("id", ip["id"]), ("id", first["id"]), ("obs", "ipv4-addr", "198.18.0.1")}
    assert domain.entry_id == first["id"] and domain.indicator_ids == (first["id"], second["id"], third["id"])
    assert domain.keys == {("id", first["id"]), ("id", second["id"]), ("id", third["id"]),
                           ("obs", "domain-name", "a.test")}
    assert domain.surface_forms == ("a.test",) and address.surface_forms == ("198.18.0.1",)
    assert (file_entry.stix_type, file_entry.entry_id) == ("file", third["id"])
    assert file_entry.weak_keys == {("file_name", "x.exe")} and file_entry.keys == {("id", third["id"])}


def test_an_indicator_of_two_types_joins_the_entry_of_each_with_its_own_based_on():
    domain, url = _sco("domain-name", 1, value="x.test"), _sco("url", 2, value="http://x.test/a")
    indicator = _indicator(1, "[domain-name:value = 'x.test'] AND [url:value = 'http://x.test/a']")
    to_domain, to_url = _rel(5, "based-on", indicator, domain), _rel(6, "based-on", indicator, url)
    indicates = _rel(7, "indicates", indicator, _malware(1))
    index, _, _ = _read(domain, url, indicator, to_domain, to_url, indicates, _malware(1))
    first, second, _ = index.entries
    assert first.indicator_ids == second.indicator_ids == (indicator["id"],)
    assert first.object_ids == (domain["id"], indicator["id"], to_domain["id"])
    assert second.object_ids == (url["id"], indicator["id"], to_url["id"])
    assert [r.relationship_type for r in index.relations] == ["indicates"]
    assert index.relations[0].source_entry == first.entry_id           # the first entry of the pattern


def test_named_sdos_are_entries_with_their_mitre_id_and_forms():
    index = _baseline("opencti_report.json")
    actor = _entry(index, "intrusion-set")
    assert (actor.entity_type, actor.value, actor.mitre_id) == ("intrusion_set", "APT29", "G0016")
    assert actor.surface_forms == ("apt29", "cozy bear", "the dukes", "nobelium")
    assert ("named", "actor", "cozy bear") in actor.keys and ("mitre", "G0016") in actor.keys
    technique = _entry(index, "attack-pattern")
    assert (technique.entity_type, technique.mitre_id, technique.surface_forms) == ("ttp", "T1059.001", ("powershell",))
    assert _entry(index, "malware").mitre_id == "S0514"
    assert _entry(_read(_malware(1, "ZzMalware"))[0], "malware").mitre_id is None


def test_a_short_name_is_no_surface_form_and_a_duplicate_is_said_once():
    index, _, _ = _read(_malware(1, "Ab", aliases=["Ab", "Frost Ab", "AB", "Fr", "Cde"]))
    assert index.entries[0].surface_forms == ("frost ab", "cde")


def test_the_author_and_a_system_identity_are_no_entry_but_a_sector_and_a_victim_are():
    author = _obj("identity", 1, name="Author", identity_class="organization")
    system = _obj("identity", 2, name="A system", identity_class="system")
    sector = _obj("identity", 3, name="Financial Services", identity_class="class")
    victim = _obj("identity", 4, name="Acme Bank", identity_class="organization")
    index, _, _ = _read(author, system, sector, victim, _malware(1, created_by_ref=author["id"]))
    assert [e.value for e in index.entries] == ["Financial Services", "Acme Bank", "WellMess"]
    assert {author["id"], system["id"]} <= index.passthrough_ids
    assert index.lookup(bs.keys_for_row("identity", "financial  services")[0], "identity").value == "Financial Services"


def test_the_other_named_types_and_a_vulnerability_a_location_and_a_campaign():
    vulnerability = _obj("vulnerability", 1, name="CVE-2024-12345")
    france = _obj("location", 2, name="France", country="fr")
    nowhere = _obj("location", 3, region="europe")
    campaign = _obj("campaign", 4, name="Frost run", aliases=["Operation Frost"])
    infra = _obj("infrastructure", 5, name="Frost infra")
    incident = _obj("incident", 6, name="Frost incident")
    tool = _obj("tool", 7, name="Mimikatz")
    index, _, _ = _read(vulnerability, france, nowhere, campaign, infra, incident, tool)
    assert [(e.entity_type, e.value) for e in index.entries] == [
        ("cve", "CVE-2024-12345"), ("location", "France"), ("campaign", "Frost run"), ("infrastructure", "Frost infra"),
        ("incident", "Frost incident"), ("tool", "Mimikatz")]
    assert index.passthrough_ids == {nowhere["id"]}
    assert index.lookup(bs.keys_for_row("cve", "cve-2024-12345")[0], "vulnerability").value == "CVE-2024-12345"
    assert index.lookup(bs.keys_for_row("location", "France")[0], "location").value == "France"
    assert index.lookup(bs.keys_for_row("campaign", "operation frost")[0], "campaign").value == "Frost run"
    assert _entry(index, "tool").mitre_id == "S0002"
    only_a_country = _read(_obj("location", 8, country="de"))[0].entries[0]
    assert (only_a_country.value, only_a_country.surface_forms) == ("DE", ())


def test_unknown_and_unmodelled_types_are_copied():
    custom = {"type": "x-frost-note", "spec_version": "2.1", "id": _id("x-frost-note", 1),
              "created": TS, "modified": TS}
    note = _obj("note", 2, content="c", object_refs=[_id("malware", 1)])
    sighting = _obj("sighting", 3, sighting_of_ref=_id("malware", 1))
    index, summary, _ = _read(custom, note, sighting, _malware(1))
    assert index.passthrough_ids == {custom["id"], note["id"], sighting["id"]}
    assert summary.counts["x-frost-note"] == 1


def test_a_relationship_to_something_that_is_no_entry_has_no_entry_on_that_side():
    malware = _malware(1)
    note = _obj("note", 2, content="c", object_refs=[malware["id"]])
    absent = _id("tool", 9)
    to_note = _obj("relationship", 3, relationship_type="related-to", source_ref=malware["id"], target_ref=note["id"])
    dangling = _obj("relationship", 4, relationship_type="uses", source_ref=absent, target_ref=malware["id"])
    index, summary, _ = _read(malware, note, to_note, dangling)
    assert [(r.source_entry, r.target_entry) for r in index.relations] == [(malware["id"], None), (None, malware["id"])]
    assert summary.counts["dangling_refs"] == 1


def test_a_based_on_that_joins_nothing_is_a_relation():
    ip = _sco("ipv4-addr", 1, value="198.18.0.1")
    stray = _indicator(1, "[file:name MATCHES 'x']")
    index, _, _ = _read(ip, stray, _rel(2, "based-on", stray, ip))
    assert [r.relationship_type for r in index.relations] == ["based-on"]
    assert index.relations[0].source_entry is None and index.relations[0].target_entry == ip["id"]


@pytest.mark.parametrize("name", sorted(p.name for p in BASELINES.glob("*.json") if p.name != "stix20.json"))
def test_every_imported_object_is_in_one_entry_one_relation_or_the_passthrough(name):
    kwargs = {"report_id": "report--daaf07ee-a8da-4ace-ae5b-0dde5deeb9ef"} if name == "two_reports.json" else {}
    index, summary, _ = bs.intake(_fixture(name), **kwargs)
    in_entries = [oid for e in index.entries for oid in e.object_ids]
    parts = [in_entries, [r.stix_id for r in index.relations], sorted(index.passthrough_ids)]
    assert set(sum(parts, [])) == set(index.imported_ids)
    # only an Indicator of several observable types is in more than one place
    repeated = {oid for oid, n in Counter(sum(parts, [])).items() if n > 1}
    assert all(oid.startswith("indicator--") for oid in repeated)
    assert sum(summary.counts.values()) - summary.counts["out_of_scope"] - summary.counts["dangling_refs"] == \
        len(index.imported_ids)


# ── The index: lookup ───────────────────────────────────────────────────────

def test_a_cozy_bear_row_finds_the_intrusion_set_and_the_hash_row_finds_the_file():
    index = _baseline("opencti_report.json")
    actor = _entry(index, "intrusion-set")
    assert index.lookup(bs.keys_for_row("threat_actor", "Cozy Bear")[0], "threat-actor") is actor
    assert index.lookup(bs.keys_for_row("threat_actor", "Cozy Bear")[0]) is actor
    assert index.lookup(bs.keys_for_row("intrusion_set", "NOBELIUM")[0], "intrusion-set") is actor
    assert index.lookup(bs.keys_for_row("sha256", SHA256)[0], "file") is _entry(index, "file")
    assert index.lookup(bs.keys_for_row("md5", MD5)[0], "file") is _entry(index, "file")
    assert index.lookup(bs.keys_for_row("ipv4", "198.18.12[.]77")[0], "ipv4-addr") is _entry(index, "ipv4-addr")
    assert index.lookup(bs.keys_for_row("ttp", "PowerShell", "T1059.001")[0], "attack-pattern") is \
        _entry(index, "attack-pattern")
    assert index.lookup(bs.keys_for_row("malware", "SUNBURST")[0], "malware") is None


def test_a_file_name_alone_matches_nothing_and_neither_does_a_name_of_another_family():
    index = _baseline("opencti_report.json")
    assert index.lookup({("file_name", "svchost_update.dll")}, "file") is None
    assert index.lookup(bs.keys_for_row("file", "svchost_update.dll")[0], "file") is None
    assert index.lookup(bs.keys_for_row("malware", "APT29")[0], "malware") is None


def test_an_actor_and_an_intrusion_set_of_one_name_are_told_apart_by_the_exact_type():
    actor, group = _obj("threat-actor", 1, name="APT29", threat_actor_types=["nation-state"]), \
        _obj("intrusion-set", 2, name="APT29")
    index, _, _ = _read(actor, group)
    row = bs.keys_for_row("intrusion_set", "APT29")[0]
    assert index.lookup(row, "intrusion-set").entry_id == group["id"]
    assert index.lookup(row, "threat-actor").entry_id == actor["id"]
    assert index.lookup({("named", "actor", "apt29")}, "campaign") is None        # a name of another family
    assert index.lookup({("mitre", "G0016")}, "campaign") is bs.AMBIGUOUS         # a strong key crosses families
    assert index.lookup(row) is bs.AMBIGUOUS
    assert index.lookup(bs.keys_for_row("malware", "APT29")[0], "malware") is None


def test_a_capec_pattern_in_the_baseline_meets_a_row_with_a_capec_id():
    pattern = _obj("attack-pattern", 1, name="Frost injection",
                   external_references=[{"source_name": "capec", "external_id": "CAPEC-123"}])
    index, _, _ = _read(pattern)
    row = bs.keys_for_row("ttp", "Something CTIParsor named otherwise", mitre_id="CAPEC-123")[0]
    assert index.lookup(row, "attack-pattern").entry_id == pattern["id"]


def test_a_ctiparsor_bundle_given_back_is_found_by_ids():
    bundle = s4.build_stix_bundle([RawEntity(value="198.18.0.1", entity_type=EntityType.IPV4),
                                   RawEntity(value="FrostCampaign", entity_type=EntityType.CAMPAIGN)],
                                  LLMEnrichmentResult(malware_families=["ZzMalware"]), "r", report_text="198.18.0.1")
    index, summary, _ = bs.intake(bundle.serialize().encode())
    assert summary.excluded == [] and summary.warnings == [] and summary.min_tlp in s4.TLP_LEVELS
    assert {e.value for e in index.entries} >= {"198.18.0.1", "FrostCampaign", "ZzMalware"}
    for obj in bundle.objects:
        if obj["type"] in ("ipv4-addr", "campaign", "malware"):
            found = index.lookup(bs.keys_for_object(obj)[0], obj["type"])
            assert found is not None and found.entry_id == obj["id"]
    assert index.report_ids == (next(o["id"] for o in bundle.objects if o["type"] == "report"),)


def test_the_lookup_map_is_built_once_and_is_not_part_of_the_index():
    index = _baseline("opencti_report.json")
    twin = bs.BaselineIndex.from_json(index.to_json())
    assert index._by_key is None
    index.lookup({("cve", "CVE-2024-1")})
    built = index._by_key
    index.lookup({("cve", "CVE-2024-1")})
    assert index._by_key is built and index == twin and "_by_key" not in index.to_json()


# ── JSON ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", sorted(p.name for p in BASELINES.glob("*.json") if p.name != "stix20.json"))
def test_the_index_of_every_valid_fixture_survives_json(name):
    kwargs = {"report_id": "report--bee50ac0-42cd-4813-98b3-02d6d948b618"} if name == "two_reports.json" else {}
    index, summary, _ = bs.intake(_fixture(name), **kwargs)
    again = bs.BaselineIndex.from_json(index.to_json())
    assert again == index and isinstance(again.entries, list) and isinstance(again.imported_ids, frozenset)
    assert all(isinstance(e.keys, frozenset) and isinstance(e.object_ids, tuple) for e in again.entries)
    assert again.to_json() == index.to_json()
    assert bs.Intake(**json.loads(json.dumps(dataclasses.asdict(summary)))) == summary


def test_the_json_of_an_index_is_stable_and_sorted():
    index = _baseline("opencti_report.json")
    data = json.loads(index.to_json())
    assert data["version"] == bs.INDEX_VERSION and data["imported_ids"] == sorted(data["imported_ids"])
    assert data["entries"][0]["keys"] == sorted(data["entries"][0]["keys"])
    assert index.to_json() == bs.BaselineIndex.from_json(index.to_json()).to_json()


def test_an_index_of_another_version_is_refused():
    data = json.loads(_baseline("opencti_report.json").to_json())
    data["version"] = bs.INDEX_VERSION + 1
    with pytest.raises(bs.BaselineError, match="version"):
        bs.BaselineIndex.from_json(json.dumps(data))


@pytest.mark.parametrize("raw", ["", "not json", "[]", "{}", '{"version": 1}',
                                 json.dumps({"version": 1, "sha256": "x"})])
def test_what_is_no_index_is_refused(raw):
    with pytest.raises(bs.BaselineError):
        bs.BaselineIndex.from_json(raw)


def test_an_index_with_a_broken_entry_is_refused():
    data = json.loads(_baseline("opencti_report.json").to_json())
    del data["entries"][0]["keys"]
    with pytest.raises(bs.BaselineError, match="not a baseline index"):
        bs.BaselineIndex.from_json(json.dumps(data))


def test_entries_and_relations_compare_by_value_and_are_frozen():
    index = _baseline("opencti_report.json")
    twin = _baseline("opencti_report.json")
    assert index == twin and index.entries[0] == twin.entries[0] and index.relations[0] == twin.relations[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        index.entries[0].value = "other"                       # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        index.relations[0].stix_id = "other"                   # type: ignore[misc]


# ── The contract the fuzz target relies on ──────────────────────────────────

def test_deeply_nested_json_is_a_baseline_error():
    with pytest.raises(bs.BaselineError):
        bs.intake(b"[" * 100_000 + b"]" * 100_000)


def test_a_recursion_error_after_the_json_is_read_is_a_baseline_error(monkeypatch):
    def too_deep(*args, **kwargs):
        raise RecursionError
    monkeypatch.setattr(bs, "_build_index", too_deep)
    with pytest.raises(bs.BaselineError, match="nested too deeply"):
        _read(_malware(1))


def test_an_object_stix2_cannot_read_for_its_depth_is_excluded_and_the_others_stay(monkeypatch):
    terms = " OR ".join(f"ipv4-addr:value = '198.18.{i // 250}.{i % 250}'" for i in range(1200))
    deep = _indicator(1, f"[{terms}]")
    index, summary, _ = _read(deep, _malware(2), validate=False)
    assert [(e["id"], e["reason"], e["detail"]) for e in summary.excluded] == [
        (deep["id"], bs.INVALID, "pattern too long or too deeply nested to read")]
    assert [e.value for e in index.entries] == ["WellMess"]

    def too_deep(obj, **kwargs):
        raise RecursionError
    monkeypatch.setattr(bs.stix2, "parse", too_deep)
    _, summary, _ = _read(_malware(1), _malware(2, "Other"), validate=False)
    assert [e["detail"] for e in summary.excluded] == ["too deeply nested to read"] * 2


def test_a_recursion_error_in_the_validator_excludes_the_object_it_comes_from(monkeypatch):
    def too_deep(text, quiet=False):
        raise RecursionError
    monkeypatch.setattr(bs.stage5_validation, "validate_bundle", too_deep)
    index, summary, _ = _read(_malware(1))
    assert [(e["reason"], e["detail"]) for e in summary.excluded] == [(bs.INVALID, "too deeply nested to read")]
    assert index.entries == []


def _nest(depth: int) -> dict:
    node: dict = {"leaf": 1}
    for _ in range(depth):
        node = {"child": node}
    return node


@pytest.mark.parametrize("depth", [50, 400, 900, 990])
def test_a_deep_object_is_read_or_refused_with_a_baseline_error(depth):
    try:
        index, _, _ = _read(_malware(1, x_deep=_nest(depth)), _malware(2, "Other"))
    except bs.BaselineError:
        return
    assert index is not None


_WEIRD = [None, 7, -1, 1.5, True, [], {}, [1, "a"], {"a": [1]}, "", " ", "x" * 50, [_id("identity", 1)],
          "2020-13-45", "[ipv4-addr:value = '1.1.1.1']", float("nan")]


def _paths(node, prefix=()):
    yield prefix
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _paths(value, prefix + (key,))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _paths(value, prefix + (i,))


def _mutate(document: dict, rng: random.Random) -> dict:
    document = copy.deepcopy(document)
    for _ in range(rng.randint(1, 4)):
        path = rng.choice([p for p in _paths(document) if p])
        parent = document
        for step in path[:-1]:
            parent = parent[step]
        roll = rng.random()
        if roll < 0.25:
            parent.pop(path[-1])
        elif roll < 0.9:
            parent[path[-1]] = rng.choice(_WEIRD)
        else:
            donor = document
            for step in rng.choice(list(_paths(document))):
                donor = donor[step]
            parent[path[-1]] = copy.deepcopy(donor)
    return document


def test_a_mutated_fixture_is_read_or_refused_with_a_baseline_error_and_nothing_else():
    rng = random.Random(20261024)
    documents = [json.loads((BASELINES / name).read_text(encoding="utf-8"))
                 for name in sorted(p.name for p in BASELINES.glob("*.json"))]
    for i in range(30):
        try:
            raw = json.dumps(_mutate(rng.choice(documents), rng)).encode()
        except (ValueError, RecursionError):
            continue
        try:
            index, summary, _ = bs.intake(raw, preview=bool(i % 2))
        except bs.BaselineError:
            continue
        for excluded in summary.excluded:
            assert set(excluded) == {"id", "type", "reason", "detail"}
            assert all(isinstance(v, str) for v in excluded.values())
        if index is None:
            assert summary.needs_report_choice
        else:
            assert not summary.needs_report_choice
            assert bs.BaselineIndex.from_json(index.to_json()) == index


# ── Review: hostile input ───────────────────────────────────────────────────

_HOSTILE = [[], {}, 7, 1.5, None, True, "x" * 3000, [[[]]], "\u0000", "\ud800", "-" * 20000 + " ",
            ["a", 1, None, {"b": []}]]


def _hostile_cases():
    for path in sorted(BASELINES.glob("*.json")):
        if path.name == "stix20.json":
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        for i, obj in enumerate(document["objects"]):
            for key in obj:
                for value in _HOSTILE:
                    objects = [*document["objects"][:i], {**obj, key: value}, *document["objects"][i + 1:]]
                    yield json.dumps({**document, "objects": objects}).encode()


def test_no_top_level_field_of_a_fixture_object_makes_intake_raise_anything_but_baseline_error():
    for raw in _hostile_cases():
        try:
            bs.intake(raw, preview=True, validate=False)
        except bs.BaselineError:
            pass


def test_a_sample_of_the_same_sweep_with_the_schemas_on():
    for raw in list(_hostile_cases())[::233]:
        try:
            bs.intake(raw, preview=True)
        except bs.BaselineError:
            pass


@pytest.mark.parametrize("value", [["identity--7b24b13f-17ba-4194-b6ae-4b1d3423bf15"], {"a": 1}, 7, None])
def test_an_unknown_type_with_a_created_by_ref_that_is_no_id_is_copied(value):
    custom = {"type": "x-frost", "spec_version": "2.1", "id": _id("x-frost", 1), "created": TS, "modified": TS,
              "created_by_ref": value, "object_marking_refs": value, "granular_markings": value}
    index, _, _ = _read(custom, _obj("identity", 2, name="Someone", identity_class="organization"), validate=False)
    assert custom["id"] in index.passthrough_ids and [e.value for e in index.entries] == ["Someone"]


def test_a_reference_string_of_a_million_characters_is_handled():
    hostile = "a" + "-" * 1_000_000 + " "
    long_type = "a" * 1_000_000 + "--x"
    ok = "malware--" + "b" * 1_000_000
    refs = list(bs.iter_refs({"x_ref": hostile, "y_refs": [hostile, long_type, ok, "x--y z"]}))
    assert refs == [long_type, ok] or sorted(refs) == sorted([long_type, ok])


def test_the_reference_check_is_the_pattern_it_replaced_on_every_small_case():
    old = re.compile(r"[a-z][a-z0-9-]*--\S+")
    for text in ["", "a", "a--", "--x", "a--b", "A--b", "1a--b", "a-b--c", "a---b", "a--b--c", "a--b c", "a-- b",
                 "a --b", "a-- ", "a--é", "é--a", "malware--0f", "x_y--z", "a--b\n", "a\n--b"]:
        assert bs._is_ref_id(text) == bool(old.fullmatch(text)), repr(text)


def test_a_json_with_more_objects_than_the_guard_is_refused_before_it_is_read_whole(monkeypatch):
    monkeypatch.setattr(bs, "_MAX_JSON_OBJECTS", 5)
    with pytest.raises(bs.BaselineError, match="more than 5 JSON objects"):
        bs.intake(json.dumps({"type": "bundle", "objects": [{"a": {}}] * 4}).encode())


def test_the_ids_types_and_names_quoted_back_are_cut():
    long_id = "malware--" + "z" * 1000
    _, summary, _ = _read(_malware(1), {**_malware(2), "id": long_id}, {**_malware(3), "type": "t" * 1000})
    assert all(len(e["id"]) <= 201 and len(e["type"]) <= 201 for e in summary.excluded) and len(summary.excluded) == 2
    reports = [{**_report(1), "name": "n" * 1000}, _report(2)]
    _, summary, _ = bs.intake(_bundle(*reports), preview=True)
    assert len(summary.reports[0]["name"]) <= 201
    with pytest.raises(bs.BaselineError) as caught:
        _read(_report(1), report_id="r" * 1000)
    assert len(str(caught.value)) < 300


# ── Review: the search for what the schemas refuse is bounded ──────────────

def test_objects_the_validator_falls_over_on_stop_the_search_with_a_clear_refusal():
    bad = [_crashing(n, f"Bad {n}") for n in range(1, 61)]
    with pytest.raises(bs.BaselineError,
                       match="too many objects fail the STIX schemas to locate them.*bytes validated.*fix the bundle"):
        _read(*bad)


def test_two_hundred_objects_that_fail_by_name_are_all_listed_and_never_refused():
    bad = [_malware(n, f"Bad {n}", lang="not a lang!") for n in range(1, 201)]
    _, summary, _ = _read(*bad, _malware(500, "Fine"))
    assert len(summary.excluded) == 200 and summary.warnings == []


def test_the_budget_is_a_constant_of_the_module(monkeypatch):
    objects = [_malware(n, f"Fine {n}") for n in range(1, 17)]
    objects[3] = _crashing(4)
    assert list(_reasons(_read(*objects)[1])) == [_id("malware", 4)]
    monkeypatch.setattr(bs, "_VALIDATION_BUDGET_FACTOR", 1)
    with pytest.raises(bs.BaselineError, match="too many objects"):
        _read(*objects)


def test_one_culprit_among_ten_thousand_objects_is_within_the_budget(monkeypatch):
    objects = [{"id": f"x--{n}"} for n in range(10_000)]
    checked = []

    def validate(batch):
        checked.append(len(batch))
        bad = any(o["id"] == "x--4242" for o in batch)
        return bs.stage5_validation.ValidationResult(bs.stage5_validation.INVALID if bad else "validated", ["bad"])
    monkeypatch.setattr(bs, "_validate", validate)
    assert bs._schema_failures(objects, []) == [({"id": "x--4242"}, "bad")]
    assert 2.9 * len(objects) < sum(checked) < 3 * len(objects) + 30


# ── Review: locations, compound patterns, forms ────────────────────────────

@pytest.mark.parametrize("prop, value", [
    ("city", "Paris"), ("administrative_area", "FR-75"), ("street_address", "1 rue X"), ("postal_code", "75001"),
    ("latitude", 0.0), ("longitude", 48.8)])
def test_a_location_finer_than_a_country_has_no_iso_key(prop, value):
    obj = {"type": "location", "name": "France", "country": "FR", prop: value}
    strong, _ = bs.keys_for_object(obj)
    assert not [k for k in strong if k[0] == "loc"] and ("named", "location", "france") in strong
    assert ("loc", "FR") in bs.keys_for_object({"type": "location", "name": "France", "country": "FR", prop: ""})[0]


def test_a_france_row_finds_the_country_and_not_paris():
    paris = _obj("location", 1, name="Paris", country="FR", city="Paris")
    france = _obj("location", 2, name="France", country="FR")
    index, _, _ = _read(paris, france)
    in_paris, in_france = index.entries
    assert ("loc", "FR") not in in_paris.keys and ("loc", "FR") in in_france.keys
    assert index.lookup(bs.keys_for_row("location", "France")[0], "location") is in_france
    assert index.lookup(bs.keys_for_row("location", "Paris")[0], "location") is in_paris


def test_a_domain_of_a_compound_pattern_is_not_the_ip_address_beside_it():
    ip = _sco("ipv4-addr", 1, value="1.2.3.4")
    both = _indicator(1, "[ipv4-addr:value = '1.2.3.4' AND domain-name:value = 'x.test']")
    just_the_domain = _indicator(2, "[domain-name:value = 'x.test']")
    index, _, _ = _read(ip, both, just_the_domain)
    address, domain = index.entries
    assert address.keys == {("id", ip["id"]), ("id", both["id"]), ("obs", "ipv4-addr", "1.2.3.4")}
    assert domain.keys == {("id", both["id"]), ("id", just_the_domain["id"]), ("obs", "domain-name", "x.test")}
    assert (domain.stix_type, domain.indicator_ids) == ("domain-name", (both["id"], just_the_domain["id"]))
    row = bs.keys_for_row("domain", "x.test")[0]
    assert index.lookup(row, "domain-name") is domain and index.lookup(row) is domain
    assert index.lookup(bs.keys_for_row("ipv4", "1.2.3.4")[0], "ipv4-addr") is address
    assert index.lookup(bs.keys_for_row("ipv4", "1.2.3.4")[0]) is address


def test_an_observable_key_only_designates_an_entry_of_its_own_type():
    wrong = bs.Entry("e", "ipv4-addr", "ipv4", "1.2.3.4", None, frozenset({("obs", "domain-name", "x.test"),
                                                                           ("hash", "MD5", "aa")}), frozenset())
    index = bs.BaselineIndex(bs.INDEX_VERSION, "s", "b", [wrong], [], frozenset(), frozenset(), ())
    assert index.lookup({("obs", "domain-name", "x.test")}, None) is None
    assert index.lookup({("hash", "MD5", "aa")}, None) is None
    right = dataclasses.replace(wrong, stix_type="file", keys=frozenset({("hash", "MD5", "aa")}))
    index = bs.BaselineIndex(bs.INDEX_VERSION, "s", "b", [right], [], frozenset(), frozenset(), ())
    assert index.lookup({("hash", "MD5", "aa")}, None) is right


def test_a_thousand_indicators_on_one_address_make_one_entry_without_repeated_forms():
    ip = _sco("ipv4-addr", 1, value="198.18.0.1")
    indicators = [_indicator(n, "[ipv4-addr:value = '198.18.0.1']") for n in range(1, 2001)]
    index, _, _ = _read(ip, *indicators, validate=False)
    [entry] = index.entries
    assert len(entry.indicator_ids) == len(set(entry.indicator_ids)) == 2000
    assert entry.surface_forms == ("198.18.0.1",) and len(entry.keys) == 2002


def test_a_form_shorter_than_three_characters_is_never_a_surface_form_and_an_asn_is_written_as_an_asn():
    short = _sco("mutex", 1, name="ab")
    asn = _sco("autonomous-system", 2, number=7)
    index, _, _ = _read(short, asn, _obj("campaign", 3, name="Q", aliases=["Quux"]))
    assert [e.surface_forms for e in index.entries] == [(), ("as7", "as 7"), ("quux",)]
    assert bs._forms_of({("obs", "autonomous-system", "64500"), ("hash", "MD5", "ab")}) == ["ab", "as64500", "as 64500"]


def test_ambiguous_is_falsy_and_is_told_by_identity():
    assert not bs.AMBIGUOUS and bs.AMBIGUOUS is not None
    assert [x for x in (None, bs.AMBIGUOUS) if x is bs.AMBIGUOUS] == [bs.AMBIGUOUS]


# ── Review: markings ───────────────────────────────────────────────────────

@pytest.mark.parametrize("name, expected", [
    ("TLP: AMBER+STRICT", "AMBER+STRICT"), ("TLP:AMBER STRICT", "AMBER+STRICT"), ("tlp:amber+strict", "AMBER+STRICT"),
    ("TLP:Amber Strict", "AMBER+STRICT"), (" TLP : GREEN ", "GREEN"), ("TLP:AMBER", "AMBER"), ("TLP:WHITE", "CLEAR"),
    ("TLP\tCLEAR", None), ("TLP:AMBER+STRICTLY", None),
])
def test_a_tlp_name_is_read_tolerantly(name, expected):
    states = bs._marking_states({"name": name})
    assert states == ({("tlp", expected)} if expected else set())


def test_a_long_text_states_no_level_and_is_not_squeezed():
    assert bs._level_in("TLP:AMBER" + " " * 10_000) is None
    assert bs._level_in(7) is None


def test_the_most_restrictive_reading_of_a_marking_wins_not_the_first():
    assert bs._marking_states({"name": "TLP:GREEN", "definition": {"tlp": "red"}}) == {("tlp", "RED")}
    assert bs._marking_states({"name": "TLP:RED", "definition": {"tlp": "green", "statement": "TLP:AMBER"}}) == \
        {("tlp", "RED")}
    assert bs._marking_states({"name": "PAP:RED", "definition": {"statement": "PAP:GREEN"}}) == {("pap", "RED")}
    both = bs._marking_states({"name": "TLP:GREEN", "definition": {"statement": "PAP:AMBER"}})
    assert both == {("tlp", "GREEN"), ("pap", "AMBER")}


def test_the_forms_opencti_really_exports_are_read():
    assert bs._marking_states({"definition_type": "tlp", "name": "TLP:AMBER+STRICT",
                               "definition": {"tlp": "amber+strict"}}) == {("tlp", "AMBER+STRICT")}
    assert bs._marking_states({"definition_type": "pap", "name": "PAP:AMBER",
                               "definition": {"pap": "pap:amber"}}) == {("pap", "AMBER")}
    assert bs._marking_states({"definition_type": "pap", "definition": {"pap": "green"}}) == {("pap", "GREEN")}
    assert bs._marking_states({"definition_type": "statement", "definition": {"statement": "PAP:WHITE"}}) == \
        {("pap", "WHITE")}


def test_the_tlp_2_0_extension_is_read():
    marking = _obj("marking-definition", 1, name="Whatever", extensions={
        "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
            "extension_type": "property-extension", "tlp_2_0": "amber+strict"}})
    assert bs._marking_states(marking) == {("tlp", "AMBER+STRICT")}
    _, summary, _ = _read(marking, _marked(marking["id"]))
    assert summary.min_tlp == "AMBER+STRICT" and summary.warnings == []
    assert bs._marking_states({"extensions": {"x": "no", "y": {"tlp_2_0": 5}}}) == set()


def test_granular_markings_count_in_the_minimum():
    red = {"marking_ref": stix2.TLP_RED.id, "selectors": ["name"]}
    obj = _malware(1, "Granular", object_marking_refs=[stix2.TLP_GREEN.id], granular_markings=[red])
    assert bs.intake(_bundle(obj))[1].min_tlp == "RED"
    assert bs._marking_refs({"granular_markings": [{"marking_ref": "a"}, {"marking_ref": 3}, "oops", None]}) == ["a"]
    assert bs._marking_refs({"granular_markings": "no"}) == []


def test_a_marking_that_presents_itself_as_a_level_and_states_none_is_warned_about():
    purple = _named_marking(5, "TLP:PURPLE")
    pap = _named_marking(6, "PAP:BLUE", definition_type="pap")
    statement = _obj("marking-definition", 7, definition_type="statement",
                     definition={"statement": "Use PAP: BLUE here"})
    paper = _obj("marking-definition", 8, definition_type="statement", definition={"statement": "A paper statement"})
    copyright_ = _obj("marking-definition", 9, definition_type="statement", definition={"statement": "(c) 2026"})
    ext = _obj("marking-definition", 10, extensions={"extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
        "extension_type": "property-extension", "tlp_2_0": "violet"}})
    markings = [purple, pap, statement, paper, copyright_, ext]
    _, summary, _ = _read(*markings, _marked(*[m["id"] for m in markings], stix2.TLP_GREEN.id))
    named = sorted(w.split()[2] for w in summary.warnings if "looks like" in w)
    assert named == sorted(m["id"] for m in (purple, pap, statement, ext))
    assert (summary.min_tlp, summary.min_pap) == ("GREEN", None)
    # said once for a marking carried by several objects
    _, summary, _ = _read(purple, _marked(purple["id"]), _marked(purple["id"], n=2))
    assert len([w for w in summary.warnings if "looks like" in w]) == 1


# ── The validator names the object of each error ───────────────────────────

_SCHEMA_KINDS = {
    "missing property": {k: v for k, v in _malware(1).items() if k != "is_family"},
    "id that is no UUID": {**_malware(2), "id": "malware--00000000-0000-4000-0000-000000000002"},
    "timestamp without milliseconds": _malware(3, created="2026-03-02T08:14:55Z"),
    "language tag": _malware(4, lang="not a lang!"),
    "nested external reference": _malware(5, external_references=[{"source_name": "s", "url": "not a url"}]),
    "extension": _malware(6, extensions={OPENCTI_EXT: {"extension_type": "nope"}}),
    "custom property name": _malware(7, **{"X_Bad": 1, "BadCase": 2}),
    "relationship type": _obj("relationship", 8, relationship_type="Uses Badly", source_ref=_id("malware", 1),
                              target_ref=_id("malware", 7)),
    "observable extension": {"type": "file", "spec_version": "2.1", "id": _id("file", 9), "name": "a",
                             "extensions": {"windows-pebinary-ext": {"pe_type": "dll", "sections": [{"name": 7}]}}},
    "marking": {**_obj("marking-definition", 10), "definition_type": "statement", "definition": {"statement": 5}},
    "confidence": _malware(11, confidence=500),
    "empty observable": _sco("ipv4-addr", 12, value=""),
}


@pytest.mark.parametrize("kind", sorted(_SCHEMA_KINDS))
def test_every_error_of_the_validator_starts_with_the_id_of_its_object(kind):
    bad = _SCHEMA_KINDS[kind]
    text = json.dumps({"type": "bundle", "id": BUNDLE_ID, "objects": [bad, _malware(99, "Fine")]})
    verdict = bs.stage5_validation.validate_bundle(text, quiet=True)
    assert verdict.status == bs.stage5_validation.INVALID and verdict.errors
    assert all(error.startswith(f"{bad['id']}: ") for error in verdict.errors), verdict.errors


@pytest.mark.parametrize("kind", sorted(_SCHEMA_KINDS))
def test_each_kind_of_error_excludes_its_object_without_a_search(kind, monkeypatch):
    bad = _SCHEMA_KINDS[kind]
    calls = _count_validations(monkeypatch)
    _, summary, _ = _read(bad, _malware(99, "Fine"))
    assert [(e["id"], e["reason"]) for e in summary.excluded] == [(bad["id"], bs.INVALID)]
    assert summary.excluded[0]["detail"] and len(calls) <= 2     # the bundle, the object alone


# ── Review 2: a borrowed id, a heavy object, locations, markings ───────────

def test_an_error_borrowed_from_another_objects_data_excludes_the_culprit_and_spares_the_object_it_names():
    victim = _malware(2, "Victim")
    spoof = _malware(1, "Spoofer", x_l=[{"id": victim["id"], "type": "malware", "created": "2024-01-01T00:00:00Z",
                                         "modified": "2023-01-01T00:00:00Z"}])
    text = json.dumps({"type": "bundle", "id": BUNDLE_ID, "objects": [spoof, victim]})
    errors = bs.stage5_validation.validate_bundle(text, quiet=True).errors
    assert errors and all(e.startswith(victim["id"] + ": ") for e in errors)     # the validator blames the victim
    index, summary, _ = _read(spoof, victim)
    assert list(_reasons(summary)) == [spoof["id"]] and victim["id"] in index.imported_ids


def test_a_heavy_valid_object_is_not_validated_again_at_every_level(monkeypatch):
    objects = [_malware(n, f"Fine {n}") for n in range(1, 16)]
    objects += [_malware(16, "Heavy", description="x" * 1_500_000), _crashing(17)]
    sizes: list[int] = []
    real = bs.stage5_validation.validate_bundle

    def counting(text, quiet=False):
        sizes.append(len(text))
        return real(text, quiet=quiet)
    monkeypatch.setattr(bs.stage5_validation, "validate_bundle", counting)
    _, summary, _ = _read(*objects)
    assert list(_reasons(summary)) == [_id("malware", 17)]
    assert sum(sizes) < 2.2 * sizes[0]                  # the bundle, then its two halves: the heavy one once


def test_the_split_weighs_bytes_and_never_leaves_a_half_empty():
    obj = {"id": "x"}
    assert bs._split([(obj, 1)] * 4) == 2
    assert bs._split([(obj, 10), (obj, 1), (obj, 1)]) == 1
    assert bs._split([(obj, 1), (obj, 1), (obj, 10)]) == 2


def _location(**props) -> dict:
    return {"type": "location", **props}


@pytest.mark.parametrize("props, iso", [
    ({"name": "France", "country": "France"}, "FR"),
    ({"name": "France", "country": "France", "extensions": {OPENCTI_EXT: {"location_type": "Country"}}}, "FR"),
    ({"name": "France", "country": "FR", "x_opencti_location_type": "country"}, "FR"),
    ({"country": "FR"}, "FR"),
    ({"country": "fr", "name": "FR"}, "FR"),
    ({"name": "Germany"}, "DE"),
    ({"name": "Paris", "city": "Paris", "extensions": {OPENCTI_EXT: {"location_type": "City"}}}, None),
    ({"name": "Paris", "country": "FR"}, None),
    ({"name": "Georgia", "x_opencti_location_type": "City"}, None),
    ({"name": "Georgia", "country": "US"}, None),
    ({"name": "France", "country": "France", "extensions": {OPENCTI_EXT: {"location_type": "Region"}}}, None),
    ({"name": "Atlantis", "country": "Atlantis"}, None),
    ({"name": "France", "country": "France", "extensions": {OPENCTI_EXT: "no", "other": {"location_type": "City"}}},
     "FR"),
    ({"name": "France", "country": "France", "extensions": "no", "x_opencti_location_type": 7}, "FR"),
    ({"name": "France", "country": 7}, "FR"),
    ({"region": "europe"}, None),
])
def test_a_location_resolves_to_a_country_only_when_it_is_one(props, iso):
    strong, _ = bs.keys_for_object(_location(**props))
    assert {k for k in strong if k[0] == "loc"} == ({("loc", iso)} if iso else set())


def test_an_opencti_country_is_found_by_its_name_and_its_city_is_not():
    france = _obj("location", 1, name="France", country="France",
                  extensions={OPENCTI_EXT: {"extension_type": "property-extension", "location_type": "Country"}})
    paris = _obj("location", 2, name="Paris", city="Paris", region="western-europe",
                 extensions={OPENCTI_EXT: {"extension_type": "property-extension", "location_type": "City"}})
    index, _, _ = _read(france, paris)
    country, city = index.entries
    assert index.lookup(bs.keys_for_row("location", "France")[0], "location") is country
    assert ("loc", "FR") in country.keys and not [k for k in city.keys if k[0] == "loc"]


def test_every_marking_opencti_and_stix_name_by_id_is_known():
    tlp = {k for k, (kind, _) in bs._KNOWN_MARKINGS.items() if kind == "tlp"}
    assert tlp == {
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",       # TLP:WHITE / CLEAR
        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",       # GREEN
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",       # AMBER
        "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",       # AMBER+STRICT (OpenCTI's)
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"}       # RED
    assert len(bs._KNOWN_MARKINGS) == 9


def test_a_marking_that_resolves_to_nothing_is_warned_about_once_each_and_capped():
    ids = [_id("marking-definition", n) for n in range(1, 14)]
    malware = [_malware(n, f"M{n}", object_marking_refs=ids[:n] + [stix2.TLP_GREEN.id]) for n in range(1, 14)]
    _, summary, _ = _read(*malware)
    said = [w for w in summary.warnings if "cannot be read" in w]
    assert said[:10] == [f"marking {i} cannot be read: not counted in the TLP/PAP minimum" for i in ids[:10]]
    assert said[10] == "3 more marking(s) cannot be read: not counted in the TLP/PAP minimum" and len(said) == 11
    assert summary.min_tlp == "GREEN"


@pytest.mark.parametrize("kind", sorted(_SCHEMA_KINDS))
def test_the_solo_run_of_an_object_gives_the_messages_the_bundle_run_gave_for_it(kind):
    bad = _SCHEMA_KINDS[kind]
    run = bs.stage5_validation.validate_bundle
    together = run(json.dumps({"type": "bundle", "id": BUNDLE_ID, "objects": [bad, _malware(99, "Fine")]}), quiet=True)
    alone = run(json.dumps({"type": "bundle", "id": BUNDLE_ID, "objects": [bad]}), quiet=True)
    assert bs._own(bad["id"], together.errors) == bs._own(bad["id"], alone.errors) != set()


def test_ten_genuine_culprits_cost_one_validation_of_the_bundle_and_one_of_each(monkeypatch):
    objects = [_malware(n, f"Fine {n}") for n in range(1, 41)]
    for n in range(1, 41, 4):
        objects[n - 1] = _malware(n, f"Bad {n}", lang="not a lang!")
    validations = _count_validations(monkeypatch)
    _, summary, _ = _read(*objects)
    assert len(summary.excluded) == 10 and validations == [40] + [1] * 10


# ── A name-only Indicator joins the file its based-on names (lot 7, A3) ─────

def test_a_name_only_indicator_joins_the_file_its_based_on_names():
    exe = _sco("file", 1, name="cmd.exe")
    ind = _indicator(2, "[file:name = 'cmd.exe']")
    index, _, _ = _read(exe, ind, _rel(3, "based-on", ind, exe), validate=False)
    (entry,) = index.entries
    assert entry.entry_id == exe["id"] and entry.indicator_ids == (ind["id"],)
    assert set(entry.object_ids) == {exe["id"], ind["id"], _id("relationship", 3)}
    assert index.lookup_weak({("file_name", "cmd.exe")}) == entry


def test_a_name_only_indicator_with_no_based_on_stays_an_entry_of_its_own():
    exe = _sco("file", 1, name="cmd.exe")
    ind = _indicator(2, "[file:name = 'cmd.exe']")
    index, _, _ = _read(exe, ind, validate=False)
    assert len(index.entries) == 2
    assert index.lookup_weak({("file_name", "cmd.exe")}) is None      # two carriers: no status from a name


def test_an_indicator_based_on_an_observable_of_another_value_does_not_join_it():
    ip = _sco("ipv4-addr", 1, value="203.0.113.9")
    ind = _indicator(2, "[ipv4-addr:value = '198.51.100.7']")
    index, _, _ = _read(ip, ind, _rel(3, "based-on", ind, ip), validate=False)
    assert len(index.entries) == 2                                   # each value keeps its own entry
    assert index.lookup({("obs", "ipv4-addr", "198.51.100.7")}).entry_id == ind["id"]


def test_an_indicator_based_on_two_files_of_its_name_joins_neither():
    one = _sco("file", 1, name="cmd.exe", hashes={"MD5": "1" * 32})
    two = _sco("file", 2, name="cmd.exe", hashes={"MD5": "2" * 32})
    ind = _indicator(3, "[file:name = 'cmd.exe']")
    index, _, _ = _read(one, two, ind, _rel(4, "based-on", ind, one), _rel(5, "based-on", ind, two),
                        validate=False)
    assert {e.entry_id for e in index.entries} == {one["id"], two["id"], ind["id"]}
    assert index.lookup_weak({("file_name", "cmd.exe")}) is None
