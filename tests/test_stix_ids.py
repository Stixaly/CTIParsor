"""STIX ids are OpenCTI's standard ids (ADR-0066).

Each expected value below was produced by OpenCTI's own Python client, running
the `generate_id` function of `client-python/pycti/entities/opencti_<type>.py`
from the OpenCTI master tree of 2026-10-01 on the same input.  A difference
means a CTIParsor object would no longer land on the object OpenCTI already
holds.
"""
import uuid

import pytest

from pipeline import stix_ids

PYCTI = [
    (lambda: stix_ids.named_object_id("malware", "  WellMess "),
     "malware--1bf57b7d-3541-5b44-a0c9-7664b2636ca4"),
    (lambda: stix_ids.named_object_id("tool", "Mimikatz"),
     "tool--dae20ca4-ebdf-5248-83ac-0f7a52f94fcc"),
    (lambda: stix_ids.named_object_id("campaign", "Operation X"),
     "campaign--2a255954-118d-5211-ad86-400748c21db3"),
    (lambda: stix_ids.named_object_id("intrusion-set", "APT29"),
     "intrusion-set--36319194-19e1-50ac-9163-778b56a1bf12"),
    (lambda: stix_ids.named_object_id("infrastructure", "C2 cluster"),
     "infrastructure--dcc51d41-e4a5-5279-b6a2-5ffa3a5271a0"),
    (lambda: stix_ids.named_object_id("vulnerability", "CVE-2021-44228"),
     "vulnerability--693c68fd-9a33-5d6d-b44e-407b6a48b05b"),
    (lambda: stix_ids.named_object_id("threat-actor", "Sandworm"),
     "threat-actor--06caa0ee-320e-5e7b-b1ce-468f38fd1c1e"),
    (lambda: stix_ids.attack_pattern_id("PowerShell", "T1059.001"),
     "attack-pattern--b4d20430-6a7e-59fd-b2e4-8d3f6be56a6a"),
    (lambda: stix_ids.attack_pattern_id("Group Policy Modification"),
     "attack-pattern--8b987c05-e29f-5b54-902a-73384f06d0b4"),
    (lambda: stix_ids.course_of_action_id("Disable macros"),
     "course-of-action--d6db4a81-4695-5e00-8d9e-fc158cc7face"),
    (lambda: stix_ids.identity_id("Energy", "class"),
     "identity--166544e2-ba1f-5a6c-89cf-a63d0c01e91c"),
    (lambda: stix_ids.identity_id("CTIParsor", "system"),
     "identity--df314057-d669-5e4d-aa9c-5257582a7ecd"),
    (lambda: stix_ids.location_id("Ukraine"),
     "location--fb56af0f-b28e-54d2-b738-6ef5ceb2ce5b"),
    (lambda: stix_ids.indicator_id("[domain-name:value = 'evil.example.com']"),
     "indicator--251b41b7-1baf-527e-a251-5821a471dd65"),
    (lambda: stix_ids.marking_id("PAP", "PAP:GREEN"),
     "marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1"),
]


@pytest.mark.parametrize("make,expected", PYCTI, ids=[e.split("--")[0] + str(i) for i, (_, e) in enumerate(PYCTI)])
def test_ids_match_pycti(make, expected):
    assert make() == expected


def test_case_and_spaces_do_not_change_an_id():
    assert stix_ids.named_object_id("malware", "WellMess") == stix_ids.named_object_id("malware", " wellmess ")
    assert stix_ids.attack_pattern_id("x", "T1059.001") == stix_ids.attack_pattern_id("y", "t1059.001")


def test_an_attack_id_wins_over_the_name_but_capec_does_not():
    assert stix_ids.attack_pattern_id("Name A", "T1059") == stix_ids.attack_pattern_id("Name B", "T1059")
    # pycti reads x_mitre_id only from a "mitre-*" reference; CAPEC is not one.
    assert stix_ids.attack_pattern_id("Abuse", "CAPEC-112") == stix_ids.attack_pattern_id("Abuse")


def test_ids_are_uuidv5_and_carry_their_type():
    sid = stix_ids.identity_id("Energy", "class")
    assert sid.startswith("identity--")
    assert uuid.UUID(sid.split("--", 1)[1]).version == 5


def test_unknown_name_rule_is_refused():
    with pytest.raises(ValueError):
        stix_ids.named_object_id("report", "x")
