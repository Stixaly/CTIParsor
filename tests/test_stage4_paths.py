"""Stage 4 — the STIX helpers one observable type or one malformed input at a
time (SCOs, SDOs, patterns, PAP, embedded rules, pin budget and grounding,
relationship guards), then the merge and fallback branches of
build_stix_bundle that test_stage4.py's reports never reach."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import stix2

from models.schemas import EntityType, RawEntity
from pipeline import stage4_stix_mapping as s4
from pipeline.stage3_llm import IoCAssociation, LLMEnrichmentResult, RelationshipExtracted

_SHA1 = "a" * 40
_MD5 = "b" * 32


def _e(value: str, etype: EntityType, **kw) -> RawEntity:
    return RawEntity(value=value, entity_type=etype, **kw)


def _objects(bundle, stix_type: str) -> list:
    return [o for o in bundle.objects if o.get("type") == stix_type]


# ── Observables and their patterns ───────────────────────────────────────────

@pytest.mark.parametrize("etype,value,stix_type,pattern", [
    (EntityType.IPV6, "2001:db8::1", "ipv6-addr", "[ipv6-addr:value = '2001:db8::1']"),
    (EntityType.URL, "http://evil.example/a'b", "url", "[url:value = 'http://evil.example/a\\'b']"),
    (EntityType.EMAIL, "ops@evil.example", "email-addr", "[email-addr:value = 'ops@evil.example']"),
    (EntityType.MAC_ADDR, "00:11:22:33:44:55", "mac-addr", "[mac-addr:value = '00:11:22:33:44:55']"),
    (EntityType.SHA1, _SHA1, "file", f"[file:hashes.'SHA-1' = '{_SHA1}']"),
    (EntityType.MD5, _MD5, "file", f"[file:hashes.MD5 = '{_MD5}']"),
    (EntityType.FILE, "C:\\Temp\\x.dll", "file", "[file:name = 'C:\\\\Temp\\\\x.dll']"),
    (EntityType.MUTEX, "Global\\M1", "mutex", "[mutex:name = 'Global\\\\M1']"),
    (EntityType.USER_ACCOUNT, "svc_backup", "user-account", "[user-account:user_id = 'svc_backup']"),
    (EntityType.NETWORK_TRAFFIC, "tcp/445", "software", "[software:name = 'tcp/445']"),
    (EntityType.ASN, "as64500", "autonomous-system", "[autonomous-system:number = 64500]"),
])
def test_each_observable_becomes_an_sco_with_a_pattern(etype, value, stix_type, pattern):
    sco = s4._entity_to_sco(_e(value, etype))
    assert sco.type == stix_type
    assert s4._build_stix_pattern(value, sco) == pattern


@pytest.mark.parametrize("entity", [
    _e("ASxyz", EntityType.ASN),                  # no number
    _e("zz", EntityType.MD5),                     # stix2 refuses the hash
    _e("APT29", EntityType.THREAT_ACTOR),         # not an observable
])
def test_what_cannot_be_an_sco_is_none(entity):
    assert s4._entity_to_sco(entity) is None


@pytest.mark.parametrize("value,sco", [
    ("ASxyz", {"type": "autonomous-system"}),
    ("x", {"type": "file", "hashes": {}, "name": "  "}),
    ("x", {"type": "x-unknown"}),
    ("x", object()),                              # not a mapping at all
])
def test_no_pattern_for_what_a_pattern_cannot_express(value, sco):
    assert s4._build_stix_pattern(value, sco) is None


@pytest.mark.parametrize("etype,value,stix_type", [
    (EntityType.INTRUSION_SET, "Lazarus", "intrusion-set"),
    (EntityType.CAMPAIGN, "Operation Ghost", "campaign"),
    (EntityType.INCIDENT, "Breach 2024-03", "incident"),
])
def test_named_sdos_get_deterministic_ids(etype, value, stix_type):
    first, second = s4._entity_to_sdo(_e(value, etype)), s4._entity_to_sdo(_e(value, etype))
    assert first.type == stix_type and first.name == value and first.id == second.id


def test_an_sdo_stix2_refuses_is_none(monkeypatch):
    def refuse(**kw):
        raise stix2.exceptions.InvalidValueError(stix2.Campaign, "name", "refused")

    monkeypatch.setattr(s4.stix2, "Campaign", refuse)
    assert s4._entity_to_sdo(_e("Operation Ghost", EntityType.CAMPAIGN)) is None


# ── Markings and provenance ──────────────────────────────────────────────────

def test_pap_levels_become_statement_markings():
    assert s4._pap_marking(None) is None and s4._pap_marking("PURPLE") is None
    amber = s4._pap_marking(" amber ")
    assert amber.definition == {"statement": "PAP:AMBER"} and amber.id == s4._pap_marking("AMBER").id


def test_a_marking_definition_is_never_stamped():
    marking = s4._pap_marking("RED")
    actor = stix2.ThreatActor(name="APT29")
    stamped = s4._stamp_objects([marking, actor], "identity--" + "1" * 8 + "-1111-4111-8111-" + "1" * 12,
                                [marking.id])
    assert stamped[0] is marking
    assert stamped[1]["object_marking_refs"] == [marking.id]


def test_a_pap_level_marks_every_object_of_the_bundle():
    bundle = s4.build_stix_bundle([], LLMEnrichmentResult(threat_actors=["APT29"]), "r", pap_level="green")
    pap = [o for o in bundle.objects if o.get("type") == "marking-definition"
           and o.get("definition", {}).get("statement") == "PAP:GREEN"]
    assert len(pap) == 1
    assert all(pap[0].id in o.get("object_marking_refs", []) for o in _objects(bundle, "threat-actor"))


# ── Embedded detection rules (ADR-0042) ──────────────────────────────────────

def _embedded(pattern_type="yara", pattern="rule Emotet_Loader { condition: true }", title="Emotet_Loader",
              llm=None, name_to_stix=None, seen_ids=None):
    objects: list = []
    s4._add_embedded_rule_indicator(
        objects, name_to_stix or {}, seen_ids if seen_ids is not None else set(),
        pattern_type=pattern_type, pattern=pattern, title=title,
        llm_result=llm or LLMEnrichmentResult(), pol_index=None, seen_rel_keys=set(),
    )
    return objects


def test_an_embedded_rule_links_only_names_long_enough_and_known():
    emotet = stix2.Malware(name="Emotet", is_family=True)
    llm = LLMEnrichmentResult(malware_families=["Emotet", "RAT", "Qakbot"], tools=["Mimikatz"])

    objects = _embedded(title="Emotet RAT loader", llm=llm,
                        name_to_stix={"emotet": emotet})          # Qakbot/Mimikatz not in title, RAT too short

    indicator, rel = objects
    assert indicator.pattern_type == "yara" and indicator.name == "Yara rule: Emotet RAT loader"
    assert (rel.source_ref, rel.relationship_type, rel.target_ref) == (indicator.id, "indicates", emotet.id)


def test_a_name_in_the_title_without_an_sdo_links_nothing():
    objects = _embedded(title="Emotet loader", llm=LLMEnrichmentResult(malware_families=["Emotet"]))
    assert [o.type for o in objects] == ["indicator"]


def test_the_same_rule_twice_is_one_indicator():
    seen: set = set()
    assert len(_embedded(seen_ids=seen)) == 1
    assert _embedded(seen_ids=seen) == []


def test_a_rule_stix2_refuses_is_skipped():
    assert _embedded(pattern_type="stix", pattern="not a stix pattern") == []


def test_a_net_rule_without_an_option_body_is_skipped():
    text = "alert tcp any any -> any any ) no body ("
    assert s4._find_embedded_net_rules(text) == []


def test_two_sigma_rules_in_a_row_are_both_found():
    text = (
        "title: Rule One\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image: a.exe\n"
        "  condition: sel\n"
        "title: Rule Two\ndetection:\n  sel:\n    Image: b.exe\n  condition: sel\n"
    )
    assert [doc["title"] for _, doc in s4._find_embedded_sigma_rules(text)] == ["Rule One", "Rule Two"]


def test_a_sigma_candidate_larger_than_the_window_is_skipped():
    text = "title: Endless\ndetection:\n  sel: x\n" + "  - line\n" * 30_000
    assert s4._find_embedded_sigma_rules(text) == []


# ── Pins: budget, grounding, policy parsing ──────────────────────────────────

def test_a_budget_smaller_than_the_rule_count_is_still_spent_in_full():
    assert s4._fair_share([3, 3, 3], 2) == [0, 1, 1]
    assert s4._fair_share([5, 1], 4) == [3, 1]
    assert s4._fair_share([4, 4], 0) == [0, 0]


def test_an_object_without_an_id_has_no_pin_key():
    assert s4._pin_edge_key(SimpleNamespace(type="malware"), "uses", stix2.Malware(name="X", is_family=True)) \
        is None


def test_the_sentence_index_ignores_objects_without_a_string_id():
    assert s4._build_sentence_index([{"type": "malware", "name": "Emotet"}], ["Emotet spreads."]) == {}


def test_grounding_measures_the_distance_both_ways():
    src = {"id": "malware--a", "type": "malware"}
    tgt = {"id": "tool--b", "type": "tool"}
    assert s4._pair_is_grounded(src, tgt, {"malware--a": {5}, "tool--b": {1, 9}}, window=3) == (False, "")
    assert s4._pair_is_grounded(src, tgt, {"malware--a": {5}, "tool--b": {1, 7}}, window=3) == (True, "window:2")
    no_id = {"type": "malware"}
    assert s4._pair_is_grounded(no_id, tgt, {"tool--b": {1}}, window=3) == (True, "unanchorable")


@pytest.mark.parametrize("policy,budget,mode", [
    ({"global": "enforce", "max_pinned_edges": "many"}, 200, "fair-share"),
    ({"global": "enforce", "max_pinned_edges": -5, "pin_budget_mode": "greedy"}, 0, "fair-share"),
    ({"global": "enforce", "pin_budget_mode": "sequential", "pin_evidence": "cooccurrence"}, 200, "sequential"),
    ({"global": "enforce", "pin_evidence": {"mode": "nearby", "window": "wide"}}, 200, "fair-share"),
    ({"global": "enforce", "pin_evidence": {"window": -1}}, 200, "fair-share"),
])
def test_a_malformed_pin_policy_falls_back_to_the_defaults(policy, budget, mode):
    stats = s4._materialise_pinned_edges([], policy, set())
    assert (stats.budget, stats.mode, stats.rules) == (budget, mode, [])


# ── _add_relationship guards ─────────────────────────────────────────────────

def test_relationship_guards():
    actor = stix2.ThreatActor(name="APT29")
    malware = stix2.Malware(name="SUNBURST", is_family=True)
    objects: list = []
    seen: set = set()

    assert s4._add_relationship(objects, SimpleNamespace(), "uses", malware) is None        # no id
    assert s4._add_relationship(objects, actor, "uses", actor) is None                      # self-pair
    rel = s4._add_relationship(objects, actor, "made-up-verb", malware, seen=seen)
    assert rel.relationship_type == "related-to"
    assert s4._add_relationship(objects, actor, "made-up-verb", malware, seen=seen) is None  # duplicate
    pinned = s4._add_relationship(objects, actor, "related-to", malware,
                                  pol_index={"threat-actor>malware": {"verb": "uses", "mode": "pin",
                                                                      "enabled": True}})
    assert pinned.relationship_type == "uses"
    broken = SimpleNamespace(id="not-a-stix-id", type="malware")
    assert s4._add_relationship(objects, actor, "uses", broken) is None                     # stix2 refuses
    assert len(objects) == 2


# ── build_stix_bundle branches ───────────────────────────────────────────────

def test_raw_techniques_carry_capec_tactic_and_attack_references():
    bundle = s4.build_stix_bundle([
        _e("Buffer Overflow via Environment Variables", EntityType.TECHNIQUE, mitre_id="CAPEC-10"),
        _e("Initial Access", EntityType.TACTIC, mitre_id="TA0001"),
    ], LLMEnrichmentResult(), "r", graph_completion=False)

    refs = {p.name: p.external_references[0] for p in _objects(bundle, "attack-pattern")}
    capec = refs["Buffer Overflow via Environment Variables"]
    assert (capec.source_name, capec.url) == ("capec", "https://capec.mitre.org/data/definitions/10.html")
    assert refs["Initial Access"].url == "https://attack.mitre.org/tactics/TA0001/"


def test_a_cve_seen_twice_is_one_vulnerability_with_its_cvss():
    meta = {"CVE-2020-10148": {"description": "Orion API auth bypass", "cvss_score": 9.8,
                               "cvss_vector": "CVSS:3.1/AV:N"}}
    bundle = s4.build_stix_bundle(
        [_e("CVE-2020-10148", EntityType.CVE), _e("cve-2020-10148", EntityType.CVE, source="llm")],
        LLMEnrichmentResult(), "r", cve_metadata=meta, graph_completion=False)

    (vuln,) = _objects(bundle, "vulnerability")
    assert vuln.description == "Orion API auth bypass"
    assert (vuln.x_cvss_v3_score, vuln.x_cvss_v3_vector) == (9.8, "CVSS:3.1/AV:N")


def test_a_cvss_score_without_a_vector_carries_the_score_only():
    bundle = s4.build_stix_bundle([_e("CVE-2021-44228", EntityType.CVE)], LLMEnrichmentResult(), "r",
                                  cve_metadata={"CVE-2021-44228": {"cvss_score": 10.0}}, graph_completion=False)
    (vuln,) = _objects(bundle, "vulnerability")
    assert vuln.x_cvss_v3_score == 10.0 and "x_cvss_v3_vector" not in vuln and "description" not in vuln


def test_a_named_sdo_already_built_is_merged_not_duplicated():
    from pipeline.bundle_ledger import MappingLedger

    ledger = MappingLedger()
    bundle = s4.build_stix_bundle(
        [_e("Operation Ghost", EntityType.CAMPAIGN), _e("operation ghost", EntityType.CAMPAIGN)],
        LLMEnrichmentResult(campaign_name="OPERATION GHOST"), "r", ledger=ledger, graph_completion=False)

    assert len(_objects(bundle, "campaign")) == 1
    outcomes = [(e["value"], e["outcome"]) for e in ledger.to_dict()["entities"]]
    assert outcomes.count(("operation ghost", "merged")) == 1 and ("OPERATION GHOST", "merged") in outcomes


def test_one_ioc_indicating_two_families_is_one_indicator_with_two_edges():
    llm = LLMEnrichmentResult(
        malware_families=["SUNBURST", "TEARDROP"],
        ioc_associations=[
            IoCAssociation(ioc_value="185.220.101.45", malware_name="SUNBURST", relationship_type="indicates"),
            IoCAssociation(ioc_value="185.220.101.45", malware_name="TEARDROP", relationship_type="indicates"),
            IoCAssociation(ioc_value="185.220.101.45", malware_name="", relationship_type="indicates"),
            IoCAssociation(ioc_value="10.9.9.9", malware_name="SUNBURST", relationship_type="indicates"),
        ],
    )
    bundle = s4.build_stix_bundle([_e("185.220.101.45", EntityType.IPV4)], llm, "r", graph_completion=False)

    (indicator,) = _objects(bundle, "indicator")
    malware = {m.id: m.name for m in _objects(bundle, "malware")}
    indicated = sorted(malware[r.target_ref] for r in _objects(bundle, "relationship")
                       if r.relationship_type == "indicates" and r.source_ref == indicator.id)
    assert indicated == ["SUNBURST", "TEARDROP"]


def test_a_date_that_cannot_be_applied_never_costs_the_edge(monkeypatch, caplog):
    def refuse(sro, plan):
        raise ValueError("stop_time before start_time")

    monkeypatch.setattr(s4, "_with_temporal", refuse)
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"], malware_families=["SUNBURST"],
        relationships=[RelationshipExtracted(source_value="APT29", relationship_type="uses",
                                             target_value="SUNBURST", evidence_text="APT29 used SUNBURST in 2020.",
                                             times=[{"role": "within", "time_text": "in 2020", "value": "2020"}])])
    from pipeline.stage3_llm import check_relationship_times
    llm = check_relationship_times(llm, "APT29 used SUNBURST in 2020.", None)

    bundle = s4.build_stix_bundle([], llm, "r", report_text="APT29 used SUNBURST in 2020.",
                                  graph_completion=False)

    uses = [r for r in _objects(bundle, "relationship") if r.relationship_type == "uses"]
    assert len(uses) == 1 and "x_temporal_assertions" not in uses[0]
    assert "relationship dates not applied" in caplog.text


def test_a_source_artifact_stix2_refuses_is_left_out(monkeypatch):
    def refuse(**kw):
        raise ValueError("payload too large")

    monkeypatch.setattr(s4.stix2, "Artifact", refuse)
    bundle = s4.build_stix_bundle([], LLMEnrichmentResult(threat_actors=["APT29"]), "r",
                                  source_bytes=b"%PDF-1.4", source_hash="c" * 64, graph_completion=False)
    assert _objects(bundle, "artifact") == [] and len(_objects(bundle, "report")) == 1


def test_a_report_stix2_refuses_is_rebuilt_without_its_optional_fields(monkeypatch):
    real = s4.stix2.Report
    calls = []

    def picky(**kw):
        calls.append(sorted(kw))
        if "description" in kw:
            raise stix2.exceptions.InvalidValueError(real, "description", "refused")
        return real(**kw)

    monkeypatch.setattr(s4.stix2, "Report", picky)
    bundle = s4.build_stix_bundle([], LLMEnrichmentResult(threat_actors=["APT29"]), "the-report",
                                  report_text="APT29 did things.", graph_completion=False)

    (report,) = _objects(bundle, "report")
    assert report.name == "the-report" and "description" not in report
    assert len(calls) == 2


def test_ioc_coverage_names_what_is_missing():
    bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")], allow_custom=True)
    report = s4.verify_ioc_coverage([_e("1.2.3.4", EntityType.IPV4), _e("5.6.7.8", EntityType.IPV4)], bundle)
    assert [m["value"] for m in report["missing_sco"]] == ["5.6.7.8"]
    assert [m["value"] for m in report["missing_indicator"]] == ["1.2.3.4", "5.6.7.8"]


def test_bundle_round_trips_as_json():
    bundle = s4.build_stix_bundle([_e("2001:db8::1", EntityType.IPV6)], LLMEnrichmentResult(), "r")
    assert json.loads(bundle.serialize())["type"] == "bundle"
