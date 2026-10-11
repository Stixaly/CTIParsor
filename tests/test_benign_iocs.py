"""A value the report names without accusing it gets no Indicator (audit B 8.1.7).

The audit's text: "The malware checks connectivity by contacting www.google.com
and microsoft.com, then beacons to 45.77.12.9.  The victim host 10.0.0.5 and
192.168.1.20 were compromised.  See https://attack.mitre.org/... and
https://www.mandiant.com/...": every value became an Indicator typed
`malicious-activity`, a detection a consumer would alert on.
"""
from __future__ import annotations

import pytest

from models.schemas import EntityType, RawEntity
from pipeline import benign
from pipeline import stage4_stix_mapping as s4
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import IoCAssociation, LLMEnrichmentResult, RelationshipExtracted

T = EntityType


@pytest.mark.parametrize("etype, value, reason", [
    (T.IPV4, "10.0.0.5", "non_routable_address"),
    (T.IPV4, "127.0.0.1", "non_routable_address"),
    (T.IPV6, "fe80::1", "non_routable_address"),
    (T.IPV4, "8.8.8.8", "public_dns_resolver"),
    (T.IPV4, "45.77.12.9", None),
    (T.DOMAIN, "www.google.com", "popular_domain:tranco10k"),
    (T.DOMAIN, "google.com", "popular_domain:tranco10k"),
    (T.DOMAIN, "evil.duckdns.org", None),          # a popular parent does not make it popular
    (T.DOMAIN, "evil-c2.example-bad.top", None),
    (T.URL, "https://www.mandiant.com/resources/blog/apt29", "reference_site:security-provider-blogpost"),
    (T.URL, "https://attack.mitre.org/techniques/T1071/", "reference_site:security-provider-blogpost"),
    (T.URL, "https://analyze.intezer.com/analyses/abc", "reference_site:automated-malware-analysis"),
    # Platforms anyone publishes on stay indicators, even where a list names them.
    (T.URL, "https://raw.githubusercontent.com/x/y/payload.ps1", None),
    (T.URL, "https://github.com/attacker/tool", None),
    (T.URL, "https://s3-eu-west-1.amazonaws.com/bucket/p.exe", None),
    # A URL on a popular domain is not a reference.
    (T.URL, "https://www.google.com/url?q=https://evil.example/payload", None),
])
def test_why_a_value_is_not_an_indicator(etype, value, reason):
    assert benign.benign_reason(etype, value) == reason


def test_the_filter_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("BENIGN_IOC_FILTER", "false")
    assert benign.benign_reason(T.IPV4, "10.0.0.5") is None


def _build(entities, llm=None):
    ledger = MappingLedger()
    bundle = s4.build_stix_bundle(entities, llm or LLMEnrichmentResult(), "r",
                                  report_text="text", ledger=ledger)
    return bundle, ledger.to_dict()


AUDIT_IOCS = [
    RawEntity(value="www.google.com", entity_type=T.DOMAIN),
    RawEntity(value="45.77.12.9", entity_type=T.IPV4),
    RawEntity(value="10.0.0.5", entity_type=T.IPV4),
    RawEntity(value="https://www.mandiant.com/resources/blog/apt29", entity_type=T.URL),
]


def test_benign_values_ship_as_observables_without_an_indicator():
    bundle, ledger = _build(AUDIT_IOCS)
    patterns = {o["pattern"] for o in bundle.objects if o["type"] == "indicator"}
    assert patterns == {"[ipv4-addr:value = '45.77.12.9']"}
    observables = {o.get("value") for o in bundle.objects if o["type"] in ("ipv4-addr", "domain-name", "url")}
    assert {"www.google.com", "45.77.12.9", "10.0.0.5",
            "https://www.mandiant.com/resources/blog/apt29"} <= observables
    marked = {info.get("benign") for info in ledger["objects"].values() if info.get("no_indicator") == "benign"}
    assert marked == {"popular_domain:tranco10k", "non_routable_address",
                      "reference_site:security-provider-blogpost"}

    cov = s4.verify_ioc_coverage(AUDIT_IOCS, bundle)
    assert cov["ok"] and cov["with_indicator"] == 1 and len(cov["benign"]) == 3
    assert cov["missing_indicator"] == []


def test_an_association_with_a_benign_value_builds_no_indicator():
    llm = LLMEnrichmentResult(malware_families=["BlackLoader"], ioc_associations=[
        IoCAssociation(ioc_value="www.google.com", malware_name="BlackLoader")])
    bundle, ledger = _build([RawEntity(value="www.google.com", entity_type=T.DOMAIN)], llm)
    assert not [o for o in bundle.objects if o["type"] == "indicator"]
    [entry] = [e for e in ledger["entities"] if e["value"] == "www.google.com" and e["outcome"] == "dropped"]
    assert entry["reason"] == "benign" and entry["input"] == "ioc_association"


def test_a_claim_routed_to_a_benign_value_says_why_it_was_dropped():
    # "uses" is not a STIX verb for malware → domain-name: it goes through the
    # observable's Indicator, which a benign value does not have.
    llm = LLMEnrichmentResult(malware_families=["BlackLoader"], relationships=[RelationshipExtracted(
        source_value="BlackLoader", relationship_type="uses", target_value="www.google.com",
        confidence=0.8, evidence_text="BlackLoader checks connectivity with www.google.com.")])
    _, ledger = _build([RawEntity(value="www.google.com", entity_type=T.DOMAIN)], llm)
    [rel] = [r for r in ledger["relationships"] if r["target_value"] == "www.google.com"]
    assert rel["outcome"] == "dropped" and rel["reason"] == "benign_observable"
