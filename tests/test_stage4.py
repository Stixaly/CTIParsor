import stix2

from models.schemas import EntityType, RawEntity
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted, TTPExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle, verify_ioc_coverage


def _make_minimal_llm_result() -> LLMEnrichmentResult:
    return LLMEnrichmentResult(
        threat_actors=["APT29"],
        malware_families=["WellMess"],
        tools=["Cobalt Strike"],
        ttps=[TTPExtracted(technique_name="Spearphishing Attachment", mitre_id="T1566.001")],
        relationships=[
            RelationshipExtracted(
                source_value="APT29",
                relationship_type="uses",
                target_value="WellMess",
                confidence=0.9,
            )
        ],
        targeted_sectors=["government"],
        targeted_countries=["France"],
        campaign_name=None,
    )


def test_bundle_is_stix_bundle():
    entities = [RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4)]
    bundle = build_stix_bundle(entities, _make_minimal_llm_result(), "test_report")
    assert isinstance(bundle, stix2.Bundle)


def test_bundle_contains_threat_actor():
    bundle = build_stix_bundle([], _make_minimal_llm_result(), "test_report")
    types = [obj.get("type") for obj in bundle.objects]
    assert "threat-actor" in types


def test_bundle_contains_malware():
    bundle = build_stix_bundle([], _make_minimal_llm_result(), "test_report")
    types = [obj.get("type") for obj in bundle.objects]
    assert "malware" in types


def test_bundle_contains_relationship():
    bundle = build_stix_bundle([], _make_minimal_llm_result(), "test_report")
    types = [obj.get("type") for obj in bundle.objects]
    assert "relationship" in types


def test_bundle_contains_attack_pattern():
    bundle = build_stix_bundle([], _make_minimal_llm_result(), "test_report")
    types = [obj.get("type") for obj in bundle.objects]
    assert "attack-pattern" in types


def test_ipv4_becomes_sco():
    entities = [RawEntity(value="1.2.3.4", entity_type=EntityType.IPV4)]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "test")
    types = [obj.get("type") for obj in bundle.objects]
    assert "ipv4-addr" in types


def test_duplicate_input_entities_yield_one_sco():
    """Passing the same IoC twice (e.g. the CLI flattening overlapping chunks)
    must not put two identical-id SCO objects into the bundle."""
    entities = [
        RawEntity(value="1.2.3.4", entity_type=EntityType.IPV4),
        RawEntity(value="1.2.3.4", entity_type=EntityType.IPV4),
    ]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "dup")
    ids = [o.id for o in bundle.objects if hasattr(o, "id")]
    assert len(ids) == len(set(ids)), "duplicate object ids in bundle"
    assert sum(1 for o in bundle.objects if o.get("type") == "ipv4-addr") == 1


def test_asn_becomes_autonomous_system_sco():
    """An 'AS15169' ASN entity must map to an autonomous-system SCO with the
    correct integer number (removeprefix, not lstrip char-set strip)."""
    entities = [RawEntity(value="AS15169", entity_type=EntityType.ASN)]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "test")
    asn = next((o for o in bundle.objects if o.get("type") == "autonomous-system"), None)
    assert asn is not None
    assert asn.number == 15169


def test_discovered_observable_gets_indicator_and_link():
    """A bare IoC must yield SCO + Indicator + based-on relationship."""
    entities = [RawEntity(value="185.225.74.19", entity_type=EntityType.IPV4)]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "test")
    types = [obj.get("type") for obj in bundle.objects]
    assert "ipv4-addr" in types
    assert "indicator" in types
    based_on = [
        o for o in bundle.objects
        if o.get("type") == "relationship" and o.relationship_type == "based-on"
    ]
    assert len(based_on) == 1


def test_no_duplicate_location_identity_sdos():
    """
    Regression: a country/sector that appears BOTH as a pipeline LOCATION/IDENTITY
    RawEntity AND in the LLM's targeted_countries/targeted_sectors used to produce
    two SDOs with an identical deterministic id (and a duplicated Report.object_refs
    entry), which fails STIX validation.
    """
    from collections import Counter

    raw_entities = [
        RawEntity(value="Russia", entity_type=EntityType.LOCATION),
        RawEntity(value="Finance", entity_type=EntityType.IDENTITY),
    ]
    llm = LLMEnrichmentResult(
        targeted_countries=["Russia"],
        targeted_sectors=["Finance"],
    )
    bundle = build_stix_bundle(raw_entities, llm, "dup_test")

    ids = [o.id for o in bundle.objects if hasattr(o, "id")]
    assert len(ids) == len(set(ids)), "bundle contains duplicate object ids"

    locations = [o for o in bundle.objects if o.get("type") == "location"]
    assert len(locations) == 1

    report = next((o for o in bundle.objects if o.get("type") == "report"), None)
    assert report is not None
    ref_counts = Counter(report.object_refs)
    assert all(c == 1 for c in ref_counts.values()), "duplicate entries in object_refs"


# ── Relationship policy — enforce mode ──────────────────────────────────────────

_PIN_POLICY = {
    "version": 1,
    "global": "enforce",
    "rules": [{"src": "threat-actor", "verb": "uses", "tgt": "malware",
               "mode": "pin", "enabled": True}],
}


def _rel_verbs(bundle):
    return [o.relationship_type for o in bundle.objects if o.get("type") == "relationship"]


def test_enforce_pin_overrides_inferred_verb():
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"], malware_families=["WINELOADER"],
        relationships=[RelationshipExtracted(
            source_value="APT29", relationship_type="related-to",
            target_value="WINELOADER", confidence=0.9)],
    )
    verbs = _rel_verbs(build_stix_bundle([], llm, "r", relationship_policy=_PIN_POLICY))
    assert verbs.count("uses") == 1
    assert "related-to" not in verbs


def test_enforce_pin_creates_missing_edge():
    """Pin rule materialises the edge even when no stage inferred it."""
    llm = LLMEnrichmentResult(threat_actors=["APT29"],
                              malware_families=["WINELOADER", "ROOTSAW"])
    bundle = build_stix_bundle([], llm, "r", relationship_policy=_PIN_POLICY)
    # 1 actor × 2 malware → 2 forced "uses" edges
    assert _rel_verbs(bundle).count("uses") == 2


def test_enforce_pin_does_not_duplicate_existing_edge():
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"], malware_families=["WINELOADER"],
        relationships=[RelationshipExtracted(
            source_value="APT29", relationship_type="controls",
            target_value="WINELOADER", confidence=0.8)],
    )
    bundle = build_stix_bundle([], llm, "r", relationship_policy=_PIN_POLICY)
    assert _rel_verbs(bundle) == ["uses"]


def test_auto_mode_does_not_create_edges():
    auto_rule = {**_PIN_POLICY, "rules": [{**_PIN_POLICY["rules"][0], "mode": "auto"}]}
    global_auto = {**_PIN_POLICY, "global": "auto"}
    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["WINELOADER"])
    assert _rel_verbs(build_stix_bundle([], llm, "r", relationship_policy=auto_rule)) == []
    assert _rel_verbs(build_stix_bundle([], llm, "r", relationship_policy=global_auto)) == []


# ── STIX 2.1 suggested-relationship compliance ─────────────────────────────────

def _find_rel(bundle, src_type, tgt_type):
    objs = {o.id: o for o in bundle.objects}
    for o in bundle.objects:
        if o.get("type") != "relationship":
            continue
        s = objs.get(o.source_ref)
        t = objs.get(o.target_ref)
        if s is not None and t is not None and s.get("type") == src_type and t.get("type") == tgt_type:
            return o
    return None


def test_non_suggested_verb_downgraded_to_related_to():
    # malware --targets--> threat-actor is permitted but NOT suggested → related-to
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"], malware_families=["WINELOADER"],
        relationships=[RelationshipExtracted(
            source_value="WINELOADER", relationship_type="targets",
            target_value="APT29", confidence=0.9)],
    )
    bundle = build_stix_bundle([], llm, "r")
    rel = _find_rel(bundle, "malware", "threat-actor")
    assert rel is not None and rel.relationship_type == "related-to"


def test_suggested_verb_preserved():
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"], malware_families=["WINELOADER"],
        relationships=[RelationshipExtracted(
            source_value="APT29", relationship_type="uses",
            target_value="WINELOADER", confidence=0.9)],
    )
    bundle = build_stix_bundle([], llm, "r")
    rel = _find_rel(bundle, "threat-actor", "malware")
    assert rel is not None and rel.relationship_type == "uses"


def test_indicator_based_on_observed_data_chain():
    # Spec-pure chain: SCO ◄ observed-data ◄ indicator --based-on-->.
    entities = [RawEntity(value="9.9.9.9", entity_type=EntityType.IPV4)]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "r")
    types = [o.get("type") for o in bundle.objects]
    assert "observed-data" in types
    # indicator --based-on--> observed-data
    rel = _find_rel(bundle, "indicator", "observed-data")
    assert rel is not None and rel.relationship_type == "based-on"
    # observed-data references the SCO via object_refs
    od = next(o for o in bundle.objects if o.get("type") == "observed-data")
    sco = next(o for o in bundle.objects if o.get("type") == "ipv4-addr")
    assert sco.id in od.object_refs


def test_forced_edge_for_non_suggested_pair_is_downgraded():
    # Pin a non-suggested pair (tool uses malware is not in the spec table);
    # the forced edge must be emitted as related-to, never the bogus verb.
    pol = {"version": 1, "global": "enforce",
           "rules": [{"src": "tool", "verb": "uses", "tgt": "malware",
                      "mode": "pin", "enabled": True}]}
    llm = LLMEnrichmentResult(tools=["Cobalt Strike"], malware_families=["WINELOADER"])
    bundle = build_stix_bundle([], llm, "r", relationship_policy=pol)
    rel = _find_rel(bundle, "tool", "malware")
    assert rel is not None and rel.relationship_type == "related-to"


# ── IoC coverage verification ──────────────────────────────────────────────────

def test_ioc_coverage_all_observables_covered():
    entities = [
        RawEntity(value="185.225.74.19", entity_type=EntityType.IPV4),
        RawEntity(value="evil.com", entity_type=EntityType.DOMAIN),
        RawEntity(value="44d88612fea8a8f36de82e1278abb02f", entity_type=EntityType.MD5),
        RawEntity(value="AS15169", entity_type=EntityType.ASN),
    ]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "r")
    cov = verify_ioc_coverage(entities, bundle)
    assert cov["total_iocs"] == 4
    assert cov["with_sco"] == 4
    assert cov["with_indicator"] == 4
    assert cov["ok"] is True
    assert cov["missing_indicator"] == []


def test_ioc_coverage_flags_missing_indicator():
    # network_traffic maps to a 'software' SCO with no STIX pattern → no Indicator.
    entities = [
        RawEntity(value="8.8.8.8", entity_type=EntityType.IPV4),
        RawEntity(value="tcp/4444", entity_type=EntityType.NETWORK_TRAFFIC),
    ]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "r")
    cov = verify_ioc_coverage(entities, bundle)
    assert cov["total_iocs"] == 2
    assert cov["with_sco"] == 2           # both get an SCO
    assert cov["with_indicator"] == 1     # only the IPv4 gets an Indicator
    assert cov["ok"] is False
    assert cov["missing_indicator"] == [{"value": "tcp/4444", "type": "network_traffic"}]


def test_ioc_coverage_ignores_non_observable_entities():
    # CVE is regex-extracted but becomes a Vulnerability SDO, not an observable.
    entities = [
        RawEntity(value="CVE-2026-21412", entity_type=EntityType.CVE),
        RawEntity(value="1.2.3.4", entity_type=EntityType.IPV4),
    ]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "r")
    cov = verify_ioc_coverage(entities, bundle)
    assert cov["total_iocs"] == 1         # only the IPv4 counts as an observable IoC
    assert cov["ok"] is True


def test_ioc_coverage_deduplicates():
    entities = [
        RawEntity(value="1.2.3.4", entity_type=EntityType.IPV4),
        RawEntity(value="1.2.3.4", entity_type=EntityType.IPV4),
    ]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "r")
    cov = verify_ioc_coverage(entities, bundle)
    assert cov["total_iocs"] == 1


def test_cve_becomes_vulnerability():
    entities = [RawEntity(value="CVE-2021-40444", entity_type=EntityType.CVE)]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "test")
    types = [obj.get("type") for obj in bundle.objects]
    assert "vulnerability" in types


def test_report_object_present():
    bundle = build_stix_bundle([], _make_minimal_llm_result(), "my_report")
    reports = [obj for obj in bundle.objects if obj.get("type") == "report"]
    assert len(reports) == 1
    assert reports[0]["name"] == "my_report"


# ── External reference routing ─────────────────────────────────────────────────
# stix2validator enforces that external_id values matching CAPEC-N+ format
# MUST use source_name="capec".  Routing them to "mitre-attack" marks the
# bundle Invalid with error {104}. The tests below lock in the correct routing
# for all three ID families: CAPEC, ATT&CK tactic (TA), ATT&CK technique (T).

class TestExternalReferenceRouting:
    def _attack_patterns(self, mitre_id: str) -> list:
        """Build a bundle for a single TTP and return its attack-pattern objects."""
        llm = LLMEnrichmentResult(
            ttps=[TTPExtracted(technique_name="Test Technique", mitre_id=mitre_id)]
        )
        bundle = build_stix_bundle([], llm, "test_routing")
        return [obj for obj in bundle.objects if obj.get("type") == "attack-pattern"]

    def _ext_ref(self, mitre_id: str) -> dict:
        patterns = self._attack_patterns(mitre_id)
        assert len(patterns) == 1, f"Expected 1 attack-pattern, got {len(patterns)}"
        refs = patterns[0].get("external_references", [])
        assert len(refs) == 1, f"Expected 1 external_reference, got {len(refs)}"
        return refs[0]

    def test_capec_id_uses_capec_source_name(self):
        """CAPEC IDs must use source_name='capec', not 'mitre-attack'."""
        ref = self._ext_ref("CAPEC-98")
        assert ref["source_name"] == "capec"

    def test_capec_id_has_correct_url(self):
        """CAPEC URL must point to capec.mitre.org, not attack.mitre.org."""
        ref = self._ext_ref("CAPEC-630")
        assert ref["url"] == "https://capec.mitre.org/data/definitions/630.html"

    def test_capec_id_preserves_external_id(self):
        ref = self._ext_ref("CAPEC-233")
        assert ref["external_id"] == "CAPEC-233"

    def test_tactic_id_uses_mitre_attack_source(self):
        ref = self._ext_ref("TA0001")
        assert ref["source_name"] == "mitre-attack"
        assert "tactics" in ref["url"]

    def test_tactic_id_url_format(self):
        ref = self._ext_ref("TA0001")
        assert ref["url"] == "https://attack.mitre.org/tactics/TA0001/"

    def test_technique_id_uses_mitre_attack_source(self):
        ref = self._ext_ref("T1566.001")
        assert ref["source_name"] == "mitre-attack"

    def test_technique_id_url_format(self):
        ref = self._ext_ref("T1566.001")
        assert ref["url"] == "https://attack.mitre.org/techniques/T1566/001/"

    def test_technique_id_no_subtechnique(self):
        ref = self._ext_ref("T1059")
        assert ref["url"] == "https://attack.mitre.org/techniques/T1059/"

    def test_capec_id_case_insensitive(self):
        """Lowercase 'capec-98' should route the same as 'CAPEC-98'."""
        ref = self._ext_ref("capec-98")
        assert ref["source_name"] == "capec"

    def test_no_mitre_id_produces_no_external_refs(self):
        """A TTP without a MITRE ID should produce an attack-pattern with no external_references."""
        llm = LLMEnrichmentResult(
            ttps=[TTPExtracted(technique_name="Custom Loader")]
        )
        bundle = build_stix_bundle([], llm, "test_no_id")
        patterns = [obj for obj in bundle.objects if obj.get("type") == "attack-pattern"]
        assert len(patterns) == 1
        # external_references absent or empty
        refs = patterns[0].get("external_references") or []
        assert refs == []
