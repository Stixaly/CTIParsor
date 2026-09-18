import stix2

from models.schemas import EntityType, RawEntity
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted, TTPExtracted
from pipeline.stage4_stix_mapping import (
    _entity_to_sdo,
    build_stix_bundle,
    verify_ioc_coverage,
)


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


def test_alias_actors_merge_into_one_sdo():
    """Two aliases of the same MITRE group (APT34 / OilRig, G0049) must collapse
    into a single ThreatActor SDO — the Option B pipeline merge."""
    llm = LLMEnrichmentResult(threat_actors=["APT34", "OilRig"])
    bundle = build_stix_bundle([], llm, "alias_merge")
    actors = [o for o in bundle.objects if getattr(o, "type", "") == "threat-actor"]
    assert len(actors) == 1, f"expected 1 merged actor, got {[a.name for a in actors]}"
    assert actors[0].name == "OilRig"   # canonical name wins


def test_relationship_resolves_via_alias():
    """A relationship that names the actor by an alias (APT34) resolves to the
    canonical node (OilRig), producing a real edge — not a dropped one."""
    llm = LLMEnrichmentResult(
        threat_actors=["OilRig"],
        malware_families=["WellMess"],
        relationships=[
            RelationshipExtracted(
                source_value="APT34",              # alias, not the emitted canonical
                relationship_type="uses",
                target_value="WellMess",
                confidence=0.9,
            )
        ],
    )
    bundle = build_stix_bundle([], llm, "alias_rel")
    actors = [o for o in bundle.objects if getattr(o, "type", "") == "threat-actor"]
    rels = [o for o in bundle.objects if getattr(o, "type", "") == "relationship"]
    assert len(actors) == 1
    assert any(r.source_ref == actors[0].id for r in rels), "alias edge should resolve"


def test_relationship_start_stop_time_and_description_propagate():
    """STIX 2.1 §5.1.2: start_time/stop_time/description are native SRO
    properties — an LLM relationship that carries them must produce a
    stix2.Relationship with those same fields set, not just the x_evidence_label
    custom property."""
    from datetime import datetime, timezone

    start = datetime(2022, 11, 4, tzinfo=timezone.utc)
    stop = datetime(2023, 3, 1, tzinfo=timezone.utc)
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"],
        malware_families=["WellMess"],
        relationships=[
            RelationshipExtracted(
                source_value="APT29",
                relationship_type="uses",
                target_value="WellMess",
                confidence=0.9,
                evidence_text="APT29 used WellMess between November 2022 and March 2023.",
                start_time=start,
                stop_time=stop,
            )
        ],
    )
    bundle = build_stix_bundle([], llm, "temporal")
    rel = next(o for o in bundle.objects if getattr(o, "type", "") == "relationship")
    assert rel.start_time == start
    assert rel.stop_time == stop
    assert rel.description == "APT29 used WellMess between November 2022 and March 2023."


def test_relationship_without_dates_has_no_start_stop_time():
    """No regression: a relationship with no extracted dates must not gain
    start_time/stop_time (and must not error trying to set them to None)."""
    bundle = build_stix_bundle([], _make_minimal_llm_result(), "no_dates")
    rel = next(o for o in bundle.objects if getattr(o, "type", "") == "relationship")
    assert "start_time" not in rel
    assert "stop_time" not in rel


def test_spurious_observable_to_ttp_edge_dropped():
    """An observable (domain) → attack-pattern edge is a type error the LLM
    sometimes emits; Stage 4 must drop it, not emit it as related-to."""
    entities = [RawEntity(value="evil.example.com", entity_type=EntityType.DOMAIN)]
    llm = LLMEnrichmentResult(
        ttps=[TTPExtracted(technique_name="Application Layer Protocol", mitre_id="T1071.001")],
        relationships=[
            RelationshipExtracted(
                source_value="evil.example.com",
                relationship_type="communicates-with",
                target_value="Application Layer Protocol",
                confidence=0.8,
            )
        ],
    )
    bundle = build_stix_bundle(entities, llm, "spurious")
    rels = [o for o in bundle.objects if getattr(o, "type", "") == "relationship"]
    ap = next(o for o in bundle.objects if getattr(o, "type", "") == "attack-pattern")
    dom = next(o for o in bundle.objects if getattr(o, "type", "") == "domain-name")
    assert not any(
        {r.source_ref, r.target_ref} == {ap.id, dom.id} for r in rels
    ), "observable↔attack-pattern edge should be dropped"


def test_valid_actor_uses_ttp_edge_kept():
    """The type guard must NOT drop a legitimate actor uses attack-pattern edge."""
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"],
        ttps=[TTPExtracted(technique_name="Application Layer Protocol", mitre_id="T1071.001")],
        relationships=[
            RelationshipExtracted(
                source_value="APT29",
                relationship_type="uses",
                target_value="Application Layer Protocol",
                confidence=0.9,
            )
        ],
    )
    bundle = build_stix_bundle([], llm, "valid")
    rels = [o for o in bundle.objects if getattr(o, "type", "") == "relationship"]
    assert any(getattr(r, "relationship_type", "") == "uses" for r in rels), \
        "actor→TTP 'uses' edge must survive"


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


# ── Location entities whose name isn't a known country ─────────────────────────
# STIX 2.1 requires a Location to carry 'region', 'country', or 'latitude'+
# 'longitude'. A name-only Location always fails that constraint, so a raw
# LOCATION entity (city, region, ...) not in the hardcoded country table must
# be skipped rather than produce a Location object that can never construct.

def test_entity_to_sdo_skips_unmapped_location_name():
    """A LOCATION entity whose value isn't a known country (e.g. a city or
    region name) must return None instead of attempting a doomed Location()
    construction that always raises and gets silently swallowed."""
    entity = RawEntity(value="Kyiv", entity_type=EntityType.LOCATION)
    assert _entity_to_sdo(entity) is None


def test_entity_to_sdo_builds_location_for_known_country():
    entity = RawEntity(value="Ukraine", entity_type=EntityType.LOCATION)
    sdo = _entity_to_sdo(entity)
    assert sdo is not None
    assert sdo.type == "location"
    assert sdo.country == "UA"


def test_bundle_skips_unmapped_location_without_error():
    """A report mentioning a city (not in the country table) must not crash
    bundle generation, and must not produce a broken Location SDO."""
    raw_entities = [RawEntity(value="Kyiv", entity_type=EntityType.LOCATION)]
    llm = LLMEnrichmentResult(threat_actors=["APT29"])
    bundle = build_stix_bundle(raw_entities, llm, "unmapped_location")
    locations = [o for o in bundle.objects if o.get("type") == "location"]
    assert locations == []


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


def test_ioc_coverage_network_traffic_gets_an_indicator():
    # ADR-0041: network_traffic maps to a 'software' SCO, which now has a STIX
    # pattern branch — it used to be silently dropped here (no Indicator),
    # which would have made ADR-0041's "route through the Indicator, or drop"
    # rule delete every network-traffic relationship instead of fixing it.
    entities = [
        RawEntity(value="8.8.8.8", entity_type=EntityType.IPV4),
        RawEntity(value="tcp/4444", entity_type=EntityType.NETWORK_TRAFFIC),
    ]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "r")
    cov = verify_ioc_coverage(entities, bundle)
    assert cov["total_iocs"] == 2
    assert cov["with_sco"] == 2           # both get an SCO
    assert cov["with_indicator"] == 2     # both get an Indicator
    assert cov["ok"] is True
    assert cov["missing_indicator"] == []


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


# ── ADR-0041: observables route through their Indicator ───────────────────────

def test_observable_to_malware_relationship_routes_through_indicator():
    """ADR-0041: a relationship from an observable SCO to an SDO must be
    re-anchored on the SCO's Indicator rather than the raw SCO itself."""
    entities = [RawEntity(value="evil.example.org", entity_type=EntityType.DOMAIN)]
    llm = LLMEnrichmentResult(
        malware_families=["WellMess"],
        relationships=[
            RelationshipExtracted(
                source_value="evil.example.org",
                relationship_type="hosts",
                target_value="WellMess",
                confidence=0.8,
            )
        ],
    )
    bundle = build_stix_bundle(entities, llm, "route_test")

    domain = next(o for o in bundle.objects if o.get("type") == "domain-name")
    malware = next(o for o in bundle.objects if o.get("type") == "malware")
    relationships = [o for o in bundle.objects if o.get("type") == "relationship"]
    indicators = {o.id for o in bundle.objects if o.get("type") == "indicator"}

    assert relationships, "expected at least one relationship in the bundle"
    for rel in relationships:
        assert rel.source_ref != domain.id
        assert rel.target_ref != domain.id

    assert any(
        rel.source_ref in indicators and rel.target_ref == malware.id
        for rel in relationships
    )


def test_observable_to_observable_relationship_left_alone():
    """ADR-0041 scope boundary: when both endpoints are observable SCOs the
    edge is left as a direct SCO-to-SCO relationship (no redirect)."""
    entities = [
        RawEntity(value="evil.example.org", entity_type=EntityType.DOMAIN),
        RawEntity(value="1.2.3.4", entity_type=EntityType.IPV4),
    ]
    llm = LLMEnrichmentResult(
        relationships=[
            RelationshipExtracted(
                source_value="evil.example.org",
                relationship_type="resolves-to",
                target_value="1.2.3.4",
                confidence=0.9,
            )
        ]
    )
    bundle = build_stix_bundle(entities, llm, "both_observable")

    domain = next(o for o in bundle.objects if o.get("type") == "domain-name")
    ip = next(o for o in bundle.objects if o.get("type") == "ipv4-addr")
    relationships = [o for o in bundle.objects if o.get("type") == "relationship"]

    assert any(
        rel.source_ref == domain.id and rel.target_ref == ip.id
        for rel in relationships
    )


def test_network_traffic_gets_an_indicator():
    """ADR-0041: the new 'software' pattern branch means a NETWORK_TRAFFIC
    entity (placeholder SCO type 'software') now yields an Indicator instead
    of being silently dropped."""
    entities = [
        RawEntity(value="beacon to 10.0.0.1:443", entity_type=EntityType.NETWORK_TRAFFIC)
    ]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "nt_test")

    types = {o.get("type") for o in bundle.objects}
    assert "software" in types
    assert "indicator" in types


# ── ADR-0042: embedded detection rules become Indicator SDOs ──────────────────

def test_embedded_yara_rule_becomes_indicator_and_links_to_malware():
    report_text = """Some prose before.

rule Detects_LOCKBIT_Variant
{
  meta:
    author = "x"
  strings:
    $s1 = "foo"
  condition:
    $s1
}

More prose after.
"""
    bundle = build_stix_bundle([], LLMEnrichmentResult(malware_families=["LOCKBIT"]), "r", report_text=report_text)
    indicators = [o for o in bundle.objects if o.get("type") == "indicator" and o.get("pattern_type") == "yara"]
    assert len(indicators) == 1
    indicator = indicators[0]
    assert indicator.name == "Yara rule: Detects_LOCKBIT_Variant"
    malware = next(o for o in bundle.objects if o.get("type") == "malware" and o.get("name") == "LOCKBIT")
    rels = [
        o for o in bundle.objects
        if o.get("type") == "relationship"
        and o.get("source_ref") == indicator.id
        and o.get("target_ref") == malware.id
    ]
    assert len(rels) == 1


def test_embedded_yara_private_rule_is_not_extracted():
    report_text = """Some prose.

private rule Helper_1 { condition: true }

More prose."""
    bundle = build_stix_bundle([], LLMEnrichmentResult(), "r", report_text=report_text)
    assert not any(o.get("type") == "indicator" and o.get("pattern_type") == "yara" for o in bundle.objects)


_SURICATA_LINE = (
    'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
    '(msg:"ET TROJAN Sandworm C2 Checkin"; sid:2030001; rev:1;)'
)


def test_embedded_suricata_rule_becomes_indicator():
    report_text = f"Some prose.\n\n{_SURICATA_LINE}\n\nMore prose."
    bundle = build_stix_bundle([], LLMEnrichmentResult(), "r", report_text=report_text)
    indicators = [o for o in bundle.objects if o.get("type") == "indicator" and o.get("pattern_type") == "suricata"]
    assert len(indicators) == 1
    indicator = indicators[0]
    assert indicator.name == "Suricata rule: ET TROJAN Sandworm C2 Checkin"
    assert indicator.pattern == _SURICATA_LINE


def test_embedded_rule_is_typed_snort_via_context_word():
    report_text = f"The following Snort rule detects this:\n\n{_SURICATA_LINE}"
    bundle = build_stix_bundle([], LLMEnrichmentResult(), "r", report_text=report_text)
    indicators = [o for o in bundle.objects if o.get("type") == "indicator" and o.get("pattern_type") == "snort"]
    assert len(indicators) == 1


def test_embedded_net_rule_ignores_non_rule_lines():
    report_text = "Some prose.\n\nalert everyone: the deploy failed\n\nMore prose."
    bundle = build_stix_bundle([], LLMEnrichmentResult(), "r", report_text=report_text)
    assert not any(
        o.get("type") == "indicator" and o.get("pattern_type") in ("suricata", "snort")
        for o in bundle.objects
    )


def test_embedded_sigma_rule_becomes_indicator():
    report_text = """Some prose.

title: Suspicious PowerShell Download
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: DownloadString
    condition: selection
level: high

More prose after."""
    bundle = build_stix_bundle([], LLMEnrichmentResult(), "r", report_text=report_text)
    indicators = [o for o in bundle.objects if o.get("type") == "indicator" and o.get("pattern_type") == "sigma"]
    assert len(indicators) == 1
    indicator = indicators[0]
    assert indicator.name == "Sigma rule: Suspicious PowerShell Download"
    assert indicator.pattern == (
        "title: Suspicious PowerShell Download\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        "    selection:\n"
        "        CommandLine|contains: DownloadString\n"
        "    condition: selection\n"
        "level: high"
    )


def test_embedded_sigma_rule_without_detection_key_is_not_extracted():
    report_text = """Some prose.

title: Not Actually A Sigma Rule
description: just a title and a description, no detection logic

More prose after."""
    bundle = build_stix_bundle([], LLMEnrichmentResult(), "r", report_text=report_text)
    assert not any(o.get("type") == "indicator" and o.get("pattern_type") == "sigma" for o in bundle.objects)


def test_embedded_rule_indicator_ids_are_stable_across_rebuilds():
    report_text = """Some prose before.

rule Detects_LOCKBIT_Variant
{
  meta:
    author = "x"
  strings:
    $s1 = "foo"
  condition:
    $s1
}

More prose after.
"""
    bundle1 = build_stix_bundle([], LLMEnrichmentResult(malware_families=["LOCKBIT"]), "r", report_text=report_text)
    bundle2 = build_stix_bundle([], LLMEnrichmentResult(malware_families=["LOCKBIT"]), "r", report_text=report_text)
    ind1 = next(o for o in bundle1.objects if o.get("type") == "indicator" and o.get("pattern_type") == "yara")
    ind2 = next(o for o in bundle2.objects if o.get("type") == "indicator" and o.get("pattern_type") == "yara")
    assert ind1.id == ind2.id


# ── ADR-0043: source document embedded as Artifact.payload_bin ────────────────

def test_source_bytes_produce_a_self_contained_artifact():
    """STIX 2.1 requires exactly one of payload_bin/url on an Artifact — a
    hash alone (the pre-ADR-0043 behaviour) can never produce a valid object."""
    import base64
    import hashlib

    data = b"%PDF-1.4 fake pdf bytes for testing"
    real_hash = hashlib.sha256(data).hexdigest()
    bundle = build_stix_bundle(
        [], LLMEnrichmentResult(), "r",
        original_filename="report.pdf", source_hash=real_hash, source_bytes=data,
    )
    artifact = next(o for o in bundle.objects if o.get("type") == "artifact")
    assert artifact.mime_type == "application/pdf"
    assert base64.b64decode(artifact.payload_bin) == data
    assert artifact.hashes["SHA-256"] == real_hash
    report = next(o for o in bundle.objects if o.get("type") == "report")
    assert artifact.id in report.object_refs


def test_no_artifact_without_source_bytes():
    """A hash with no bytes behind it must not attempt (and silently fail) to
    build an Artifact — this was the bug ADR-0043 fixes: source_hash alone
    used to raise MutuallyExclusivePropertiesError, swallowed by a bare
    except Exception, so the artifact silently never existed."""
    import hashlib

    real_hash = hashlib.sha256(b"anything").hexdigest()
    bundle = build_stix_bundle(
        [], LLMEnrichmentResult(), "r",
        original_filename="report.pdf", source_hash=real_hash, source_bytes=None,
    )
    assert not any(o.get("type") == "artifact" for o in bundle.objects)
