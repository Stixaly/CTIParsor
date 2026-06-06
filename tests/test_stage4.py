import stix2
from models.schemas import RawEntity, EntityType
from pipeline.stage3_llm import LLMEnrichmentResult, TTPExtracted, RelationshipExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle


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
