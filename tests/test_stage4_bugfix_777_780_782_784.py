"""Stage 4 duplicate objects: one id, one object in the bundle (#777, #780, #782, #784)."""
from models.schemas import EntityType, RawEntity
from pipeline.stage3_llm import LLMEnrichmentResult, TTPExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle


def _objects(bundle, stix_type: str) -> list:
    return [o for o in bundle.objects if getattr(o, "type", "") == stix_type]


def _assert_ids_unique(bundle) -> None:
    ids = [o.id for o in bundle.objects if getattr(o, "id", None)]
    assert len(ids) == len(set(ids)), f"duplicate ids in bundle: {ids}"


# ── #777: two TTPs with the same MITRE id ────────────────────────────────────

def test_777_two_ttps_with_the_same_mitre_id_give_one_attack_pattern():
    """(#777) PowerShell / PowerShell Execution, both T1059.001: one AttackPattern, unique ids."""
    llm = LLMEnrichmentResult(ttps=[
        TTPExtracted(technique_name="PowerShell", mitre_id="T1059.001"),
        TTPExtracted(technique_name="PowerShell Execution", mitre_id="T1059.001"),
    ])
    bundle = build_stix_bundle([], llm, "r777", graph_completion=False)
    assert len(_objects(bundle, "attack-pattern")) == 1
    _assert_ids_unique(bundle)


# ── #780: course of action names differing only by case ──────────────────────

def test_780_course_of_action_names_differing_by_case_give_one_object():
    """(#780) "Enable MFA" / "enable mfa" share one deterministic id: one CourseOfAction."""
    llm = LLMEnrichmentResult(course_of_action=["Enable MFA", "enable mfa"])
    bundle = build_stix_bundle([], llm, "r780", graph_completion=False)
    assert len(_objects(bundle, "course-of-action")) == 1
    _assert_ids_unique(bundle)


# ── #782: an SDO must not merge into an object of another STIX type ─────────

def test_782_domain_and_infrastructure_with_the_same_value_give_both_objects():
    """(#782) DOMAIN example.com does not stop INFRASTRUCTURE example.com from being created."""
    entities = [
        RawEntity(value="example.com", entity_type=EntityType.DOMAIN, source_stage="regex"),
        RawEntity(value="example.com", entity_type=EntityType.INFRASTRUCTURE, source_stage="llm"),
    ]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "r782", graph_completion=False)
    assert len(_objects(bundle, "infrastructure")) == 1
    assert len(_objects(bundle, "domain-name")) == 1


# ── #784: keys ignore surrounding whitespace, as the ids do ──────────────────

def test_784_infrastructure_values_differing_by_trailing_space_give_one_object():
    """(#784) "Alpha" / "Alpha " share one standard id: one Infrastructure."""
    entities = [
        RawEntity(value="Alpha", entity_type=EntityType.INFRASTRUCTURE, source_stage="llm"),
        RawEntity(value="Alpha ", entity_type=EntityType.INFRASTRUCTURE, source_stage="llm"),
    ]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "r784", graph_completion=False)
    assert len(_objects(bundle, "infrastructure")) == 1
    _assert_ids_unique(bundle)


def test_784_targeted_countries_differing_by_trailing_space_give_one_location():
    """(#784) "France" / "France " share one Location id: one object."""
    llm = LLMEnrichmentResult(targeted_countries=["France", "France "])
    bundle = build_stix_bundle([], llm, "r784b", graph_completion=False)
    assert len(_objects(bundle, "location")) == 1
    _assert_ids_unique(bundle)


def test_784_targeted_sectors_differing_by_trailing_space_give_one_identity():
    """(#784) "Finance" / "Finance " share one Identity id: one object."""
    llm = LLMEnrichmentResult(targeted_sectors=["Finance", "Finance "])
    bundle = build_stix_bundle([], llm, "r784c", graph_completion=False)
    # the bundle's own author Identity is not a sector: only the "class" ones count
    sectors = [o for o in _objects(bundle, "identity") if o.identity_class == "class"]
    assert len(sectors) == 1
    _assert_ids_unique(bundle)
