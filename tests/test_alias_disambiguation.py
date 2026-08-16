"""Regression tests for ADR-0021 type-aware alias resolution."""
import json
from pathlib import Path

import pipeline.aliases


def test_unambiguous_name_resolves_without_a_type():
    # rule 2 — an unambiguous form is unaffected by the fix.
    assert pipeline.aliases.mitre_id_for("oilrig") is not None
    assert pipeline.aliases.mitre_id_for("oilrig") == pipeline.aliases.mitre_id_for("oilrig", "threat-actor")


def test_snake_resolves_to_the_group_when_asked_for_a_threat_actor():
    assert pipeline.aliases.mitre_id_for("snake", "threat-actor") == "G0010"


def test_snake_resolves_to_the_malware_when_asked_for_malware():
    assert pipeline.aliases.mitre_id_for("snake", "malware") == "S0022"


def test_ambiguous_name_without_a_type_resolves_to_nothing():
    # refusing to guess is the point; the old code returned whichever id
    # the gazetteer listed last.
    assert pipeline.aliases.mitre_id_for("snake") is None


def test_ambiguous_name_keeps_its_own_name():
    assert pipeline.aliases.canonical_name("snake") == "snake"
    assert pipeline.aliases.canonical_name("sofacy") == "sofacy"


def test_canonical_name_is_type_aware():
    assert pipeline.aliases.canonical_name("snake", "threat-actor") == "Turla"
    assert pipeline.aliases.canonical_name("snake", "malware") == "Uroburos"


def test_surface_forms_never_leak_the_other_objects_aliases():
    forms = pipeline.aliases.alias_surface_forms("snake")
    assert forms == {"snake"}
    actor_forms = pipeline.aliases.alias_surface_forms("snake", "threat-actor")
    assert "turla" in actor_forms
    assert "g0010" in actor_forms
    # this is the defect that mis-wired relationship endpoints — the
    # malware node used to absorb every Turla group alias.


def test_two_groups_sharing_an_alias_are_never_merged():
    assert pipeline.aliases.mitre_id_for("uac-0056", "threat-actor") is None
    assert pipeline.aliases.canonical_name("uac-0056", "threat-actor") == "uac-0056"
    # G1031 and G1003 are distinct ATT&CK groups; the type cannot narrow
    # them, so passthrough is correct.


def test_no_surface_form_silently_overwrites_another():
    gaz_path = Path(pipeline.aliases.__file__).parent / "data" / "gazetteer.json"
    entries = json.loads(gaz_path.read_text(encoding="utf-8"))
    expected: dict[str, set[str]] = {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        mid = e.get("mitre_id")
        if not isinstance(mid, str) or not mid.strip():
            continue
        mid = mid.strip()
        name = (e.get("name") or "").lower().strip()
        canonical = (e.get("canonical") or "").strip()
        if name:
            expected.setdefault(name, set()).add(mid)
        if canonical:
            c_lower = canonical.lower().strip()
            expected.setdefault(c_lower, set()).add(mid)
    name2ids, _, _, _ = pipeline.aliases._load()
    assert name2ids == expected
    # locks the "keep every candidate" property itself, so a
    # future refactor cannot reintroduce last-write-wins.


def test_empty_and_non_string_inputs_are_safe():
    assert pipeline.aliases.mitre_id_for("") is None
    assert pipeline.aliases.mitre_id_for(None) is None
    assert pipeline.aliases.mitre_id_for(123) is None
    assert pipeline.aliases.canonical_name("") == ""
    assert pipeline.aliases.alias_surface_forms("") == set()
    assert pipeline.aliases.mitre_id_for("snake", 42) is None


def test_unknown_names_pass_through():
    assert pipeline.aliases.canonical_name("totally-unknown-actor-xyz") == "totally-unknown-actor-xyz"
    assert pipeline.aliases.mitre_id_for("totally-unknown-actor-xyz") is None
