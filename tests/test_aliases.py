"""Tests for pipeline.aliases — offline MITRE alias canonicalisation (Option B)."""
from pipeline.aliases import (
    alias_surface_forms,
    canonical_name,
    mitre_id_for,
    technique_id_for,
    technique_name_for,
)


def test_alias_shares_mitre_id():
    """APT34 and OilRig are the same MITRE group (G0049)."""
    assert mitre_id_for("APT34") == mitre_id_for("OilRig") == "G0049"
    assert mitre_id_for("apt35") == mitre_id_for("Magic Hound") == "G0059"


def test_canonical_name_resolves_alias():
    """An alias resolves to its canonical display name."""
    assert canonical_name("APT34") == "OilRig"
    assert canonical_name("apt35") == "Magic Hound"


def test_canonical_name_passthrough_for_unknown():
    """Unknown names pass through unchanged (safe to apply blindly)."""
    assert canonical_name("Totally Novel Actor 9000") == "Totally Novel Actor 9000"
    assert mitre_id_for("Totally Novel Actor 9000") is None


def test_alias_surface_forms_are_bidirectional():
    """Surface forms for the canonical name include the alias, and vice versa."""
    forms = alias_surface_forms("OilRig")
    assert "apt34" in forms                # emitted canonical grounds against alias
    assert "oilrig" in forms
    assert "g0049" in forms                # the MITRE id is included too

    forms_from_alias = alias_surface_forms("APT34")
    assert "oilrig" in forms_from_alias    # emitted alias grounds against canonical


def test_technique_name_to_id_roundtrip():
    """A canonical technique name resolves to its MITRE id and back."""
    tid = technique_id_for("Spearphishing Link")
    assert tid == "T1566.002"
    assert technique_name_for("T1566.002") == "Spearphishing Link"


def test_technique_id_for_unknown_is_none():
    assert technique_id_for("Not A Real Technique") is None
