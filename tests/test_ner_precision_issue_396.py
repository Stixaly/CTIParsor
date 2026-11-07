"""Issue 396: a country written in lower case is not a place, and a multi-word product
name ("Active Directory") is not a threat actor.

The filters are pure functions (ADR-0088), so these are tested on the functions directly.
"""
import pytest

from models.schemas import EntityType
from pipeline import ner_precision

ACTOR = EntityType.THREAT_ACTOR
LOCATION = EntityType.LOCATION


# ── D. spaCy places: the capital letter comes before the country table ───────

@pytest.mark.parametrize("value", ["us", "russia", "iran", "usa", "the us", "north korea"])
def test_a_lowercase_country_is_not_a_place(value):
    assert ner_precision.refine_spacy(value, LOCATION) == ""


@pytest.mark.parametrize("value", ["US", "UK", "Russia", "Iran", "the United States", "Saudi\nArabia"])
def test_a_capitalised_country_is_still_a_place(value):
    """Control: the same countries with a capital letter are kept, as before."""
    assert ner_precision.refine_spacy(value, LOCATION) != ""


# ── A. CyNER threat actors: a product name is not a name of an actor ─────────

@pytest.mark.parametrize("value", ["Active Directory", "active directory", "Active\nDirectory", "Active  Directory"])
def test_active_directory_is_not_a_threat_actor(value):
    assert ner_precision.actor_is_ordinary(value) is True
    assert ner_precision.refine_cyner(value, ACTOR) == ""


def test_active_directory_is_in_the_platform_list():
    """Read from the Stage 2 product blocklist, not kept in ner_precision."""
    assert "active directory" in ner_precision._platforms()


def test_a_real_actor_name_still_passes(monkeypatch):
    """Control: an actor name made of ordinary words is kept."""
    assert ner_precision.actor_is_ordinary("Lazarus Group") is False
    assert ner_precision.refine_cyner("Lazarus Group", ACTOR) == "Lazarus Group"
