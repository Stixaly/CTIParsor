import pytest

from models.schemas import EntityType, EvidenceLabel, RawEntity
from pipeline.stage3_llm import TTPExtracted
from pipeline.stage3c_mitre import normalize_ttps

_INDEX_OK = len(normalize_ttps([TTPExtracted(technique_name="Phishing",
                                             mitre_id="T1566")])) == 1


def _llm_ttp(mitre_id: str, description: str = "",
             evidence_text: str | None = None) -> TTPExtracted:
    """An LLM-extracted technique."""
    return TTPExtracted(technique_name="X", mitre_id=mitre_id,
                        description=description, evidence_text=evidence_text)


def _sem_ent(mitre_id: str, context: str, confidence: float) -> RawEntity:
    """A Stage 2c semantic match: its context is a sentence SELECTED from the
    report, so it is verbatim by construction."""
    return RawEntity(value="X", entity_type=EntityType.TTP, context=context,
                     confidence=confidence, mitre_id=mitre_id, source="semantic")


@pytest.mark.skipif(not _INDEX_OK, reason="MITRE index unavailable")
def test_llm_own_quote_is_preferred():
    """The LLM's own evidence quote must win over a medium-confidence semantic match."""
    ttps = [_llm_ttp("T1566.002", evidence_text="LLM QUOTE")]
    sems = [_sem_ent("T1566.002", "SEM SENTENCE", 0.50)]
    out = normalize_ttps(ttps, sems)
    assert len(out) == 1
    assert out[0].evidence_text == "LLM QUOTE"


@pytest.mark.skipif(not _INDEX_OK, reason="MITRE index unavailable")
def test_medium_semantic_supplies_evidence_when_llm_has_none():
    """Corroboration case: the LLM names the technique, the semantic match supplies the verbatim sentence."""
    ttps = [_llm_ttp("T1566.002")]
    sems = [_sem_ent("T1566.002", "SEM SENTENCE", 0.50)]
    out = normalize_ttps(ttps, sems)
    assert len(out) == 1
    assert out[0].evidence_text == "SEM SENTENCE"


@pytest.mark.skipif(not _INDEX_OK, reason="MITRE index unavailable")
def test_high_semantic_supplies_evidence_when_llm_has_none():
    """A high-confidence semantic match also fills in the evidence when the LLM has none."""
    ttps = [_llm_ttp("T1566.002")]
    sems = [_sem_ent("T1566.002", "SEM SENTENCE", 0.70)]
    out = normalize_ttps(ttps, sems)
    assert len(out) == 1
    assert out[0].evidence_text == "SEM SENTENCE"


@pytest.mark.skipif(not _INDEX_OK, reason="MITRE index unavailable")
def test_high_semantic_evidence_survives_a_longer_llm_description():
    """Regression: a longer LLM description must not clobber the semantic evidence text."""
    long_desc = "A very long description that is definitely longer than the semantic context string."
    ttps = [_llm_ttp("T1566.002", description=long_desc)]
    sems = [_sem_ent("T1566.002", "SEM", 0.70)]
    out = normalize_ttps(ttps, sems)
    assert len(out) == 1
    assert out[0].description == long_desc
    assert out[0].evidence_text == "SEM"


@pytest.mark.skipif(not _INDEX_OK, reason="MITRE index unavailable")
def test_medium_semantic_alone_still_creates_a_technique():
    """A medium-confidence semantic match on an id the LLM did not mention still yields an entry."""
    sems = [_sem_ent("T1027", "SEM SENTENCE", 0.50)]
    out = normalize_ttps([], sems)
    assert len(out) == 1
    assert out[0].evidence_text == "SEM SENTENCE"


@pytest.mark.skipif(not _INDEX_OK, reason="MITRE index unavailable")
def test_semantic_never_renames_a_technique_the_llm_found():
    """The semantic match must not rename the technique the LLM already resolved."""
    ttps = [_llm_ttp("T1105")]
    sems = [_sem_ent("T1105", "SEM SENTENCE", 0.50)]
    out = normalize_ttps(ttps, sems)
    assert len(out) == 1
    assert out[0].mitre_id == "T1105"


@pytest.mark.skipif(not _INDEX_OK, reason="MITRE index unavailable")
def test_no_semantic_entities_leaves_llm_evidence_untouched():
    """Passing None for semantic entities must leave the LLM evidence text intact."""
    ttps = [_llm_ttp("T1071.001", evidence_text="LLM QUOTE")]
    out = normalize_ttps(ttps, None)
    assert len(out) == 1
    assert out[0].evidence_text == "LLM QUOTE"


@pytest.mark.skipif(not _INDEX_OK, reason="MITRE index unavailable")
def test_empty_semantic_context_is_ignored():
    """An empty semantic context must not be used as evidence text."""
    ttps = [_llm_ttp("T1566.002")]
    sems = [_sem_ent("T1566.002", "", 0.50)]
    out = normalize_ttps(ttps, sems)
    assert len(out) == 1
    assert out[0].evidence_text is None


@pytest.mark.skipif(not _INDEX_OK, reason="MITRE index unavailable")
def test_evidence_label_is_preserved_from_the_llm():
    """The evidence label set by the LLM must be preserved in the output."""
    ttp = _llm_ttp("T1566.002")
    ttp.evidence_label = EvidenceLabel.OBSERVED
    out = normalize_ttps([ttp], None)
    assert len(out) == 1
    assert out[0].evidence_label == EvidenceLabel.OBSERVED


@pytest.mark.skipif(not _INDEX_OK, reason="MITRE index unavailable")
def test_parent_is_subsumed_but_child_keeps_its_evidence():
    """A parent technique is removed when its sub-technique is present; the child keeps its evidence."""
    ttps = [
        _llm_ttp("T1059"),
        _llm_ttp("T1059.001", evidence_text="CHILD"),
    ]
    out = normalize_ttps(ttps, None)
    ids = {t.mitre_id for t in out}
    assert "T1059" not in ids
    assert "T1059.001" in ids
    child = next(t for t in out if t.mitre_id == "T1059.001")
    assert child.evidence_text == "CHILD"


@pytest.mark.skipif(not _INDEX_OK, reason="MITRE index unavailable")
def test_returns_a_list_of_ttpextracted():
    """The return value must be a list of TTPExtracted instances."""
    ttps = [_llm_ttp("T1566.002")]
    out = normalize_ttps(ttps, None)
    assert isinstance(out, list)
    for item in out:
        assert isinstance(item, TTPExtracted)
