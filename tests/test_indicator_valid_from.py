"""An IoC's Indicator is valid from the report's date, not the build's (audit B 8.1.10).

`valid_from` was the time the bundle was built, and there was no
`valid_until`: an IoC a 2021 report names was valid "from today", for ever.
It is now the report's publication date when the document gives one; OpenCTI
computes `valid_until` from its decay rule and creates an Indicator whose
lifetime is over already revoked, as an IoC of an old report should be.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from models.schemas import EntityType, RawEntity
from pipeline import stage4_stix_mapping as s4
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import IoCAssociation, LLMEnrichmentResult
from pipeline.temporal import Anchor

IOCS = [RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4),
        RawEntity(value="evil-c2.example-bad.top", entity_type=EntityType.DOMAIN)]
LLM = LLMEnrichmentResult(malware_families=["WellMess"], ioc_associations=[
    IoCAssociation(ioc_value="185.220.101.45", malware_name="WellMess")])
YARA = "rule Loader { strings: $a = \"loader\" condition: $a }"


def _build(anchor):
    ledger = MappingLedger()
    bundle = s4.build_stix_bundle(IOCS, LLM, "r", report_text=f"text\n{YARA}\n",
                                  document_anchor=anchor, ledger=ledger)
    iocs = [o for o in bundle.objects if o["type"] == "indicator" and o["pattern_type"] == "stix"]
    return bundle, iocs, ledger.to_dict()


def _stamp(value) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def test_an_iocs_indicator_is_valid_from_the_report_date():
    _, iocs, ledger = _build(Anchor(value="2021-05-10", source="publication_meta"))
    assert len(iocs) == 2
    for ind in iocs:
        assert _stamp(ind["valid_from"]) == datetime(2021, 5, 10, tzinfo=timezone.utc)
        assert "valid_until" not in ind
        assert ledger["objects"][ind.id]["valid_from_basis"] == "report_published"


def test_without_a_report_date_it_is_the_build_time():
    for anchor in (None,
                   Anchor(value="2021-05-10", source="file_metadata"),        # not publication-grade
                   Anchor(value="2999-01-01", source="publication_meta")):    # not a past date
        before = datetime.now(timezone.utc) - timedelta(seconds=5)
        _, iocs, ledger = _build(anchor)
        for ind in iocs:
            assert _stamp(ind["valid_from"]) >= before
            assert ledger["objects"][ind.id]["valid_from_basis"] == "build_time"


def test_a_quoted_detection_rule_keeps_the_build_time():
    """A rule still detects its family years later: not dated by the report."""
    before = datetime.now(timezone.utc) - timedelta(seconds=5)
    bundle, _, _ = _build(Anchor(value="2021-05-10", source="publication_meta"))
    rules = [o for o in bundle.objects if o["type"] == "indicator" and o["pattern_type"] == "yara"]
    assert rules and all(_stamp(r["valid_from"]) >= before for r in rules)
