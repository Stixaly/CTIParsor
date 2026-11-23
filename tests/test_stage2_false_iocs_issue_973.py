"""pipeline/stage2_extraction.py — observables the regex pass made of a version
number, a technology name or a fingerprint that is not a file's hash (issue #973).

The rows of the issue's table must give nothing, or the right type.  The inverse
cases keep the real indicators the same guards must not drop.  The discard record
and the orchestrator's stage 2 details say what was refused, and why.
"""
import pytest

from models.schemas import EntityType
from pipeline.orchestrator import RAN, Document, RunOptions, run_document
from pipeline.stage2_extraction import discarded_counts, discarded_iocs, extract_entities

_OBSERVABLE_TYPES = {
    EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN, EntityType.URL, EntityType.FILE,
    EntityType.MD5, EntityType.SHA1, EntityType.SHA256,
}
_SHA256 = "3a7bd3e2360a3d80f6d1f0d5c1f0c5e2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6"


def _observables(text: str) -> set[tuple[str, str]]:
    return {(e.entity_type.value, e.value) for e in extract_entities(text) if e.entity_type in _OBSERVABLE_TYPES}


@pytest.mark.parametrize("text", [
    "The actor exploited Apache Log4j version 2.17.1.0 on the server.",
    "The web shell is written in ASP.NET and Node.js for the backend.",
    "imphash: 0123456789abcdef0123456789abcdef",
    "JA3 fingerprint 51c64c77e60f3980eea90869b68c58a8 was observed.",
    "fixed in commit 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 of the repo",
])
def test_a_row_of_the_issue_table_gives_no_observable(text):
    assert _observables(text) == set()


@pytest.mark.parametrize("text, expected", [
    ("Connections to 2.17.1.0:443", {("ipv4", "2.17.1.0")}),
    ("The C2 at asp[.]net", {("domain", "asp.net")}),
    ("MD5: 0123456789abcdef0123456789abcdef", {("md5", "0123456789abcdef0123456789abcdef")}),
    ("Version 1.2 of the tool contacted 185.220.101.45", {("ipv4", "185.220.101.45")}),
])
def test_a_real_indicator_next_to_a_version_or_a_label_is_kept(text, expected):
    assert _observables(text) == expected


def test_an_ordinary_ioc_table_with_a_sha256_header_is_unchanged():
    text = (
        "File name SHA256\n"
        f"invoice.exe {_SHA256}\n"
        "Indicators:\n"
        f"SHA256\n{_SHA256}\n"
        "185.220.101.45 evil-c2.com\n"
    )
    assert _observables(text) == {
        ("sha256", _SHA256), ("file", "invoice.exe"),
        ("ipv4", "185.220.101.45"), ("domain", "evil-c2.com"),
    }


def test_the_refusals_of_one_call_are_counted_with_examples():
    text = (
        "The actor exploited Apache Log4j version 2.17.1.0 and rev. 1.2.3.4. "
        "The web shell is written in ASP.NET and Node.js for VB.NET. "
        "imphash: 0123456789abcdef0123456789abcdef. "
        "JA3 fingerprint 51c64c77e60f3980eea90869b68c58a8 was observed. "
        "fixed in commit 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12."
    )
    extract_entities(text)

    assert discarded_counts() == {"version_number": 2, "technology_name": 3,
                                  "imphash": 1, "ja3": 1, "commit_id": 1}
    assert discarded_iocs()["version_number"] == ["2.17.1.0", "1.2.3.4"]
    assert discarded_iocs()["technology_name"] == ["ASP.NET", "VB.NET", "Node.js"]


def test_the_record_keeps_five_examples_and_starts_over_on_each_call():
    extract_entities(" ".join(f"version 10.0.0.{i}." for i in range(1, 8)))

    assert discarded_counts() == {"version_number": 7}
    assert discarded_iocs() == {"version_number": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]}

    extract_entities("Nothing refused here: 185.220.101.45.")
    assert discarded_counts() == {}
    assert discarded_iocs() == {}


@pytest.fixture
def _no_heavy_models(monkeypatch):
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


def _opts() -> RunOptions:
    """Fixed options: nothing read from the developer's .env."""
    return RunOptions(consensus=False, document_relations=False, llm_parallelism=1,
                      verify_relationships=False, verify_ttps=False, disabled=frozenset({"2f"}))


def test_stage_2_details_say_what_it_refused_summed_over_the_chunks(mock_llm, monkeypatch, _no_heavy_models):
    monkeypatch.setattr("pipeline.stage1_ingestion.chunk_text", lambda text, **kwargs: [
        "The actor exploited Apache Log4j version 2.17.1.0 on the server.",
        "Apache version 2.17.1.1 ran Node.js and ASP.NET.",
    ])
    monkeypatch.setattr("pipeline.stage2_extraction.nlp_status",
                        lambda: {"spacy_model": "en_core_web_sm", "spacy_skipped": False, "iocextract": True})

    result = run_document(Document(text="APT29 used SUNBURST."), _opts())

    stage2 = result.outcome("2")
    assert stage2.status == RAN
    assert stage2.details == {"spacy_model": "en_core_web_sm", "iocextract": True,
                              "discarded_iocs": {"version_number": 2, "technology_name": 2}}


def test_a_version_label_with_a_colon_is_not_an_address():
    from pipeline.stage2_extraction import extract_entities
    found = {(e.entity_type.value, e.value) for e in extract_entities("Version: 2.17.1.0 is affected.")}
    assert ("ipv4", "2.17.1.0") not in found
