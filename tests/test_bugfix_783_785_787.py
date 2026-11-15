"""Regression tests for three bugs found in triage.

#783: validate_bundle() let TypeError escape when a bundle's ``objects`` is
null or holds a non-object: the verdict must be INVALID, not an exception.
#785: a bundle with an empty ``objects`` (list or object) was VALIDATED; the
bundle schema requires at least one object.
#787: document-level relations (3doc) ran after Stage 3 had failed, making
another call to the same unusable provider; they must be skipped.
"""
from __future__ import annotations

from dataclasses import replace

import pytest
import stix2

import pipeline.stage3_llm as s3
from pipeline import stage5_validation
from pipeline.orchestrator import Document, run_document
from pipeline.stage3_llm import LLMEnrichmentResult
from pipeline.stage5_validation import (
    INVALID,
    VALIDATED,
    validate_and_export,
    validate_bundle,
    validate_without_trusted,
)
from tests.test_orchestrator import _opts

BUNDLE_ID = "bundle--00000000-0000-4000-8000-000000000000"


@pytest.fixture
def schemas():
    """The vendored schemas must be in place: the schema layer is what #785 needs."""
    assert stage5_validation.install_schemas(), "the vendored schemas could not be installed"


def _bundle(objects: str) -> str:
    return f'{{"type": "bundle", "id": "{BUNDLE_ID}", "objects": {objects}}}'


# ── #783 ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("objects", ["null", "[null]", "[1]"])
def test_783_a_non_object_in_objects_is_invalid_not_an_exception(schemas, objects):
    result = validate_bundle(_bundle(objects), quiet=True)

    assert result.status == INVALID
    assert result.errors


# ── #785 ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("objects", ["{}", "null", "3", '"x"'])
def test_785_an_objects_that_is_not_a_list_is_invalid(schemas, objects):
    result = validate_bundle(_bundle(objects), quiet=True)

    assert result.status == INVALID
    assert any("objects" in e for e in result.errors)


def test_785_an_empty_objects_list_stays_validated(schemas):
    """Guard for the decision: [] is a legitimate subset once the trusted
    baseline objects are filtered out (validation_json), so it is not refused."""
    result = validate_bundle(_bundle("[]"), quiet=True)

    assert result.status == VALIDATED


def test_785_a_bundle_with_no_object_is_invalid(schemas, tmp_path):
    out = tmp_path / "bundle.json"
    bundle = stix2.Bundle(allow_custom=True)

    result = validate_and_export(bundle, str(out))

    assert result.status == INVALID
    assert any("no object" in e for e in result.errors)
    assert (tmp_path / "bundle_invalid.json").exists() and not out.exists()


def test_785_a_bundle_whose_objects_are_all_trusted_stays_validated(schemas, tmp_path):
    """The subset Stage 5 sees is empty, the bundle is not."""
    out = tmp_path / "bundle.json"
    malware = stix2.v21.Malware(name="Known", is_family=False)
    bundle = stix2.Bundle(malware, allow_custom=True)

    result = validate_and_export(bundle, str(out), trusted=frozenset({malware.id}))

    assert result.status == VALIDATED
    assert out.exists() and not (tmp_path / "bundle_invalid.json").exists()
    assert malware.id in out.read_text(encoding="utf-8")


def test_785_the_worker_gives_the_same_verdicts(schemas):
    whole = _bundle("[]")
    assert validate_without_trusted(whole, frozenset()).status == INVALID
    assert validate_without_trusted(whole, frozenset({"malware--x"})).status == INVALID


# ── #787 ─────────────────────────────────────────────────────────────────────

def test_787_document_relations_are_skipped_when_stage3_failed(sample_cti_text, monkeypatch):
    """Every Stage 3 call fails: 3 is FAILED, so 3doc must be SKIPPED and must
    not call the provider again."""
    def not_found(system, user, max_tokens=None):
        raise RuntimeError("Error code: 404 - The model `Qwen` does not exist.")

    monkeypatch.setattr(s3, "_PROVIDER", "anthropic")
    monkeypatch.setattr(s3, "_call_anthropic_impl", not_found)
    calls = []

    def doc_relations(*args, **kwargs):
        calls.append(args)
        return LLMEnrichmentResult()

    monkeypatch.setattr(s3, "enrich_document_relations", doc_relations)

    result = run_document(Document(text=sample_cti_text),
                          replace(_opts(), document_relations=True))

    assert result.outcome("3").status == "failed"
    skipped = result.outcome("3doc")
    assert skipped.status == "skipped"
    assert skipped.reason == "Stage 3 failed"
    assert calls == []


@pytest.mark.parametrize("off", [
    {"disabled": frozenset({"2f", "3doc"}), "document_relations": True},
    {"document_relations": False},
])
def test_787_a_switched_off_3doc_keeps_its_disabled_status_when_stage3_failed(
        sample_cti_text, monkeypatch, off):
    """3doc is off: the failed Stage 3 must not rewrite its status as
    'Stage 3 failed', and the provider is still not called."""
    def not_found(system, user, max_tokens=None):
        raise RuntimeError("Error code: 404 - The model `Qwen` does not exist.")

    monkeypatch.setattr(s3, "_PROVIDER", "anthropic")
    monkeypatch.setattr(s3, "_call_anthropic_impl", not_found)
    calls = []

    def doc_relations(*args, **kwargs):
        calls.append(args)
        return LLMEnrichmentResult()

    monkeypatch.setattr(s3, "enrich_document_relations", doc_relations)

    result = run_document(Document(text=sample_cti_text), replace(_opts(), **off))

    assert result.outcome("3").status == "failed"
    skipped = result.outcome("3doc")
    assert skipped.status == "skipped"
    assert skipped.reason == "disabled"
    assert calls == []
