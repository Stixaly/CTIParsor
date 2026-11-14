"""Regression tests for issue #786: a baseline URL whose path has capitals is found in the report.

The baseline is a small synthetic bundle, read by `intake`, the same way the pipeline
reads one; the report text is searched by `reconcile` (Stage 3r).
"""
from __future__ import annotations

import stix2

from pipeline import baseline_stix as bs
from pipeline.stage3_llm import LLMEnrichmentResult


def _index(*objects) -> bs.BaselineIndex:
    index, _intake, _bundle = bs.intake(stix2.Bundle(objects=list(objects)).serialize().encode(), validate=False)
    assert index is not None
    return index


def test_a_baseline_url_with_capitals_in_its_path_is_in_the_text_issue_786():
    url = "https://example.com/Payload.exe"
    index = _index(stix2.URL(value=url, allow_custom=True))
    entry = index.entries[0]
    report = f"The loader fetched {url} before it ran."
    rec = bs.reconcile([], LLMEnrichmentResult(), report, index)
    [row] = rec.imported_entities
    assert row.baseline_stix_id == entry.entry_id
    assert row.status == bs.BASELINE_IN_TEXT
    assert row.evidence_text == url
    assert report[row.evidence_start:row.evidence_end] == url
