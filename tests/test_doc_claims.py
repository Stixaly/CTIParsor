"""The numbers the documentation states still match their source of truth.

`make check-docs` (scripts/check_doc_claims.py) did this on demand only, so a
rebuilt gazetteer or a retuned threshold could leave README.md and
docs/pipeline.md wrong without anyone running it.  As a test it runs in CI.
"""
from __future__ import annotations

from scripts.check_doc_claims import DOCS, check_all


def _rows() -> list[tuple[str, str, str, str]]:
    return check_all("\n".join(p.read_text(encoding="utf-8") for p in DOCS))


def test_every_documented_number_matches_its_source():
    failed = [row for row in _rows() if row[0] == "FAIL"]
    assert not failed, f"documented number differs from its source (claim, documented, actual): {failed}"


def test_every_claim_is_still_found_in_the_docs():
    # A claim whose sentence was reworded or moved reports SKIP, and would then
    # stop being checked without anyone noticing.
    skipped = [row for row in _rows() if row[0] == "SKIP"]
    assert not skipped, f"claim no longer found, update its pattern in scripts/check_doc_claims.py: {skipped}"
