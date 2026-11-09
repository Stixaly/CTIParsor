"""validate_bundle returns an invalid verdict for a bundle nested past the recursion
limit, instead of letting RecursionError escape (#613, same contract as #500).

The stix2validator JSON decoder raises RecursionError on ~10 000+ levels of
nesting; before this fix only baseline_stix.intake caught it.
"""
import time

import pytest

from pipeline import stage5_validation
from pipeline.stage5_validation import INVALID, validate_bundle

MAX_SECONDS = 5.0

DEEP_BUNDLE = (
    '{"type": "bundle", "id": "bundle--11111111-1111-4111-8111-111111111111", "objects": ['
    + "[" * 20000 + "]" * 20000 + "]}"
)


@pytest.fixture
def schemas():
    """validate_bundle only runs the JSON-schema layer when the schemas are in place."""
    assert stage5_validation.install_schemas(), "the vendored schemas could not be installed"


def test_deep_bundle_is_invalid_not_an_exception(schemas):
    """(#613) A bundle nested 20 000 levels: INVALID verdict, no exception, fast."""
    start = time.perf_counter()
    result = validate_bundle(DEEP_BUNDLE)
    assert time.perf_counter() - start < MAX_SECONDS
    assert result.status == INVALID
    assert result.ok is False
    assert result.errors and "nested too deeply" in result.errors[0]


def test_deep_bundle_is_invalid_when_quiet(schemas):
    """(#613) `quiet` gives the same verdict for a deep bundle."""
    result = validate_bundle(DEEP_BUNDLE, quiet=True)
    assert result.status == INVALID
    assert result.errors
