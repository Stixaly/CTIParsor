"""validate_bundle returns an invalid verdict for a bundle nested very deeply,
instead of letting RecursionError escape (#613, same contract as #500).

Where the decoder gives up depends on the interpreter (3.13 raises
RecursionError at ~10 000 levels, 3.14 at ~100 000), so the deep bundles are
taken on both sides of the limit, and the RecursionError path is also forced.
"""
import time

import pytest

from pipeline import stage5_validation
from pipeline.stage5_validation import INVALID, validate_bundle

MAX_SECONDS = 5.0


def _deep_bundle(depth: int) -> str:
    return ('{"type": "bundle", "id": "bundle--11111111-1111-4111-8111-111111111111", "objects": ['
            + "[" * depth + "]" * depth + "]}")


@pytest.fixture
def schemas():
    """validate_bundle only runs the JSON-schema layer when the schemas are in place."""
    assert stage5_validation.install_schemas(), "the vendored schemas could not be installed"


@pytest.mark.parametrize("depth", [20000, 200000])
@pytest.mark.parametrize("quiet", [False, True])
def test_a_deep_bundle_is_invalid_not_an_exception(schemas, depth, quiet):
    """(#613) Nested 20 000 or 200 000 levels: an INVALID verdict, no exception, fast."""
    start = time.perf_counter()
    result = validate_bundle(_deep_bundle(depth), quiet=quiet)
    assert time.perf_counter() - start < MAX_SECONDS
    assert result.status == INVALID
    assert result.ok is False
    assert result.errors


def test_a_recursion_error_is_the_nested_too_deeply_verdict(schemas, monkeypatch):
    """(#613) The message is the one baseline_stix.intake gives for the same input."""
    def past_the_limit(*_args, **_kwargs):
        raise RecursionError("maximum recursion depth exceeded while decoding a JSON array")
    monkeypatch.setattr(stage5_validation, "validate_string", past_the_limit)
    result = validate_bundle(_deep_bundle(10), quiet=True)
    assert result.status == INVALID
    assert result.errors and "nested too deeply" in result.errors[0]
