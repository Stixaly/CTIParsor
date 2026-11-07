"""validate_bundle returns an invalid verdict for input that is not a STIX bundle,
instead of raising (#500).

Before the fix, an empty string or malformed JSON raised JSONDecodeError, an
object without id/type raised stix2validator's ValidationError, and a JSON list
raised AttributeError.  The documented result for a bad bundle is
ValidationResult(INVALID, errors=[...]).
"""
import pytest

from pipeline import stage5_validation
from pipeline.stage5_validation import INVALID, validate_bundle


@pytest.fixture
def schemas():
    """validate_bundle only runs the JSON-schema layer when the schemas are in place."""
    assert stage5_validation.install_schemas(), "the vendored schemas could not be installed"


@pytest.mark.parametrize("raw", [
    "",                     # empty input: JSONDecodeError before the fix
    "{not json",            # malformed JSON
    '{"foo": "bar"}',       # an object without id/type: ValidationError before the fix
    "[]",                   # a JSON list: AttributeError before the fix
    '"just a string"',      # a JSON scalar
])
def test_bad_input_is_invalid_not_an_exception(raw, schemas):
    """(#500) A non-bundle input comes back as INVALID with at least one message."""
    result = validate_bundle(raw)
    assert result.status == INVALID
    assert result.ok is False
    assert result.errors and all(isinstance(e, str) and e for e in result.errors)


def test_bad_input_is_invalid_when_quiet(schemas):
    """(#500) `quiet` gives the same verdict without logging it."""
    result = validate_bundle("[]", quiet=True)
    assert result.status == INVALID
    assert result.errors
