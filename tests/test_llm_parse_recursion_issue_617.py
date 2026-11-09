"""LLM response parsers degrade to "unparsable" on JSON nested past the recursion
limit, instead of letting RecursionError escape and fail the whole job (#617).

Each parser scans a response for the first JSON value with raw_decode.  A value
nested ~20 000 levels deep raises RecursionError, which only llm_parse's
_drop_reasoning_blocks caught before this fix.  The scanning loops stop at the
first RecursionError: retrying at each later bracket would re-decode the deep
value every time, which took seconds per response.
"""
import json
import time

import pytest

from pipeline.llm_parse import parse_numbered_claims
from pipeline.stage3_llm import _parse_llm_response
from pipeline.stage3f_ttp_select import parse_selection, salvage_selection
from pipeline.stage4c_long_distance import _parse
from pipeline.vlm import _parse_payload

MAX_SECONDS = 5.0

DEEP_ARRAY = "[" * 30000 + "]" * 30000          # ~60 KB, the issue's input
DEEP_OBJECT = '{"a":' * 20000 + "1" + "}" * 20000  # ~140 KB, the issue's input


def _timed(fn, *args):
    start = time.perf_counter()
    result = fn(*args)
    return result, time.perf_counter() - start


def test_parse_numbered_claims_deep_array_is_unparsable():
    """(#617) parse_numbered_claims: no exception, None, under the time budget."""
    result, elapsed = _timed(parse_numbered_claims, DEEP_ARRAY, 3)
    assert result is None
    assert elapsed < MAX_SECONDS


def test_parse_numbered_claims_still_reads_a_normal_array():
    """(#617) The recursion guard does not change ordinary parsing."""
    raw = '[{"n": 1, "verified": true, "quote": "q"}]'
    result = parse_numbered_claims(raw, 3)
    assert result == {1: {"n": 1, "verified": True, "quote": "q"}}


def test_parse_selection_deep_object_is_unparsable():
    """(#617) parse_selection: no exception, None, under the time budget."""
    result, elapsed = _timed(parse_selection, DEEP_OBJECT)
    assert result is None
    assert elapsed < MAX_SECONDS


def test_parse_selection_deep_array_is_unparsable():
    """(#617) parse_selection on a deep bare array: None."""
    result, elapsed = _timed(parse_selection, DEEP_ARRAY)
    assert result is None
    assert elapsed < MAX_SECONDS


def test_salvage_selection_deep_object_is_unparsable():
    """(#617) salvage_selection (second raw_decode of stage 3f): None, no exception."""
    raw = '{"selected": [' + DEEP_OBJECT
    result, elapsed = _timed(salvage_selection, raw)
    assert result is None
    assert elapsed < MAX_SECONDS


def test_parse_llm_response_deep_object_is_unparsable():
    """(#617) stage 3 _parse_llm_response: no exception, None, under the time budget."""
    result, elapsed = _timed(_parse_llm_response, DEEP_OBJECT)
    assert result is None
    assert elapsed < MAX_SECONDS


def test_parse_llm_response_deep_array_is_unparsable():
    """(#617) stage 3 _parse_llm_response on a deep array: None."""
    result, elapsed = _timed(_parse_llm_response, DEEP_ARRAY)
    assert result is None
    assert elapsed < MAX_SECONDS


def test_stage4c_parse_deep_object_is_unparsable():
    """(#617) stage 4c _parse: no exception, None, under the time budget."""
    result, elapsed = _timed(_parse, DEEP_OBJECT)
    assert result is None
    assert elapsed < MAX_SECONDS


def test_vlm_parse_payload_deep_object_is_unparsable():
    """(#617) VLM _parse_payload: no exception; its unparsable outcome is ValueError,
    the one the callers already handle."""
    start = time.perf_counter()
    with pytest.raises(ValueError, match="nested too deeply"):
        _parse_payload(DEEP_OBJECT)
    assert time.perf_counter() - start < MAX_SECONDS


def test_vlm_parse_payload_still_reads_a_normal_object():
    """(#617) The guard does not change ordinary parsing."""
    assert _parse_payload('{"figure_kind": "chart"}') == {"figure_kind": "chart"}


def test_deep_input_really_exceeds_the_recursion_limit():
    """Sanity check: the inputs really are past the recursion limit on this interpreter."""
    with pytest.raises(RecursionError):
        json.JSONDecoder().raw_decode(DEEP_OBJECT, 0)
