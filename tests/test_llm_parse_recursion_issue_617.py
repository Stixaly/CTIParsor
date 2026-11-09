"""LLM response parsers degrade to "unparsable" on JSON nested very deeply, or
never closed, instead of failing the whole job or scanning for minutes (#617).

Each parser scans a response for the first JSON value with raw_decode.  What a
deep value does depends on the interpreter: Python 3.13 raises RecursionError
at ~20 000 levels, 3.14 decodes 30 000 levels and raises at ~100 000.  Either
way, retrying at each later bracket re-read the rest of the text every time:
quadratic, 15 s to a minute per 60 kB response on 3.14.  `JsonScan` stops a
scan on RecursionError, and once its attempts have read a few times the text.

The tests do not depend on where the interpreter's limit is: every parser is
run on deep inputs on both sides of it (no exception, fast), and the
RecursionError path is forced with a decoder that raises it.
"""
import json
import time

import pytest

from pipeline.llm_parse import JsonScan, ScanExhausted, parse_numbered_claims, strip_reasoning
from pipeline.stage3_llm import _parse_llm_response
from pipeline.stage3f_ttp_select import parse_selection, salvage_selection
from pipeline.stage4c_long_distance import _parse
from pipeline.vlm import _parse_payload

MAX_SECONDS = 5.0

DEEP_INPUTS = {
    "array": "[" * 30000 + "]" * 30000,                 # the issue's input, ~60 kB
    "object": '{"a":' * 20000 + "1" + "}" * 20000,      # the issue's input, ~140 kB
    "unclosed array": "[" * 30000,
    "unclosed object": '{"a":' * 30000,
    "past every limit": "[" * 200000 + "]" * 200000,    # RecursionError on 3.13 and 3.14
}

PARSERS = {
    "parse_numbered_claims": lambda raw: parse_numbered_claims(raw, 3),
    "strip_reasoning": strip_reasoning,
    "parse_selection": parse_selection,
    "salvage_selection": lambda raw: salvage_selection('{"selected": [' + raw),
    "stage3 _parse_llm_response": _parse_llm_response,
    "stage4c _parse": _parse,
}


@pytest.mark.parametrize("parser", PARSERS.values(), ids=PARSERS.keys())
@pytest.mark.parametrize("raw", DEEP_INPUTS.values(), ids=DEEP_INPUTS.keys())
def test_a_deep_answer_neither_raises_nor_takes_long(parser, raw):
    """(#617) Whatever the interpreter's recursion limit: no exception, under the time budget."""
    start = time.perf_counter()
    parser(raw)
    assert time.perf_counter() - start < MAX_SECONDS


@pytest.mark.parametrize("raw", DEEP_INPUTS.values(), ids=DEEP_INPUTS.keys())
def test_vlm_parse_payload_on_a_deep_answer_raises_only_its_value_error(raw):
    """(#617) VLM _parse_payload: its unparsable outcome is ValueError, which the callers handle."""
    start = time.perf_counter()
    try:
        _parse_payload(raw)
    except ValueError:
        pass
    assert time.perf_counter() - start < MAX_SECONDS


@pytest.fixture
def decoder_past_its_limit(monkeypatch):
    """A JSON decoder that raises RecursionError, as one nested past the limit does
    (json.loads goes through raw_decode too)."""
    def raw_decode(self, s, idx=0):
        raise RecursionError("maximum recursion depth exceeded while decoding a JSON array")
    monkeypatch.setattr(json.JSONDecoder, "raw_decode", raw_decode)


ANSWER = '{"selected": [{"id": "T1059"}], "a": [1]}'


@pytest.mark.parametrize("parser", [
    lambda raw: parse_numbered_claims("[" + raw + "]", 3),
    parse_selection,
    lambda raw: salvage_selection('{"selected": [' + raw),
    _parse_llm_response,
    _parse,
], ids=["parse_numbered_claims", "parse_selection", "salvage_selection",
        "stage3 _parse_llm_response", "stage4c _parse"])
def test_a_recursion_error_is_unparsable(decoder_past_its_limit, parser):
    """(#617) RecursionError from the decoder: None, not an exception that fails the job."""
    assert parser(ANSWER) is None


def test_vlm_parse_payload_turns_a_recursion_error_into_its_value_error(decoder_past_its_limit):
    with pytest.raises(ValueError, match="nested too deeply"):
        _parse_payload(ANSWER)


def test_strip_reasoning_still_drops_the_think_block_past_a_recursion_error(decoder_past_its_limit):
    assert strip_reasoning("[1] <think>draft</think> answer") == "[1] answer"


def test_the_scan_stops_once_its_attempts_have_read_a_few_times_the_text():
    """(#617) An answer that never closes: a handful of attempts, then ScanExhausted."""
    raw = "[" * 30000
    scan = JsonScan(raw)
    attempts = 0
    with pytest.raises(ScanExhausted):
        for i in range(len(raw)):
            attempts += 1
            try:
                scan.decode(i)
            except json.JSONDecodeError:
                continue
    assert attempts < 20


def test_the_scan_budget_leaves_ordinary_answers_alone():
    """(#617) Prose with many brackets before the answer is read as before."""
    raw = "evil[.]com and [x] " * 2000 + ANSWER
    assert parse_selection(raw) == [{"id": "T1059"}]


def test_ordinary_answers_are_read_as_before():
    """(#617) The guard does not change ordinary parsing."""
    assert parse_numbered_claims('[{"n": 1, "verified": true, "quote": "q"}]', 3) == {
        1: {"n": 1, "verified": True, "quote": "q"}}
    assert parse_selection(ANSWER) == [{"id": "T1059"}]
    assert _parse('note {"links": []}') == {"links": []}
    assert _parse_payload('{"figure_kind": "chart"}') == {"figure_kind": "chart"}
