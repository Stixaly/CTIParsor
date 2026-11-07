"""The VLM reply parser takes the JSON object when text follows it (#509).

Before the fix, the slice from the first `{` to the last `}` ran only when the
reply did not start with `{`: a reply that starts with the object and carries a
note after it failed with "Extra data".
"""
import pytest

from pipeline.vlm import _parse_payload


def test_object_followed_by_a_note_is_parsed():
    """(#509) The reply starts with `{` and a note follows the object."""
    raw = '{"figure_kind": "diagram", "verbatim_text": ["a"]}\nNote: extracted from figure 1.'
    assert _parse_payload(raw) == {"figure_kind": "diagram", "verbatim_text": ["a"]}


def test_object_followed_by_a_note_that_has_a_brace_is_parsed():
    """(#509) A brace in the trailing note does not move the end of the object."""
    raw = '{"figure_kind": "none", "iocs": []} (the figure shows {a} legend)'
    assert _parse_payload(raw) == {"figure_kind": "none", "iocs": []}


def test_reasoning_block_before_the_object_is_skipped():
    """(#509) A <think> block with a brace inside it is not read as the answer."""
    raw = '<think>Maybe {"figure_kind": "table"}?</think>\n{"figure_kind": "diagram"}'
    assert _parse_payload(raw) == {"figure_kind": "diagram"}


def test_fenced_object_followed_by_a_note_is_parsed():
    """(#509) A fenced reply with a note after the closing fence."""
    raw = '```json\n{"figure_kind": "diagram"}\n```\nNote: see figure 1.'
    assert _parse_payload(raw) == {"figure_kind": "diagram"}


@pytest.mark.parametrize("raw", ["[1, 2]", "no json here", "}{"])
def test_text_without_an_object_is_rejected(raw):
    """(#509) No object to find: ValueError, as before."""
    with pytest.raises(ValueError):
        _parse_payload(raw)
