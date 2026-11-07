"""Regression tests for issue #435: the join of a meta string cut after a backslash.

A line that ends in an escaping backslash used to be joined with a space, which
made the escape `\\ ` (a space), an unknown escape for YARA.  The join now adds
nothing after an odd run of backslashes.
"""
from __future__ import annotations

from pipeline.detection.yara_check import rejoin_wrapped_meta_strings


def _joined_line(body: str) -> tuple[str, int]:
    text, joined = rejoin_wrapped_meta_strings(body)
    return text.splitlines()[2], joined


def test_a_break_after_an_escaping_backslash_joins_without_space_issue_435():
    """`"C:\\temp\\` + `path"` joins to `"C:\\temp\\path"`: no `\\ ` is created."""
    body = 'rule r {\n  meta:\n    desc = "C:\\temp\\\n      path"\n  condition:\n    true\n}\n'
    line, joined = _joined_line(body)
    assert line == '    desc = "C:\\temp\\path"'
    assert joined == 1
    assert "\\ " not in rejoin_wrapped_meta_strings(body)[0]


def test_a_break_after_a_doubled_backslash_keeps_the_space_issue_435():
    """Control: `\\\\` is an escaped backslash, not an escape, so the space stays."""
    body = 'rule r {\n  meta:\n    desc = "C:\\\\\n      path"\n  condition:\n    true\n}\n'
    line, joined = _joined_line(body)
    assert line == '    desc = "C:\\\\ path"'
    assert joined == 1


def test_a_break_after_an_odd_run_of_three_backslashes_joins_without_space_issue_435():
    """Three backslashes end in an escape, so the join adds nothing."""
    body = 'rule r {\n  meta:\n    desc = "a\\\\\\\n      b"\n  condition:\n    true\n}\n'
    line, _ = _joined_line(body)
    assert line == '    desc = "a\\\\\\b"'


def test_a_break_after_a_word_keeps_the_space_control_issue_435():
    """Control: a wrap after a plain word still joins with one space."""
    body = 'rule r {\n  meta:\n    desc = "searching for\n      executables"\n  condition:\n    true\n}\n'
    line, joined = _joined_line(body)
    assert line == '    desc = "searching for executables"'
    assert joined == 1
