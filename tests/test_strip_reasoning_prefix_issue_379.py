"""strip_reasoning removes a `<think>` block that comes after some text (issue #379).

Before the fix, only a block at the very start of the reply (after whitespace) was
removed, so a log prefix or a preamble left the whole reasoning in the answer.
"""
from pipeline.llm_parse import strip_reasoning

_ANSWER = '{"selected": []}'


def test_a_block_after_a_log_prefix_is_removed_and_the_prefix_is_kept_issue_379():
    text = 'INFO model=qwen <think>plan</think>\n' + _ANSWER
    assert strip_reasoning(text) == 'INFO model=qwen ' + _ANSWER


def test_a_block_after_a_newline_prefix_is_removed_issue_379():
    text = 'INFO\n<think>plan</think>\n' + _ANSWER
    assert strip_reasoning(text) == 'INFO\n' + _ANSWER


def test_braces_inside_a_block_after_a_prefix_are_removed_issue_379():
    text = 'INFO <think>Maybe {"x": 1}, or a lone { brace.</think>' + _ANSWER
    assert strip_reasoning(text) == 'INFO ' + _ANSWER


def test_every_block_before_the_answer_is_removed_issue_379():
    text = 'INFO <think>one</think>x<think>two</think>' + _ANSWER
    assert strip_reasoning(text) == 'INFO x' + _ANSWER


def test_every_block_at_the_start_is_removed_issue_379():
    text = '<think>a</think>\n<think>b</think>\n[{"n": 1}]'
    assert strip_reasoning(text) == '[{"n": 1}]'


def test_a_think_tag_inside_the_json_answer_is_kept_after_a_prefix_issue_379():
    answer = '{"evidence": "the report says <think>x</think> here"}'
    assert strip_reasoning('INFO <think>plan</think>' + answer) == 'INFO ' + answer
    assert strip_reasoning('INFO ' + answer) == 'INFO ' + answer


def test_a_think_tag_inside_the_json_answer_is_kept_when_there_is_no_block_issue_379():
    answer = '{"evidence": "<think>q</think>"}'
    assert strip_reasoning(answer) == answer


def test_an_unclosed_block_after_a_prefix_is_kept_issue_379():
    text = 'INFO\n<think>cut {"x": 1}'
    assert strip_reasoning(text) == text
