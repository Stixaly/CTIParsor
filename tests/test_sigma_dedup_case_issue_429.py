"""Issue #429: the dedup key folds case and whitespace that are part of the match.

`|base64` and `|base64offset` decode case-sensitively, and a value's leading or
trailing space is part of the match, so neither may be folded away.
"""

from pipeline.detection.sigma import SigmaAdapter


def _sigma_doc(value, modifier):
    return {"title": "t", "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {"selection": {"CommandLine|" + modifier: value}, "condition": "selection"}}


def _same_key(value_a, value_b, modifier):
    return (SigmaAdapter._dedup_key(_sigma_doc(value_a, modifier))
            == SigmaAdapter._dedup_key(_sigma_doc(value_b, modifier)))


def test_base64_values_keep_their_case_issue_429():
    # `SGVsbG8=` and `sgvsbg8=` are different base64 payloads.
    for modifier in ("base64", "base64offset"):
        assert not _same_key("SGVsbG8=", "sgvsbg8=", modifier)


def test_base64_identical_values_still_share_a_key_issue_429():
    for modifier in ("base64", "base64offset"):
        assert _same_key("SGVsbG8=", "SGVsbG8=", modifier)


def test_contains_keeps_a_leading_space_issue_429():
    # " evil" matches only where a space precedes it; "evil" matches more.
    assert not _same_key(" evil", "evil", "contains")


def test_contains_keeps_a_trailing_space_issue_429():
    assert not _same_key("evil ", "evil", "contains")


def test_contains_still_folds_the_case_of_its_value_issue_429():
    # Control: `|contains` is case-insensitive, so only whitespace separates keys.
    assert _same_key("Foo", "foo", "contains")


def test_case_insensitive_regex_still_folds_issue_429():
    # Control: `|re|i` folds case like a plain value.
    assert _same_key("Foo.*bar", "foo.*bar", "re|i")


def test_modifier_key_case_still_folds_issue_429():
    # Control: keys are still normalized; only values lose the strip.
    doc_a = {"detection": {"sel": {"CommandLine|Contains": "evil"}, "condition": "sel"}}
    doc_b = {"detection": {"sel": {"commandline|contains": "evil"}, "condition": "sel"}}
    assert SigmaAdapter._dedup_key(doc_a) == SigmaAdapter._dedup_key(doc_b)


def test_a_block_scalar_line_break_does_not_split_a_copy_issue_429():
    from pipeline.detection.sigma import SigmaAdapter
    plain = {"logsource": {"product": "windows"},
             "detection": {"sel": {"CommandLine|contains": "evil"}, "condition": "sel"}}
    block = {"logsource": {"product": "windows"},
             "detection": {"sel": {"CommandLine|contains": "evil\n"}, "condition": "sel"}}
    assert SigmaAdapter._dedup_key(plain) == SigmaAdapter._dedup_key(block)
