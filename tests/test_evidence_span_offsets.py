"""Offset and coverage invariants of `pipeline.evidence_span` (bug-hunt 2026-08)."""
from pipeline.evidence_span import _normalise, locate


def test_normalise_index_map_length_matches_normalised():
    """Verify len(norm) == len(imap) for various edge cases."""
    cases = [
        "hello world",
        "Badİdea here",
        "oﬀice ﬁle ﬂow",
        "a b​c  d",
        "İİİ"
    ]
    # This equality is the invariant that all imap[...] lookups depend on.
    for text in cases:
        norm, imap = _normalise(text)
        assert len(norm) == len(imap), (
            f"Length mismatch for {text!r}: {len(norm)} vs {len(imap)}"
        )

def test_normalise_index_map_points_at_original_character():
    """Verify imap indices are valid and non-decreasing."""
    text = "Badİdea here is the quoted sentence about malware."
    norm, imap = _normalise(text)
    for i in range(len(imap)):
        assert 0 <= imap[i] < len(text)
        if i > 0:
            assert imap[i] >= imap[i-1]

def test_locate_after_multichar_lowercase_returns_exact_text():
    """Test that locate returns exact text after multi-char lowercase normalization."""
    text = "Badİdea here is the quoted sentence about malware."
    quote = "dea here is the quoted sentence"
    span = locate(quote, text)
    assert span is not None
    # This test FAILS on current code (returns "ea here is the quoted sentence " — off by one char).
    assert text[span.start:span.end].lower() == quote.lower()

def test_padded_quote_does_not_inflate_coverage():
    """Test that padded quotes do not inflate coverage."""
    report = "Alpha beta gamma. The actor deployed the loader onto the host. Omega."
    quote  = "  the actor deployed the loader onto the WRONGWORD  "
    span = locate(quote, report)
    assert span is not None
    # The last word is absent from the report, so coverage cannot be 1.0.
    assert span.coverage < 1.0
    assert span.exact is False

def test_padded_quote_matches_stripped_quote():
    """Test that padded quotes match stripped quotes."""
    report = "Alpha beta gamma. The actor deployed the loader onto the host. Omega."
    quote  = "  the actor deployed the loader onto the WRONGWORD  "
    # Leading/trailing spaces carry no information.
    assert locate(quote, report) == locate(quote.strip(), report)

def test_zero_width_space_padding_does_not_inflate_coverage():
    """Test that zero-width space padding does not inflate coverage."""
    report = "Alpha beta gamma. The actor deployed the loader onto the host. Omega."
    quote  = "​the actor deployed the loader onto the WRONGWORD​"
    span = locate(quote, report)
    assert span is not None
    assert span.coverage < 1.0

def test_exact_quote_still_reports_full_coverage():
    """Test that exact quotes still report full coverage."""
    report = "Alpha beta gamma. The actor deployed the loader onto the host."
    quote  = "The actor deployed the loader"
    span = locate(quote, report)
    assert span.exact is True and span.coverage == 1.0
    assert report[span.start:span.end] == "The actor deployed the loader"

def test_quote_shorter_than_three_words_is_refused():
    """Test that quotes shorter than three words are refused."""
    assert locate("the actor", "The actor deployed the loader onto the host.") is None

def test_quote_absent_from_text_returns_none():
    """Test that quotes absent from text return None."""
    assert locate("completely unrelated words here", "Alpha beta gamma delta.") is None

def test_curly_quotes_and_newlines_are_matched():
    """Test that curly quotes and newlines are matched."""
    report = "The malware’s configuration\n\nwas modified by the actor."
    quote  = "The malware's configuration was modified"
    span = locate(quote, report)
    assert span is not None
    # Typographic apostrophe and double newline, exactly what PDF extraction produces.
    assert span.coverage == 1.0

def test_coverage_is_a_real_fraction():
    """Test that coverage is a real fraction."""
    report = "Alpha beta gamma. The actor deployed the loader onto the host. Omega."
    quote  = "the actor deployed the loader onto the WRONGWORD"
    span = locate(quote, report)
    assert span is not None
    assert 0.0 < span.coverage <= 1.0
    # 7 words found out of 8, so coverage should be 7/8.
    assert abs(span.coverage - 7/8) < 1e-9
