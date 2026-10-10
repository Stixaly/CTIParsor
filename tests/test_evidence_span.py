# tests/test_evidence_span.py
from pipeline.evidence_span import Span, _normalise, locate, sentence_bounds, sentence_index_of, stated_in, words


def test_normalise_index_map_has_same_length():
    text = "ﬁle “hello”  world"
    normalised, index_map = _normalise(text)
    assert len(normalised) == len(index_map)

def test_normalise_maps_back_to_original_offsets():
    text = "Hello  World"
    normalised, index_map = _normalise(text)
    # "Hello  World" -> "hello world"
    # index_map[0] should be 0 ('H')
    # index_map[5] should be 6 ('W')?
    # Let's trace:
    # H(0) -> h, map[0]=0
    # e(1) -> e, map[1]=1
    # l(2) -> l, map[2]=2
    # l(3) -> l, map[3]=3
    # o(4) -> o, map[4]=4
    # space(5) -> space, map[5]=5
    # space(6) -> skipped
    # W(7) -> w, map[6]=7
    assert text[index_map[0]] == 'H'
    assert text[index_map[6]] == 'W'

def test_normalise_collapses_whitespace():
    text = "a \n\t b"
    normalised, _ = _normalise(text)
    assert normalised == "a b"

def test_normalise_expands_ligatures():
    text = "ﬁle"
    normalised, index_map = _normalise(text)
    assert normalised == "file"
    assert index_map[0] == 0
    assert index_map[1] == 0

def test_locate_exact_quote():
    text = "The quick brown fox."
    quote = "quick brown fox"
    span = locate(quote, text)
    assert span is not None
    assert span.exact is True
    assert span.coverage == 1.0
    assert text[span.start:span.end] == quote

def test_locate_with_curly_quotes():
    text = "It’s a test."
    quote = "It's a test"
    span = locate(quote, text)
    assert span is not None
    assert span.exact is True

def test_locate_with_collapsed_whitespace():
    text = "Line one\nLine two"
    quote = "Line one Line two"
    span = locate(quote, text)
    assert span is not None

def test_locate_returns_none_when_absent():
    text = "Hello world"
    quote = "Goodbye universe"
    span = locate(quote, text)
    assert span is None

def test_locate_returns_none_for_short_quote():
    text = "This is a long sentence with many words."
    quote = "the"
    span = locate(quote, text)
    assert span is None

def test_locate_returns_none_for_empty_inputs():
    text = "Some text"
    assert locate("", text) is None
    assert locate("quote", "") is None

def test_locate_longest_prefix():
    text = "The cat sat on the mat."
    # Quote is the sentence + 5 invented words
    quote = "The cat sat on the mat invented words here now"
    span = locate(quote, text)
    assert span is not None
    assert span.exact is False
    assert 0.6 <= span.coverage < 1.0

def test_locate_longest_suffix():
    text = "The cat sat on the mat."
    # Quote is 5 invented words + the sentence
    quote = "invented words here now The cat sat on the mat"
    span = locate(quote, text)
    assert span is not None
    assert span.exact is False

def test_locate_respects_min_coverage():
    text = "The cat sat on the mat."
    quote = "The cat sat on the mat invented words here now"
    span = locate(quote, text, min_coverage=0.99)
    assert span is None

def test_locate_span_never_exceeds_text_length():
    text = "Start the middle end"
    quote = "the middle end"
    span = locate(quote, text)
    assert span is not None
    assert span.end <= len(text)

def test_sentence_bounds_offsets_are_exact():
    text = "One. Two! Three?"
    bounds = sentence_bounds(text)
    expected = ["One.", "Two!", "Three?"]
    assert len(bounds) == 3
    for i, (a, b) in enumerate(bounds):
        assert text[a:b].strip() == expected[i]

def test_sentence_bounds_empty():
    assert sentence_bounds("") == []

def test_sentence_index_of_finds_containing_sentence():
    text = "First sentence. Second sentence. Third sentence."
    bounds = sentence_bounds(text)
    # Span in the middle of the second sentence
    # "Second sentence." starts at index 15 (0-based: "First sentence. " is 14 chars)
    # Let's just pick a span inside the second sentence
    span = Span(start=16, end=20, coverage=1.0, exact=True)
    idx = sentence_index_of(span, bounds)
    assert idx == 1

def test_sentence_index_of_returns_none_outside():
    text = "First. Second."
    bounds = sentence_bounds(text)
    span = Span(start=100, end=110, coverage=1.0, exact=True)
    assert sentence_index_of(span, bounds) is None

def test_locate_then_sentence_index_round_trip():
    text = "First sentence. Second sentence. Third sentence is here."
    quote = "Third sentence is here"
    span = locate(quote, text)
    assert span is not None
    bounds = sentence_bounds(text)
    idx = sentence_index_of(span, bounds)
    assert idx == 2


# ── stated_in: Stage 3d's quote check (ADR-0082) ─────────────────────────────
# The four dev-run quotes an exact comparison missed, each with only Markdown
# or punctuation between it and the text.

def test_a_quote_without_the_markdown_around_it_is_stated():
    text = ("**Filename**: STRTbbbn7przuvwav4hbpbps.vbs \n"
            "| http://141.164.41.231/host64_sh.bin | URL | MirrorBlast Payload (FlawedGrace) |\n"
            "a zero day in the VSA server was exploited to distribute [REvil](/threat-actors/revil) "
            "ransomware.")
    tw = words(text)
    assert stated_in("Filename: STRTbbbn7przuvwav4hbpbps.vbs", tw)
    assert stated_in("http://141.164.41.231/host64_sh.bin | URL | MirrorBlast Payload (FlawedGrace)", tw)
    assert stated_in("exploited to distribute REvil ransomware.", tw)


def test_a_quote_cut_inside_a_link_target_is_still_compared_by_its_words():
    tw = words("On 19 January, [Malwarebytes reported](https://blog.example.com/a-long-path) that it was hit.")
    assert stated_in("On 19 January, [Malwarebytes reported](https://blog.example.com/a-lo", tw)


def test_a_paraphrase_is_not_stated():
    tw = words("Tianyi Credit, a subsidiary of China Telecom, collected the data.")
    assert not stated_in("Tianyi Credit is a subsidiary of China Telecom", tw)


def test_every_part_of_a_two_sentence_quote_must_be_stated():
    tw = words("The group, tracked as APT29, is Russian. Later on, the group deployed SUNBURST.")
    assert stated_in("The group, tracked as APT29, is Russian. [...] the group deployed SUNBURST.", tw)
    assert not stated_in("The group, tracked as APT28, is Russian. [...] the group deployed SUNBURST.", tw)


def test_words_are_whole_words():
    tw = words("UNC2452 deployed SUNBURST on the servers.")
    assert not stated_in("UNC245 deployed SUNBURST", tw)
    assert not stated_in("deployed SUNBURST on the server", tw)


def test_a_word_or_two_is_no_quote():
    tw = words("The loader downloaded the payload.")
    assert not stated_in("downloaded", tw)
    assert not stated_in("the payload", tw)
    assert stated_in("downloaded the payload", tw)


def test_non_latin_words_count():
    tw = words("Группа использовала вредоносную программу.")
    assert stated_in("использовала вредоносную программу", tw)
    assert not stated_in("использовала другую программу", tw)
