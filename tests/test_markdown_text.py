"""The Markdown escapes of report text (ADR-0093): what the report says stays literal."""
import pytest

from pipeline.markdown_text import blockquote, defang, escape_inline, escape_line


@pytest.mark.parametrize("ch", list("\\`*_[]<>&|~#="))
def test_every_active_character_is_escaped(ch):
    assert escape_inline(ch) == "\\" + ch


def test_a_sentence_full_of_active_characters():
    assert (escape_inline("a*b_c [x] <y> &z | ~w # @h")
            == "a\\*b\\_c \\[x\\] \\<y\\> \\&z \\| \\~w \\# @h")


def test_a_double_equals_sign_is_escaped_for_the_flexible_markers_of_opencti():
    assert escape_inline("uint16(0) == 0x5A4D") == "uint16(0) \\=\\= 0x5A4D"


@pytest.mark.parametrize(("url", "defanged"), [
    ("http://evil.example/x", "hxxp://evil.example/x"),
    ("https://evil.example/x", "hxxps://evil.example/x"),
    ("HTTP://evil.example/x", "HXXP://evil.example/x"),
    ("HTTPS://evil.example/x", "HXXPS://evil.example/x"),
])
def test_a_web_url_is_defanged_and_keeps_its_case(url, defanged):
    assert defang(url) == defanged


def test_an_ftp_url_is_not_defanged():
    # GFM makes no link of ftp://, so the text stays as the report wrote it
    assert defang("ftp://evil.example/x") == "ftp://evil.example/x"
    assert escape_inline("ftp://evil.example/x") == "ftp://evil.example/x"


@pytest.mark.parametrize("text", ["www.evil.example", "WWW.evil.example", "Www.Evil.example"])
def test_www_prefix_is_defanged_whatever_the_case(text):
    assert escape_inline(text) == text[:3] + "\\[.\\]" + text[4:]


def test_www_in_the_middle_of_a_sentence_is_defanged():
    assert escape_inline("visit www.evil.example now") == "visit www\\[.\\]evil.example now"


def test_www_after_an_opening_parenthesis_is_defanged():
    assert defang("(www.evil.example)") == "(www[.]evil.example)"


def test_www_inside_a_word_is_not_defanged():
    assert defang("awww.x") == "awww.x"


def test_an_e_mail_address_is_defanged():
    assert defang("mail ops@evil.example") == "mail ops[@]evil.example"
    assert escape_inline("a@b.c") == "a\\[@\\]b.c"


@pytest.mark.parametrize("text", ["@echo off", "user @ host"])
def test_an_at_sign_that_is_not_in_an_address_is_kept(text):
    assert escape_inline(text) == text


def test_ordinary_text_is_unchanged():
    text = "Group X targets energy firms (2023), per Mandiant: 3 samples; v1.2.3 - final."
    assert escape_inline(text) == text


@pytest.mark.parametrize(("line", "escaped"), [
    ("# Title", "\\# Title"),
    ("> quoted", "\\> quoted"),
    ("- item", "\\- item"),
    ("+ item", "\\+ item"),
    ("===", "\\=\\=\\="),
    ("---", "\\---"),
    ("    indented", "indented"),
    ("\tindented", "indented"),
])
def test_escape_line_neutralises_block_markers(line, escaped):
    assert escape_line(line) == escaped


@pytest.mark.parametrize(("line", "escaped"), [
    ("1. x", "1\\. x"),
    ("12) x", "12\\) x"),
    ("123456789. x", "123456789\\. x"),
    ("1.", "1\\."),
])
def test_an_ordered_list_number_is_escaped(line, escaped):
    assert escape_line(line) == escaped


@pytest.mark.parametrize("line", ["1.5 x", "1.5 GHz", "2023-03-15", "a - b", "12 items", "1234567890. x"])
def test_escape_line_leaves_text_that_is_not_a_block_marker(line):
    assert escape_line(line) == line


def test_blockquote_merges_line_breaks():
    assert blockquote("a sentence\n  cut by a\n\npage break") == "> a sentence cut by a page break"


def test_blockquote_escapes_a_heading_mark():
    assert blockquote("# title") == "> \\# title"


def test_www_after_a_character_whose_lower_case_is_longer():
    # "İ".lower() is two characters: the scan must not use the lowered copy's offsets.
    assert escape_inline("İ www.evil.com") == "İ www\\[.\\]evil.com"
