"""
Report text inside Markdown: the descriptions Stage 4 writes (ADR-0093).

OpenCTI renders a STIX `description` as GitHub-flavoured Markdown.  Text taken
from a report (a quoted sentence, an object's name, the document itself) must
read there as it reads in the report: no heading, list or quote it did not
have, no emphasis made of a `*.exe`, and no link made of a live URL or address
the report names as an IoC.  The words stay the report's; backslashes are added,
and what GFM would turn into a link is defanged the way CTI reports write it.
"""
from __future__ import annotations

# Every character GFM gives a meaning inline or at the start of a line, plus
# `=`: OpenCTI's display also loads remark-flexible-markers, which highlights
# `==text==`.  A backslash before ASCII punctuation always renders as the
# character itself (CommonMark §2.4).
_ACTIVE = frozenset("\\`*_[]<>&|~#=")

# The characters GFM accepts on either side of the `@` of an e-mail autolink.
_EMAIL_LOCAL = frozenset("-.+_")



def defang(text: str) -> str:
    """`text` with what GFM autolinks defanged: `http://` and `https://` as
    `hxxp://`, `www.` as `www[.]`, an e-mail `a@b.c` as `a[@]b.c`.

    Escaping is not enough: remark-gfm finds autolinks in the text after the
    escapes are decoded, so `http:\\/\\/` is still a link (checked on remark-gfm
    4.0.1, the version OpenCTI's front end and ours use)."""
    out: list[str] = []
    n = len(text)
    i = 0
    while i < n:
        # Compared slice by slice: lowering "İ" yields two characters, so the
        # offsets of a lowered copy of the whole text would drift.
        head = text[i:i + 8].lower()
        if head.startswith(("http://", "https://")):
            out.append(text[i] + ("XX" if text[i + 1:i + 3].isupper() else "xx"))
            i += 3
        elif head.startswith("www.") and (i == 0 or not text[i - 1].isalnum()):
            out.append(text[i:i + 3] + "[.]")
            i += 4
        elif (text[i] == "@" and 0 < i < n - 1
              and (text[i - 1].isalnum() or text[i - 1] in _EMAIL_LOCAL)
              and (text[i + 1].isalnum() or text[i + 1] in "-_")):
            out.append("[@]")
            i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def escape_inline(text: str) -> str:
    """`text` defanged, then every Markdown-active character backslash-escaped
    (the brackets of `[.]` and `[@]` included)."""
    return "".join("\\" + ch if ch in _ACTIVE else ch for ch in defang(text))


def escape_line(line: str) -> str:
    """One line of report text, made literal: `escape_inline`, plus the block
    markers that only act at the start of a line (a list dash or plus, a setext
    underline, an ordered-list number).  Leading whitespace is dropped, since
    four spaces would open a code block."""
    out = escape_inline(line.lstrip())
    if out[:1] in ("-", "+"):
        return "\\" + out
    # An ordered-list item: one to nine ASCII digits, "." or ")", then a space
    # or the end of the line ("1. text", "12) text").
    digits = len(out) - len(out.lstrip("0123456789"))
    if (1 <= digits <= 9 and out[digits:digits + 1] in (".", ")")
            and (len(out) == digits + 1 or out[digits + 1].isspace())):
        return out[:digits] + "\\" + out[digits:]
    return out


def collapse_whitespace(text: str) -> str:
    """Runs of whitespace, line breaks included, as one space; ends trimmed."""
    return " ".join(text.split())


def blockquote(text: str) -> str:
    """`text` as a one-paragraph Markdown blockquote: its whitespace collapsed
    (a quote cut from a PDF carries the page's line breaks), escaped."""
    return "> " + escape_line(collapse_whitespace(text))
