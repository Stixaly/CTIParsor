"""Shared ReDoS-safe regex compilation (ADR-0049).

Every regex applied to report text (attacker-controlled input) should compile
through `compile_pattern` rather than `re.compile` directly, so it inherits
re2's linear-time guarantee instead of being one edit away from reintroducing
catastrophic backtracking.
"""
import logging
import re
import sys
import unicodedata

# stdlib logging: this module is imported before any other, logging config included.
_logger = logging.getLogger(__name__)

try:
    import re2 as _re2_module
    _RE2_AVAILABLE = True
except ImportError:
    _re2_module = None
    _RE2_AVAILABLE = False

#: (module, pattern) of every pattern RE2 refused and `re` compiled instead: no
#: linear-time guarantee for those.  tests/test_re2_fallbacks.py pins the list
#: and runs each entry on adversarial input; a new one fails it until it is
#: rewritten for RE2 or measured and added there.
FALLBACKS: list[tuple[str, str]] = []

# RE2 has no equivalent of re's integer flags -- it takes them as an inline
# prefix in the pattern itself ("(?i)", "(?m)", "(?s)", combinable "(?im)").
# re.ASCII needs none: RE2's `\w`, `\d`, `\s` and `\b` are ASCII whatever the
# flags, and re.ASCII asks `re` for the same.  A pattern that says `\b` passes it
# so that both engines cut the same words (ADR-0049, 2026-10-18 amendment).
# Anything else (VERBOSE, LOCALE, ...) falls through to the stdlib path below
# rather than being silently ignored.
_RE2_INLINE_FLAGS: dict[int, str] = {
    re.IGNORECASE: "i",
    re.MULTILINE: "m",
    re.DOTALL: "s",
}
_RE2_MAPPABLE_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL | re.ASCII

#: The 29 characters Python's `\s` matches in a str pattern (str.isspace()), to
#: write inside a character class.  RE2's `\s` is ASCII only ([\t\n\f\r ]), so a
#: pattern moved from `re` to RE2 says this instead of `\s` to keep matching what
#: it matched: a no-break space (U+00A0) between two words of an HTML page is
#: whitespace to both.  Literal characters, not escapes: `\uXXXX` is Python's
#: syntax and `\x{XXXX}` RE2's.  `tests/test_re2_fallbacks.py` checks the list.
#: A class body, not a set of characters: it writes U+2000..U+200A as a range,
#: so `str.strip(PY_WHITESPACE)` would strip "-".  `tests/test_unicode_whitespace.py`
#: fails on a module-level pattern that says `\s` without a reason.
PY_WHITESPACE = ("\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0  - "
                 "    　")


def _class_body(escape: str, scan: str, first: int = 0) -> str:
    """The characters of `scan` from U+`first` on that `escape` matches under this
    Python's `re`, as literal ranges for the body of a character class."""
    return "".join(f"{chr(m.start())}-{chr(m.end() - 1)}"
                   for m in re.compile(escape + "+").finditer(scan, first))


# Every character below U+40000 (no letter or digit lies past it: a test checks),
# to read the running Python's Unicode tables from.  A list written out here
# would lag one Python or the other: `\w` past ASCII is 744 ranges in 3.12 and
# 767 in 3.14.  Reading both classes takes about 20 ms at import.
_SCAN = "".join(map(chr, range(0x40000)))
#: Python's `\d` (str.isdecimal(): the digits of every script) as a class body,
#: for a pattern that means it: RE2's `\d` is [0-9].  Literal ranges, as
#: PY_WHITESPACE, which RE2 and `re` read alike.
PY_DIGIT = _class_body(r"\d", _SCAN)
#: Python's `\w` past ASCII (str.isalnum()) as a class body.  RE2's `\w` is
#: [0-9A-Za-z_]; `[A-Za-z0-9_{PY_NON_ASCII_WORD}]` is Python's.  Large: a pattern
#: that repeats it many times outgrows RE2's DFA (stage2g_alias_list masks
#: instead).
PY_NON_ASCII_WORD = _class_body(r"\w", _SCAN, 0x80)
del _SCAN


def continues_a_word(ch: str) -> bool:
    """`ch`, glued to an ASCII match, makes it part of a longer word: a letter of a
    script with case (Latin, Greek, Cyrillic...), which writes spaces between its
    words, or a digit.  RE2's `\\b`, like re.ASCII's, takes any non-ASCII character
    for a boundary, and so cut "o@evil.com" out of "joão@evil.com".  A Chinese,
    Japanese, Korean or Thai character does not continue the match: those scripts
    write no spaces, and glue an ASCII token to the words around it."""
    return len(ch) == 1 and (unicodedata.category(ch) in ("Lu", "Ll", "Lt") or ch.isdecimal())


def glued_to_a_word(text: str, start: int, end: int) -> bool:
    """The character right before or right after text[start:end] continues a word
    (`continues_a_word`)."""
    return continues_a_word(text[start - 1:start]) or continues_a_word(text[end:end + 1])


def compile_pattern(pattern: str, flags: int = 0):
    """
    Compile a regex pattern, using re2 if available for ReDoS protection.

    re2 guarantees linear time matching and prevents catastrophic backtracking.
    Falls back to standard re if re2 is not installed, if `flags` includes a
    flag re2's inline syntax has no equivalent for, or if re2 rejects the
    pattern itself (e.g. a backreference, which RE2's syntax does not support).
    """
    if _RE2_AVAILABLE:
        if flags & ~_RE2_MAPPABLE_FLAGS == 0:
            prefix_letters = "".join(
                letter for flag, letter in _RE2_INLINE_FLAGS.items() if flags & flag
            )
            re2_pattern = f"(?{prefix_letters}){pattern}" if prefix_letters else pattern
            try:
                return _re2_module.compile(re2_pattern)
            except Exception as exc:     # re2 refuses lookaround and backreferences
                _logger.debug("re2 refused %r (%s): compiled with re, no linear-time guarantee",
                              pattern[:80], exc)
                FALLBACKS.append((sys._getframe(1).f_globals.get("__name__", "?"), pattern))
    return re.compile(pattern, flags)
