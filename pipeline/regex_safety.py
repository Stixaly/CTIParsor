"""Shared ReDoS-safe regex compilation (ADR-0049).

Every regex applied to report text (attacker-controlled input) should compile
through `compile_pattern` rather than `re.compile` directly, so it inherits
re2's linear-time guarantee instead of being one edit away from reintroducing
catastrophic backtracking.
"""
import logging
import re
import sys

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
# Only the three flags actually used across callers are mapped; anything else
# (VERBOSE, ASCII, ...) falls through to the stdlib path below rather than
# being silently ignored.
_RE2_INLINE_FLAGS: dict[int, str] = {
    re.IGNORECASE: "i",
    re.MULTILINE: "m",
    re.DOTALL: "s",
}
_RE2_MAPPABLE_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL

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
