"""Shared ReDoS-safe regex compilation (ADR-0049).

Every regex applied to report text (attacker-controlled input) should compile
through `compile_pattern` rather than `re.compile` directly, so it inherits
re2's linear-time guarantee instead of being one edit away from reintroducing
catastrophic backtracking.
"""
import re

try:
    import re2 as _re2_module
    _RE2_AVAILABLE = True
except ImportError:
    _re2_module = None
    _RE2_AVAILABLE = False

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
            except Exception:
                pass
    return re.compile(pattern, flags)
