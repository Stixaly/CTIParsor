"""
A YARA rule quoted in a report ships only if it compiles (ADR-0067).

OpenCTI checks every YARA Indicator with ``yara.compile(source=pattern)``
(`opencti-graphql/src/python/runtime/check_indicator.py`) and refuses the ones
that do not compile ("indicator of type yara is not correctly formatted").
Every relationship that points at a refused Indicator then fails too, with
"element(s) not found".

A rule quoted in a report reaches Stage 4 through the report's layout, and the
layout can break it.  A blog post printed to PDF wraps long code lines, so a
``meta`` string can be cut in two.  A line break inside a YARA string literal is
always a syntax error.

`prepare_embedded_rule` makes two repairs. Each one only touches something that
cannot compile as it is:

- A ``meta`` string cut by a line break is joined back with a single space.  A
  meta value does not change what the rule matches.  A cut text string under
  ``strings:`` is left alone: whether the break stood for a space or for
  nothing changes what the rule matches, and the text cannot say which.
- An ``import "module"`` line that the report declares outside the rule is
  added when the rule uses that module.

The rule is then compiled with yara-python, the library OpenCTI uses.  Without
yara-python the status is ``"unverified"``, never ``"compiles"``.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from api.logging_config import get_logger

logger = get_logger(__name__)

COMPILES = "compiles"
DOES_NOT_COMPILE = "does_not_compile"
UNVERIFIED = "unverified"

_SECTION = re.compile(r"^\s*(meta|strings|condition)\s*:")
_META_STRING = re.compile(r'^\s*\w+\s*=\s*"')
# A wrapped meta value is one sentence, cut once or twice by the layout.
# Past this, the open quote is more likely a mistake than a wrap.
_MAX_CONTINUATION_LINES = 3

_warned_unverified = False


@dataclass(frozen=True)
class PreparedRule:
    pattern: str
    status: str                       # COMPILES | DOES_NOT_COMPILE | UNVERIFIED
    error: str | None = None          # the compiler's message, when it refused
    rejoined_lines: int = 0           # continuation lines joined back into a meta string
    added_imports: tuple[str, ...] = ()

    def ledger_info(self) -> dict:
        """What the mapping ledger records about the shipped pattern."""
        info: dict = {}
        if self.rejoined_lines:
            info["rejoined_lines"] = self.rejoined_lines
        if self.added_imports:
            info["added_imports"] = list(self.added_imports)
        if self.status == UNVERIFIED:
            info["pattern_check"] = UNVERIFIED
        return info


def _leaves_quote_open(line: str) -> bool:
    """True when `line` ends inside a double-quoted string (escapes honoured,
    a ``//`` comment outside a string ends the scan)."""
    inside = False
    i = 0
    while i < len(line):
        c = line[i]
        if inside and c == "\\":
            i += 2
            continue
        if c == '"':
            inside = not inside
        elif not inside and line.startswith("//", i):
            break
        i += 1
    return inside


def _close_wrapped_string(lines: list[str], i: int) -> tuple[str, int, int] | None:
    """Join the lines after the open string at ``lines[i]`` until it closes.

    Returns (joined line, index of the first line not used, continuation lines
    joined), or None when it does not close within `_MAX_CONTINUATION_LINES`
    non-blank lines, or before a section header or the rule's closing brace.
    """
    merged, used, j = lines[i].rstrip(), 0, i + 1
    while j < len(lines) and used < _MAX_CONTINUATION_LINES:
        nxt = lines[j]
        j += 1
        if not nxt.strip():
            continue
        if _SECTION.match(nxt) or nxt.strip() == "}":
            return None
        merged = f"{merged} {nxt.strip()}"
        used += 1
        if not _leaves_quote_open(merged):
            return merged, j, used
    return None


def rejoin_wrapped_meta_strings(body: str) -> tuple[str, int]:
    """Join back the ``meta`` strings a line break cut in two.

    Returns the body and the number of continuation lines joined.  A string
    that cannot be closed (see `_close_wrapped_string`) is left as it was.
    """
    lines = body.split("\n")
    out: list[str] = []
    joined, section, i = 0, None, 0
    while i < len(lines):
        line = lines[i]
        header = _SECTION.match(line)
        if header:
            section = header.group(1)
        if section == "meta" and _META_STRING.match(line) and _leaves_quote_open(line):
            closed = _close_wrapped_string(lines, i)
            if closed is not None:
                merged, i, used = closed
                out.append(merged)
                joined += used
                continue
        out.append(line)
        i += 1
    return "\n".join(out), joined


def with_declared_imports(body: str, imports: Iterable[str]) -> tuple[str, tuple[str, ...]]:
    """Prefix the ``import`` lines the report declared and the rule uses.

    Never invents an import: a module the report did not import stays out, and
    the compiler reports it.
    """
    added = tuple(
        m for m in imports
        if re.search(rf"\b{re.escape(m)}\.", body)
        and not re.search(rf'^\s*import\s+"{re.escape(m)}"', body, re.MULTILINE)
    )
    if not added:
        return body, ()
    header = "".join(f'import "{m}"\n' for m in added)
    return f"{header}\n{body}", added


def compile_status(source: str) -> tuple[str, str | None]:
    """Compile `source` the way OpenCTI does: any exception is a refusal."""
    global _warned_unverified
    try:
        import yara
    except ImportError:
        if not _warned_unverified:
            _warned_unverified = True
            logger.warning(
                "yara-python is not installed: YARA rules quoted in reports ship "
                "without a compile check, and OpenCTI may refuse them"
            )
        return UNVERIFIED, None
    try:
        yara.compile(source=source)
    except Exception as exc:  # noqa: BLE001 — OpenCTI refuses on any exception
        return DOES_NOT_COMPILE, str(exc)
    return COMPILES, None


def prepare_embedded_rule(body: str, imports: Iterable[str] = ()) -> PreparedRule:
    """Repair what the layout broke, then compile.  See the module docstring."""
    pattern, rejoined = rejoin_wrapped_meta_strings(body)
    pattern, added = with_declared_imports(pattern, imports)
    status, error = compile_status(pattern)
    return PreparedRule(pattern=pattern, status=status, error=error,
                        rejoined_lines=rejoined, added_imports=added)
