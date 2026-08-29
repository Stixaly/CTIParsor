"""Text primitives shared by the atom extractors."""
from __future__ import annotations

from collections.abc import Mapping


def unescape(value: str, table: Mapping[str, str]) -> str:
    """Decode one escaped literal in a single left-to-right pass.

    The single pass is what prevents a decoded backslash from being re-read
    as the start of a new escape. Escapes absent from *table* are preserved
    verbatim, backslash included.
    """
    if not isinstance(value, str):
        return ""

    parts: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        if value[i] == "\\" and i + 1 < n:
            nxt = value[i + 1]
            if nxt in table:
                parts.append(table[nxt])
            else:
                parts.append("\\")
                parts.append(nxt)
            i += 2
        else:
            parts.append(value[i])
            i += 1
    return "".join(parts)
