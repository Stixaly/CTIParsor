"""Flexible ISO-8601 date parsing shared by Stage 3 (LLM relationship
extraction) and the manual relationship-edit API.

Split out of pipeline/stage3_llm.py so a lightweight caller (the API route
layer) doesn't have to import that module at the top level -- stage3_llm
pulls in anthropic/tenacity/dotenv, and every other call site in this
codebase imports it lazily inside a function body for exactly that reason
(keeping heavy/unstable deps out of the parent uvicorn process; see
api/worker.py). This module has no dependency beyond the standard library.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pipeline.regex_safety import compile_pattern

_YEAR_ONLY_RE = compile_pattern(r"^\d{4}$")
_YEAR_MONTH_RE = compile_pattern(r"^\d{4}-\d{2}$")


def parse_flexible_date(value) -> datetime | None:
    """
    Parse a relationship start_time/stop_time written as ISO 8601 (full, or
    the coarser YYYY-MM / YYYY precision the Stage 3 prompt allows) into a
    timezone-aware datetime. Never raises: anything that is not a non-empty
    string, or a string that doesn't parse, or an implausible year, returns
    None -- one bad date must not cost the whole chunk (see stage3_llm's
    enrich_chunk, which discards everything on a Pydantic ValidationError).
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if _YEAR_ONLY_RE.match(text):
        text = f"{text}-01-01"
    elif _YEAR_MONTH_RE.match(text):
        text = f"{text}-01"
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if not (1990 <= dt.year <= datetime.now(timezone.utc).year + 2):
        return None
    return dt
