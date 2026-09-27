"""Single vocabulary for environment settings: boolean flags, integers, numbers.

Seven call sites each parsed their own flag differently — `== "1"`,
`in ("true","1","yes")`, `not in ("false","0","no")`, `!= "true"` — so
`ENABLE_CONSENSUS=1` left consensus off while `ENABLE_STIX_VERIFICATION=1`
turned verification on, and `api.run_config` recorded a third answer into the
bundle's provenance block.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import TypeVar

logger = logging.getLogger(__name__)

_N = TypeVar("_N", int, float)

_TRUTHY: frozenset[str] = frozenset({"1", "true", "yes", "on"})
_FALSY: frozenset[str] = frozenset({"0", "false", "no", "off"})


def env_bool(name: str, *, default: bool = False) -> bool:
    """Read *name* as a boolean, falling back to *default*.

    An unset variable and an unrecognised value both yield *default*.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in _TRUTHY:
        return True
    if v in _FALSY:
        return False
    # Unrecognised values fall back to the default rather than being treated as true,
    # so that CYNER_ENABLED=maybe keeps the stage active as before.
    return default


def env_int(name: str, *, default: int) -> int:
    """Read *name* as an integer, falling back to *default*.

    Unset or blank yields *default* silently.  A value that is not an integer
    yields *default* with a warning: a typo in .env then degrades one setting
    instead of stopping the process at import with a bare ValueError.
    """
    return _env_number(name, default, int, "an integer")


def env_float(name: str, *, default: float) -> float:
    """Read *name* as a number, falling back to *default* (see env_int)."""
    return _env_number(name, default, float, "a number")


def _env_number(name: str, default: _N, parse: Callable[[str], _N], expected: str) -> _N:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return parse(raw.strip())
    except ValueError:
        logger.warning("%s=%r is not %s — using the default %r", name, raw, expected, default)
        return default
