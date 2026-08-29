"""Single vocabulary for boolean environment flags.

Seven call sites each parsed their own flag differently — `== "1"`,
`in ("true","1","yes")`, `not in ("false","0","no")`, `!= "true"` — so
`ENABLE_CONSENSUS=1` left consensus off while `ENABLE_STIX_VERIFICATION=1`
turned verification on, and `api.run_config` recorded a third answer into the
bundle's provenance block.
"""
from __future__ import annotations

import os

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
