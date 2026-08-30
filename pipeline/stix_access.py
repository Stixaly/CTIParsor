"""Uniform field access for STIX objects that may be dicts or stix2 instances.

Stage 4 and its two completion passes each grew their own copy of this
accessor (`_field`, `_otype`, `_type`, `_name`).
"""
from __future__ import annotations

from typing import Any


# Returns `Any`, not `object`: the value read out of a STIX object is a dict
# entry or an attribute whose type is only knowable at the call site. Declaring
# `object` makes every caller that promises `-> str` a type error, which is how
# `_otype`, `_name` and `_type` each ended up unusable to mypy.
def field(obj: object, key: str) -> Any | None:
    """Read a field from a mapping or attribute-based object."""
    if hasattr(obj, "get"):
        return obj.get(key)  # type: ignore[union-attr]
    return getattr(obj, key, None)
