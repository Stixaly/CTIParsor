"""Uniform field access for STIX objects that may be dicts or stix2 instances.

Stage 4 and its two completion passes each grew their own copy of this
accessor (`_field`, `_otype`, `_type`, `_name`).
"""
from __future__ import annotations


def field(obj: object, key: str) -> object | None:
    """Read a field from a mapping or attribute-based object."""
    if hasattr(obj, "get"):
        return obj.get(key)  # type: ignore[union-attr]
    return getattr(obj, key, None)
