"""Shared path-containment check (Zip Slip / path traversal guard).

Used everywhere an untrusted relative path or archive member name is joined
onto a trusted destination root before being read or written: corpus tarball
extraction (pipeline/detection/sync.py), the STIX schema self-heal zip
extraction (pipeline/stage5_validation.py), and corpus registration
(api/routes/settings.py). One place to hold this check means a future
hardening (e.g. rejecting a symlinked component of the destination itself)
lands everywhere at once instead of needing to be remembered in three places.
"""
from pathlib import Path


def is_contained(candidate: Path, root: Path) -> bool:
    """True if `candidate` resolves to a path inside resolved `root`.

    Both paths are resolved here (symlinks and `..` collapsed) rather than
    trusting the caller to have done it -- the whole point of this check is
    that `candidate` was built from untrusted input.
    """
    return candidate.resolve().is_relative_to(root.resolve())
