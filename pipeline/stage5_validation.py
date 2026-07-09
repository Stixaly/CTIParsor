from __future__ import annotations

import io
import os
import tempfile
import urllib.request
from urllib.parse import urlparse
import zipfile
from pathlib import Path

import stix2
from stix2validator import ValidationOptions, print_results, validate_string

# Initialize logging
from api.logging_config import get_logger

logger = get_logger(__name__)

# Sentinel written to the project root the first time schemas are confirmed
# missing AND the auto-restore failed.  Subsequent subprocess invocations
# check the file and skip the warning+restore attempt without re-checking.
_PROJECT_ROOT  = Path(__file__).parent.parent
_WARN_SENTINEL = _PROJECT_ROOT / ".stix2_schemas_missing"

# GitHub archive URL for the OASIS STIX 2.1 JSON schema repository.
# The archive is a ZIP of the full repo; we extract only the schemas/ subtree.
_SCHEMA_ZIP_URL = (
    "https://github.com/oasis-open/cti-stix2-json-schemas"
    "/archive/refs/heads/master.zip"
)
# Prefix inside the ZIP archive where the schemas live.
# cti-stix2-json-schemas-master/schemas/{common,observables,sdos,sros}/*.json
_ZIP_SCHEMA_PREFIX = "cti-stix2-json-schemas-master/schemas/"


def _validate_url_scheme(url: str) -> None:
    """Validate that URL uses http or https scheme."""
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f"Invalid URL scheme: {parsed.scheme}. Only http/https are allowed.")


def _schema_dir() -> Path:
    """Return the directory where stix2validator expects its bundled schemas.

    stix2validator looks for JSON schemas in:
        {package_dir}/schemas-{version}/schemas/
    using os.walk() recursively.  The cti-stix2-json-schemas repo has the
    following layout under its schemas/ directory:
        common/       core, cyber-observable-core, external-reference, \x1a
        observables/  ipv4-addr, domain-name, file, \x1a
        sdos/         malware, threat-actor, indicator, \x1a
        sros/         relationship, sighting
    """
    import stix2validator as _v
    return Path(_v.__file__).parent / "schemas-2.1" / "schemas"


def _schemas_installed() -> bool:
    """Return True if stix2-validator's bundled JSON schemas are present.

    Uses rglob (recursive) because the JSON files live in subdirectories
    (common/, observables/, sdos/, sros/)  a non-recursive glob("*.json")
    always returns empty even when schemas are correctly installed.
    """
    d = _schema_dir()
    return d.is_dir() and any(d.rglob("*.json"))


def _try_restore_schemas() -> bool:
    """
    Download the full OASIS cti-stix2-json-schemas archive from GitHub and
    extract the schemas/ subtree into the stix2validator package directory.

    This is a one-time self-healing step for the packaging bug in
    stix2validator 3.3.x where the git-submodule schemas are absent from the
    PyPI wheel.

    Layout after restore:
        {schema_dir}/common/core.json
        {schema_dir}/common/cyber-observable-core.json
        {schema_dir}/observables/ipv4-addr.json
        {schema_dir}/sdos/malware.json
        ...

    Returns True if at least one schema was extracted successfully.
    """
    dest = _schema_dir()
    try:
        _validate_url_scheme(_SCHEMA_ZIP_URL)
        logger.info(
            f"Downloading STIX 2.1 JSON schemas from OASIS GitHub "
            f"({_SCHEMA_ZIP_URL})\u2026"
        )
        # nosec: B310 - URL scheme is validated above
        with urllib.request.urlopen(_SCHEMA_ZIP_URL, timeout=30) as resp:  # noqa: S310
            zip_bytes = resp.read()

        extracted = 0
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for entry in zf.namelist():
                if not entry.startswith(_ZIP_SCHEMA_PREFIX):
                    continue
                rel = entry[len(_ZIP_SCHEMA_PREFIX):]   # e.g. "common/core.json"
                if not rel or not rel.endswith(".json"):
                    continue
                out = dest / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                # Atomic write: stage to a temp file in the same directory, then
                # os.replace() into place.  Multiple worker subprocesses can hit
                # this self-heal concurrently; a plain write_bytes() would let one
                # process read a half-written schema another is still writing.
                # os.replace() is atomic on the same filesystem, so a reader sees
                # either the old absent file or the complete new one  never a
                # torn JSON document.
                fd, tmp = tempfile.mkstemp(dir=str(out.parent), suffix=".tmp")
                try:
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(zf.read(entry))
                    os.replace(tmp, out)
                    extracted += 1
                finally:
                    if os.path.exists(tmp):
                        os.unlink(tmp)

        if extracted:
            logger.info(f"Restored {extracted} STIX 2.1 schema files to {dest}")
            return True

        logger.warning(f"No schema files found in archive from {_SCHEMA_ZIP_URL}")
        return False

    except Exception as exc:
        logger.warning(f"Failed to restore STIX schemas: {exc}")
        return False


def _ensure_schemas() -> bool:
    """One-shot schema restore.

    Returns True if schemas are now available (either were already present
    or were successfully restored).
    """
    if _schemas_installed():
        return True

    if _try_restore_schemas():
        return True

    # Write sentinel so we don't spam the log on every subprocess start
    _WARN_SENTINEL.write_text("")
    logger.warning(
        "STIX 2.1 JSON schemas are missing and could not be auto-restored. "
        "Validation will fall back to the bundled validator without schemas. "
        "To fix: pip install --force-reinstall stix2validator"
    )
    return False


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_STIX_VERSION = "2.1"


def _stix_options() -> ValidationOptions:
    """Return validator options tuned for CTI reports."""
    return ValidationOptions(version=_STIX_VERSION)


def validate_bundle(bundle: stix2.Bundle) -> tuple[bool, list[str]]:
    """Validate a STIX 2.1 bundle and return (is_valid, errors).

    Uses the stix2validator library with the official OASIS JSON schemas.
    If schemas are missing, falls back to the library's bundled validator
    (which may be outdated).
    """
    _ensure_schemas()

    # Serialize the bundle to JSON string for validation
    bundle_json = bundle.serialize(pretty=True)

    # Validate against STIX 2.1 schemas
    validation_results = validate_string(bundle_json, _stix_options())

    is_valid = validation_results.is_valid
    errors = []

    if not is_valid:
        for error in validation_results.errors:
            errors.append(str(error))
        for warning in validation_results.warnings:
            errors.append(f"WARNING: {warning}")

    return is_valid, errors
