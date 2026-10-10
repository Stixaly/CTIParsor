from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import stix2
from stix2validator import ValidationOptions, print_results, validate_string

# Initialize logging
from api.logging_config import get_logger

logger = get_logger(__name__)

# The OASIS STIX 2.1 JSON schemas, carried by this repository: the
# stix2-validator 3.3.x wheels ship without them (the git submodule that holds
# them is missing from the wheel).  `schemas/` of
# oasis-open/cti-stix2-json-schemas at one commit (master on 2026-01-19),
# unchanged, with its BSD-3-Clause LICENSE (pipeline/data/stix2_json_schemas/).
# The image installs them into the package at build time (Dockerfile); another
# install gets them at its first Stage 5 run (install_schemas).  Nothing is
# downloaded: Stage 5 used to fetch them from GitHub, and in the read-only
# container it fetched them again on every run without ever installing them
# (ADR-0069, amendment of 2026-10-10).
SCHEMA_COMMIT = "9af1db41b7b86c06324f899649ae83480134f66e"
VENDORED_SCHEMAS = Path(__file__).parent / "data" / "stix2_json_schemas" / "schemas"

# install_schemas() failing is said once per process, not once per bundle.
_missing_reported = False

VALIDATED = "validated"
INVALID = "invalid"
UNVERIFIED = "unverified"


@dataclass
class ValidationResult:
    """What Stage 5 knows about a bundle.

    ``unverified`` means the JSON schemas were missing: only the stix2 library's
    own checks ran.  It used to be reported as ``True``, the same answer as a
    bundle the schemas accepted.  ``warnings`` are the validator's best-practice
    findings (e.g. {202}, a relationship STIX does not suggest for the pair);
    they never make a bundle invalid.
    """
    status: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """The bundle was written under its own name (not ``_invalid``)."""
        return self.status != INVALID


def _schema_dir() -> Path:
    """Return the directory where stix2validator expects its bundled schemas.

    stix2validator looks for JSON schemas in:
        {package_dir}/schemas-{version}/schemas/
    using os.walk() recursively.  The cti-stix2-json-schemas repo has the
    following layout under its schemas/ directory:
        common/      — core, cyber-observable-core, external-reference, …
        observables/ — ipv4-addr, domain-name, file, …
        sdos/        — malware, threat-actor, indicator, …
        sros/        — relationship, sighting
    """
    import stix2validator as _v
    return Path(_v.__file__).parent / "schemas-2.1" / "schemas"


def _has_schemas(d: Path) -> bool:
    """True if `d` holds JSON schemas.  Recursive: they live in subdirectories
    (common/, observables/, sdos/, sros/)."""
    return d.is_dir() and any(d.rglob("*.json"))


def _schemas_installed() -> bool:
    """Return True if stix2-validator's bundled JSON schemas are present."""
    return _has_schemas(_schema_dir())


def install_schemas(dest: Path | None = None) -> bool:
    """Copy the vendored schemas into stix2-validator's package directory.

    Returns True when the schemas are in place afterwards; never raises.  The
    tree is copied next to its destination, then renamed into place: several
    worker subprocesses can run this at once, and none ever reads a
    half-copied directory.  The one whose rename loses finds the winner's
    copy.  Local files only: nothing is downloaded.
    """
    dest = dest or _schema_dir()
    if _has_schemas(dest):
        return True
    staging: Path | None = None
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".schemas-", dir=dest.parent))
        shutil.copytree(VENDORED_SCHEMAS, staging, dirs_exist_ok=True)
        os.replace(staging, dest)    # onto a missing or empty directory only
        staging = None
    except OSError as exc:
        logger.debug(f"Schema install into {dest} failed ({type(exc).__name__}): {exc}")
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
    return _has_schemas(dest)


def validate_and_export(bundle: stix2.Bundle, output_path: str) -> ValidationResult:
    """
    Validate the STIX 2.1 bundle and write it to disk.

    Args:
        bundle: STIX bundle to validate.
        output_path: destination file path.

    Returns a `ValidationResult`:
        validated  — the JSON schemas accepted it; file written at output_path.
        unverified — the schemas are missing, only the stix2 library checked it;
                     file written at output_path.
        invalid    — the schemas refused it; file written with _invalid suffix.

    Schema-validation layer vs. stix2-library validation:
        The stix2 library validates every STIX object at *construction* time
        using Pydantic.  The stix2validator JSON-schema layer is a second
        defence that catches edge cases the Pydantic models don't cover (e.g.
        extra required properties from the spec not reflected in the model).
        Both layers run when schemas are present; only stix2 runs when absent.
    """
    bundle_json = bundle.serialize(pretty=True)

    if not _schemas_installed() and not install_schemas():
        # Only where the package directory is read-only and lacks them: an image
        # built without the Dockerfile's install step.
        global _missing_reported
        if not _missing_reported:
            _missing_reported = True
            logger.error(
                f"STIX JSON schemas missing from {_schema_dir()} and not installable "
                f"from {VENDORED_SCHEMAS}: bundles are 'unverified', checked by the "
                "stix2 library only.  The Dockerfile installs them at build time: "
                "rebuild the image."
            )
        _write_file(bundle_json, output_path)
        return ValidationResult(UNVERIFIED)

    # ── Full JSON-schema validation ───────────────────────────────────────────
    options = ValidationOptions(version="2.1")
    results = validate_string(bundle_json, options=options)
    found = getattr(results, "object_results", None) or [results]
    errors = [str(e) for r in found for e in (r.errors or [])]
    warnings = [str(w) for r in found for w in (r.warnings or [])]
    if warnings:
        logger.info(f"[Stage 5] {len(warnings)} best-practice warning(s), e.g. {warnings[0]}")

    if not results.is_valid:
        logger.error("STIX 2.1 validation errors detected:")
        print_results(results)
        p = Path(output_path)
        invalid_path = str(p.with_stem(p.stem + "_invalid"))
        _write_file(bundle_json, invalid_path)
        return ValidationResult(INVALID, errors, warnings)

    _write_file(bundle_json, output_path)
    return ValidationResult(VALIDATED, errors, warnings)


def _write_file(content: str, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    logger.info(f"File written: {output_path}")


def print_bundle_summary(bundle: stix2.Bundle) -> None:
    """Print a readable summary of the generated bundle."""
    type_counts: dict[str, int] = {}
    for obj in bundle.objects:
        t = obj.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    logger.info("--- STIX Bundle Summary ---")
    for stix_type, count in sorted(type_counts.items()):
        logger.info(f"  {stix_type:<30} {count}")
    logger.info(f"  {'TOTAL':<30} {sum(type_counts.values())}")
    logger.info("-----------------------------")
