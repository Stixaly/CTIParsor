from __future__ import annotations

import io
import os
import tempfile
import urllib.request
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


def _schemas_installed() -> bool:
    """Return True if stix2-validator's bundled JSON schemas are present.

    Uses rglob (recursive) because the JSON files live in subdirectories
    (common/, observables/, sdos/, sros/) — a non-recursive glob("*.json")
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
        logger.info(
            f"Downloading STIX 2.1 JSON schemas from OASIS GitHub "
            f"({_SCHEMA_ZIP_URL})…"
        )
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
                # either the old absent file or the complete new one — never a
                # torn JSON document.
                fd, tmp = tempfile.mkstemp(dir=str(out.parent), suffix=".tmp")
                try:
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(zf.read(entry))
                    os.replace(tmp, out)
                except BaseException:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                    raise
                extracted += 1

        if extracted:
            logger.info(
                f"stix2-validator schemas restored: "
                f"{extracted} JSON files written to {dest}"
            )
        return extracted > 0

    except Exception as exc:
        logger.debug(
            f"Schema auto-restore failed ({type(exc).__name__}): {exc}"
        )
        return False


def validate_and_export(bundle: stix2.Bundle, output_path: str) -> bool:
    """
    Validate the STIX 2.1 bundle and write it to disk.

    Args:
        bundle: STIX bundle to validate.
        output_path: destination file path.

    Returns:
        True  — bundle passed JSON-schema validation (or validation was skipped
                because schemas are unavailable); file written at output_path.
        False — bundle failed validation; file written with _invalid suffix.

    Callers should not treat True as "schema-clean" when schemas are absent —
    use _schemas_installed() to distinguish the two True cases if needed.

    Schema-validation layer vs. stix2-library validation:
        The stix2 library validates every STIX object at *construction* time
        using Pydantic.  The stix2validator JSON-schema layer is a second
        defence that catches edge cases the Pydantic models don't cover (e.g.
        extra required properties from the spec not reflected in the model).
        Both layers run when schemas are present; only stix2 runs when absent.
    """
    bundle_json = bundle.serialize(pretty=True)

    if not _schemas_installed():
        # ── Missing-schemas recovery path ────────────────────────────────────
        # Only warn + attempt recovery once per server installation (not once
        # per job).  The sentinel file persists across subprocess restarts.
        if not _WARN_SENTINEL.exists():
            logger.warning(
                "stix2-validator schemas not found in the installed package "
                "(packaging bug in stix2-validator 3.3.x — git submodule missing from PyPI wheel). "
                "Attempting auto-restore from OASIS GitHub…"
            )
            restored = _try_restore_schemas()
            if restored and _schemas_installed():
                logger.info(
                    "Schema restore succeeded — full JSON-schema validation now active."
                )
                # Fall through to the validation block below
            else:
                logger.warning(
                    "Schema auto-restore failed. "
                    "Falling back to stix2-library-only validation (still catches most errors). "
                    "To restore full validation manually:\n"
                    "  pip install 'git+https://github.com/oasis-open/cti-stix-validator'"
                )
                try:
                    _WARN_SENTINEL.touch()
                except OSError:
                    pass
                _write_file(bundle_json, output_path)
                return True
        else:
            # Sentinel present — schemas still missing, skip silently
            _write_file(bundle_json, output_path)
            return True

    # ── Full JSON-schema validation ───────────────────────────────────────────
    options = ValidationOptions(version="2.1")
    results = validate_string(bundle_json, options=options)

    if not results.is_valid:
        logger.error("STIX 2.1 validation errors detected:")
        print_results(results)
        p = Path(output_path)
        invalid_path = str(p.with_stem(p.stem + "_invalid"))
        _write_file(bundle_json, invalid_path)
        return False

    _write_file(bundle_json, output_path)
    return True


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
