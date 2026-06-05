from __future__ import annotations

import os
from pathlib import Path
import stix2
from stix2validator import validate_string, print_results, ValidationOptions


def _schemas_installed() -> bool:
    """Return True if stix2-validator's bundled JSON schemas are present.

    stix2-validator 3.x ships its STIX schemas as a git-submodule that is
    sometimes absent from the PyPI wheel (packaging bug in 3.3.x).  When the
    schemas directory is missing every object raises SchemaInvalidError and
    the bundle is incorrectly marked invalid.
    """
    import stix2validator as _v
    schema_dir = os.path.join(os.path.dirname(_v.__file__), "schemas-2.1", "schemas")
    return os.path.isdir(schema_dir)


_SCHEMAS_WARNED = False   # long "schemas not found" explanation (once per process)
_SKIP_WARNED    = False   # short "⚠ validation skipped" line (once per process)


def validate_and_export(bundle: stix2.Bundle, output_path: str) -> bool:
    """
    Valide le bundle STIX 2.1 et l'écrit sur le disque si valide.

    Args:
        bundle: bundle STIX à valider
        output_path: chemin du fichier de sortie

    Returns:
        True  — bundle passed JSON-schema validation and was written.
        False — bundle failed validation (written with _invalid suffix).
        True  — validation was skipped (schemas missing); bundle still written.
                Callers should not interpret True as "schema-clean" when schemas
                are absent — check _schemas_installed() separately if needed.
    """
    global _SCHEMAS_WARNED, _SKIP_WARNED
    bundle_json = bundle.serialize(pretty=True)

    if not _schemas_installed():
        # stix2-validator PyPI wheel 3.3.x ships without its bundled JSON
        # schemas (packaging bug).  The stix2 library already validates every
        # object at construction time, so skip the schema-validation layer and
        # write directly.  Install from source to restore full validation:
        #   pip install git+https://github.com/oasis-open/cti-stix-validator
        if not _SCHEMAS_WARNED:
            print(
                "[VALIDATION] stix2-validator schemas not found — "
                "skipping JSON schema check (stix2 library validation still active).\n"
                "            To restore full validation install from source:\n"
                "            pip install git+https://github.com/oasis-open/cti-stix-validator"
            )
            _SCHEMAS_WARNED = True
        # Print the skip warning BEFORE writing the file so the output order is:
        #   ⚠ Validation skipped …
        #   [OK] Fichier écrit …
        # rather than the confusing reversed order.
        # Suppress after the first occurrence so repeated calls (e.g. finalize)
        # don't spam the log.
        if not _SKIP_WARNED:
            print("[VALIDATION] ⚠ Validation skipped — schemas unavailable. Bundle written as-is.")
            _SKIP_WARNED = True
        _write_file(bundle_json, output_path)
        return True

    options = ValidationOptions(version="2.1")
    results = validate_string(bundle_json, options=options)

    if not results.is_valid:
        print("[VALIDATION] Erreurs STIX 2.1 détectées :")
        print_results(results)
        # Export with _invalid suffix for debugging — use Path to avoid
        # accidentally replacing ".json" in a directory component of the path.
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
    print(f"[OK] Fichier écrit : {output_path}")


def print_bundle_summary(bundle: stix2.Bundle) -> None:
    """Affiche un résumé lisible du bundle généré."""
    type_counts: dict[str, int] = {}
    for obj in bundle.objects:
        t = obj.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    print("\n--- Résumé du bundle STIX ---")
    for stix_type, count in sorted(type_counts.items()):
        print(f"  {stix_type:<30} {count}")
    print(f"  {'TOTAL':<30} {sum(type_counts.values())}")
    print("-----------------------------\n")
