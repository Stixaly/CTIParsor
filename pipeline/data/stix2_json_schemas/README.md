# STIX 2.1 JSON schemas (vendored)

The OASIS STIX 2.1 JSON schemas that `stix2-validator` validates against, in
Stage 5 (`pipeline/stage5_validation.py`).

- **Source:** `schemas/` of
  [oasis-open/cti-stix2-json-schemas](https://github.com/oasis-open/cti-stix2-json-schemas).
- **Commit:** `9af1db41b7b86c06324f899649ae83480134f66e` (master on
  2026-01-19), copied unchanged. `SCHEMA_COMMIT` in
  `pipeline/stage5_validation.py` names the same commit.
- **Licence:** BSD-3-Clause, OASIS Open (`LICENSE`, kept with the files).

## Why they are in this repository

`stix2-validator` looks for them in its own package directory, under
`schemas-2.1/schemas/`. Its 3.3.x wheels ship without them: the upstream git
submodule that holds them is missing from the PyPI wheel. So they are
installed from this copy:

- **The image** gets them at build time (`Dockerfile`, runtime stage). The
  container's filesystem is read-only at runtime.
- **Any other install** (CI, the test suite, a host) gets them at its first
  Stage 5 run, by `install_schemas()`, when the package directory is
  writable.

Nothing is downloaded. Stage 5 used to fetch the archive from GitHub at run
time (ADR-0069, amendment of 2026-10-10).

## Updating them

1. Pick a commit of `oasis-open/cti-stix2-json-schemas`.
2. Replace `schemas/` and `LICENSE` here with that commit's.
3. Set `SCHEMA_COMMIT` and this page to it.
4. Run `tests/test_stage5.py`, which checks the files and validates real
   bundles against them.
