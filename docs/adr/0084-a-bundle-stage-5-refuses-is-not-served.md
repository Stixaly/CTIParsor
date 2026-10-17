# ADR-0084: A bundle Stage 5 refuses is not served, and never completes a job

**Status:** Accepted
**Date:** 2026-10-17
**Deciders:** maintainer
**Amends:** ADR-0069 (item 3: Stage 5 returns `validated`, `unverified` or
`invalid`; until now nothing downstream read the answer)
**Relates to:** ADR-0035 (a stored bundle says which pipeline built it), ADR-0061
(the ledger is written with the bundle it describes), ADR-0077 (versioned
migrations)
**Amended by:** [0086](0086-a-bundle-names-its-build-and-a-slower-build-does-not-overwrite-it.md)
(concurrent finalizations)

## Context

The audit of 2026-10-17 (Q01), reproduced on `88bd1d7`, found that Stage 5's
verdict stopped at the stage. `validate_and_export`
(`pipeline/stage5_validation.py`) returns a `ValidationResult`: `validated`,
`unverified` (the JSON schemas are missing, only the stix2 library checked the
bundle) or `invalid`, with the validator's errors. Four places then ignored it:

| Where | What it did with `invalid` |
|---|---|
| the initial run (`_run_pipeline`) | the orchestrator put the status in the stage report; the worker stored the bundle without reading it |
| `re_run_final_stages` (finalize) | called `validate_and_export` and dropped the return value |
| a full finalize | marked the job `completed`, even for an invalid bundle |
| `GET /api/jobs/{id}/bundle` | served whatever `jobs.bundle_json` held |

The only trace of the refusal was a file, `output/{report}_bundle_invalid.json`,
which nothing in the application reads. The CLI (`main.py`) already returned
failure on an invalid bundle; the web path did not.

So an analyst could finalize a report, see it `completed`, and download a
bundle the STIX 2.1 schemas refuse, with no sign that Stage 5 had said so.

## Decision

**1. The verdict is stored with the bundle.** Migration v0011
(`api/migrations/v0011_bundle_validation.py`) adds two nullable columns to
`jobs`:

- `bundle_validation`: `validated`, `unverified` or `invalid`;
- `bundle_validation_errors`: a JSON list of Stage 5's error messages, the
  first 20, each cut to 500 characters.

They are written in the same `UPDATE` as `bundle_json` and `bundle_ledger_json`
(the initial run's `_finalize_job`, and `re_run_final_stages`), so a verdict
never describes another build. A bundle saved through `api/storage.py`
carries none and clears the old one, as it clears the ledger.

`NULL` means the bundle was built before v11, or Stage 5 did not run: the
verdict is **unknown**. Such a bundle is served as before. There is no backfill.

**2. An invalid bundle never completes a job.**

- A full finalize that rebuilds an invalid bundle leaves the job's status
  alone; a job that was `completed` goes back to `for_review`. The quick
  finalize (the debounced rebuild after an edit) already left the status
  alone, and does the same.
- The bundle is stored with its verdict and errors, then finalize raises
  `BundleInvalidError`.
- The initial run still stores the job `for_review`: nothing is published at
  that stage. It logs a warning.
- `unverified` completes as before.

**3. The API says what Stage 5 said.**

| Route | Bundle invalid | Otherwise |
|---|---|---|
| `GET /api/jobs/{id}/bundle` | 409, `{"detail": {"validation": "invalid", "errors": [...]}}` | the bundle, with the header `X-Bundle-Validation: validated`, `unverified` or `unknown` |
| `POST /api/jobs/{id}/finalize` (`quick` or not) | 409, same detail, when the rebuilt bundle is invalid | the existing response, plus `"validation"` |
| `PATCH /api/jobs/{id}` | 409, same detail, for `status="completed"` while the stored bundle is invalid | unchanged; every other status is unaffected |
| `GET /api/jobs/{id}/bundle/ledger` | unchanged: it describes the stored bundle, valid or not | |

The 409 is declared in the OpenAPI schema of the three routes. The PATCH reads
the verdict and writes the status under the same lock and connection, so a
rebuild cannot slip its verdict in between.

**4. The UI shows a refusal as a refusal.** The graph view, Finalize and the
download show the first errors, where a failed read used to mean "bundle not
built yet".

**The file on disk stays.** `validate_and_export` writes an invalid bundle to
`{report}_bundle_invalid.json` and leaves the previous valid
`{report}_bundle.json` alone. The `_invalid` file remains the candidate for
diagnosis.

## Options rejected

- **Keep the last valid bundle and store the invalid candidate apart.** The
  analyst would keep a bundle to download. But it needs more columns for the
  candidate and a state to display, "this bundle is older than your edits",
  that the UI and the API would both have to carry. The `_invalid` file on
  disk already serves diagnosis.
- **422 for finalize.** It is the status FastAPI uses, and declares in the
  OpenAPI schema, for a request that fails validation, with a list as
  `detail` (`HTTPValidationError`). Ours is an object. Reusing the code would
  give one status two shapes. 409 says what happened: the job's state
  conflicts with the request.

## Consequences

- **A refused bundle is visible and not downloadable.** The graph view, which
  reads `GET /bundle`, shows the refusal and its first errors until a rebuild
  passes. A rebuild that passes replaces the verdict.
- **An invalid rebuild replaces the valid bundle in the database.** The API
  never serves the candidate, but the previous valid bundle is no longer in
  `jobs.bundle_json`. Its file in `output/` is untouched.
- **Existing bundles are unknown, not valid.** Rows built before v11 are served
  with `X-Bundle-Validation: unknown`. Until they are rebuilt, nothing says
  whether Stage 5 would accept them.
- **Clients that read the bundle** now see a 409 on an invalid one, and a
  header on every 200.
- **Finalizing the same job twice at once is not made safe here.** Each build
  writes its bundle and verdict in one statement, but nothing serialises two
  finalizations: the last write wins. This ADR does not change that;
  ADR-0086 does (a build never replaces a bundle built from newer rows).
- The CLI is unchanged: it returned failure on an invalid bundle already.

## Validation

- `tests/test_worker.py`: an invalid rebuild is stored with its errors and
  never completes the job (quick and full, from `reviewing`, `for_review` and
  `completed`); a full finalize completes and stores `validated` and
  `unverified`; a valid rebuild replaces an invalid verdict; a run stores the
  verdict with its bundle and stays in review; a run whose Stage 5 did not run
  stores none; the storage layer clears the verdict; a reclaimed job and a
  finalize without a bundle keep the stored one.
- `tests/test_jobs_routes.py`: the 409 and its detail on GET, finalize (both
  modes) and PATCH; the header for each stored value; finalize's
  `validation`; the 409 declared in OpenAPI; the ledger route unaffected.
- `frontend/src/api/client.test.ts`: a 409 with a refusal detail becomes a
  `BundleRefusedError` carrying its errors, with a message that starts with
  the status, the same from every route; other errors are unchanged;
  `errorDetail` reads it. `frontend/src/pages/Review.test.tsx`: a refused
  Finalize says so and why instead of "check server logs". The graph view's
  refused state has no test of its own.
- Full suite after the change, run locally on 2026-10-17: 2618 passed,
  9 skipped, 0 failed; `ruff check .` and mypy (133 source files) clean;
  `npm run check`: 18 test files, 153 tests passed.
- Not measured: how many stored bundles are `invalid`.
