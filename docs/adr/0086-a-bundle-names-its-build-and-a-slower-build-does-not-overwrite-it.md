# ADR-0086: A bundle names the build that made it, and a slower build does not overwrite a newer one

**Status:** Accepted
**Date:** 2026-10-17
**Deciders:** maintainer
**Depends on:** ADR-0084 (the verdict and the ledger are written in the same
`UPDATE` as the bundle), ADR-0077 (versioned migrations)
**Amends:** ADR-0059 (decision 2: finalize builds its bundle through the same
`build_bundle()`; the "still not done" list of its amendment of 2026-10-17),
ADR-0035 (a bundle is judged on the revision of the run that made it)
**Relates to:** ADR-0024 (the run config), ADR-0052 (entity overrides), ADR-0061
(the ledger is written with the bundle it describes)

## Context

The audit of 2026-10-17, lot L1 (after lot 0, ADR-0084), found two defects in
`re_run_final_stages` (`POST /api/jobs/{id}/finalize`, quick or full).

### 1. A finalize recorded nothing

A finalize rebuilds Stages 4 and 5 with the current policy, data and code.
`jobs.run_config_json` still described the initial run: its policy, its
`git_rev`, its environment, its manifest. Two things followed.

- **A rebuild never cleared a staleness.** `pipeline/bundle_revisions.py`
  (ADR-0035) judged a bundle on the run's `git_rev`, although Stages 4 and 5 had
  run with the finalize's code. `scripts/audit_bundle_invariants.py` told people
  to rebuild a stale bundle, and reported it stale again after they had.
- **Entity overrides were recorded as counts.** `entity_overrides` (ADR-0052)
  held the number of active deny and promote rows. Replacing one deny row with
  another left the run config unchanged.

### 2. Two finalizes published in the order they finished

`re_run_final_stages` read the job's rows under `_lock`, released it for the
mapping, then wrote the bundle without a condition. The review page schedules a
quick finalize 4 s after each edit, and the Finalize button starts another. A
slow finalize A and a fast finalize B, started after one more decision, could
publish in the reverse order of their reads: the bundle built from the older
rows replaced the one built from the newer.

ADR-0084 left this open: "the last write wins". A test reproduced it before any
change. `tests/test_bundle_builds.py::test_a_slow_finalize_does_not_publish_over_a_newer_one`
failed on the old code: the stored bundle was A's, without the entity the
analyst had just added.

Two details made it worse. `_lock` is per process, so it covers neither several
API processes nor the workers. And the rejected rows, which filter the job's
JSON blob, were read in a second, separate block after the first had released
the lock, so one bundle could mix two states of the same job.

## Decision

**1. A job counts the writes to its rows (migration v12).**
`api/migrations/v0012_bundle_builds.py` adds three columns to `jobs`:

| Column | Meaning |
|---|---|
| `review_revision` `BIGINT NOT NULL DEFAULT 0` | the number of writes to the job's `entities` and `relationships` rows |
| `bundle_review_revision` `BIGINT` | the `review_revision` the stored bundle was read at. `NULL`: built before v12, or by a writer with no snapshot (`api/storage.py::save_bundle`); any build may replace it |
| `bundle_build_json` `TEXT` | what built the stored bundle (decision 5). `NULL`: built before v12; `run_config_json` describes it |

A row-level `AFTER INSERT OR UPDATE OR DELETE` trigger bumps `review_revision`
in the same transaction as the write: function `bump_review_revision()`,
triggers `entities_review_revision` and `relationships_review_revision`. A row
moved to another job bumps both jobs. There is no backfill: every job starts at
revision 0.

**2. The finalize reads one snapshot.** The job row, the shipped entities, the
relationships and the rejected entities are read in one `REPEATABLE READ READ
ONLY` transaction (`api.db.transaction(conn, snapshot=True)`). The rows match
the revision read with them. The rejected rows used to be read in a separate
block.

**3. One conditional `UPDATE` publishes.** The bundle, the ledger, the Stage 5
verdict, the build record, the revision and the status are written together:

```sql
UPDATE jobs SET bundle_json=?, bundle_ledger_json=?, bundle_validation=?,
       bundle_validation_errors=?, bundle_build_json=?, bundle_review_revision=?,
       status = CASE WHEN ? THEN 'completed'
                     WHEN ? AND status = 'completed' THEN 'for_review'
                     ELSE status END, updated_at=?
 WHERE id=? AND (bundle_review_revision IS NULL OR bundle_review_revision <= R)
```

where `R` is the revision the build read. A build never replaces a bundle built
from newer rows. An equal or newer one publishes. Equal revisions mean the same
rows, so the last writer wins. The status rules are ADR-0084's: a full finalize
of a valid bundle completes the job, an invalid bundle never does and sends a
`completed` job back to `for_review`, a quick finalize of a valid bundle leaves
the status alone.

**4. A refused build publishes nothing, and the stored bundle stands.**

- It returns the stored bundle.
- The full finalize (the Finalize button) completes the job with that stored,
  newer bundle, unless its verdict is `invalid`. One transaction does the
  completion and reads the stored bundle.
- If the stored verdict is `invalid`, the call raises `BundleInvalidError` with
  the stored errors, and the route answers 409 as in ADR-0084. The 409 describes
  what is stored.
- The refused build's own verdict acts on nothing: it neither raises nor
  touches the status.
- The HTTP contract of `/finalize` is unchanged.
- The export file in `output/` stays as the refused build wrote it. It is never
  served: the job store is authoritative.

**5. A bundle names its build.** `jobs.bundle_build_json` holds:

| Field | Value |
|---|---|
| `kind` | `run`, `finalize` (the Finalize button) or `quick` (the auto-finalize) |
| `built_at` | UTC time, `%Y-%m-%dT%H:%M:%SZ` |
| `git_rev` | the revision of the process that built the bundle |
| `policy` | the relationship policy passed to `build_bundle`, read once |
| `env` | the `_CAPTURED_ENV` allow-list, names that are set and their values. The environment is never scanned, so no key can appear |
| `manifest` | `build_manifest()`: models, prompts, data files, packages |

`api/run_config.py::build_record` builds it for a finalize. The run's own
`_finalize_job` writes a `run` record copied from its run config
(`run_build_record`): Stage 4 ran in the run's subprocess, with the code and
data its run config captured at the start. The same `UPDATE` sets
`bundle_review_revision` to the job's current `review_revision`, so a finalize
that read the rows before the run's write is refused. `save_bundle` clears the
record and the revision, as it clears the ledger and the verdict.

Recording the build never fails the finalize: when `build_record` raises, the
record is `kind`, `built_at` and the `error`, without `git_rev`, so freshness
falls back to the run's revision, as for a bundle built before v12.

The record carries no overrides. Stages 4 and 5 never read them: they act in
Stages 2 and 3, and a finalize reads rows the run already filtered.

**6. Overrides are recorded by content.** The run config's `entity_overrides`
keeps `enabled`, `deny` and `promote`, and gains `fingerprint`
(`pipeline/overrides.py::overrides_fingerprint`): the first 16 hex characters of
the SHA-256 of the canonical JSON of the active deny keys and promote entries.
It does not depend on row order. It says whether the same rows applied, not
which rows.

**7. Freshness is judged on the build for a mapping fix.** Each
`BUNDLE_AFFECTING` entry gains a fourth field, its scope:

| Scope | The fix changes | Judged on | Cleared by |
|---|---|---|---|
| `mapping` | Stages 4 and 5 only | the revision of the build | a finalize at a revision that has the fix |
| `extraction` | Stages 1 to 3, maybe 4 too | the revision of the run and of the build: stale when either predates it | a new run |

`eaee534` (the self-edge guard) is `mapping`. `3a25f45` (ADR-0063: Stage 1 and 3
dates, and Stage 4) is `extraction`. A finalize rereads the rows a run wrote and
cannot add what the run never extracted. When in doubt, a new entry is
`extraction`: it never claims a rebuild fixed what a rebuild cannot.

`audit_staleness` returns `build_rev` as well, from `bundle_build_json`.
`unknown` is true only when neither revision is known. The audit script prints
both revisions when they differ (`run X, built Y`: an `extraction` fix can be
missing from the run while the finalize has it), the one known otherwise, and the
remedy for each scope: `POST /api/jobs/{id}/finalize` for a `mapping` fix, a new
run for an `extraction` fix.

## Alternatives considered

- **An explicit bump in each write path.** It works until a writer forgets one:
  a route, the worker's persistence, auto-accept, a future script. The trigger
  runs for every writer and cannot be forgotten.
- **Revision = `max(review_decisions.id)`.** The journal (ADR-0058) records
  changes of `accepted`. It does not record adds, edits or deletes.
- **A hash of the rows' content.** A hash is not ordered. It cannot say which of
  two builds is the newer.
- **Holding `_lock` through the mapping.** It serialises every finalize for the
  whole build. And `_lock` is per process: it does not cover several API
  processes or the workers.
- **Retrying a refused full finalize.** It costs an extra build, and the stored
  bundle already reflects newer decisions than the click's.

## Consequences

- **Every write to `entities` and `relationships` also updates its job row.**
  The cost is about 0.1 ms per row. 5,000 entity `INSERT`s took 0.66 s with the
  trigger and 0.16 s without, measured on a throwaway schema.
- **Policy, data and code changes do not bump the revision.** They are not
  decisions. Two builds from the same rows under different policies both
  publish: the last to finish wins, until the next finalize.
- **The job's own inputs are written by the run.** `report_text`,
  `llm_result_json`, `tlp_level` and `pap_level` do not bump the revision; the
  run's final write sets it.
- **The run stamps the revision current at its final write**, not the one its
  Stage 4 saw: the run maps what it holds in memory. An edit made while the job
  is still `processing` is not in the run's bundle, yet carries its revision.
  The next finalize, at that revision or a later one, publishes and replaces it.
- **`git_rev` is read from the checkout at build time**, as the run config reads
  it. An API process left running across a `git pull` names a revision whose
  code it may not have loaded, and can clear a `mapping` staleness it does not
  run the fix for. Restart the API after updating a checkout; an image carries
  the revision it was built from (ADR-0044).
- **A rebuild clears a `mapping` staleness, and only that.** A bundle stale for
  an `extraction` fix stays stale after any number of finalizes.
- **Bundles built before v12 are judged as before.** Their `bundle_build_json`
  is `NULL`, so the run's revision stands.
- **A refused full finalize returns, and completes the job with, a bundle built
  from newer decisions than the click's.** The route's response describes the
  stored bundle.
- **During a rolling restart, a finalize by an old-image process** writes the
  bundle without the record or the revision, and without the condition. It
  leaves `bundle_build_json` describing the previous build.
- **The export file is written by every build**, including refused ones.
  `output/{report}_bundle.json` can be a refused build's. Nothing reads it.

## Implementation

- `api/migrations/v0012_bundle_builds.py`; `trigger_exists` and `triggers_exist`
  in `api/migrations/__init__.py`.
- `api/db.py`: `transaction(conn, snapshot=True)`.
- `api/worker.py`: `re_run_final_stages` (snapshot, one conditional `UPDATE`),
  `_stored_newer_build`, `_finalize_job(build_json=...)`, `_WorkerHooks.run_config`.
- `api/run_config.py`: `captured_env`, `build_record`, `run_build_record`, and
  `entity_overrides.fingerprint` in `build_run_config`. `api/storage.py`:
  `save_bundle` clears the record and the revision.
- `pipeline/overrides.py`: `overrides_fingerprint`.
- `pipeline/bundle_revisions.py`: the scope field, `stale_entries(..., build_rev=)`,
  `audit_staleness`. `scripts/audit_bundle_invariants.py` prints the build
  revision and the remedy per scope; `scripts/audit_store_invariants.py` checks
  `bundle_build_json` as JSON.

Tests:

- `tests/test_bundle_builds.py`: the reproduction; the stored row is the newer
  build's in every column; a full finalize that loses the race completes the job
  with the newer bundle; a refused build's own verdict acts on nothing; a refused
  build raises the stored invalid verdict, quick and full; two builds from the
  same rows both publish; a build from newer rows replaces the stored one; a job
  deleted during a build is not an error; a damaged stored error list gives a
  409 without errors, not a 500; the snapshot reads one state and refuses
  writes, and every read of the rows by a finalize, the rejected ones included,
  runs inside it; `INSERT`, `UPDATE` and `DELETE` on both tables bump the
  revision, a row moved to another job bumps both, a route bumps it, and
  deleting a job with rows still works; the build record of a finalize (policy
  read once, no secret), and one that cannot be built; the run's write stores its record and revision; a
  finalize that read the rows before the run's write is refused.
- `tests/test_migrations.py`: v12 from a database at v11.
- `tests/test_bundle_staleness.py`: the scope of each known fix; a `mapping` fix
  judged on the build, an `extraction` fix stays stale after a rebuild; a missing
  revision judges nothing; `audit_staleness` reads the build record; the audit
  line names both revisions when they differ.
- `tests/test_run_config.py`, `tests/test_overrides_runtime.py`,
  `tests/test_edge_provenance.py`, `tests/test_worker.py`: the allow-listed
  environment, the build record, the fingerprint (order-independent, content
  sensitive, ignores rows that do not act), a run stores its build, the storage
  layer clears it.
- Run locally on 2026-10-17 (PostgreSQL test server, `SKIP_HEAVY_MODELS=1`):
  full suite 2,747 passed, 9 skipped (mostly optional packages absent
  locally: schemathesis, google-re2, atheris), 0 failed; `ruff check .` clean; mypy clean on 134 files.
