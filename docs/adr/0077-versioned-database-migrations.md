# ADR-0077: The database knows its version; every start brings it up to date

**Status:** Accepted — application schema (part A) implemented; engine guards (part B) to do
**Date:** 2026-10-04
**Deciders:** maintainer
**Amends:** ADR-0045 (PostgreSQL job store), ADR-0053 (PostgreSQL only), ADR-0076 (PostgreSQL 18)

## Context

Two kinds of version change reach the database, and neither was tracked.

**1. The application's data model.** `api/db.py` held two tuples of
statements, `_RULE_STORE_DDL_POSTGRES` and `_JOB_STORE_DDL_POSTGRES`, that
`init_db()` replayed at every API start and every `bootstrap`. Every statement
was idempotent — `CREATE TABLE IF NOT EXISTS`, `ALTER TABLE … ADD COLUMN IF
NOT EXISTS`, two backfills that "after the first run match nothing". The
comment said it: *this list is the migration mechanism too*. It worked
because every change so far was additive. It could not express anything else:

- no record of what was applied, when, by which code: the database could not
  say which version it was at;
- a change that is not idempotent by construction — rename or retype a
  column, split a table, drop a column, move data, rewrite stored JSON — had
  no place in the list;
- backfills ran at every start, forever;
- an older image started on a newer database was not detected;
- concurrency was handled by tolerating duplicate-object errors, and the
  worker never ran `init_db()`: it relied on the API having started first.

Part of the data model lives **inside columns**: `llm_result_json` (a
Pydantic model), `bundle_json`, `bundle_ledger_json` (`LEDGER_VERSION`),
`times_json` (`TemporalAssertion`), `policy_json` (`"version": 1`).

**2. The database engine.** ADR-0076 moved PostgreSQL 17 → 18 with a one-off
script run by hand before `docker compose up`; skipped, the new server starts
on an empty cluster and the app shows no reports, without an error. With the
18 image's single mount at `/var/lib/postgresql`, the next major will do the
same: 19 will find `18/docker` beside an empty `19/docker` and initialise it.

**Requirements (maintainer, 2026-10-04).** When the application starts, the
server checks the tables present and applies the migrations needed to be up to
date — schema *and* data — whatever earlier version the database is at; so
there is a history of verification and upgrade scripts, one per version. The
history starts with the PostgreSQL versions: the SQLite store before
ADR-0045 was a prototype and is out of scope.

Constraints: one maintainer; compose stack with an `app` and N `worker`
containers on one PostgreSQL; air-gapped installs; the app container has no
PostgreSQL client and is given no Docker socket; dependency count and supply
chain matter (ADR-0075); Dependabot keeps the engine moving forward.

## Decision

### A. The application schema: a versioned history, applied at every start

1. **`schema_migrations`** records each version a database has: `version`,
   `name`, `checksum`, `how` (`applied`, or `recognised` for a database
   created before the history), `applied_at`, `duration_ms`, `app_revision`.
   The database's version is the highest one.
2. **The history is code:** `api/migrations/vNNNN_<name>.py`, one module per
   version, numbered without gaps from **version 1 = the first PostgreSQL job
   store (ADR-0045, commit 5e2c2f8)**. The nine versions to date were rebuilt
   from git, each with the exact statements its commit added: job store (1),
   `model_thresholds` (2), `entity_overrides` (3), relationship time bounds
   (4), rule store (5), decision provenance and its `legacy` backfill (6),
   `review_decisions` without its key to `jobs` (7), bundle ledger (8),
   relationship dates (9).
3. **Each version carries its verification**, `is_applied(conn)`: the tables,
   columns, indexes, constraints — and data conditions where it has a data
   step (version 6: no decision left without an origin) — that its changes
   leave. It is used twice: after applying, to roll the version back if its
   changes are not there; and on a database created before the history, to
   recognise how far that database had got.
4. **Forward only, one transaction per version**: snapshot of the tables it
   declares (`snapshot_tables` → `_pre_vNNNN_<table>`, for drops, renames,
   retypes, rewrites in place), statements, `data(conn)` Python step (JSON
   rewrites, batched backfills), verification, record. A failure rolls the
   whole version back and stops the start. No down-migrations: the snapshot
   (or a `pg_dump`) is the way back.
5. **Applied at every start, by every process**: `init_db()` — called by the
   API at start, by every worker at start, by `bootstrap`, by the test
   fixtures — runs `api.migrate.upgrade` under a **PostgreSQL advisory lock**
   (one per schema), so whichever process starts first migrates and the
   others wait and find nothing left; the worker no longer depends on the
   API starting first.
6. **Refusals that stop the start, with the reason and what to do**: a
   database newer than the code (an older image after a newer one migrated);
   a recorded checksum that no longer matches its file (an applied migration
   was edited — a change is always a new file). The checksum covers the
   statements and the data step, whitespace-normalised, not the comments.
7. `python -m api.migrate status | up | check` for operators and scripts;
   the one-shot SQLite import scripts get each store's statements from the
   history (`store_statements`), and the database they fill is recognised at
   the next start.

### B. The engine: detect the major version, never start on an empty cluster (to do)

8. **A guard in front of PostgreSQL's entrypoint** (`docker/postgres/guard.sh`,
   mounted read-only, compose `entrypoint:`): if `$PGDATA` has no cluster yet
   but another `/var/lib/postgresql/<major>/docker/PG_VERSION` exists in the
   volume, exit with "cluster of PostgreSQL <old> found, this image is
   <new>: run `make db-upgrade`" instead of initialising an empty one.
9. **The app remembers which cluster it was on**: the cluster's
   `system_identifier` and the schema version in `cti-state/db-identity.json`;
   an empty database where that file says data existed on another cluster
   stops the start ("PostgreSQL upgraded without moving the data? run
   `make db-upgrade`"); a database restored from a dump (new identifier,
   tables present) is accepted and recorded.
10. **`make db-upgrade`** generalises ADR-0076's script: reads the cluster's
    major from `PG_VERSION` in the volume, the target from the compose image,
    dumps with a throwaway server of the source major, restores, compares
    every table's row count; the next start then applies the schema history.

## Options considered

### Application schema

#### Option A1: keep the idempotent list, add a version stamp

| Dimension | Assessment |
|---|---|
| Complexity | Low — a table and a number |
| Cost | None |
| Scalability | Breaks at the first non-additive change |
| Team familiarity | High — the previous code |

**Pros:** nothing to learn.
**Cons:** the stamp gives a number but the list still cannot express a
rename, a split, a data move; backfills replay at every start; no history of
what each version was, so "whatever earlier version" cannot be honoured.

#### Option A2: Alembic

| Dimension | Assessment |
|---|---|
| Complexity | Medium — SQLAlchemy as a new dependency for its engine, `env.py`, revision graph |
| Cost | Two new dependencies (SQLAlchemy, Alembic) to audit and keep current |
| Scalability | Proven at any size; branches and merges of revision graphs |
| Team familiarity | Widely known; but this code base uses raw psycopg and SQL strings, no ORM |

**Pros:** the standard tool; version table; offline SQL generation.
**Cons:** autogenerate — its main convenience — needs SQLAlchemy models the
project does not have, so migrations are written by hand anyway; no
recognition of databases created before it (a manual `stamp`); no advisory
lock built in; a second database layer beside `api/db_backend.py`.

#### Option A3: in-house runner over numbered Python modules *(chosen)*

| Dimension | Assessment |
|---|---|
| Complexity | Low–medium — ~250 lines of runner, three commands, one table |
| Cost | No new dependency |
| Scalability | A linear history fits one product with one database |
| Team familiarity | Same idioms as `api/db.py` (psycopg, SQL strings, `transaction()`) |

**Pros:** exactly the guarantees asked for — version, order, once,
transaction, lock, verification per version, recognition of older databases,
refuse-newer, checksum — and nothing else; plain files a reviewer reads;
works offline.
**Cons:** ours to maintain; branch merges of the history would have to be
written if ever needed.

#### Option A4: an external migration binary (dbmate, golang-migrate, Flyway)

| Dimension | Assessment |
|---|---|
| Complexity | Low to use, medium to ship (a binary per architecture, or a JVM) |
| Cost | One more artefact to pin, attest and audit (ADR-0075) |
| Scalability | Proven |
| Team familiarity | Low |

**Pros:** mature; version table and locking included.
**Cons:** data migrations that rewrite JSON with the project's own models need
Python anyway; no per-version verification of the kind A3 uses to recognise
older databases.

### Engine major version

- **E1, a hand-written script per upgrade** (ADR-0076): works, but the
  failure when it is skipped is silent.
- **E2, detect and guard, then one generic command** *(chosen, to do)*.
- **E3, automatic in-place `pg_upgrade --link` via a third-party image
  (pgautoupgrade):** fastest, but hands the only copy of the data to an
  unaudited image at start; rejected in ADR-0076.

## Trade-off analysis

Every migration this project writes is hand written (no ORM to diff), half the
data model is JSON inside columns that only the project's Python models can
rewrite, several processes start against one database, and the databases in
the field were created by an unversioned list. A3 answers all four: Python
modules hold SQL and data steps alike, the advisory lock serialises the
starts, and the per-version verification that guards each application is the
same check that recognises an older database's version. A2 would add an ORM
layer for its version table without its main feature, and would still need
the recognition written by hand; A1 cannot meet "whatever earlier version"
for non-additive changes; A4 still needs Python for the data half.

Migrating at start rather than in a separate one-shot step is what the
maintainer asked for, and is safe here because of the lock and the
transaction per version; the cost — a start blocked while a long data
migration runs — is visible in the log and is the moment it has to happen
anyway. Forward-only with snapshots is preferred to down-migrations: a
down-migration of a data change rarely restores what was transformed; the
snapshot taken in the same transaction always does.

## Consequences

- **Easier:** any schema or data change ships as a file with a test; a
  database at any version since ADR-0045 is brought up to date by starting
  the application; `migrate status` answers "which version is this
  database"; an older image is refused instead of writing to a schema it does
  not know; the worker no longer depends on the API's start order.
- **Harder:** every schema change needs a migration module, its verification
  and a test; applied migrations cannot be edited.
- **Verified (2026-10-04):** the history builds exactly the schema the old
  `init_db()` built (columns, types, defaults, constraints, indexes compared
  through the catalog); a database stopped at each of versions 1–8 with data
  in it is brought to 9 with its data and the version-6 backfill; the
  pre-versioning schema and a copy of the preview database (7 reports) are
  recognised at version 9 without a change; four processes starting together
  migrate once; a failing version and a version whose check does not see it
  roll back entirely; an edited migration and a newer database are refused.
- **To revisit:** part B; if a data migration ever takes long enough to make
  a start unacceptably slow, run it as a one-shot `migrate up` before
  deploying (the command exists).

## Action items

1. [x] `api/migrate.py`: runner (`status`, `up`, `check`), `schema_migrations`,
       advisory lock, checksums, refuse-newer, verification after apply,
       recognition of pre-history databases, snapshots.
2. [x] `api/migrations/v0001`–`v0009` rebuilt from git; `init_db()` runs the
       runner; the DDL tuples are derived from the history.
3. [x] The API, every worker and `bootstrap` migrate at start.
4. [x] `tests/test_migrations.py`; `tests/fixtures/schema_before_adr0077.json`
       freezes the schema the old `init_db()` built.
5. [x] docs: `docs/development.md` (writing a migration), `docs/database-schema.md`.
6. [ ] Part B: `docker/postgres/guard.sh` and compose `entrypoint:`; cluster
       identity in `cti-state`; `make db-upgrade`; `docs/upgrading.md`.
7. [ ] CI job that migrates a dump of the previous release's database.
