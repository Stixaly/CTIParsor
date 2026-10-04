# ADR-0077: The database knows its version; a migration runner brings it up to date

**Status:** Proposed
**Date:** 2026-10-04
**Deciders:** maintainer
**Amends:** ADR-0045 (PostgreSQL job store), ADR-0053 (PostgreSQL only), ADR-0076 (PostgreSQL 18)

## Context

Two kinds of version change reach the database, and neither is tracked today.

**1. The application's data model.** `api/db.py` holds two tuples of
statements, `_RULE_STORE_DDL_POSTGRES` and `_JOB_STORE_DDL_POSTGRES`, that
`init_db()` replays on every API start and every `bootstrap`. Every statement
is written to be idempotent — `CREATE TABLE IF NOT EXISTS`,
`ALTER TABLE … ADD COLUMN IF NOT EXISTS`, and two backfills
(`UPDATE … SET decision_origin='legacy' WHERE … IS NULL`) that "after the
first run match nothing". The comment says it plainly: *this list is the
migration mechanism too*. It has worked because every change so far was
additive. It cannot express anything else:

- no record of what was applied, when, by which code revision: the database
  cannot say which version it is at;
- a change that is not idempotent by construction — rename or retype a
  column, split a table, drop a column, move data from one column into a new
  table, rewrite stored JSON — has no place in the list;
- backfills run on every start, forever, and grow with the data;
- an older image started against a newer database (a rollback) is not
  detected;
- concurrency is handled by tolerating duplicate-object errors
  (`_apply_postgres_ddl`), and the worker never runs `init_db()`: it relies
  on the API having started first.

Part of the data model lives **inside columns**: `llm_result_json`
(a Pydantic model), `bundle_json`, `bundle_ledger_json` (`LEDGER_VERSION`),
`times_json` (`TemporalAssertion`, with a `legacy` origin), `policy_json`
(`"version": 1`). Their evolution is handled by tolerant readers in the code;
nothing ever rewrites old rows, and since lot 0's D10 a row a reader can no
longer parse is logged, not silently skipped.

**2. The database engine.** ADR-0076 moved PostgreSQL 17 → 18 with a
one-off script, run by hand before `docker compose up`, because a major
version cannot open the previous one's data directory. If the step is
skipped, the new server starts on an empty cluster and the app sees no
reports — no error anywhere. With the 18 image's single mount at
`/var/lib/postgresql`, the next major will do exactly that again: PostgreSQL 19
will find `18/docker` beside its empty `19/docker` and initialise the latter.

The requirement (maintainer, 2026-10-04): **whenever the data model or the
version changes, a migration step must find out which version the database
is at and apply the upgrades of the schema and of the data that are needed.**
Constraints that shape the answer: one maintainer; compose stack with an
`app` and N `worker` containers on one PostgreSQL; air-gapped installs; the
app container has no PostgreSQL client and is given no Docker socket;
dependency count and supply chain matter (ADR-0075); Dependabot keeps the
engine moving forward.

## Decision

### A. The application schema: versioned migrations, applied by one runner

1. **`schema_migrations` table**: `version` (integer, primary key), `name`,
   `checksum` (SHA-256 of the migration's source), `applied_at`,
   `duration_ms`, `app_revision` (git revision of the code that applied it).
   The database's version is `max(version)`.
2. **Migrations are files**, `api/migrations/NNNN_short_name.{sql,py}`,
   numbered without gaps, **forward-only**. SQL for schema changes; Python
   (`def upgrade(conn): …`) for data changes — backfills in batches, rewriting
   JSON columns from one stored format to the next. Each runs **in one
   transaction** (PostgreSQL has transactional DDL), so a failure leaves the
   version unchanged; a migration that cannot run in a transaction
   (`CREATE INDEX CONCURRENTLY`) says so in a header and runs alone.
3. **Migration 0001 is the baseline**: today's two DDL tuples, unchanged,
   still idempotent — on an existing database it changes nothing and records
   version 1; on an empty one it creates everything. The tuples are frozen
   after it; every later change is a new file. The two legacy backfills move
   into it and stop running at each start.
4. **One runner**, `python -m api.migrate`, with `status` (current, target,
   pending, checksum mismatches), `up` (apply what is pending) and `check`
   (exit non-zero unless the database is exactly at the code's version):
   - takes a PostgreSQL **advisory lock**, so app, workers and a manual run
     never migrate concurrently — the others wait, then find nothing pending;
   - refuses to run if an applied migration's checksum changed (an applied
     migration is never edited; write a new one);
   - refuses to touch a database whose version is **newer** than the code's
     (an older image after a rollback): the process stops with "database at
     version N, this code knows up to M — restore the pre-migration backup or
     deploy a newer image".
5. **Who runs it.** A one-shot `migrate` service in compose (the app image,
   `command: migrate`), between `postgres` and `app`/`worker`:
   `app` and `worker` depend on it with `condition: service_completed_successfully`.
   `bootstrap` runs it first. At start, `app` and `worker` only run
   `migrate check` and stop with a clear message if the version is not
   theirs — they never migrate themselves. `init_db()` becomes `migrate up`
   for host and test setups, so tests always build the schema the same way
   production does.
6. **Backups before what cannot be undone.** A migration declares itself
   `destructive` (drops, renames, type changes, rewriting data in place). The
   runner applies additive migrations by itself; it applies a destructive one
   only if a backup was recorded after the database reached its current
   version (`schema_backups` row, written by `make db-backup`, which runs
   `pg_dump -Fc` inside the postgres container — the only place a `pg_dump`
   of the server's own major is guaranteed). Otherwise it stops and says
   which command to run. Restoring that dump is the way back: there are no
   down-migrations.
7. **Rules for writing migrations** (docs/development.md): expand then
   contract — a new column is added nullable, filled, and only made required
   or used exclusively in a later migration, so a worker of the previous
   revision never meets a schema it cannot write to during a rolling restart;
   a stored JSON format gets a version field, its migration rewrites old rows
   in batches, and the tolerant reader is removed one release later.

### B. The engine: detect the major version, never start on an empty cluster by mistake

8. **A guard in front of PostgreSQL's entrypoint** (`docker/postgres/guard.sh`,
   mounted read-only, compose `entrypoint:`): if `$PGDATA` has no cluster yet
   but another `/var/lib/postgresql/<major>/docker/PG_VERSION` exists in the
   volume, it exits with "cluster of PostgreSQL <old> found, this image is
   <new>: run `make db-upgrade`" instead of initialising an empty one. This
   is the failure ADR-0076 could only document.
9. **The app remembers which cluster it was on.** The runner records the
   cluster's `system_identifier` and the schema version in
   `cti-state/db-identity.json`. If at start the database is empty while that
   file says data existed on another cluster, it refuses to create a fresh
   schema: "the database was replaced and is empty — PostgreSQL upgraded
   without moving the data? run `make db-upgrade`". A database restored from
   a dump (new identifier, tables present) is accepted and recorded.
10. **`make db-upgrade` generalises ADR-0076's script**: it reads the
    cluster's major from `PG_VERSION` in the volume (a throwaway `alpine`
    container), the target major from the compose image, dumps with a
    throwaway server of the **source** major (`postgres:<old>-alpine`), starts
    the target, restores, compares every table's row count, and then runs
    `migrate up` — so an engine upgrade and the schema migrations it may
    bring happen in one command, in the right order. `scripts/upgrade_postgres_17_to_18.sh`
    becomes the special case for the pre-18 layout.

## Options considered

### Application schema

#### Option A1: keep the idempotent list, add a version stamp

| Dimension | Assessment |
|---|---|
| Complexity | Low — a table and a number |
| Cost | None |
| Scalability | Breaks at the first non-additive change |
| Team familiarity | High — it is today's code |

**Pros:** nothing to learn; nothing to migrate.
**Cons:** the stamp says a number but the list still cannot express a rename,
a split, a data move; backfills still replay at every start; no ordering
between data and schema steps.

#### Option A2: Alembic

| Dimension | Assessment |
|---|---|
| Complexity | Medium — SQLAlchemy as a new dependency for its engine, `env.py`, revision graph |
| Cost | Two new dependencies (SQLAlchemy, Alembic) to audit and keep current |
| Scalability | Proven at any size; branches and merges of revision graphs |
| Team familiarity | Widely known; but this code base uses raw psycopg and SQL strings, no ORM models |

**Pros:** the standard tool; `alembic_version` table; downgrade scaffolding;
offline SQL generation.
**Cons:** autogenerate — its main convenience — needs SQLAlchemy models the
project does not have, so migrations are written by hand anyway; no advisory
lock built in (still to add); a second database layer (SQLAlchemy engine)
beside `api/db_backend.py`; down-migrations encourage a false sense of
reversibility for data changes.

#### Option A3: in-house runner over numbered SQL/Python files *(chosen)*

| Dimension | Assessment |
|---|---|
| Complexity | Low–medium — ~200 lines of runner, three commands, two tables |
| Cost | No new dependency; tests to write once |
| Scalability | Linear history fits one product with one database; no branching needed |
| Team familiarity | Same idioms as `api/db.py` (psycopg, SQL strings, `_apply_postgres_ddl`) |

**Pros:** exactly the guarantees asked for (version, order, once, transaction,
lock, checksum, refuse-newer, backup gate) and nothing else; migrations are
plain files a reviewer reads; works offline; reuses `api/db_backend.py`.
**Cons:** ours to maintain; no generator for SQL (not needed: there are no
models to diff); features like branch merges would have to be written if ever
needed.

#### Option A4: an external migration binary (dbmate, golang-migrate, Flyway)

| Dimension | Assessment |
|---|---|
| Complexity | Low to use, medium to ship (one more binary or a JVM in the image) |
| Cost | A binary per architecture to pin, attest and audit (ADR-0075) |
| Scalability | Proven |
| Team familiarity | Low |

**Pros:** mature, SQL-only, version table and locking included (Flyway, golang-migrate).
**Cons:** data migrations that rewrite JSON with the project's own Pydantic
models need Python anyway; a second toolchain in a Python image; Flyway brings
a JVM.

### Engine major version

#### Option E1: a hand-written script per upgrade (ADR-0076 as it is)

Works, tested; but relies on the operator reading the upgrade notes, and the
failure when they do not is silent (empty database).

#### Option E2: detect and guard, then one generic command *(chosen)*

Guard in the postgres entrypoint, cluster identity on the app side,
`make db-upgrade` that reads both versions and does dump → restore → verify →
`migrate up`. Dump/restore is slower than `pg_upgrade --link` but needs only
the official images and works across any number of majors.

#### Option E3: automatic in-place upgrade (`pg_upgrade --link` via a third-party image such as pgautoupgrade)

Fastest and fully automatic, but hands the only copy of the data to an
unaudited image at container start, with both binaries' versions to keep in
step; rejected in ADR-0076 for the same reason.

## Trade-off analysis

The deciding facts are that every migration this project will write is hand
written (no ORM to diff), that half of the data model is JSON inside columns
whose migration needs the project's own Python models, and that the stack
runs several processes against one database. A3 gives version tracking,
ordering, exactly-once, transactions and a lock in a few hundred lines that
use the code base's own database layer; A2 would add an ORM layer to obtain
the same table and runner, without its main feature; A1 does not meet the
requirement for non-additive changes; A4 still needs Python for the data half.

On the engine side, the cost that matters is not the minutes a dump/restore
takes but the silent empty database when the step is forgotten: E2 turns
that into a refusal with the command to run, at two independent points (the
postgres guard and the app's cluster identity), and keeps the data path on
official images only.

Forward-only with a mandatory backup before destructive steps is preferred to
down-migrations: a down-migration of a data change rarely restores the data
that was transformed, and a restore of the dump taken just before always does.

## Consequences

- **Easier:** any schema or data change — rename, split, retype, move data,
  rewrite stored JSON — ships as a file with a test; `migrate status` answers
  "which version is this database at"; a rollback to an older image is
  refused instead of writing to a schema it does not know; a forgotten engine
  upgrade stops with instructions instead of showing an empty application.
- **Harder:** every schema change needs a migration file and a test; applied
  migrations cannot be edited; destructive migrations need `make db-backup`
  first (one command, on purpose).
- **Startup:** `docker compose up` gains a short one-shot `migrate` step
  before `app` and `worker`; the API no longer creates tables at start.
- **To revisit:** if the project ever needs several deployable branches with
  diverging schemas, the linear numbering will need merge handling (A2's
  strength); if a database grows large enough that dump/restore takes too
  long, `pg_upgrade --link` with official images.

## Action items

1. [ ] `api/migrate.py`: runner (`status`, `up`, `check`), `schema_migrations`
       and `schema_backups` tables, advisory lock, checksums, refuse-newer,
       destructive gate, cluster identity file.
2. [ ] `api/migrations/0001_baseline.sql` from today's two DDL tuples and
       their two backfills; `init_db()` calls the runner; the tuples are
       frozen with a comment pointing here.
3. [ ] Tests: empty database → target version equals the baseline schema
       (compared with `information_schema`); existing database at the
       pre-ADR schema → version 1, no change; two concurrent runners → one
       applies, one waits and finds nothing; edited checksum → refused;
       newer database → refused; destructive migration without backup →
       refused; a sample Python data migration in batches; CI job that
       migrates a dump of the previous release's schema.
4. [ ] compose: `migrate` one-shot service; `app`/`worker` depend on it with
       `service_completed_successfully`; their entrypoints run `migrate check`;
       `bootstrap` runs `migrate up` first.
5. [ ] `make db-backup` (pg_dump in the postgres container, records a
       `schema_backups` row), `make db-status`, `make db-migrate`.
6. [ ] `docker/postgres/guard.sh` and compose `entrypoint:` for the postgres
       service; test it with an 18 cluster in a volume and a 19 image.
7. [ ] `make db-upgrade`: generic engine upgrade (detect, dump with the source
       major, restore, verify row counts, `migrate up`); ADR-0076's script kept
       for the pre-18 layout.
8. [ ] docs: `docs/development.md` (how to write a migration: expand/contract,
       destructive flag, JSON formats), `docs/upgrading.md` (one procedure for
       every upgrade), `docs/database-schema.md` (where the version lives).
