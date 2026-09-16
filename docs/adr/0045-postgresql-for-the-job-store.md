# ADR-0045 — PostgreSQL for the job store, SQLite kept for the rule corpus

**Status:** Accepted (implemented and validated 2026-09-16)
**Date:** 2026-09-16
**Relates to:** [0036](0036-architecture-service-multi-utilisateur.md) (no ORM;
repository-style raw SQL is the migration surface), [0037](0037-scaling-to-30-40-users.md)
(Option C: PostgreSQL for the transactional tables, the read-only corpus stays in
SQLite), [0044](0044-container-images.md) (the compose stack this adds a service to),
[0002](0002-concurrent-report-ingestion.md) (the worker subprocess owns its own
connection)

## Context

ADR-0037 accepted PostgreSQL "deferred and narrowed": for `jobs`, `entities`,
`relationships` and `progress_events`, at the moment authentication makes
concurrent writers real, and never for the detection corpus. ADR-0044 packaged
the application as one container and a volume, with no database service, for
the same reason. The maintainer has now decided to bring the PostgreSQL step
forward: a database container beside the application, the classic two-tier
deployment, without waiting for authentication.

What the code does today, measured on 2026-09-16:

| Fact | Value |
|---|---|
| SQL call sites (`execute`/`executemany`/`executescript`) | 213 in total — 70 in `api/`, ~50 in `pipeline/detection/`, the rest in one-off `scripts/` |
| Functions annotated `sqlite3.Connection` | 80 — 17 in `pipeline/detection/store.py` alone |
| Placeholders | `?` everywhere; PostgreSQL's driver wants `%s` |
| Row access | 89 `row["col"]`, 6 `dict(row)`, 4 `.keys()`, a handful of `row[0]` — `sqlite3.Row` supports all of them |
| SQLite-only statements on the per-job tables | 7 upserts (`INSERT OR REPLACE` / `INSERT OR IGNORE`), one `AUTOINCREMENT`, one `BEGIN IMMEDIATE` |
| SQLite-only statements on the rule tables | FTS5 virtual table `rule_text` with `MATCH`, two `INDEXED BY` hints, 12 upserts, `sqlite_master` probes |
| `%` or `LIKE` literals in per-job SQL | none (placeholder translation is safe) |
| Where both stores meet in one function | `pipeline/detection/coverage.py` (`job_technique_ids`, `_evidence_for_job` and their callers), `relevance.py::job_observable_rows`, `artifacts.py::coverage_for_job` — each reads `entities` and rule tables through the *same* connection |
| Real database | 9 jobs, 1,010 entities, 242 relationships, 192 progress events, 71 report figures, 91 figure reads; largest `bundle_json` 738 KB |
| SQLite in use | 3.46 — `INSERT … ON CONFLICT` (3.24+) is available |
| Driver | psycopg 3.3.5, binary wheels for CPython 3.12–3.14 |

Two facts shape the decision. First, the rule corpus **cannot** move without a
rewrite: `rule_text` is an FTS5 table queried with `MATCH` (ADR-0031), and
`store.py` carries planner hints that PostgreSQL has no equivalent for. Second,
the per-job SQL is already portable except for seven upserts, and every row is
read by column name — so a thin driver adapter, not an ORM, is enough.

## Decision

**Two stores, selected by one variable.**

- `DATABASE_URL` unset (host installs, the CLI, the test suite): everything
  stays in `cti_stix.db` exactly as today. Zero behaviour change.
- `DATABASE_URL=postgresql://…` (the compose stack): the per-job tables live in
  PostgreSQL — `jobs`, `entities`, `relationships`, `progress_events`,
  `relationship_policy`, `report_figures`, `figure_reads`, `cve_cache`. The
  rule corpus — `detection_rules`, `rule_bytes`, `rule_techniques`,
  `rule_atoms`, `rule_related`, `rule_text` — stays in the SQLite file, which
  becomes a rebuildable index (ADR-0044's `bootstrap` fills it).

`api/db.py` grows two getters instead of one: `get_conn()` returns the **job
store** (PostgreSQL or SQLite), `get_rule_conn()` always returns the SQLite
rule store. With no `DATABASE_URL` both are the same connection object, which
is what keeps every existing caller and test valid.

### The adapter, not an ORM

A new `api/db_backend.py` holds what PostgreSQL needs and nothing else:

| Piece | What it does | Why |
|---|---|---|
| `translate_placeholders(sql)` | `?` → `%s` outside string literals, `%` → `%%` | keeps 70 call sites untouched; psycopg has no `qmark` mode |
| `Row` | a tuple that also answers `row["col"]`, `.keys()`, `dict(row)` | the code's access pattern is `sqlite3.Row`'s; a `dict_row` would break the `row[0]` sites |
| `PgConnection` | `execute` / `executemany` / `commit` / `rollback` / `close`, thread-local like today, **autocommit** like today, a context manager that does **not** close the connection | psycopg's own `with conn:` closes it, which would kill the per-thread cache on the first route |
| DDL for PostgreSQL | the same eight tables, `IDENTITY` instead of `AUTOINCREMENT`, `DOUBLE PRECISION` instead of `REAL`, `IF NOT EXISTS` on every column migration | `REAL` in PostgreSQL is a 4-byte float and would round every confidence score |

The seven per-job upserts are rewritten to standard `INSERT … ON CONFLICT (…)
DO UPDATE/NOTHING`, which SQLite 3.24+ and PostgreSQL both accept — one
statement, both engines. The twelve rule-store upserts are not touched.

### Where the stores meet

The coverage functions gain a keyword `jobs_conn` (default `None`, meaning
"same as `conn`"): the route passes `conn=get_rule_conn(), jobs_conn=get_conn()`,
a test keeps passing one in-memory connection. Nothing in `pipeline/detection`
learns about PostgreSQL.

### Operations

- `scripts/migrate_jobs_to_postgres.py` copies the eight tables from an existing
  `cti_stix.db` into PostgreSQL, in foreign-key order, preserving
  `progress_events` ids (the SSE resume point) and resetting the sequence.
- `backup_db()` keeps backing up the SQLite file (rule store, and the job
  store when there is no `DATABASE_URL`); with PostgreSQL it logs that
  `pg_dump` is the operator's tool.
- Compose adds a `postgres:17-alpine` service on the `backend` network only,
  no published port, running as the image's `postgres` user with every
  capability dropped, a `pg_isready` healthcheck the app waits for, and its
  own volume. The password comes from `.env` (`CTI_DB_PASSWORD`, required).

## Options considered

### A — Adapter over raw SQL, two stores (accepted)

Days, not weeks; the FTS5 corpus is untouched; host installs and 1,188 tests
keep running on SQLite; the PostgreSQL path is exercised by the same tests
through a `CTIPARSOR_TEST_DATABASE_URL` switch in the `temp_db` fixture.

### B — SQLAlchemy / SQLModel

Rejected by ADR-0036 and nothing has changed: FTS5 stays raw `text()`, the
autocommit design fights the unit-of-work, and the measured problems were
never in the data-access layer.

### C — Move the rule corpus too

Rejected. `MATCH` becomes `to_tsvector`/`pg_trgm` with different tokenisation
(ADR-0031 chose FTS5 precisely for its word-boundary semantics), the two
`INDEXED BY` hints have no equivalent, `build_detection_index.py` and the
whole of `pipeline/detection/` would be rewritten, and the corpus is a
batch-built, read-only index with no concurrency requirement. ADR-0037 said
the same.

### D — PostgreSQL only, drop SQLite

Rejected. Every host install would need a database daemon; the CLI
(`main.py`) would need one to run a single report; the test suite would need
one to run at all. The `DATABASE_URL` switch costs one branch in `get_conn()`.

### E — A routing connection that sends each statement to the right store by table name

Rejected. It would let the coverage code stay untouched, but a query joining
both stores would fail at runtime instead of at review time, and tests would
exercise an object production never uses.

## Consequences

- Host installs: nothing changes. `DATABASE_URL` is opt-in.
- Compose: the job store is PostgreSQL by default; `cti-state` keeps the SQLite
  rule store, uploads, outputs; a new `pg-data` volume holds the database, and
  `docs/docker.md` says which of the two to back up (both).
- The worker subprocess opens its own PostgreSQL connection (it already had
  its own SQLite connection). Peak connections ≈ uvicorn's thread pool plus
  one per running report; the default `max_connections=100` covers it and the
  figure is documented.
- What becomes harder: two things to back up instead of one; a test that
  touches both stores must ask for both connections; `sqlite3.OperationalError`
  handling in migrations is replaced by `IF NOT EXISTS` DDL.
- Still not done, deliberately: authentication. This ADR changes where the
  rows live, not who may read them — ADR-0037's condition for PostgreSQL was
  authentication, and that order is now reversed by the maintainer's decision.

## What building it changed

1. **The connection protocol had to be loose.** A `Protocol` whose `execute`
   took `Sequence | None` did not match typeshed's `sqlite3.Connection.execute`
   (`SupportsLenAndGetItem | Mapping`), so mypy rejected every `get_conn()`
   return. The protocol's parameter types are `Any`; the wrapper stays typed.
2. **`sqlite3.Error` handlers do not catch psycopg errors.** `figure_store.py`
   guarded its cache reads and writes with `except sqlite3.Error` — on
   PostgreSQL a failed cache write would have aborted the job instead of
   logging. `api.db.DB_ERRORS` is now the tuple to catch, `(sqlite3.Error,
   psycopg.Error)` when the driver is installed.
3. **`REAL` would have changed stored scores.** Caught by design review, then
   locked by a test: a confidence of `0.9` reads back as exactly `0.9` only with
   `DOUBLE PRECISION`.
4. **76 tests encoded the single-store assumption.** They wrote rule tables
   through the job-store connection and passed only because both were the same
   file. Two of them (`backup_db`, a `PRAGMA table_info` probe) are SQLite by
   nature and now skip on PostgreSQL; the other 74 were rewritten to ask for
   both connections and pass `jobs_conn=`. They remain valid on SQLite, where
   both getters return the same object.
5. **Forgetting `jobs_conn` on PostgreSQL fails loudly**, with `no such table:
   entities` from the SQLite rule store — not with an empty coverage. The
   integration test asserts the error rather than a zero.
6. **The migration script needed `pg = None` before its `try`**, or a failed
   connect would raise `NameError` from the `finally` instead of the real
   error. And the delivered tests had invented `relationships` columns
   (`source_id`, `target_id`, `rel_type`) — the spec had said "9 columns"
   without listing them; corrected from the real schema.

## Validation record (2026-09-16)

| Check | Result |
|---|---|
| Full suite, SQLite mode (`SKIP_HEAVY_MODELS=1`) | **1198 passed**, 12 skipped (the 10 PostgreSQL-only integration tests, plus 2 pre-existing) |
| Full suite, PostgreSQL mode (`CTIPARSOR_TEST_DATABASE_URL`, `postgres:17-alpine`, one disposable schema per test) | **1206 passed**, 4 skipped (2 SQLite-only), **0 failed** — down from 76 failures before the test rewrite |
| `tests/test_db_backend.py` (adapter, no server) | 10 passed |
| `tests/test_db_postgres.py` (live server) | 10 passed, including the migration script end to end: ids preserved, sequence realigned, `--append` guard |
| ruff `--select E,F,W,I` on `pipeline/ api/ models/ tests/` | clean |
| mypy on `pipeline/ api/ models/` | clean |
| Container: `docker compose up` with the `postgres` service | both healthy; `backend()` answers `postgresql`, `SELECT version()` round trip |
| Container: migrating the pre-existing SQLite job store on `cti-state` | `--dry-run` then real run: 47 rows across the eight tables copied in one transaction, committed, exit 0; the API lists the migrated job |
| Container: `scripts/docker_smoke.sh --no-build --job` with the job store on the `postgres` service | **0 failures**: health, UI, uid 1001, read-only root, `job store is PostgreSQL and answers`, sandboxed Chromium; `tests/fixtures/sample_report.txt` reached `for_review` with 32 entities and a **53-object bundle**, no traceback; 13 min 12 s wall clock, dominated by the LLM stage on the LAN Ollama |

Two operational blind spots named after this landed — no image registry
path, no way to see queue backlog short of log-watching — are closed by
[ADR-0047](0047-publish-image-to-ghcr.md) and
[ADR-0048](0048-queue-status-endpoint.md).
| Compose with every profile, and with `CTI_DB_PASSWORD` unset | valid; the unset password is refused with the intended message |
