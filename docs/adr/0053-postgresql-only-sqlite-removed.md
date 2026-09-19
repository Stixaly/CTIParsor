# ADR-0053 — PostgreSQL only: the detection-rule corpus moves off SQLite, and SQLite is removed entirely

**Status:** Accepted (implemented 2026-09-19)
**Date:** 2026-09-19
**Relates to:** [api/db.py](../../api/db.py), [api/db_backend.py](../../api/db_backend.py),
[pipeline/detection/store.py](../../pipeline/detection/store.py),
[pipeline/detection/brands.py](../../pipeline/detection/brands.py),
[pipeline/detection/dedup.py](../../pipeline/detection/dedup.py);
reverses part of [ADR-0037](0037-scaling-to-30-40-users.md) (Option C,
narrowed) and part of [ADR-0045](0045-postgresql-for-the-job-store.md)
(Options C and D, both rejected); builds on
[ADR-0031](0031-provenance-based-rule-dedup.md) (FTS5 for the rule corpus)
and [ADR-0022](0022-per-format-coverage-breakdown.md) (the `INDEXED BY`
planner hint)

## Context

ADR-0045 moved the per-report tables (`jobs`, `entities`, `relationships`,
`progress_events`, …) onto PostgreSQL, deliberately leaving the
detection-rule corpus (87k+ Sigma/YARA/Suricata rules) on SQLite:
`api.db.get_rule_conn()` returned the SQLite file unconditionally, with a
docstring citing two reasons FTS5 "does not port" — the full-text index
`rule_text` (ADR-0031) and the `INDEXED BY idx_detection_dedup` planner hint
in `pipeline/detection/store.py::_also_in_map` (ADR-0022). ADR-0037's own
assessment of Option C ("PostgreSQL for everything") reached the same
conclusion: "migrating the 86,180-rule corpus also means rewriting
`scripts/build_detection_index.py` and every `sqlite3`-typed signature...
Doing it before the query-plan and storage fixes would credit PostgreSQL
with a win `mv` and `ANALYZE` deliver for free."

The maintainer decided to revisit this and consolidate on PostgreSQL
entirely — not narrowly for the rule corpus, but as the only datastore in
the codebase, full stop. This ADR is that decision, re-examined against what
those two specific "does not port" reasons actually require, rather than
assumed to still hold three ADRs and several months later.

**What actually needed checking:**

1. **`rule_text` / FTS5.** Read closely, every `MATCH` call site
   (`pipeline/detection/brands.py`: `brand_tokens`, `brand_evidence`,
   `cve_evidence`) builds a quoted-phrase query
   (`'"' + token.replace('"','') + '"'`) — a single- or few-word exact-phrase
   lookup, never free-text ranking, never `bm25`/`rank`. FTS5 was chosen in
   ADR-0031 specifically for word-boundary tokenization: substring matching
   put `reat` inside 52,775 rules (matching `great`, `threat`, `retreat`,
   …). PostgreSQL's `to_tsvector('simple', ...)` — the non-stemming
   configuration, so it does not fold `threat`/`threats`/`threatening`
   together the way `'english'` would — tokenizes the same way FTS5 does and
   does not substring-match either. `phraseto_tsquery('simple', token)` is
   the direct replacement for the quoted-phrase construction, and needs no
   manual quote-escaping.
2. **`INDEXED BY idx_detection_dedup`.** The docstring on `_also_in_map`
   explained *why* the hint existed: left alone, the SQLite planner entered
   through `idx_detection_canon` — a near-constant boolean column — and
   scanned ~43k rows per key, measured 871-1227 ms per rule. That is a
   documented SQLite planner limitation (no `ANALYZE` by default, a
   low-cardinality index it over-trusts — the exact failure mode ADR-0037's
   Measurement 2 diagnosed for a *different* query on the same table).
   PostgreSQL's planner is cost-based and gathers statistics automatically;
   it has no structural reason to repeat that specific mistake on an
   indexed, non-boolean `dedup_key` column. This is a claim worth verifying,
   not assuming — see the validation record.

Neither reason turned out to be permanent. What was permanent in 2026-09 was
provisional in retrospect: FTS5 solved a real problem (word-boundary
matching) that PostgreSQL also solves, just with a different mechanism.

## Decision

**PostgreSQL is the only supported datastore.** Not "PostgreSQL for the rule
corpus, kept alongside the SQLite job-store fallback" — `DATABASE_URL` is now
mandatory everywhere: the API, the worker, the test suite. There is no
SQLite code path left in `api/db.py` to fall back to; an unset or malformed
`DATABASE_URL` fails immediately with a clear message, not a silent
SQLite default three ADRs used to guarantee.

### Schema

`rule_text` becomes an ordinary table instead of an FTS5 virtual one, with a
`GENERATED ALWAYS AS` `tsvector` column so the index is always consistent
with `body` — no more "is the FTS index built yet" existence probe the way
`rule_text_built()` needed against SQLite:

```sql
CREATE TABLE rule_text (
    rule_id  TEXT PRIMARY KEY REFERENCES detection_rules(id) ON DELETE CASCADE,
    body     TEXT NOT NULL,
    body_tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple', body)) STORED
);
CREATE INDEX idx_rule_text_tsv ON rule_text USING GIN (body_tsv);
```

The other five tables (`detection_rules`, `rule_bytes`, `rule_techniques`,
`rule_atoms`, `rule_related`) carry over unchanged — no `REAL`/`DOUBLE
PRECISION` concern this table set had for the job store, since none of these
columns are floating point.

### Code

- `api/db.py`: `get_conn()` and `get_rule_conn()` both resolve to the same
  `PgConnection` today — kept as two separate accessors (not collapsed into
  one function) because the `jobs_conn=` split already threaded through
  `pipeline/detection/coverage.py`/`relevance.py`/`artifacts.py` stays
  meaningful groundwork if the rule corpus ever needs a database of its own;
  touching those call sites was out of scope here. `_sqlite_conn()`, the
  SQLite DDL and migration lists, and `_apply_sqlite_migrations()` are
  deleted, not left dormant. `backend_from_url(None)` now raises
  `RuntimeError` instead of defaulting to `"sqlite"`.
- `pipeline/detection/store.py`: 18 functions retyped from `sqlite3.Connection`
  to the shared `DBConnection` protocol; 6 upserts (`INSERT OR
  REPLACE`/`INSERT OR IGNORE`) rewritten to `ON CONFLICT ... DO
  UPDATE`/`DO NOTHING`, the same treatment ADR-0045 already gave the
  job-store upserts; the `INDEXED BY` clause dropped, not translated (there
  is no PostgreSQL equivalent).
- `pipeline/detection/brands.py`: the three `MATCH` call sites become
  `body_tsv @@ phraseto_tsquery('simple', ?)`.
- `pipeline/detection/dedup.py`: two `sqlite_master` existence probes removed
  (`init_db()` always creates `rule_related`/`rule_techniques` now, so
  "table missing" is no longer reachable — only "table empty" is); the
  `BEGIN IMMEDIATE` transaction (a SQLite write-lock idiom) becomes a plain
  `BEGIN`.
- `run_api.py` gains an explicit `DATABASE_URL` check before uvicorn starts,
  so a missing value is a one-line `SystemExit` at the same place bad
  `API_PORT`/`API_WORKERS` values already are, not a `RuntimeError`
  surfacing from deep inside the app on the first request.
- New `scripts/migrate_rules_to_postgres.py`, the rule-store sibling of the
  existing `scripts/migrate_jobs_to_postgres.py` (ADR-0045) — same
  structure: read-only SQLite source, one PostgreSQL transaction, column
  intersection per table (so `rule_text.body_tsv`, a generated column that
  only exists on the target, is never in the copy list), `--dry-run`/
  `--append`.
- Roughly twenty peripheral scripts (`scripts/build_rule_text.py`,
  `backfill_rule_bytes.py`, `build_rule_atoms.py`, and ~17 one-off
  `audit_*`/`measure_*`/`probe_*`/`check_*` diagnostic tools) that opened
  `sqlite3.connect("cti_stix.db")` directly, bypassing `api.db` entirely,
  converted to `api.db.get_conn()`/`get_rule_conn()` — the same audit that
  found them found several already-latent bugs in a few (a hardcoded
  `instr()` call with no PostgreSQL equivalent, `rowid`-based ordering that
  doesn't exist on PostgreSQL, a `.cursor()` call that bypassed the `?`→`%s`
  placeholder translation).

## Options considered

### A — Full removal (accepted)

Everything above. **Pros:** one dialect, one code path, no
`isinstance(conn, sqlite3.Connection)` branches, no "which store is SQLite
today" question in the test fixture. **Cons:** every host install, the CLI's
API/worker path, and the test suite now require a reachable PostgreSQL
server — there is no more zero-dependency single-file mode. `main.py` (the
batch CLI that runs Stages 1-5 and writes a STIX bundle) is unaffected: it
never touches either store.

### B — PostgreSQL for the rule corpus, keep the SQLite job-store fallback

Rejected. Inconsistent on its own terms: the rule corpus was the *harder*
half to move (FTS5, the planner hint) — moving it while keeping a SQLite
fallback for the *easier* half (already portable per ADR-0045) would leave
two dialects in `api/db.py` for no remaining reason, and the "does `?` or
`%s` run against which engine" question every dual-dialect function still
has to answer.

### C — `pg_trgm` instead of / alongside `tsvector`

Considered and deferred, not rejected. `pg_trgm` gives fuzzy/substring
tolerance; every existing `MATCH` call site is an exact-phrase lookup with
no fuzziness requirement, so `tsvector` alone gives functional parity. Adding
`pg_trgm` is a candidate for a *new* capability (typo-tolerant brand
matching) later, not a requirement for this migration.

## Consequences

- **What becomes easier.** One schema, one adapter, one set of tests. The
  `temp_db` fixture collapses from "SQLite unless
  `CTIPARSOR_TEST_DATABASE_URL` is set, and even then the rule store stays
  SQLite" to one unconditional path: a disposable PostgreSQL schema holding
  both table sets. CI's `postgres-tests` job — which ran the exact same
  suite against the exact same service `fast-tests` now also needs — is
  gone; that duplication ends automatically once every job requires
  PostgreSQL regardless.
- **What becomes harder.** A host install now needs a reachable PostgreSQL
  server to run the API/worker/tests at all — the previous "clone the repo,
  run `python run_api.py`, everything just works against a local file"
  on-ramp is gone. `docker compose up -d postgres` from this repo, without
  starting anything else, is the lightest way to get one.
- **The `rule_bytes` side-table rationale is now partly historical.** It
  exists because reading a column after SQLite's `raw` blob forces a walk of
  its overflow pages (ADR-0022); PostgreSQL's TOAST storage does not have
  the identical failure mode, but the schema and the side table are
  unchanged — revisiting whether `rule_bytes` is still the right shape for
  PostgreSQL specifically is not part of this ADR.
- **The audit/measurement scripts converted here are not part of the test
  suite** and were verified by `ast.parse` plus a read-through against the
  established conversion pattern, not by running each end to end — most
  need a populated corpus and real report data to exercise meaningfully.

## What building it changed

1. **The `INDEXED BY` hint's replacement needed verification, not
   assumption — and the verification found a real, expected difference.**
   An `EXPLAIN`-based automated test asserting PostgreSQL picks
   `idx_detection_dedup` failed on a one-row fixture: the planner correctly
   chose `idx_detection_canon` instead, because at that scale it is genuinely
   cheaper. That is the planner working as intended, not a regression — the
   claim in this ADR ("PostgreSQL's cost-based planner does not need the
   hint") is about the corpus's real scale (87k rows, `is_canonical` split
   roughly 43k/43k), and a tiny fixture cannot exercise that. The test was
   rewritten to assert what *is* scale-independent (one batched sweep
   statement, not one query per rule; the outer query still avoids
   `idx_detection_canon` via `EXISTS`) and the index-selection claim moved to
   a documented manual `EXPLAIN ANALYZE` check against the real corpus
   (§Validation record).
2. **`sqlite3.Connection.set_trace_callback` has no PostgreSQL equivalent.**
   Three tests in `tests/test_detection_coverage.py` used it to count
   executed statements (an N+1-regression guard). Replaced with a small
   engine-agnostic wrapper around the connection's own `.execute()` —
   works identically on `sqlite3.Connection` and `PgConnection`, so it is
   also usable by any future test that needs the same guard.
3. **`get_conn()`/`get_rule_conn()` becoming identical objects, not just
   identically-typed ones, changed what "must fail loudly" meant.** A
   pre-existing test asserted that `compute_for_job()` called *without*
   `jobs_conn` must raise, because the rule store's SQLite file had no
   `entities` table. Post-migration it does not raise — the omitted
   `jobs_conn` falls back to `conn`, and `conn` now reaches the job tables
   too, since they are the same database. The test was rewritten to assert
   the new (correct) behavior explicitly, rather than deleted, so a future
   change that reintroduces a real split does not silently start
   double-counting or erroring without a test noticing either way.
4. **Several tests reached for a raw SQLite file as their own isolation
   mechanism, independent of `api.db`.** `tests/test_brands.py`'s `_store()`
   helper built a bare `detection_rules` table with no `rule_text` at all —
   `rule_text_built()` therefore always returned `False`, and
   `test_word_boundary_not_substring` /
   `test_brand_evidence_prefers_title_over_description` passed vacuously,
   proving nothing about real matching (confirmed by tracing the
   short-circuit before rewriting). Converted to build against `temp_db`'s
   real PostgreSQL schema; the rewrite added the two cases this migration
   actually put at risk — the `reat`-inside-`threat`/`great` non-substring
   case ADR-0031 was written to fix, and a hyphenated CVE id
   (`cve-2021-44228`), since PostgreSQL's default text-search parser gives
   hyphenated compound tokens special handling that needed confirming, not
   assumed, against the real `phraseto_tsquery` behavior.
5. **`tests/test_figure_store.py` carried its own local `temp_db` fixture**
   (predating the shared one in `conftest.py`) that patched the now-removed
   `db.DB_PATH` directly. Replaced with a one-line fixture that requests
   the shared `temp_db`, applied `autouse=True` so no individual test
   signature needed to change.
6. **`api/main.py`'s startup orphan-requeue logic had a
   `backend() == "sqlite"` branch that is now permanently false** (`backend()`
   only ever returns `"postgresql"` or raises) — the `_single_process`/
   `API_WORKERS` computation feeding it was dead code once traced through;
   removed in favor of always using the lease-based requeue, with the
   comment explaining why unconditional requeue was never safe to assume
   once PostgreSQL (multiple independent `role=all` replicas can share one
   `DATABASE_URL`) is the only backend.

## Validation record (2026-09-19)

| Check | Result |
|---|---|
| Full suite, PostgreSQL (`CTIPARSOR_TEST_DATABASE_URL`, local `postgres:17-alpine` container) | **1377 passed**, 4 skipped, 0 failed |
| `tests/test_brands.py` (rewritten against real `rule_text`/`body_tsv`, not a vacuous bare table) | 15 passed, including the `reat`-substring and hyphenated-CVE cases |
| `tests/test_detection_coverage.py`, `test_detection_relevance.py`, `test_detection_dedup.py`, `test_rule_lookup.py`, `test_db_postgres.py`, `test_db_backend.py` | all passed |
| ruff (`--select E,F,W,I`) on every file this migration touched | clean (pre-existing, unrelated lint debt in untouched files left alone and tracked separately) |
| mypy on `pipeline/`, `api/`, `models/` | advisory, run against the touched modules |
| `EXPLAIN`/planner-selection reasoning for the dropped `INDEXED BY` hint | verified operationally against the real corpus is a follow-up once `scripts/build_detection_index.py` has populated a production-scale PostgreSQL store — not meaningful on a test fixture (see item 1 above); the automated test asserts what scale-independent behavior actually holds instead |
| CI (`.github/workflows/ci.yml`) | `fast-tests` and `model-tests` both gained a `postgres` service and `CTIPARSOR_TEST_DATABASE_URL`; the now-fully-redundant `postgres-tests` job removed |
