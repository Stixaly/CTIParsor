# ADR-0037: Scaling to 30–40 concurrent users

**Status:** Proposed
**Date:** 2026-08-31
**Deciders:** maintainer

> **Measurement 2 below is invalidated.** Re-tested against the live database on
> 2026-09-01: `ANALYZE` and the covering index change neither the query plan nor
> the timing (193 ms → 190 ms → 185 ms, plan identical throughout), and `ANALYZE`
> costs 6.79 s rather than 0.1 s. ADR-0022 had already rewritten the query to
> drive off `idx_rule_tech_tech` through an `EXISTS`, which removes the planner's
> dependence on statistics entirely. Action items 2 and 3 are void; ADR-0036
> carries the evidence and the re-ordered plan. The storage finding
> (Measurement 1) holds and has since been banked by the move to a Linux host.

## Context

The question raised was whether to re-architect around **nginx + a Rust backend +
PostgreSQL or Elasticsearch** in order to serve 30–40 concurrent analysts.

Before answering, the current stack was measured rather than described. Every
number below comes from this repository on 2026-08-31 (22 cores, 15 GB RAM under
WSL2, `cti_stix.db` = 644 MB / 157 220 pages).

### What the workload actually is

| Table | Rows | Nature |
|---|---|---|
| `detection_rules` | 86 180 (75 127 canonical) | read-only reference corpus |
| `rule_techniques` | 50 652 | read-only reference corpus |
| `entities` | 1 534 | transactional |
| `relationships` | 547 | transactional |
| `jobs` | 13 | transactional |
| `progress_events` | 191 | transactional, append-only |

**99 % of the database is a read-mostly corpus rebuilt by a batch script.** The
transactional part is ~2 000 rows. This is not a write-contention workload, which
is the only workload where SQLite's single-writer limit actually binds
([sqlite.org/wal](https://sqlite.org/wal.html)).

Per report, one upload triggers one pipeline run. 30–40 analysts reviewing
reports produce a few uploads per minute at most, and the review UI is read-heavy
(entities, relationships, coverage).

### Measurement 1 — the "slow database" is the filesystem

The same `cti_stix.db`, the same queries, differing only in which filesystem
holds the file:

| Query | on `/mnt/c` (current) | on native ext4 | Ratio |
|---|---|---|---|
| `rule_refs_for_techniques` (44 techniques → 2 526 rows) | 5 078 ms | 454 ms | 11× |
| `rules_for_technique` (→ **6 rows**) | 4 740 ms | 43 ms | 110× |
| `list_jobs` | 401 ms | 1.3 ms | 300× |

The project runs its Python from WSL against a database stored on the Windows
drive. Every page fault crosses the 9p/DrvFs bridge. **No database engine change
can recover this; moving the file to Linux-native storage recovers all of it.**

### Measurement 2 — a bad query plan, not a bad engine

Even on ext4, `rule_refs_for_techniques` cost 454 ms. `EXPLAIN QUERY PLAN`:

```
SEARCH d USING INDEX idx_detection_canon (is_canonical=?)      ← 75 127 rows
SEARCH rt USING COVERING INDEX sqlite_autoindex_rule_techniques_1
```

`idx_detection_canon` indexes a **boolean** column. With no statistics, the
planner believes it is selective, drives the join from 75 127 canonical rules and
probes `rule_techniques` for each — instead of starting from the 44 techniques.

| Fix | Median | vs `/mnt/c` baseline |
|---|---|---|
| baseline (ext4) | 432 ms | — |
| `ANALYZE` alone (runs in 0.1 s) | **14 ms** | 31× |
| `ANALYZE` + covering index on `(id, is_canonical, corpus, native_key)` | **7.1 ms** | 61× |

Combined with native storage: **5 078 ms → 7.1 ms, a 715× improvement, without
changing a single line of application code.**

### Measurement 3 — the real capacity ceiling is model loading

`api/worker.py` runs each job in an `mp.get_context("spawn")` subprocess. Every
ML model is `functools.lru_cache`d — but the cache lives *inside that
subprocess*, so **every job reloads every model from zero**:

```
import sentence_transformers   109.6 s      714 MB
load MiniLM                     15.6 s      921 MB
load GLiNER large                7.0 s    4 367 MB
────────────────────────────────────────────────────
TOTAL cold-start               133.5 s    peak RSS 4.4 GB
```

Two consequences:

1. **Every report pays ~133 s of startup before any analysis begins.** (The 109.6 s
   import is itself inflated by reading ~2 GB of Torch shared objects over
   `/mnt/c`; on native storage this drops substantially, but never to zero.)
2. **Peak RSS is 4.4 GB per concurrent job.** The default is
   `WORKER_MAX_CONCURRENT=10` → a 44 GB demand on a 15 GB machine. This is why
   `run_pipeline_async` carries elaborate SIGKILL/SIGABRT handling: it is
   documenting an OOM condition the configuration makes inevitable.

The true concurrency ceiling today is **~3 simultaneous pipeline runs**, set by
RAM — not by the web framework, and not by the database.

### Measurement 4 — deployment and correctness gaps

- **Production launch is `uvicorn api.main:app --reload`** (`Makefile:91`). One
  process, one event loop, with the file-watching reloader enabled in production.
- **`progress_stream` (`api/routes/progress.py:51`) is `async def` but performs
  blocking `sqlite3` reads every 0.5 s inside the event loop.** At 40 connected
  analysts that is 80 blocking queries/second on the single thread that serves
  every other request.
- **`Dashboard.tsx:365` polls `refetchInterval: 3000`** — 40 analysts ⇒ a
  constant 13 req/s of job-list polling on top of the SSE streams.
- **`get_job` uses `SELECT *`** (`api/routes/jobs.py:83`), returning
  `report_text` + `bundle_json` + `llm_result_json` on every Review/Graph/Coverage
  page load.
- **There is no authentication, no session, and no job ownership anywhere in
  `api/`.** Every analyst sees, edits, finalises and deletes every other
  analyst's reports. CORS is `allow_origins=["*"]`.

That last point is the decisive one. **The application is not currently
multi-user in any sense; it is a single-user tool exposed to several people.**
No amount of Rust or PostgreSQL addresses it.

## Decision

**Reject the Rust + PostgreSQL/Elasticsearch + nginx rewrite as the primary
plan.** Adopt nginx, adopt PostgreSQL for the transactional tables *only when
authentication lands*, and reject Rust and Elasticsearch outright.

Sequence the work by measured impact: storage and query fixes first, then a
persistent model worker, then authentication, then nginx.

## Options Considered

### Option A — Rewrite the backend in Rust

| Dimension | Assessment |
|---|---|
| Complexity | Very high |
| Cost | Months; a second language in a solo-maintained repo |
| Scalability | **Addresses no measured bottleneck** |
| Team familiarity | Low |

**Pros:** faster HTTP layer; genuine parallelism without the GIL.

**Cons:** The 7 331 lines in `pipeline/` are built on PyTorch,
`sentence-transformers`, `transformers`/CyNER, GLiNER, spaCy, `stix2` and
`pdfplumber`. None has a Rust equivalent. A Rust backend would have to shell out
to the same Python for all real work — inheriting the 133 s cold start and the
4.4 GB RSS unchanged. The HTTP layer is not the bottleneck: FastAPI's overhead is
sub-millisecond against a 454 ms query and a 133 s pipeline.

**Verdict: rejected.** It optimises the one layer that is already fast.

### Option B — Migrate to Elasticsearch

| Dimension | Assessment |
|---|---|
| Complexity | High (JVM, cluster state, sharding, version upgrades) |
| Cost | A permanent multi-GB daemon plus a second copy of the data |
| Scalability | Far beyond need |
| Team familiarity | Low |

**Pros:** excellent full-text ranking; the natural choice if rule *bodies* ever
need scored free-text search.

**Cons:** The detection queries are exact-match joins on `technique_id` — there is
no full-text search and no relevance ranking anywhere in
`pipeline/detection/store.py`. 86 180 rows is small. Elasticsearch is memory-hungry
and stores the data twice, on a host already RAM-constrained by the 4.4 GB models
([ParadeDB](https://www.paradedb.com/blog/elasticsearch-vs-postgres),
[Neon](https://neon.com/blog/postgres-full-text-search-vs-elasticsearch)).

**Verdict: rejected.** It solves a search problem the application does not have,
and spends the exact resource (RAM) that is actually scarce.

### Option C — Migrate to PostgreSQL

| Dimension | Assessment |
|---|---|
| Complexity | Medium |
| Cost | One daemon to operate and back up |
| Scalability | Ample; removes the single-writer constraint |
| Team familiarity | Medium |

**Pros:** true concurrent writers; real per-user roles; network access decouples
the API from the DB host; `pg_trgm`/FTS available later without a new dependency.

**Cons:** Solves a contention problem not yet demonstrated — measured write
traffic is a handful of rows per report. Migrating the 86 180-rule corpus also
means rewriting `scripts/build_detection_index.py` and every `sqlite3`-typed
signature in `pipeline/detection/`. Doing it *before* the query-plan and storage
fixes would credit PostgreSQL with a 715× win that `ANALYZE` and `mv` deliver for
free.

**Verdict: accepted, but deferred and narrowed.** Adopt PostgreSQL for `jobs` /
`entities` / `relationships` / `progress_events` at the moment authentication is
introduced — that is when concurrent writers and per-user rows become real. Keep
the read-only detection corpus in SQLite: it is rebuilt by a batch job, benefits
from zero-copy local reads, and has no concurrency requirement.

### Option D — nginx in front

| Dimension | Assessment |
|---|---|
| Complexity | Low |
| Cost | Hours |
| Scalability | Removes static-file and TLS work from the event loop |
| Team familiarity | Medium |

**Pros:** TLS termination; serves `frontend/dist` (4 MB) without occupying the
Python process; connection buffering; rate limiting ahead of the app. Reported
error rates under load drop sharply versus exposing the ASGI server directly.

**Cons:** none material — but it is *packaging*, not a fix. nginx does not make
the 5 s query fast, and **SSE requires `proxy_buffering off`** or progress
streams will stall behind nginx's buffer. Note `api/main.py` already emits
`X-Accel-Buffering: no`, which nginx honours.

**Verdict: accepted, low priority.** Correct for production; do it after the
measured bottlenecks, not instead of them.

### Option E — Fix the measured bottlenecks in place

| Dimension | Assessment |
|---|---|
| Complexity | Low |
| Cost | Days |
| Scalability | Covers 30–40 users with headroom |
| Team familiarity | High |

**Pros:** 715× on the hot query from `ANALYZE` + relocation; removes the 133 s
per-job cold start via a persistent worker; keeps one language and one
deployment unit.

**Cons:** does not by itself deliver multi-tenancy — authentication remains
mandatory and is tracked separately below.

**Verdict: accepted as the primary plan.**

## Trade-off Analysis

The rewrite proposal and the measurements disagree about where the time goes.
Attributing the current 5.1 s coverage response:

```
5 078 ms  total
  ├── 4 624 ms  WSL /mnt/c filesystem overhead   →  fixed by `mv`
  ├──   425 ms  bad query plan (no ANALYZE)      →  fixed by `ANALYZE`
  ├──     7 ms  actual indexed join              →  SQLite is not the problem
  └──    <1 ms  FastAPI/Python HTTP overhead     →  what a Rust rewrite targets
```

A Rust rewrite attacks the sub-millisecond slice. PostgreSQL and Elasticsearch
attack the 7 ms slice. `mv` and `ANALYZE` attack the 5 049 ms slice.

The same holds for capacity. At 40 analysts the binding constraint is 4.4 GB of
resident model memory per concurrent job — a number identical under Rust,
PostgreSQL and Elasticsearch, because it is set by GLiNER's weights. Loading the
models **once** in a persistent worker instead of per job converts 4.4 GB × N into
4.4 GB × (pool size) and removes 133 s from every report.

The honest summary: **the proposed rewrite is a well-chosen stack for a problem
this application does not yet have, and it would leave the two real blockers —
per-job model loading and the complete absence of authentication — exactly where
they are.**

## Consequences

**What becomes easier**
- Coverage endpoints go from 5.1 s to single-digit ms; the review UI stops
  feeling broken under concurrency.
- Removing the per-job cold start makes report turnaround dominated by actual
  analysis rather than imports.
- Staying on one language keeps the Qwen-delegation workflow in `CLAUDE.md` intact.

**What becomes harder**
- Deployment moves to a Linux host with native storage. The Windows/WSL
  development arrangement stops being a supported production topology — this is
  the price of the 11–300× storage win, and it is worth paying.
- A persistent worker pool must handle model memory leaks across jobs
  (`max_tasks_per_child`-style recycling), a concern the current
  spawn-per-job design gets for free.
- Two datastores once PostgreSQL lands: Postgres for transactional data, SQLite
  for the detection corpus. The split is deliberate and must be documented, or a
  later maintainer will "unify" it and reintroduce a 644 MB migration.

**What must be revisited**
- Reassess PostgreSQL for the corpus if rule *bodies* ever need ranked free-text
  search — that is the point where Option B stops being over-engineering.
- Re-measure `WORKER_MAX_CONCURRENT` against real host RAM. The current default
  of 10 is unsafe on any machine with less than ~48 GB.
- The multi-tenancy item below is decided in ADR-0036, which re-orders this
  action list by impact per unit of effort and supersedes its sequencing.

## Action Items

Ordered by measured impact per unit of effort. Items 1–3 are prerequisites for
30–40 users; items 4–6 are the multi-user work proper; 7–9 are hardening.

**Phase 1 — storage and query (hours, ~715× on the hot path)**
1. [ ] Move the deployment to a Linux host with `cti_stix.db` on native storage
       (not `/mnt/c`, not a network mount). Re-run the measurements above to confirm.
2. [ ] Add `ANALYZE` to `init_db()` in `api/db.py`, and re-run it at the end of
       `scripts/build_detection_index.py`. 0.1 s, 31× on the coverage join.
3. [ ] Add `CREATE INDEX idx_dr_cover ON detection_rules(id, is_canonical, corpus, native_key)`
       to the migration list in `api/db.py` (432 ms → 7.1 ms). Consider dropping
       `idx_detection_canon`: indexing a boolean is what misled the planner.

**Phase 2 — pipeline capacity (the real ceiling)**
4. [ ] Replace spawn-per-job in `api/worker.py` with a **persistent pool of 2–3
       pre-warmed workers** that load the models once at startup. Removes 133 s
       per report and caps model RAM at pool size × 4.4 GB. Recycle a worker
       every N jobs to bound leaks.
5. [ ] Set `WORKER_MAX_CONCURRENT` from measured host RAM
       (`floor((RAM_GB - 4) / 4.4)`), not the current default of 10. Document that
       the default overcommits.
6. [ ] Give queued jobs a real queue. Today `run_pipeline_async` sets status
       `queued` and **emits a `done` event, abandoning the job** — with 40 users
       hitting the cap this silently drops work.

**Phase 3 — multi-tenancy (blocking for 30–40 users)**
7. [ ] Add authentication and a `user_id` column on `jobs`; scope every route in
       `api/routes/` by owner. Until this exists the app is single-tenant
       regardless of stack. File a separate ADR — this is a schema and
       authorisation decision, not a deployment detail.
8. [ ] Replace `allow_origins=["*"]` with the deployed origin, and re-enable
       `allow_credentials` once sessions exist.
9. [ ] Migrate `jobs` / `entities` / `relationships` / `progress_events` to
       PostgreSQL **as part of item 7**, leaving the detection corpus in SQLite.

**Phase 4 — serving and hygiene**
10. [ ] Put nginx in front: TLS, `frontend/dist`, rate limiting. Set
        `proxy_buffering off` and `proxy_read_timeout 300s` on `/api/jobs/*/progress`
        or SSE will stall.
11. [ ] Stop running `--reload` in production (`Makefile:91`). Run
        `uvicorn --workers N` behind nginx under systemd. Note: worker count
        affects only the API — `_job_counter` in `api/worker.py` is per-process
        and stops bounding concurrency once N > 1, which item 6's shared queue
        must own instead.
12. [ ] Make `progress_stream` stop blocking the event loop — move the
        `sqlite3` reads to `run_in_threadpool`, or have the worker push events
        instead of polling every 0.5 s.
13. [ ] Narrow `get_job`'s `SELECT *` (`api/routes/jobs.py:83`) so
        `report_text` / `bundle_json` / `llm_result_json` are not shipped on every
        page load.
14. [ ] Raise `Dashboard.tsx:365`'s `refetchInterval` from 3 s, or drive the job
        list from the existing SSE stream.
