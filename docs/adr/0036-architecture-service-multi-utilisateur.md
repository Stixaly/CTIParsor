# ADR-0036: A layered rewrite is not what makes this multi-user

**Status:** Proposed
**Date:** 2026-09-01
**Deciders:** maintainer

## Context

A refactoring proposal was put forward: layered/hexagonal architecture, an ORM
(SQLAlchemy 2.0 or SQLModel), a Service layer, the Repository pattern, and a task
broker (Celery or ARQ), migrated in five steps beginning with configuration and
the ORM.

**Its diagnosis is accurate.** Every claim in it was checked against the code and
two are worse than stated:

| Claim | Verified |
|---|---|
| `_run_pipeline()` "over 400 lines" | **678 lines** (`api/worker.py:351`) |
| SQL scattered through the routes | **10 route files out of 10** |
| Configuration read ad hoc | **82** `os.environ.get` / `os.getenv` calls in `api/` + `pipeline/` |
| The queue is not durable | Confirmed, and worse: the job is **abandoned** (`api/worker.py:358`) |

One correction: `api/db.py` has no global connection pool. It has a per-thread
connection cache (`threading.local()`), and the `RLock` beside it is documented as
*not* coordinating across processes — cross-process safety comes from WAL plus
`busy_timeout`. The concurrency problem is therefore not the one the proposal
describes.

### Where the time actually goes

The proposal attributes a 5 078 ms coverage response to the missing `ANALYZE` and
the boolean index. That over-credits one fix with another's win:

```
5 078 ms  total
  ├── 4 624 ms  WSL /mnt/c filesystem overhead   →  fixed by moving the file
  ├──   425 ms  bad query plan                   →  already fixed by ADR-0022
  ├──     7 ms  actual indexed join
  └──    <1 ms  FastAPI/Python HTTP overhead
```

**The filesystem half is already banked.** Measured 2026-09-01 against the
deployed instance (`ctiparsor.guacamole:8000`, Linux, native storage):

| Endpoint | `/mnt/c` (ADR-0037) | deployed instance |
|---|---|---|
| `/api/health` | — | 26 ms |
| `GET /api/jobs` | 401 ms | **11.4 ms** |
| `GET /api/jobs/{id}/coverage` | 5 078 ms | **23 / 52 / 23 ms** |
| `GET /api/jobs/{id}` | — | 21 ms, **17 290 bytes** (`SELECT *`) |

Not a like-for-like comparison, and the difference matters: that job covers 34
techniques against 44, and the instance serves **23 532 canonical rules against
75 127** locally — 3.2x lighter. The filesystem penalty was constant overhead and
is gone for good, whatever the corpus size. What remains scales with the corpus,
so the deployed figures should be re-taken once the missing corpora are synced —
but as the next section shows, there is no query-plan fix left to apply for them
to reveal.

### The 425 ms slice is already gone — ADR-0037's second measurement is stale

An earlier draft of this ADR carried `ANALYZE` plus a covering index as its
cheapest, highest-return item, on the strength of ADR-0037's Measurement 2 (31x
from `ANALYZE`, 61x with a covering index). **Both were tested on 2026-09-01
against the real `cti_stix.db` and neither does anything.**

ADR-0037 profiled a query shape that no longer exists. ADR-0022 rewrote
`rule_refs_for_techniques` to drive the join off `idx_rule_tech_tech` through an
`EXISTS`, and gave `_also_in_map` an explicit `INDEXED BY idx_detection_dedup`
(`pipeline/detection/store.py:297`, `:329`). That rewrite removed the planner's
dependence on statistics altogether — which is exactly what `ANALYZE` supplies.

Measured on the current code, 44 techniques, 815 rows, best of three:

| State | Plan | Time |
|---|---|---|
| as shipped | `SEARCH rt USING INDEX idx_rule_tech_tech` | 193 ms |
| after `ANALYZE` (6.79 s to run) | **identical** | 190 ms |
| with `idx_dr_cover` added | **identical — the index is not used** | 185 ms |
| restored | — | 180 ms |

The plan never changes and the spread is noise. `ANALYZE` also costs 6.79 s, not
the 0.1 s ADR-0037 quotes. The residual ~180 ms is `/mnt/c` filesystem overhead,
which is why the same call answers in 23 ms on the deployed Linux host.

Two lessons are recorded here rather than in a commit message. First, a
measurement ages with the code it measured: ADR-0037's number was taken before
ADR-0022 landed, and nothing flagged it. Second, the correct order was validation
*then* delegation — this item was one step from being specified and built.

The database is unchanged: the test index and `sqlite_stat1` were dropped and the
WAL checkpointed.

### What is not measured, and why this ADR is Proposed

The 133 s per-job cold start comes from `/mnt/c`, where `import
sentence_transformers` alone cost 109.6 s reading ~2 GB of Torch shared objects
across the 9p bridge. It has **not** been re-measured on the deployed host and is
likely several times lower there. Two decisions below — pool sizing and the
urgency of pre-warming — depend on that number and on the host's RAM, neither of
which is known. This ADR is therefore `Proposed`, with the measurement as its
first action item.

Time and memory have different causes, which is what separates the two levers:

```
import sentence_transformers   109.6 s      714 MB   ← 82% of the TIME
load MiniLM                     15.6 s      921 MB
load GLiNER large                7.0 s    4 367 MB   ← 99% of the MEMORY
────────────────────────────────────────────────────
                               133.5 s      4.4 GB
```

### Two traps the code already documents

- **`fork` is unsafe here.** `run_pipeline_async` chose `spawn` deliberately:
  fork inherits partially-initialised native libraries — Torch's OpenMP pool —
  and deadlocks (`api/worker.py:1071`). Celery's default prefork pool and RQ both
  fork. The classic "load the models in the parent, fork N children, share the
  weights copy-on-write" preloading trick is therefore unavailable.
- **Process isolation is load-bearing.** A `std::bad_alloc` in a native extension
  calls `abort()`, which sends SIGABRT to the whole process. The pipeline runs
  out-of-process so that an OOM kills the job and not uvicorn
  (`api/worker.py:1056`). Any executor must preserve this; a thread pool cannot.

### An inert guard

`_save_entities` writes with `INSERT OR IGNORE` (`api/worker.py:334`), which reads
as a de-duplication guard. It is not one: `entities` declares only `id TEXT
PRIMARY KEY` (`api/db.py:167`), filled with a fresh `uuid4()` on every call, and
there is **no UNIQUE constraint** on `(job_id, value, entity_type)` — the sole
UNIQUE in the schema belongs to another table. `OR IGNORE` has nothing to fire on.
The same holds for `relationships`.

This is not a live bug: `_save_entities` has one call site (`api/worker.py:856`),
once per run, and `re_run_final_stages` does not call it. It becomes one the
moment any retry replays the write — which is exactly what a task broker
introduces.

### The pool is not a new decision — it is an unshipped one

ADR-0002 (**Accepted**, 2026-06-07) already chose this. Its Option B is a
"persistent in-process worker pool + shared job queue", named down to
`concurrent.futures.ProcessPoolExecutor` with an initializer that loads the models
once; its Option C rejected Celery/RQ + Redis as "a second deployable component
purely to solve a problem that a fixed worker pool already solves at this scale".
Its five action items — pool, queue, timeout + respawn, load test, tuning knobs —
are **all still unchecked**, and `run_pipeline_async` still spawns one process per
upload.

So the question this ADR answers is not "should we pool?" but "why did an accepted
decision not ship, and what has changed since?". Two things have. First, the
measurements: 0002 estimated model memory at "≈ #workers x ~1 GB"; the real figure
is 4.4 GB, dominated by GLiNER, which changes pool sizing by a factor of four and
makes `WORKER_MAX_CONCURRENT=10` an OOM rather than a tuning choice. Second, the
queue-full path has since acquired a silent data-loss bug (`api/worker.py:358`)
that 0002 did not anticipate, and that is now the most urgent item in the set.

This ADR therefore **re-affirms ADR-0002 rather than replacing it**, adds the
`fork` constraint and the timeout-watchdog cost that 0002 left implicit, and
re-orders the work so the data-loss fix precedes the pool instead of arriving with
it.

### The blind spot

The proposal never mentions authentication. There is no `user_id` column and no
route checks a caller. A faultless layered architecture with Repository, Service
layer and broker, but without ownership, is still **one shared workspace**: every
analyst can read, edit, finalise and delete every other analyst's reports, and
change the pipeline policy for everyone. That is the only blocker that is
categorical rather than a matter of degree.

And ownership is wider than a `user_id` on `jobs`. Three stores are global by
construction: `uploads/` is a flat directory keyed only by job id; the
`relationship_policy` table is declared `id INTEGER PRIMARY KEY DEFAULT 1`
(`api/db.py:204`), one row for the whole installation; and the LLM key ADR-0007
places beside it is likewise installation-wide. Adding a column to `jobs` while
leaving those three shared would produce an application that *looks* multi-tenant
and is not.

## Decision

Keep the proposal's diagnosis, reject its plan, and re-order the work by
**impact per unit of effort** rather than by architectural purity.

1. **Repository pattern with raw SQL. No ORM.**
2. **A pre-warmed, `spawn`-based process pool.** No ARQ, no RQ, no default Celery.
   A broker is deferred and conditional.
3. **Idempotent writes and a relocatable checkpoint** as preconditions for any
   retry or multi-container topology.
4. **Authentication and per-user ownership**, which is the actual multi-user gate.

And explicitly: the cheapest fix — the abandoned job — ships *before* all four.
Not because it matters more, but because it costs a few lines and is losing work
today.

## Options Considered

### Data access

#### Option A — SQLAlchemy 2.0 / SQLModel

| Dimension | Assessment |
|---|---|
| Complexity | Medium-high |
| Cost | Weeks; touches every route and the worker |
| Scalability | Addresses no measured bottleneck |
| Team familiarity | Medium |

**Pros:** typed models, unit-of-work, easier fixtures, a conventional path to
PostgreSQL later.

**Cons:** `rule_text` is an FTS5 virtual table (`api/db.py:250`) — not modelable in
an ORM, so those queries stay raw `text()` under a layer that buys nothing. The
PRAGMAs are per-connection and set in `get_conn()` (`api/db.py:65`), requiring a
`connect` event listener. `isolation_level=None` (autocommit) fights the
unit-of-work directly. And the measured problem was a missing `ANALYZE` and a
boolean index misleading the planner — an ORM would not have prevented it and
makes `EXPLAIN QUERY PLAN` harder to reach.

**Verdict: rejected.**

#### Option B — Repository classes over raw SQL

| Dimension | Assessment |
|---|---|
| Complexity | Low |
| Cost | Days, incremental, one table at a time |
| Scalability | Neutral — it is a testability change |
| Team familiarity | High |

**Pros:** removes SQL from all 10 route files, makes routes unit-testable against
a fake repository, and leaves FTS5, the PRAGMAs and autocommit untouched. It is
also the migration surface if `jobs` ever moves to PostgreSQL.

**Cons:** hand-written mapping; no schema-level type checking.

**Verdict: accepted.** This is the proposal's own fallback in its §6 Q1, and it is
the right one.

### Task execution

#### Option C — ARQ

**Pros:** asyncio-native, small, natural beside FastAPI.

**Cons:** asyncio yields concurrency on I/O waits. The pipeline is bound by CPU
and 4.4 GB of resident weights, not by I/O. It would reproduce the defect already
present in `progress_stream` (`api/routes/progress.py:51`): blocking work inside
the event loop.

**Verdict: rejected.**

#### Option D — Celery (default prefork) or RQ

**Pros:** mature, durable, retries and scheduling for free; Celery's ecosystem is
large.

**Cons:** both `fork`. That is the documented deadlock (`api/worker.py:1071`), and
it is the framework *default*, which is how it reaches production as a
non-reproducible hang. RQ additionally runs one process per job, re-paying the
cold start on every report — it does not address the latency problem at all.
Celery can be configured with a spawn-compatible pool and
`worker_max_tasks_per_child`, but at that point it is `ProcessPoolExecutor` with a
Redis dependency attached.

**Verdict: rejected as specified.** Celery stays available if a broker later
becomes necessary, configured explicitly against `fork`.

#### Option E — Pre-warmed `ProcessPoolExecutor`, spawn context

| Dimension | Assessment |
|---|---|
| Complexity | Medium — the timeout watchdog is the real work |
| Cost | Days |
| Scalability | Covers the measured ceiling with headroom |
| Team familiarity | High — same primitives already in `worker.py` |

N long-lived workers spawned at API startup. The `initializer` sets the thread
caps that `_subprocess_entry` sets today (`api/worker.py:1030`) — before any ML
import — then touches each `@lru_cache(maxsize=1)` loader once. Those caches
already exist throughout `pipeline/`; their only defect is dying with the process.
`max_tasks_per_child` (Python 3.11+; the venv is 3.12.3) bounds leaks by recycling.

**Pros:** the cold start is paid once at boot instead of per report. Model memory
becomes `pool_size x RSS`, a constant known at boot, instead of an unbounded
`jobs x RSS`. Process isolation is preserved. `WORKER_MAX_CONCURRENT` disappears —
the pool *is* the limit — which also removes a counter that is per-process
(`api/worker.py:51`) and silently stops bounding anything once `API_WORKERS > 1`.

**Cons:** a hung job no longer dies with its own process, so an explicit watchdog
must kill and replace the worker. And the memory is resident permanently: the pool
holds `pool_size x RSS` even while idle. That is the price of pre-warming — a good
trade on a large host, a bad one on a small one.

**Verdict: accepted — and already accepted, in ADR-0002.** What this ADR adds is
the `fork` constraint, the watchdog cost, the corrected memory figure (4.4 GB, not
~1 GB), and the sequencing that puts the data-loss fix first.

#### Option F — Redis broker for durability

**Pros:** durable queue across restart and redeploy, retries, visibility. The
proposal is right that the current arrangement loses queue state.

**Cons:** the `jobs` table already persists `queued` rows durably. What is missing
is a **consumer**, not a broker. Adding Redis now imports a second datastore and a
new failure mode to solve something a dispatch loop solves.

**Verdict: deferred, conditional.** Adopt a broker when workers move into separate
containers — at that point the local-disk checkpoint and shared state need it
anyway.

### Memory

GLiNER large accounts for 4 367 of the 4 400 MB. `GLINER_MODEL` is already a
supported override and `urchade/gliner_medium-v2.1` is documented beside it
(`pipeline/stage2e_gliner.py:67`), roughly halving RSS and so doubling the
affordable pool size. It is an accuracy trade, not a free setting: adopt only with
a before/after measurement on real reports.

## Trade-off Analysis

The proposal's five-step migration is ordered by architectural purity. Steps 1-3
(configuration, ORM, service layer) change no observable behaviour, cost weeks,
and carry regression risk across 1 030 tests. The step that carries the value —
decoupling the worker — is fourth.

Ranked instead by impact per unit of effort:

| Work | Effort | Measured effect |
|---|---|---|
| Stop abandoning queued jobs | a few lines | stops losing analyst work |
| Pre-warmed pool | days | removes the per-report cold start; caps model RAM |
| Idempotence + shared checkpoint | days | precondition for retry and containers |
| Authentication + `user_id` | weeks | the only categorical multi-user blocker |
| Repository extraction | days | testability; no runtime effect |
| ORM | weeks | none |

Authentication is the largest blocker *and* the largest project. Placing it first
absolutely, as the reviewed proposal does, parks a few-line fix that is destroying
work behind several weeks of schema and authorisation design. Correct order is
cheap-and-urgent first, then the pool, then tenancy.

## Consequences

**What becomes easier**
- Report turnaround stops being dominated by model loading.
- Model memory becomes a constant the host can be sized for, instead of an
  unbounded demand that made `WORKER_MAX_CONCURRENT=10` an OOM waiting to happen.
- Routes become unit-testable without a real database, without an ORM.
- Queued work survives a busy period instead of vanishing.

**What becomes harder**
- The pool needs a timeout watchdog that kills and replaces workers — a
  responsibility the current spawn-per-job design gets from the OS for free.
- Pool memory is resident even when idle.
- Recycling via `max_tasks_per_child` re-pays the preload; the recycle interval is
  a tuning parameter against observed RSS drift, not a constant to guess.

**What must be revisited**
- Re-measure the cold start on the deployed host. Every sizing figure here depends
  on it.
- Re-measure the coverage join after the corpora are synced to 75 127 canonical
  rules; the query-plan penalty returns proportionally.
- A broker, and PostgreSQL for `jobs` / `entities` / `relationships` /
  `progress_events`, both become live questions when workers move into separate
  containers or when authentication lands — see ADR-0037.
- **ADR-0002's action items are this ADR's Phase 3.** They were accepted on
  2026-06-07 and never ticked. Either they close here, or 0002 should be marked
  superseded rather than left reading as pending work.
- **ADR-0007's security model expires with loopback.** Its chosen control is a
  loopback-origin guard on mutating settings routes, correct for a local tool and
  insufficient once the app is reachable off-host. Phase 5 replaces it; 0007 needs
  a superseding note when that lands.
- **ADR-0029 assumed one user.** Pasted text and captured URLs land in the same
  flat `uploads/`, and `POST /api/ingest/url` lets any caller make the server fetch
  a URL. Both need re-reading under ownership.

## Action Items

**Phase 0 — measure (hours; everything below is sized from this)**
1. [ ] Time a real cold start on the deployed host: import, MiniLM, GLiNER,
       peak RSS. The 133 s / 4.4 GB figures are from `/mnt/c` and are stale.
2. [ ] Record the host's RAM. Set pool size to `floor((RAM_GB - 4) / RSS_GB)`.

**Phase 1 — stop losing work (a few lines)**
3. [ ] Remove the `emit_progress(job_id, "done", ...)` on the queue-full path.
       It is written **twice** — `api/worker.py:358` in `_run_pipeline` and
       `api/worker.py:1078` in `run_pipeline_async` — and only the second can
       fire: the first runs inside the spawned subprocess, which holds its own
       fresh copy of `_job_counter` starting at zero, so its check always passes
       (the code says as much at `api/worker.py:1025`). Fix both; the duplicate is
       how one of them stayed invisible. Then leave the job `queued` and have a
       dispatcher claim it when a slot frees — `queued` currently has **no reader
       anywhere in `api/`**, which is the whole bug: the status is written, never
       consumed.
4. [ ] Make `progress_stream` not close on a queued job (`api/routes/progress.py:51`),
       and bound queue depth so an overflow is an explicit 503, not silent growth.

**Phase 2 — the pool**
5. [ ] Replace spawn-per-job with `ProcessPoolExecutor(mp_context=spawn,
       initializer=..., max_tasks_per_child=K)`; preload every `lru_cache` loader
       in the initializer, after the thread caps.
6. [ ] Add the timeout watchdog that kills and replaces a hung worker.
7. [ ] Delete `WORKER_MAX_CONCURRENT` and `_job_counter`; the pool is the limit.

**Phase 3 — preconditions for retry and containers**
8. [ ] Add `UNIQUE(job_id, value, entity_type, source)` on `entities` and the
       equivalent on `relationships`, so the existing `INSERT OR IGNORE`
       (`api/worker.py:334`) starts doing what it reads as.
9. [ ] Move the Stage 3 checkpoint off local disk
       (`output/{job_id}_stage3.ckpt.json`, `api/worker.py:632`) into the database.

**Phase 4 — tenancy (ownership is wider than the `jobs` table)**
10. [ ] Authentication, `user_id` on `jobs`, and an ownership check on every route.
11. [ ] Replace `allow_origins=["*"]` (`api/main.py:87`) with the deployed origin;
        re-enable `allow_credentials` once sessions exist.
12. [ ] Segregate uploaded documents. `uploads/` is flat — `uploads/{job_id}{suffix}`
        (`api/routes/upload.py:19`, `api/routes/ingest.py:5`) — so any authenticated
        user who can guess or read a job id reaches another user's source report.
        The same applies to `output/` and the Stage 3 checkpoints. ADR-0029 added
        pasted text and captured URLs as sources without addressing this, because
        at the time there was one user.
13. [ ] Move the global single-row stores to the tenant. `relationship_policy` is
        declared `id INTEGER PRIMARY KEY DEFAULT 1` (`api/db.py:204`) — one policy
        for everyone, so one analyst's pin budget changes every other analyst's
        next run. The LLM key that ADR-0007 stores beside it is global for the same
        reason. Both need a `workspace_id`, and ADR-0007's loopback-origin guard
        stops being the right control once the app is reachable off-host.

**Phase 5 — the structural cleanup, once behaviour is settled**
14. [ ] Extract `JobRepository` / `EntityRepository` over the existing raw SQL;
        remove SQL from the 10 route files.
15. [ ] Centralise configuration in `pydantic-settings` (82 call sites).
16. [ ] Narrow `SELECT *` in `api/routes/jobs.py:84`; break up the 678-line
        `_run_pipeline`.
