# ADR-0002: Handling Concurrent Ingestion of 10+ CTI Reports

**Status:** Proposed
**Date:** 2026-06-07
**Deciders:** CTIParsor maintainers

## Context

CTIParsor currently accepts reports via `POST /api/upload` (`api/main.py`) and processes
each one in its own subprocess via `run_pipeline_async()` (`api/worker.py:728`), gated by
a `WORKER_MAX_CONCURRENT` semaphore (default 10, `api/worker.py:36`).

Each pipeline run is heavy:

- **Stage 1** — PDF/DOCX parsing (light, I/O bound)
- **Stage 2** — deterministic extraction: regex IoCs, Aho-Corasick gazetteer NER, semantic
  TTP embeddings (`sentence-transformers`, ~80 MB), GLiNER zero-shot NER (~300 MB);
  single-threaded, ~50–200s per large document
- **Stage 3** — LLM enrichment via parallel API calls (Anthropic/Mistral/Ollama),
  `LLM_PARALLELISM=3` threads per report, checkpointed every `CHECKPOINT_EVERY=5` chunks
- **Stage 3b/3c** — hallucination filtering and MITRE TTP normalization (light, fuzzy match)
- **Stage 4/5** — STIX object construction and schema validation (light)

The problem: each upload spawns a fresh `multiprocessing` subprocess (spawn context) that
**reloads the full ML stack from scratch** — sentence-transformers, transformers, GLiNER —
adding roughly 800 MB–1 GB of resident memory and 8–20 GB of virtual address space per
process, plus tens of seconds of model-load latency before any real work starts.

At ~10 concurrent uploads this means up to ~10 redundant model loads in memory
simultaneously, competing for CPU/RAM, with SQLite (WAL mode, thread-local connections,
`api/db.py:31-50`) as the shared store. We need a design that lets us comfortably ingest
10+ reports at once without the memory blow-up, while keeping operational complexity
proportionate to a project of this size.

## Decision

Move from "one subprocess per upload, full model reload each time" to a **persistent
worker pool that loads ML models once and pulls jobs from a shared queue**, while keeping
the existing FastAPI upload endpoint and SQLite store. Concretely:

1. Replace ad-hoc `multiprocessing.Process` spawning with a small fixed pool of
   long-lived worker processes (size ≈ CPU cores, independent of report count).
2. Each worker loads sentence-transformers/GLiNER/gazetteer **once at startup** and then
   pulls report jobs from a queue, so memory cost becomes O(workers) instead of O(reports).
3. Keep Stage 3 (LLM calls) as the per-report parallel/async step — it's I/O-bound and
   benefits from concurrency that doesn't require duplicating ML models.
4. Keep SQLite for now (WAL + existing locking), since the bottleneck is compute/memory,
   not DB throughput at this scale; revisit only if write contention becomes measurable.

## Options Considered

### Option A: Keep subprocess-per-upload, just raise/tune `WORKER_MAX_CONCURRENT`

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low — change a constant/env var |
| Cost | High at runtime — memory scales linearly with concurrent jobs |
| Scalability | Poor — 10 concurrent jobs ≈ 10x model loads, risk of OOM |
| Team familiarity | High — no new concepts |

**Pros:** No code changes beyond config; nothing new to operate or learn.
**Cons:** Doesn't solve the actual problem — redundant model loads remain the dominant
cost; raising the limit makes OOM more likely, not less; load-time latency (tens of
seconds per job) is paid on every single report.

### Option B: Persistent in-process worker pool + shared job queue (chosen)

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium — replace subprocess spawn with a pool + queue (e.g. `concurrent.futures.ProcessPoolExecutor` with an initializer that loads models once, or a lightweight queue like `multiprocessing.Queue`/`asyncio.Queue` feeding a fixed set of long-lived workers) |
| Cost | Low — fixed memory footprint regardless of report count; no new infrastructure |
| Scalability | Good for the 10–50 report range this project targets; bounded by `#workers x model size` |
| Team familiarity | Medium — standard Python concurrency primitives, no new services to learn |

**Pros:** Eliminates redundant model loads (the actual cost driver); keeps the stack
"batteries included" (no Redis/broker to deploy or monitor); model-load latency is paid
once at startup, not per report; throughput becomes predictable and tunable via pool size;
straightforward to keep the existing checkpoint/resume logic per job.
**Cons:** Still bounded by a single machine's RAM/CPU — won't scale past one host;
requires care around worker crash recovery (a stuck job shouldn't wedge a worker
permanently — needs a per-job timeout and respawn, which `WORKER_JOB_TIMEOUT=1800`
already gives us a starting point for).

### Option C: External task queue (Celery/RQ + Redis/RabbitMQ)

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — new broker service, new deployment unit, retry/monitoring tooling |
| Cost | Higher — extra service to run, monitor, and keep available |
| Scalability | Best — horizontal scaling across machines, mature ecosystem |
| Team familiarity | Low — no existing queue infra in the project (confirmed: none present today) |

**Pros:** Battle-tested, scales horizontally across hosts, rich monitoring/retry tooling,
natural fit if report volume grows well beyond "10 at a time" into the hundreds.
**Cons:** Introduces a broker dependency (Redis/RabbitMQ) and a second deployable
component purely to solve a problem that a fixed worker pool already solves at this
scale; adds operational surface (monitoring, upgrades, failure modes) disproportionate to
current needs; SQLite would likely need to become Postgres first to avoid becoming the
new bottleneck once the queue stops being the limiting factor.

## Trade-off Analysis

The core cost driver isn't "too many concurrent reports" — it's that **each concurrent
report currently pays the full ML-model-loading tax**. Option A papers over the symptom
and makes OOM more likely under load. Option C solves it but at a cost (new broker,
new deployable, DB migration pressure) that isn't justified for "10 or so reports at a
time" — that's solving for a scale (hundreds of concurrent jobs, multi-host) the project
isn't at. Option B directly targets the actual cost (redundant model loads) with tools
already in the stack (`multiprocessing`/`concurrent.futures`), keeping the single-host,
single-deployable shape that suits the project's current size, while leaving a clear
upgrade path to Option C if/when report volume outgrows one machine.

## Consequences

- **Easier:** Memory usage becomes predictable and bounded; throughput is tunable via a
  single "pool size" knob; model-load latency is amortized across all reports instead of
  paid per report; existing checkpoint/resume logic in Stage 3 carries over unchanged.
- **Harder:** Worker lifecycle management (startup model load, crash detection, respawn,
  per-job timeout enforcement) now lives in our code rather than being implicit in
  "spawn a fresh process per job"; need to ensure SQLite's thread-local connection model
  plays well with long-lived workers handling many jobs sequentially (connection reuse vs.
  per-job connections).
- **Revisit later:** If report volume grows from "~10 at a time" toward "hundreds
  concurrently" or needs to span multiple hosts, re-evaluate Option C (Celery/RQ +
  Redis) and a move from SQLite to Postgres — the worker-pool design here doesn't block
  that migration, it just defers it until the data justifies the added complexity.

## Action Items

1. [ ] Replace `run_pipeline_async()`'s per-upload `multiprocessing.Process` spawn
   (`api/worker.py:728`) with a fixed-size persistent worker pool whose initializer loads
   sentence-transformers/GLiNER/gazetteer once.
2. [ ] Introduce a job queue (in-process `multiprocessing.Queue` or `asyncio.Queue` +
   pool) that the upload endpoint enqueues into, replacing the current semaphore-gated
   spawn in `api/worker.py:36`.
3. [ ] Add per-job timeout + automatic worker respawn on crash, building on the existing
   `WORKER_JOB_TIMEOUT=1800` constant.
4. [ ] Load-test with 10–20 concurrent uploads to validate memory stays bounded
   (≈ `#workers x ~1 GB` instead of `#concurrent_jobs x ~1 GB`) and measure end-to-end
   latency improvement from skipping repeated model loads.
5. [ ] Document the new pool-size / queue-depth tuning knobs alongside the existing
   `LLM_PARALLELISM` / `CHECKPOINT_EVERY` settings.
