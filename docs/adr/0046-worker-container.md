# ADR-0046 — The worker is a container of its own; the `jobs` table is the queue

**Status:** Accepted (implemented and validated 2026-09-16)
**Date:** 2026-09-16
**Relates to:** [0002](0002-concurrent-report-ingestion.md) (subprocess-per-report pool, no broker),
[0036](0036-architecture-service-multi-utilisateur.md) (spawn-based pool, broker rejected, persistent
model process as a later step), [0044](0044-container-images.md) (one image, several roles),
[0045](0045-postgresql-for-the-job-store.md) (the job store is PostgreSQL in the compose stack)

## Context

After ADR-0044 and ADR-0045 the stack has four containers, but the `app`
container is still the monolith: the upload and ingest routes call
`run_pipeline_async()`, which spawns the pipeline subprocess **inside the
uvicorn process**, keeps the concurrency cap in an in-memory counter, and lets
a watcher thread dispatch the next queued job when one finishes. `api/main.py`
requeues every `processing` job at startup on the assumption that it is the
only process that could have been running one.

What that costs, measured earlier in this series: each report holds ~4.4 GB
resident (ADR-0037), so the API container must be sized for the pipeline; a
Docker memory limit on it caps the API and the reports together; and the API
cannot be scaled or restarted independently of running reports.

What is already in place and makes the split cheap:

| Fact | Where |
|---|---|
| The queue is the `jobs` table: `queued` → `processing` → terminal | `api/worker.py::_claim_next_queued` |
| The claim is a conditional `UPDATE … WHERE id=? AND status='queued'` with a rowcount check — atomic on SQLite (single writer) **and** on PostgreSQL (read-committed re-evaluates the predicate; the loser's rowcount is 0) | `_claim_next_queued`, `tests/test_job_queue.py::test_claim_next_queued_is_atomic` |
| Progress reaches the UI through the `progress_events` table, never through process memory | `api/db.py::emit_progress`, `api/routes/progress.py` |
| The uploaded file is found by id under `uploads/`, a shared volume | `_upload_path_for` |
| Stage 3 checkpoints to `output/` every `CHECKPOINT_EVERY` chunks, so a requeued job resumes | `api/worker.py` |
| One image already dispatches on a command (`serve`, `bootstrap`, `cli`) | `docker/entrypoint.sh` |

The one thing the current design cannot do is coexist with a second
processing process: `requeue_orphans()` resets **every** `processing` row, so
a second worker starting up would steal jobs the first one is running.

## Decision

**A `CTIPARSOR_ROLE` switch and a lease on claimed jobs.** No broker, no new
image, no new table.

| Role | Who runs the pipeline | Used by |
|---|---|---|
| `all` (default) | the API process itself, through the same loop, in a background thread | host installs, `python run_api.py`, the test suite — unchanged behaviour |
| `api` | nobody in this process; routes only enqueue | the compose `app` service |
| `worker` | a supervisor loop in the foreground (`python -m api.worker`, entrypoint `worker`) | the compose `worker` service, scalable with `--scale worker=N` |

The loop (`api/queue_loop.py`, class `WorkerLoop`):

1. **Claim**: the existing conditional `UPDATE`, extended to stamp
   `worker_id` and `heartbeat_at` on the row it wins.
2. **Spawn**: the existing `spawn`-context subprocess and watcher thread
   (memory isolation and crash containment stay exactly as ADR-0002 designed
   them). The watcher calls the loop's `kick()` when the subprocess exits.
3. **Heartbeat**: every `WORKER_HEARTBEAT_S` (30 s) the loop stamps
   `heartbeat_at` on the jobs it is running.
4. **Orphans**: a `processing` row whose `heartbeat_at` is older than
   `WORKER_LEASE_TIMEOUT_S` (180 s) is requeued, by any worker, at start and
   on every poll. In role `all` the startup requeue stays unconditional, since
   no other process can be running a job.
5. **Poll**: `WORKER_POLL_S` (2 s) between claim attempts; in role `all` the
   routes also `kick()` synchronously after enqueueing, so a free slot starts
   the job before the response is written and the `"processing"` answer the
   UI already knows is preserved.
6. **Shutdown**: on SIGTERM the loop stops claiming, gives running subprocesses
   `WORKER_DRAIN_S` (default 60 s) to finish, then terminates them and
   requeues their jobs — the Stage 3 checkpoint makes that cheap.
7. **Liveness**: the loop touches `/tmp/ctiparsor-worker.alive` on every
   iteration; the container healthcheck is that file's age.

`run_pipeline_async()` keeps its name and its three answers: `"rejected"`
when the queue is deeper than `API_QUEUE_MAX_DEPTH` (now a cross-process
count), `"started"` when a kick found a slot, `"queued"` otherwise.

Schema: two nullable columns on `jobs`, `worker_id TEXT` and
`heartbeat_at TEXT`, added as a SQLite migration and as `ADD COLUMN IF NOT
EXISTS` lines in the PostgreSQL DDL. The migration script copies them like any
other column.

### Compose

`worker` is a new service from the same image with the same hardening,
`command: ["worker"]`, the two volumes, the `frontend` (egress to LLM
providers), `backend` (database) and `llm` networks, no port, and
`WORKER_MAX_CONCURRENT` as *its* setting. `app` runs with
`CTIPARSOR_ROLE=api`. Each service now declares CPU and memory
reservations and limits (the maintainer's request), from measured figures:

| Service | Limit | Why |
|---|---|---|
| `app` | 2 CPU, 3 GB | 130 MB idle measured; a Settings-page corpus rebuild parses 87 k rules in-process and peaked at 2.2 GB in the bootstrap container |
| `worker` | 4 CPU, 6 GB per `WORKER_MAX_CONCURRENT=1` | 4.4 GB per report (ADR-0037) plus the supervisor; `OMP_NUM_THREADS=2` per subprocess |
| `postgres` | 1 CPU, 512 MB | default `shared_buffers` 128 MB; the job store is a few MB per report |
| `proxy` | 0.5 CPU, 128 MB | nginx |
| `bootstrap` | 2 CPU, 4 GB | model downloads plus the same rule parse |
| `ollama` | 8 CPU, 12 GB (overridable) | a 7B model in Q4; a 27B one needs ~18 GB and a GPU |

Limits are environment-overridable (`CTI_<SERVICE>_CPUS`, `CTI_<SERVICE>_MEMORY`)
because they are host facts, not application facts. When the worker limit is
hit the OOM killer takes the pipeline subprocess, not the supervisor, and the
job is marked `failed` — the same mechanism as before.

## Options considered

- **Celery / RQ / ARQ + Redis** — rejected again for the reasons in ADR-0002
  and ADR-0036: `fork` is unusable after Torch's OpenMP pool initialises,
  the workload is CPU and RAM bound, and the `jobs` table already is a
  durable queue with an atomic claim.
- **`FOR UPDATE SKIP LOCKED` on PostgreSQL** — not needed: the conditional
  `UPDATE` is correct on both engines and the contention is a handful of
  workers polling every two seconds. It stays as a later optimisation if a
  deployment ever runs dozens of workers.
- **A worker HTTP endpoint for health** — rejected: a file on tmpfs answers
  the only question the healthcheck asks, "is the loop alive", without
  opening a port on a container that must not have one.
- **Running the pipeline in-process in the worker (no subprocess)** —
  rejected: the subprocess is the memory boundary and the crash boundary;
  the persistent model process of ADR-0036 is the right next step and is
  compatible with this loop.

## Consequences

- Host installs see no change: role `all` is today's behaviour through the
  new loop, and the test suite runs on it.
- The compose `app` container becomes stateless and small; workers scale with
  `docker compose up -d --scale worker=2`, each with its own memory limit.
- What becomes harder: a job whose worker dies takes up to
  `WORKER_LEASE_TIMEOUT_S` to be requeued instead of restarting immediately
  with the API; two settings (`WORKER_HEARTBEAT_S`, `WORKER_LEASE_TIMEOUT_S`)
  must keep their ratio (lease ≥ 3 × heartbeat, enforced with a warning).
- **Unstated until now: the lease assumes synchronised clocks.**
  `heartbeat_at` and the lease cutoff are both stamped with the *worker's own*
  `now_iso()`, not a database-side `NOW()` — no code path asks PostgreSQL for
  the time. On one Docker host every container shares the kernel clock, so
  this is invisible today. It stops being invisible the moment workers run on
  separate hosts (already the condition under which the compose stack is not
  supported, §"Consequences" above, for a different reason — shared volumes).
  A worker whose clock runs ahead can look alive past its real lease; one
  whose clock runs behind can have its still-running job requeued early. NTP
  on every host removes the risk; a server-side `NOW()` in the UPDATE would
  remove the assumption instead, and is a candidate for whenever multi-host
  workers are actually built.
- Not done here: the persistent model process (ADR-0036), the browser
  container, authentication.

## What building it changed

1. **`pids_limit` and `deploy.resources.limits` cannot coexist** in a compose
   file: Compose maps the former onto `limits.pids` and refuses distinct
   values. The pids cap moved into each service's `deploy` block.
2. **A subprocess can exit before `spawn()` returns.** The watcher then calls
   `on_exit` before the loop has stored the handle, and a naive store would
   leave a phantom running job holding a slot forever. The loop stores the
   handle only if the job is still registered, and `kick()` is serialised so
   the poll thread, a request thread and a watcher thread cannot each take the
   last free slot.
3. **A default argument bound at import defeated the healthcheck test.**
   `touch_alive(path=ALIVE_FILE)` captured the path once; the function now
   reads the module attribute at call time.
4. **The API's shutdown must stop the embedded loop**, or the test client's
   context would leak a polling thread into the next test's database.

## Validation record (2026-09-16)

| Check | Result |
|---|---|
| `tests/test_job_queue.py`, SQLite and PostgreSQL | 14 passed on each engine: atomic claim under 8 threads, lease semantics, heartbeat scoping, slot accounting, the three answers under each role, `--once` |
| Full suite, SQLite (role `all`, the host install) | **1206 passed**, 12 skipped, 0 failed |
| Full suite, PostgreSQL | **1214 passed**, 4 skipped, 0 failed |
| ruff, mypy on the touched modules | clean |
| Compose config with every profile, limits rendered | valid: app 2 CPU / 3 GB, worker 4 CPU / 6 GB, postgres 1 / 512 MB, proxy 0.5 / 128 MB, bootstrap 2 / 4 GB, ollama 8 / 12 GB, pids 4096 on the three app-image services |
| Stack: `app` (role `api`) + `worker` + `postgres`, existing `pg-data` volume | the two lease columns were added in place by the `IF NOT EXISTS` DDL; worker healthy through its liveness file; API confirms role `api` |
| `scripts/docker_smoke.sh --no-build --job` | **0 failures**: the sample report reached `for_review` with 33 entities and 5 relationships, a 63-object bundle; its spawn line appears in the **worker** container's log and the API container spawned nothing; 7 min 50 s wall clock including the LLM stage on the LAN Ollama |
