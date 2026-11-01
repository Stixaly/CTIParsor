# Operations

What to watch on a running install, and what each signal does not say. The
commands are for the Compose stack ([docker.md](docker.md)) on its default
address, `127.0.0.1:8000`; use your `CTI_BIND` and `CTI_PORT`.

| Question | Look at |
|---|---|
| Does the API answer, and its database? | `GET /api/health` |
| Is a worker running, busy or idle? Is the queue backing up? | `GET /api/queue/status` |
| Why did a report fail? | its last progress event, and the worker's log |
| What fills the disk? | `docker system df -v`, `du` in `cti-state` |
| How many reports at once? | `WORKER_MAX_CONCURRENT`, `CTI_WORKER_MEMORY` |

## Health

```bash
curl -fsS http://127.0.0.1:8000/api/health
```

- **200** `{"status": "ok"}`: the API answers, and the database answered a
  `SELECT 1`. The API serves only once its start has brought the database to
  the code's schema version (ADR-0077).
- **503** `{"status": "degraded", "detail": "job store unreachable"}`: PostgreSQL
  does not answer. The app's log says why (`[health] job store unreachable:`).
- The image's `HEALTHCHECK` calls it every 30 s: `docker compose ps` shows
  `app` as `healthy` or `unhealthy`. Check the status code, not the body.
- It does not say whether a worker runs (the queue status does), whether the
  models are in `cti-cache` (`docker compose run --rm app check`), whether the
  LLM provider answers, or how much disk is left.

`docker compose ps worker` shows the worker `healthy` while its queue loop
touches its liveness file (`WORKER_ALIVE_FILE`) at least once every two
minutes. The loop touches it on every pass (`WORKER_POLL_S`, 2 s) as long as
the last write of its row in the database (every `WORKER_HEARTBEAT_S`, 30 s:
see below) succeeded. A worker that PostgreSQL does not answer turns
`unhealthy` a few minutes later: its next heartbeat fails, the file ages two
minutes, then three checks 30 s apart fail. Its log says why
(`Exception in stamp_worker: ...`, then `run_once: not touching the alive
file`). The first heartbeat that reaches the database again makes it
`healthy`. A loop that hangs stops touching the file too. It does not say that
a report would succeed: the models and the LLM are not checked. Docker
restarts a container that exits, not one that is `unhealthy`.

## The queue and its workers

```bash
curl -fsS http://127.0.0.1:8000/api/queue/status | python3 -m json.tool
```

```json
{ "role": "api", "backend": "postgresql",
  "counts": { "queued": 0, "processing": 0, "failed": 0 },
  "queue": { "depth": 0, "max_depth": 50,
             "oldest_queued_job_id": null, "oldest_queued_seconds": null },
  "workers": [ { "worker_id": "df6e6f3dc69f:7:e49bd3", "state": "idle", "role": "worker",
                 "max_concurrent": 1, "app_version": "0.2.0",
                 "started_at": "2026-10-31T23:52:06.970369+00:00", "running_jobs": 0,
                 "heartbeat_seconds_ago": 2.3, "oldest_heartbeat_seconds_ago": null,
                 "stale": false } ],
  "worker_summary": { "alive": 1, "busy": 0, "idle": 1, "stale": 0,
                      "capacity": 1, "idle_slots": 1 } }
```

- `role` is this API process's (`CTIPARSOR_ROLE`). In role `api`, the
  Compose default for `app`, the API runs no queue loop: the workers listed
  are the `worker` containers. In role `all` it runs its own, listed with
  `role: "all"`.
- `counts`: the reports by status, read from the database; `queued`,
  `processing` and `failed` are always there.
- `queue.depth` against `queue.max_depth` (`API_QUEUE_MAX_DEPTH`, 50; 0 = no
  limit). At the limit, an upload, a pasted text or a URL capture is answered
  503 ("The processing queue is full") and that report is marked failed.
  `oldest_queued_seconds`: how long the next report has waited.
- `workers`: one entry per queue loop that runs. Each loop writes its row in
  the database when it starts and every `WORKER_HEARTBEAT_S` (30 s), busy or
  idle, and deletes it when it stops cleanly (`docker compose stop`, a smaller
  `--scale`, the API stopping in role `all`). `state` is:
  - `busy`: a heartbeat within `WORKER_LEASE_TIMEOUT_S` (180 s), and
    `running_jobs` (counted from the reports in `processing`) above 0;
  - `idle`: a heartbeat within the lease, no report;
  - `stale`: no heartbeat for longer than the lease. The process died or
    hangs: its reports go back to the queue, and its row is deleted an hour
    after its last heartbeat by any loop that runs.

  `heartbeat_seconds_ago` is the age of the worker's latest heartbeat, that
  of its row or of one of its reports, and `stale` is `true` when it is above
  the lease. `oldest_heartbeat_seconds_ago` is the age of the oldest
  heartbeat of its reports, `null` when it runs none.
- `worker_summary`: `alive` (busy and idle), `capacity` (the sum of their
  `max_concurrent`; `null` when one is unlimited or unknown) and `idle_slots`.

**No live worker** (`worker_summary.alive` is 0): nothing starts the queued
reports. That is expected for a few seconds while a worker starts (it writes
its row on its first pass), while `app` and `worker` are stopped for a backup,
or when no worker is meant to run (`--scale worker=0`). Otherwise:
`docker compose ps worker` and `docker compose logs worker`.

What it does not say:

- Why a worker is `stale`: the logs do.
- That a worker which crashed is gone, until its lease expires: for up to
  180 s it is listed as it was, and counted in `capacity`.
- Anything about a worker that cannot reach the database: it writes no row,
  so it is not listed, or turns `stale` if it was. Its container turns
  `unhealthy` (*Health*, above).
- An idle worker of a version before schema version 14 (during an upgrade)
  writes no row: it is listed only while it holds a report, with `role`,
  `max_concurrent` and `started_at` at `null`, and `capacity` is then `null`.
- Whether the next report will succeed.

## Failed reports

`counts.failed` counts them. The dashboard says "Pipeline failed", the progress
dialog "Pipeline failed — check server logs": the page does not give the
reason. Two places do:

- The report's last progress event. The stream of a finished report ends
  there:

  ```bash
  curl -sN http://127.0.0.1:8000/api/jobs/<job-id>/progress
  ```

  ends with `event: done` and `data: {"status": "failed", "error": "..."}`.
- The worker's log, `docker compose logs worker | grep <job-id>`:
  `[Worker ERROR] job <id>: ...`, `[Worker TIMEOUT] job <id>: ...` (past
  `WORKER_JOB_TIMEOUT`, 1800 s), or `Subprocess for job <id> crashed: ...`
  (the subprocess was killed, often by the OOM killer: see *Sizing*).

A report refused because the queue was full fails with "Queue is full (N jobs
waiting) — try again later"; one whose uploaded file is gone, with "uploaded
file is missing".

## Disk

| Volume | What grows | How to see it |
|---|---|---|
| `pg-data-18` | every report: its text, entities, relationships, decisions, progress events, bundle, ledger and baseline (up to 20 MB); the detection-rule store | `docker system df -v` |
| `cti-state` | `uploads/` (each source, up to 50 MB), `output/` (exported bundles, Stage 3 checkpoints) | `docker compose exec app du -sh /app/state/uploads /app/state/output` |
| `cti-cache` | the models (2.6 GB) and corpora (0.7 GB) `bootstrap` downloads; it grows when they are downloaded again | `docker system df -v` |

- Nothing is deleted by default. Deleting a report deletes its rows and files;
  `JOB_RETENTION_DAYS` (0 = never) deletes the finished reports older than N
  days ([configuration.md](configuration.md)).
- The container logs are capped: 5 files of 50 MB for each `app` and `worker`
  container, 3 of 20 MB for `postgres`.
- After a few rebuilds the BuildKit cache is the largest item;
  `docker builder prune` reclaims it ([docker.md](docker.md)).
- No route reports the free space. Watch the filesystem of Docker's data
  directory (`docker info --format '{{.DockerRootDir}}'`, then `df -h` on it).

## Sizing

- `WORKER_MAX_CONCURRENT` (default 1, in the code as in Compose): the reports
  one worker runs at once. Each holds about 4.4 GB, mostly GLiNER.
- `CTI_WORKER_MEMORY` (default `6g`): the worker's memory limit. Size it
  `WORKER_MAX_CONCURRENT × 4.4 GB + 1 GB`. Past it, the OOM killer takes a
  report's subprocess and that report fails; the worker goes on.
- More reports at once: raise both, or add workers with
  `docker compose up -d --scale worker=2` (each with its own limit and
  memory); `worker_summary.capacity` sums their slots.
- Measure it on your host: `docker compose run --rm dev python
  scripts/measure_cold_start.py` ([deployment.md](deployment.md#5-workers-and-memory)).
- `API_QUEUE_MAX_DEPTH` bounds the wait: past it, uploads get a 503.

## Logs

```bash
docker compose logs -f app worker
```

- The worker's log holds the pipeline's lines for each report: each runs in a
  subprocess of the worker.
- `LOG_LEVEL` (`INFO`), and `LOG_FORMAT=json` for one JSON object per line;
  `LOG_FILE` adds a rotated file ([configuration.md](configuration.md)).
- `docker compose logs postgres` for the database.
