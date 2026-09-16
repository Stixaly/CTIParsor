# ADR-0048 — A queue-status endpoint, not a metrics exporter

**Status:** Accepted (implemented 2026-09-16)
**Date:** 2026-09-16
**Relates to:** [0046](0046-worker-container.md) (the queue and lease this reports on),
[0045](0045-postgresql-for-the-job-store.md) (the job store this reads), [0039](0039-per-stage-observability.md)
(per-stage timing inside one job — a different question from queue-wide state)

## Context

Since ADR-0046 several workers can share one queue, but nothing tells an
operator its state. The only options today are `docker compose logs -f
worker` (log-watching) or counting `queued` rows in `GET /api/jobs` by hand
— not documented anywhere as a technique, because it wasn't one until now.
There is no metrics endpoint, no Prometheus client, nothing scraping
anything: this project has zero existing observability infrastructure to
extend.

## Decision

**One read-only JSON endpoint, `GET /api/queue/status`. No new dependency,
no auth** — the same posture as every other read endpoint in this
application (`GET /api/jobs`, `GET /api/detection-corpora`); it discloses no
secret, so it does not need the hardening deferred secret-writing endpoints
require (ADR-0007, SECURITY.md §2).

```json
{
  "role": "api",
  "backend": "postgresql",
  "counts": {"queued": 3, "processing": 1, "failed": 1, "for_review": 12, "completed": 40},
  "queue": {
    "depth": 3,
    "max_depth": 50,
    "oldest_queued_job_id": "3f2a...",
    "oldest_queued_seconds": 42.5
  },
  "workers": [
    {"worker_id": "worker-1:7:a1b2c3", "running_jobs": 1,
     "oldest_heartbeat_seconds_ago": 3.2, "stale": false}
  ]
}
```

- `counts` is the real `GROUP BY status` on `jobs`, so it never claims a
  status this codebase doesn't use; `queued`, `processing` and `failed` are
  guaranteed present at `0` because those three are what "is the queue
  backing up" is actually asking about — the others are whatever the data
  contains, not a guessed status vocabulary.
- `queue.depth` / `max_depth` operationalise `API_QUEUE_MAX_DEPTH`
  (`api.worker._QUEUE_MAX_DEPTH`) directly: an operator sees the same number
  the 503-rejection path compares against, before it starts rejecting.
- `oldest_queued_seconds` answers the question an analyst actually has —
  "how long until my report starts" — not just a count.
- `workers` is the lease (ADR-0046) made visible: one row per distinct
  `worker_id` among `processing` jobs, its running count, and whether its
  newest heartbeat is already older than `WORKER_LEASE_TIMEOUT_S` (`stale:
  true` — it is about to be requeued by another worker). Empty in role `all`
  and whenever no report is running, which is the honest answer.
- `role` / `backend` are `queue_loop.role()` / `api.db.backend()` — the same
  values `run_api.py`'s startup banner (this session) already prints, now
  queryable at runtime instead of only in a log line from boot.

Portable SQL only (`GROUP BY`, `COUNT`, `MIN`/`MAX` over the `TEXT` ISO
timestamps the schema already uses — the same lexicographic-comparison
pattern `queue_loop.lease_cutoff` relies on), so the endpoint reads
identically whether the job store is SQLite or PostgreSQL. New module
`api/routes/queue.py`, mirroring `progress.py` (one file, one concern — that
one reports a single job's stream, this one the queue's aggregate state).

## Options considered

- **A Prometheus `/metrics` endpoint** — rejected. It would be the first
  metrics dependency in a codebase that has none, aimed at infrastructure
  (Grafana, a scraper, retention) most single-host or small-team deployments
  of this tool do not run. The actual question asked was answerable with one
  small endpoint; reaching for a scrape-based stack to answer it would be
  the disproportionate choice this project has consistently rejected
  elsewhere (Redis, an ORM, a broker).
- **A frontend dashboard panel** — deferred, not rejected. This ADR is the
  data; a Kanban-board badge or a Settings-page panel consuming it is a
  separate, smaller change once there is an endpoint to call. Not built here.
- **Push a queue-depth number into the existing SSE `/progress` stream** —
  rejected: that stream is scoped to one job (`job_id` in the URL) and
  consumed only while its page is open; queue-wide state needs its own
  endpoint an operator can poll independent of any job existing at all.
- **Expose it only via `docker compose logs`** (i.e., do nothing) — rejected
  as the status quo this ADR was written to fix; a log line is not
  queryable, has no stable shape, and requires a shell on the host.

## Consequences

- Answers "is the queue backing up" and "which worker is stuck" without a
  new dependency or a new container.
- What it does not do: no history, no trend, no alerting — one snapshot per
  call. A deployment that wants graphs or paging still needs the Prometheus
  path this ADR declined to build; nothing here blocks adding one later
  (the endpoint's numbers are exactly what an exporter would scrape).
- Not authenticated, like the rest of the API — the same limit
  `SECURITY.md` already states applies here too.

## Validation record (2026-09-16)

| Check | Result |
|---|---|
| `tests/test_queue_status_api.py`, SQLite and PostgreSQL | 8 passed on each: empty queue, real `GROUP BY` counts, oldest-queued ordering, heartbeat age, the lease-timeout `stale` flag, two workers reported separately, role/backend, `max_depth` |
| Full suite, SQLite | **1214 passed**, 0 failed |
| Full suite, PostgreSQL | **1222 passed**, 0 failed |
| ruff, mypy | clean |
| Live compose stack (`app` role `api`, `worker`, `postgres`), before a report | `queue.depth: 0`, `workers: []` |
| Same stack, seconds after `POST /api/upload` | `counts.processing: 1`, one worker row, `oldest_heartbeat_seconds_ago: 1.1`, `stale: false` — the lease made visible in real time, not simulated |
| Same stack, after the report reached `for_review` | `counts.processing: 0`, `workers: []` — the endpoint returns to empty on its own, no stale row left behind |

`scripts/docker_smoke.sh` gained a check that the endpoint answers with
`role: api` on every run.
