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
| Should someone be paged? | `GET /metrics`, and the alert rules of *Monitoring and alerts* |

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
| `cti-cache` | the models (2.6 GB) and corpora (0.2 GB) `bootstrap` downloads; it grows when they are downloaded again | `docker system df -v` |

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

## Backups

With the `backup` profile on, the status of the last run is in the file
`/backup-status/status.json` on the `cti-backup-status` volume, and the app
reports it on `/metrics` (see [Monitoring and alerts](#monitoring-and-alerts)).
Watch these:

- `ok` is `false`, or `error` names a step. The run failed and kept every older
  pair. Read the error, fix the cause (a full target, a wrong password file, a
  database that was down), then run `docker compose --profile backup run --rm -e BACKUP_RUN_NOW=1 backup`.
- `last_success` is older than a day. No run succeeded since then.
- `file` is the newest pair. Check it with the commands in
  [docker.md](docker.md#data-and-backups).
- The free space of `BACKUP_TARGET`. `BACKUP_KEEP` pairs take the space of
  that many dumps and archives. The backup does not check the free space
  itself: a full target makes a run fail, and the run then says so.

Routing a failure to a person is the operator's job: the status file and the
metrics are what to alert on.

## Logs

```bash
docker compose logs -f app worker
```

- The worker's log holds the pipeline's lines for each report: each runs in a
  subprocess of the worker.
- `LOG_LEVEL` (`INFO`), and `LOG_FORMAT=json` for one JSON object per line;
  `LOG_FILE` adds a rotated file ([configuration.md](configuration.md)).
- `docker compose logs postgres` for the database.

## Audit trail

The API writes one audit record for each state-changing request under `/api/` (`POST`,
`PUT`, `PATCH`, `DELETE`), whether the request was answered or refused, and one for each
change made with `python -m api.admin`. Reads (`GET`) and `/metrics` are not recorded.
The record is written after the answer, so a refused request is recorded too.

Each record has these fields:

- `at`: when the answer was written, UTC, ISO 8601.
- `request_id`: the request id: the `X-Request-ID` header when it is well formed, else a
  new one. Null for a command-line change.
- `user_id`, `username`, `role`: the signed-in account. Null when the request was anonymous,
  and with `AUTH_MODE=off`. For a command-line change, `username` is the operating-system
  user who ran the command.
- `auth`: `session` (the web cookie), `token` (a bearer token), `none` (no valid credentials)
  or `cli` (a command-line change).
- `method`: the HTTP method. Null for a command-line change.
- `route`: the route template, for example `/api/jobs/{job_id}`. When no route matched (an
  unknown path, or a refusal before routing) it is the raw path. For a command-line change
  it is the command name, for example `create-token`.
- `target`: the path parameters as a JSON object, for example `{"job_id": "..."}`. For a
  command-line change, the account (`{"username": ...}`) or the token id (`{"token_id": ...}`).
- `status`: the HTTP status of the answer. Null for a command-line change.
- `outcome`: `ok` for 2xx and 3xx; `refused` for 401, 403, 404, 409 and 429; `error` for any
  other status. A request that failed without an answer is recorded as status 500, `error`.
- `client`: the client address as the application sees it. Behind a proxy, that is the
  proxy's address, unless the proxy's forwarded address is trusted (`FORWARDED_ALLOW_IPS`).
- `attempted`: on a sign-in only, the username typed, and only when an account of that name
  exists. A name that matches no account is never written, so a typed password cannot appear.

Never recorded: a request or response body, a query string, a header, a cookie, a token or
a password.

Where the records go:

- **A JSON line on standard output** for each record, through the logger `ctiparsor.audit`.
  It is always JSON, whatever `LOG_FORMAT` says, and has the key `"audit": true`. The log
  system of the host collects it, for example
  `docker compose logs app | grep '"audit": true'` shows the lines of the API container.
  A change made with `python -m api.admin` writes its line to standard error, because
  standard output carries the token of `create-token`.
- **A row of the table `audit_events`**, read with `GET /api/audit`.

Retention: `AUDIT_RETENTION_DAYS` (default 365; `0` keeps every row, see
[configuration.md](configuration.md)). A row older than that is deleted. The check runs at
most once an hour, on the write of a record. CTIParsor does not delete the lines on standard
output; the retention of the log system applies to them.

A database error while a row is written is logged (`[audit] could not write an audit row`),
and the answer to the request does not change. The JSON line is still written. A line in the
log with no row in `audit_events` points at the database.

To read the table, sign in as an admin, or use an admin token:

```bash
curl -fsS -H "Authorization: Bearer ctp_..."   "http://127.0.0.1:8000/api/audit?outcome=refused&limit=50"
```

The filters are `user` (a username), `route` (a route template), `outcome` (`ok`, `refused`
or `error`), `since` and `until` (ISO 8601; `until` is exclusive) and `limit` (1 to 500, 100 by
default). The list is newest first. When more records follow, the response header
`X-Next-Cursor` holds the value for the `cursor` parameter of the next page.

The table has no link to `users`: a record keeps the user id and name it was written with.
An anonymous flood of refused requests fills the table until the retention deletes them.

## Monitoring and alerts

`GET /metrics` serves Prometheus text format (0.0.4). It is left out of the
API schema. It answers a client on loopback (127.0.0.0/8 or ::1), and a client
from anywhere that sends the `METRICS_TOKEN` bearer. Any other request gets
403. A connection through Docker's published port usually arrives from the
Docker network's gateway instead, so such a scraper needs the token. Verify the
scrape first:

```bash
curl -fsS http://127.0.0.1:8000/metrics
```

A Prometheus container can reach the app over loopback if it shares the app's
network namespace (`network_mode: "service:app"` in Compose). This is not run
on the stack by the project: check the scrape before relying on it.

From another host, set `METRICS_TOKEN` in `.env` (generate it with
`openssl rand -hex 32`), and send it as a bearer. The token is accepted from
any address; without it, only loopback is. Serve the scrape through the
`proxy` profile (TLS), never on a plain port, since the token travels in each
request. Keep the token in a file that only Prometheus reads:

```yaml
scrape_configs:
  - job_name: ctiparsor
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/ctiparsor-metrics-token
    static_configs:
      - targets: ["cti.example.org:443"]
```

Use the same value as `METRICS_TOKEN` in the file. Work item 14 adds an admin
token for the scraper next to this one.

The endpoint answers while the database is down: `ctiparsor_database_up` is
0, and the metrics that need the database are left out.

| Metric | Meaning |
|---|---|
| `ctiparsor_jobs{status}` | jobs per status (every status is listed, at 0 when none) |
| `ctiparsor_failed_jobs` | jobs in status `failed` |
| `ctiparsor_oldest_queued_job_age_seconds` | age of the oldest `queued` job; 0 when the queue is empty |
| `ctiparsor_workers{state}` | worker loops: `busy`, `idle`, `stale` (the rule of `GET /api/queue/status`) |
| `ctiparsor_database_up` | 1 when PostgreSQL answers `SELECT 1`, else 0 |
| `ctiparsor_state_dir_free_bytes`, `ctiparsor_state_dir_total_bytes` | free and total bytes of the filesystem holding the state directory |
| `ctiparsor_backup_last_attempt_ok` | 1 when the last backup attempt succeeded, 0 when it failed; absent without a status file |
| `ctiparsor_backup_last_success_timestamp_seconds` | Unix time of the last successful backup; absent until one succeeds |

The alert rules are in `docs/monitoring/ctiparsor.rules.yml`. Each alert below
names its rule. Routing the alerts to people (Alertmanager, mail, chat) is the
operator's to set up.

### No live worker

`CtiparsorNoLiveWorker`: no worker loop is `busy` or `idle` for 5 minutes.
Queued reports do not run. Check `docker compose ps worker` and
`docker compose logs worker`; the *Health* and *The queue and its workers*
sections say what the worker's state and log mean. A worker container that
exits is restarted by Docker; one that is `unhealthy` is not.

### Queue wait too long

`CtiparsorQueueWaitTooLong`: the oldest queued report has waited more than
30 minutes (`ctiparsor_oldest_queued_job_age_seconds` above 1800), for 5
minutes. Look at `worker_summary.idle_slots` in `GET /api/queue/status`. Zero
slots with busy workers means the reports are running and the queue is simply
long. Free slots with no progress means a worker is stuck: its log names the
report.

### Failed reports rising

`CtiparsorFailedJobsRising`: more than 3 more jobs are in status `failed` than
an hour ago. The rule is net of requeues and deletions. Read the reason of each
recent failure, as in *Failed reports* above.

### Database down

`CtiparsorDatabaseDown`: `ctiparsor_database_up` is 0 for 1 minute.
`GET /api/health` returns 503 in the same case. Check `docker compose ps
postgres` and `docker compose logs postgres`, then the app's log
(`[health] job store unreachable`).

### Disk nearly full

`CtiparsorDiskNearlyFull`: free space under the state directory is below 10 %
of the filesystem, or below 2 GiB, for 10 minutes. Nothing here deletes data
by itself, except `JOB_RETENTION_DAYS` if it is set. Find the largest items
with the table in *Disk* above.

### Backup too old

`CtiparsorBackupTooOld`: the last successful backup is more than 26 hours old,
or no backup has been reported (the metric is absent). An absent metric means
the `backup` service has not written its status file: it is not started
(`docker compose --profile backup up -d backup`), or it has no volume. An
installation that runs no scheduled backup gets this alert too; run the
backup or leave the rule out. The status file holds the timestamps:
`docker compose --profile backup logs backup`.

### Backup failed

`CtiparsorBackupLastAttemptFailed`: the last backup attempt reported
`ok: false`. The `error` field of the status file says why, and the older
backups are kept. Fix the cause (the target path, the disk, the database
password) and run the backup again with `BACKUP_RUN_NOW=1`.
