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

With `AUTH_MODE` set to `local`, `oidc` or `both`, this route needs a signed-in
reader or a token: add `-H "Authorization: Bearer ctp_..."` to the `curl`. Only
`/api/health` is open. With the default `AUTH_MODE=off`, no token is needed.

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
  `JOB_RETENTION_DAYS` (0 = never) deletes the finished reports idle for more
  than N days ([configuration.md](configuration.md),
  [what counts as activity](#what-counts-as-activity)).
- A deleted report's rows go first. A file the filesystem refuses to remove (a
  permission, a locked file, a volume that is not mounted) stays on disk, and
  its path is kept in the table `job_file_cleanups` (version 22) until it is
  removed. The removal is retried at each start of the API and of a worker, on
  each retention sweep (hourly by default), and by a `DELETE` of the same report
  id. The `DELETE` answer then carries `files_pending`, the number of files
  still waiting. To see them:
  `SELECT job_id, path, attempts, last_error FROM job_file_cleanups;`. A row
  whose `attempts` keeps rising is a file the API process cannot remove: check
  its owner and mode on the state volume. A row is dropped without removing its
  file when its path is not directly in `uploads/`, `uploads/meta/` or `output/`.
- The container logs are capped: 5 files of 50 MB for each `app` and `worker`
  container, 3 of 20 MB for `postgres`.
- After a few rebuilds the BuildKit cache is the largest item;
  `docker builder prune` reclaims it ([docker.md](docker.md)).
- No route reports the free space. Watch the filesystem of Docker's data
  directory (`docker info --format '{{.DockerRootDir}}'`, then `df -h` on it).

### What counts as activity

The retention sweep (`JOB_RETENTION_DAYS`) deletes a finished report only when
both of its clocks are older than the window:

- `updated_at`, the last change the worker or a request made to the report
  (a run ending, a bundle built, a status change);
- `activity_at`, the last human decision or edit on its entities or
  relationships (migration 21).

Activity is written in the same transaction as the change it records, so a
change that fails or is rolled back does not renew the report. These renew
`activity_at`:

- accepting, rejecting or resetting an entity or a relationship (`PATCH`, and
  the bulk routes `POST .../entities/bulk`, `POST .../entities/accept-pending`,
  `POST .../relationships/bulk`), when the change touched at least one row;
- creating, editing or deleting an entity or a relationship (`POST`, `PATCH`,
  `DELETE`).

These do not: reading a report (`GET`, polling the status). Finalizing a report
does renew it, but through `updated_at`: publishing the rebuilt bundle sets it.
The automatic accept at the end of a run is part of that run, which also sets
`updated_at`.

Existing reports: migration 21 sets `activity_at` from the newest analyst
decision in the decision journal. Edits that were not decisions (a value or a
type changed by hand) are not in the journal and are not counted for reports
that were last touched before the upgrade.

A report kept by the sweep keeps its rows, decisions and files. The sweep logs
`[retention] swept <n> job(s) older than <d>d` ([Logs](#logs)).

## Sizing

- `WORKER_MAX_CONCURRENT` (default 1, in the code as in Compose): the reports
  one worker runs at once. Each holds about 4.4 GB, mostly GLiNER. A run
  loads the GLiNER model when `GLINER_ENTITY_TYPES` names a type, which the
  default does (ADR-0098).
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

### Log tags

Each line the API and the pipeline log starts with a tag in square brackets, which names
the part of the code that wrote it. The table lists every tag in `api/` and `pipeline/`.
The command-line scripts in `scripts/` print their own `[tag]` lines to the console; they
are not in the service logs and are not listed here. Lines at `DEBUG` are not shown at the
default `LOG_LEVEL=INFO`.

The examples are the messages as the code writes them; `<...>` stands for a value.

| Tag | Module | What it covers | Example | When to worry |
|---|---|---|---|---|
| `[startup]` | `api/main.py` | The API's start-up checks: the authentication mode, the default TLP, the ATT&CK release, the browser for URL capture, the process role. | `[startup] authentication is OFF (AUTH_MODE=off): single-analyst use on loopback only; ...` | An `error` line: the process has stopped. A `warning` with `AUTH_MODE=off` on a host other people can reach. |
| `[queue]` | `api/queue_loop.py` | A worker's start (its concurrency, poll, heartbeat and lease settings) and its stop request. | `[queue] worker <id> starting: max_concurrent=..., poll=...s, heartbeat=...s, lease=...s` | No `starting` line after a restart: the worker did not come up. `stop requested` without a restart: the worker is going down. |
| `[finalize]` | `api/worker.py` | The step that builds a report's STIX bundle from the stored rows, including rebuilds after review decisions. | `[finalize] job <id>: the rebuilt bundle failed STIX schema validation (<n> error(s)); ...` | Every `error`: the job is not completed and its bundle is not served. The `warning` lines name what the bundle goes without, or a build that was not published or not recorded. |
| `[auth]` | `api/auth/deps.py`, `api/auth/oidc.py`, `api/routes/auth.py` | Sign-ins that fail or are locked, identity-provider sign-ins that are refused, accounts created or re-roled by the identity provider, and a route with no permission defined. | `[auth] failed sign-in for <name>` | Many failures for one name (a guessing attempt). Any `no permission is defined`: a route answers 403 because its permission is missing. |
| `[admin]` | `api/routes/admin.py` | Each account and token change made through the admin routes: who did it and what changed. The password is never logged. | `[admin] <actor> created the <role> account <name>` | A change nobody on the team made. |
| `[audit]` | `api/audit.py` | Failures of the audit trail: a record that could not be written, or the retention that could not be applied. | `[audit] could not write an audit row (<error type>); the answer to the request is not changed` | Any line. Requests answered while it fails are not in the audit trail (see [Audit trail](#audit-trail)). |
| `[retention]` | `api/routes/jobs.py` | The sweep that deletes finished jobs older than the retention period: how many it deleted, and the jobs it could not delete. | `[retention] swept <n> job(s) older than <d>d` | A `failed to delete job` error: that job was not deleted, and its files still use disk space ([Disk](#disk)). |
| `[cleanup]` | `api/routes/jobs.py` | The removal of the files of deleted reports: a file that could not be removed (its attempt number and the error), a path dropped because it is outside the job directories, and a warning with how many files still wait ([Disk](#disk)). | `[cleanup] could not remove <path> of job <id> (attempt <n>): <error>` | Any `could not remove` line that repeats for the same path: the file stays on disk and its row stays in `job_file_cleanups`. A `pass stopped` error: the store or the filesystem failed during the retry, and the next pass runs it again. |
| `[baseline]` | `api/baseline_store.py` | STIX objects of an uploaded baseline that are dropped as invalid, so they are not used for enrichment. | `[baseline] job <id>: dropped invalid STIX object <id> (<reason>): ...` | Many drops for one job: its enrichment is built from less than was uploaded. |
| `[db]` | `api/migrate.py`, `api/db_identity.py` | Schema migrations applied at start, and the record of which PostgreSQL cluster the database is on (`db-identity.json` in the state directory). | `[db] schema version <n> applied: <name> (<ms> ms)` | A `could not record` warning: the cluster record was not written, so a later start cannot compare against it. The migration lines are normal. |
| `[health]` | `api/main.py` | `GET /api/health` found the job store unreachable, and answers 503. | `[health] job store unreachable: <error>` | Always: the Docker health check fails. Check the `postgres` service ([Health](#health)). |
| `[metrics]` | `api/routes/metrics.py` | Gaps in `/metrics`: the job store unreachable (`ctiparsor_database_up` is 0), the free disk unknown, or the backup status file unreadable. | `[metrics] job store unreachable: <error>` | Any line: the gauge for that part is missing or reads 0 ([Monitoring](#monitoring-and-alerts)). |
| `[policy]` | `api/routes/policy.py` | The policy page's last-run figures, when the stored bundle does not parse or the last run cannot be read. | `[policy] last run not read from the job store: <error type>: <error>` | The page shows "no run yet" while a run exists. |
| `[aliases]` | `pipeline/aliases.py` | An alias file that cannot be read. Names are then not merged for the whole process. | `[aliases] <file> unreadable, no alias is resolved: <error>` | Any line: the file is broken, and the report's entity names are not resolved. |
| `[mitre_db]` | `pipeline/mitre_db.py` | A file of revoked ATT&CK ids that cannot be read; revoked ids are then not replaced. | `[mitre_db] <file> unreadable, revoked ids are not replaced: <error>` | Any line. |
| `[benign]` | `pipeline/benign.py` | A warninglist or legitimate-file list that cannot be read. Without it, no list applies, or no file is marked legitimate. | `[benign] <file> unreadable, no warninglist applies: <error>` | Any line: no warninglist (or legitimate-file list) applies until the file is fixed. |
| `[corpora]` | `pipeline/detection/sync.py` | A corpus sync that failed. The browser gets the step that failed; the log gets the exception text. | `[corpora] <step>: <error text>` | A failed sync: that corpus is not updated by it. |
| `[detection]` | `pipeline/detection/` | Detection corpora: a registry that does not parse, a corpus path that is missing, a rule file skipped, and duplicate rule ids. | `[detection] corpus '<name>': path '<root>' missing — run sync_corpora first` | A missing corpus path or a skipped file: that corpus contributes no rules, or fewer. |
| `[calibration]` | `pipeline/calibration.py` | Decided rows and proposed thresholds that are skipped: a confidence that is not a finite number, or a threshold outside 0 to 1. | `[calibration] skipping out-of-range proposed threshold <value> for (<source>, <type>)` | A count that grows from run to run: those rows are not used by calibration. |
| `[overrides]` | `pipeline/overrides.py` | The analyst's deny and promote rows: how many were loaded, and how many entities a deny row removed. | `[overrides] <n> deny / <m> promote row(s) active` | An unexpected count after a change to the rows. |
| `[thresholds]` | `pipeline/thresholds.py` | The calibrated cutoffs loaded at start. A count of 0 means the built-in thresholds apply. | `[thresholds] <n> calibrated cutoff(s) loaded` | Only when a count of 0 is not what was expected. |
| `[promotion]` | `pipeline/promotion.py` | The gazetteer terms cannot be read, so promotion candidates are not checked against them. | `[promotion] gazetteer terms unavailable, candidates not checked against them: <error>` | Any line: a candidate may duplicate a name the gazetteer already holds. |
| `[capture]` | `pipeline/web_capture.py` | Playwright is installed but does not load, so URL capture is off (`warning`); the other lines are `DEBUG`. | `[capture] Playwright is installed but does not load, URL capture is off: <error>` | The `warning`: URL sources cannot be captured until it is fixed. |
| `[anchor]` | `pipeline/stage1_ingestion.py` | Capture or HTML metadata that cannot be read for a source. `DEBUG` only. | `[anchor] HTML metadata unreadable for <file>: <error>` | Not normally: the anchor is still looked for in the other sources. |

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
An anonymous request refused with 401 (no session, no token) is written as a JSON line only, not as a row, so an unauthenticated client cannot fill the table; a failed sign-in (`POST /api/auth/login`, limited per address) is kept as a row. An unmatched path is cut to 256 characters.

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

Use the same value as `METRICS_TOKEN` in the file. `/metrics` accepts only that
token or a loopback client, whatever `AUTH_MODE` is: an API token (`ctp_…`) is
not accepted there.

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
The failure cases that check these alerts, and the restore drill, are in [1.0-failure-recipe.md](releases/1.0-failure-recipe.md).

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
