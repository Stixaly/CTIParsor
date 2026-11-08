# ADR-0097: 1.0 is a shared service for one team

**Status:** Proposed (2026-11-08). The maintainer accepts it after reading it.
**Date:** 2026-11-08
**Deciders:** maintainer
**Amends:** ADR-0094 (its decision on who 1.0 is for; its other decisions stay)
**Relates to:** ADR-0036 (multi-user, proposed), ADR-0048 (queue status
endpoint), ADR-0085 (versions before 1.0), ADR-0090 (TLP and PAP markings),
ADR-0094 (what 1.0 promises)

## Context

ADR-0094 aimed 1.0 at one analyst on a local install and rejected
authentication and several users before 1.0 (*Options rejected*). On
2026-11-08 the maintainer decided that 1.0 is a shared service for one team.
This ADR records that decision and the design that follows from it. It writes
no code.

What the code does on 2026-11-08, read from the worktree this ADR was written
in:

- **No authentication.** `api/main.py` has a Host check
  (`API_ALLOWED_HOSTS`, `TrustedHostMiddleware`), a guard that refuses a
  cross-site write, and no `CORSMiddleware`. None of them identifies a user.
  Anyone who reaches the port has full access (`SECURITY.md`, section 2).
  The 14 files of `api/routes/` (attack, baselines, coverage, entities,
  ingest, jobs, overrides, policy, progress, queue, relationships, settings,
  thresholds, upload) check nothing.
- **Outbound data is not tied to TLP.** A job stores `tlp_level` and
  `pap_level`, and Stage 4 stamps them on the bundle. Nothing reads them to
  decide which provider may receive the text, or the images Stage 1f sends.
  `LLM_PROVIDER` is one setting for every report.
- **Decisions are not attributed.** The review decisions, the finalize, the
  exports, the deletions, and the changes to settings, policy and thresholds
  record no user, because there is none.
- **Signals are not wired to alerts.** `GET /api/health`,
  `GET /api/queue/status` (the workers, `busy`, `idle` or `stale`, and the
  queue) and the container health checks exist (`docs/operations.md`). Nothing
  scrapes them and nothing raises an alert. `docs/operations.md` says no route
  reports the free disk space. ADR-0048 rejected a Prometheus `/metrics`
  endpoint, for a deployment that ran no scraper; this ADR reverses that
  rejection, because a team service needs its alerts.
- **Backups are manual.** `docs/docker.md` gives the `pg_dump` and `tar`
  commands. `scripts/check_backup_restore.py` shows that they restore
  (ADR-0094 item 3). Nothing runs them on a schedule or checks that one ran.
- **`GET /api/jobs` is not paginated.** `list_jobs` in `api/routes/jobs.py`
  selects every row of `jobs`.
- **A requeue is not bounded.** `api/queue_loop.py` requeues a job whose lease
  expired. No counter of attempts exists, so a job that kills its worker is
  requeued again and again.
- **A log line says something false.** After a job reaches `for_review`,
  `api/worker.py` calls `backup_db()`, then logs "Database backup completed".
  `backup_db()` (`api/db.py`) only logs where the real backup tool is.

## Decision

The five decisions below are the maintainer's, dated 2026-11-08, and are not
reopened here. The design after them is **decided by this ADR**, as a
proposal, until the maintainer accepts the ADR.

**1. 1.0 is a shared service for one team,** instead of one analyst on a local
install. This replaces the audience decision of ADR-0094 (decision 0, last
sentence, and *Options rejected*, last item). The contract, the migrations,
the blockers, the measurement and the providers of ADR-0094 stay.

**2. One team, shared data.** Every user sees every report. Roles limit what a
user may do. Isolation between teams (an owner per report, filtered queries)
is after 1.0.

**3. Authentication: both OIDC and local accounts.** OIDC (the organisation's
single sign-on) is for production. Local accounts are for a deployment
without an identity provider.

**4. Outbound data to LLM providers: TLP:CLEAR and TLP:GREEN only.** From
TLP:AMBER up, processing is local (vLLM, Ollama, LM Studio) or refused
explicitly. This covers the text and the images sent to a vision model.

**5. Operations: one host** (Docker Compose), alerts wired to the existing
signals, scheduled off-host backups with a restore drill. No high
availability in 1.0.

### Roles (decided by this ADR)

Three roles, each containing the one before it:

- **`reader`**: reads reports, bundles and coverage.
- **`analyst`**: a reader who also imports, records review decisions,
  finalizes, exports, and deletes the imports they made.
- **`admin`**: an analyst who also deletes any report and manages settings,
  policy, thresholds, users and tokens.

Every route is checked on the server; the interface hiding a button is not a
control. `GET /api/health` stays open. The minimum role per route group (the
files of `api/routes/`):

| Route file | Reads | Writes |
|---|---|---|
| `attack.py` | reader | analyst |
| `baselines.py` | reader | analyst |
| `coverage.py` | reader | analyst (rule export: analyst) |
| `entities.py` | reader | analyst |
| `ingest.py` | | analyst |
| `jobs.py` | reader | analyst (finalize, export); delete: own import for an analyst, any for an admin |
| `overrides.py` | reader | analyst |
| `policy.py` | reader | admin |
| `progress.py` | reader | |
| `queue.py` | reader | |
| `relationships.py` | reader | analyst |
| `settings.py` | admin | admin |
| `thresholds.py` | reader | admin |
| `upload.py` | | analyst |

The table is the starting point. Work item 14 settles each operation of the
OpenAPI schema (60 on 2026-10-31) against it and fails a test for an operation
that has no minimum role. Where a file mixes reads and writes of different
weight, the stricter one applies to the write.

### Sessions and tokens (decided by this ADR)

- **Web interface.** The user signs in with the OIDC authorization-code flow
  with PKCE, or with a local account. The server keeps the session. The
  browser holds an `HttpOnly`, `Secure`, `SameSite=Strict` cookie. A CSRF token
  is required on every state-changing request, on top of the existing
  cross-site write guard.
- **API clients and the CLI.** Personal or service tokens, sent as a bearer.
  Stored hashed, revocable, with an expiry.
- **Roles from OIDC.** They come from the identity provider's groups, through
  a mapping the admin configures.
- **Local accounts.** Passwords are hashed with Argon2id. No self-registration.
  The first admin is created by a command (`python -m api.admin create-admin`,
  or similar), never by a default password.

### Network posture (decided by this ADR)

The API may listen beyond loopback only behind TLS (the existing nginx `proxy`
profile) and with authentication on. `API_ALLOWED_HOSTS` stays the Host check.
A deployment with authentication off stays possible only on loopback, for one
analyst (the 0.x behaviour), and the start log says so. A start with
authentication off and a non-loopback bind is refused.

### Egress policy (decided by this ADR)

A report's TLP decides which providers may receive its content:

| TLP of the report | Allowed providers |
|---|---|
| CLEAR, GREEN | any configured provider |
| AMBER, AMBER+STRICT, RED | local providers only: `vllm`, `ollama`, `lmstudio`, pointing at a non-public address the admin declares |
| none | treated as AMBER (fail closed) |

A forbidden combination is refused before any call, with the reason in the
stage report and in the interface. Stage 1f follows the same rule for the
images it sends; the rule applies to the provider that `VISION_PROVIDER=auto`
resolves to (ADR-0094 decision 14). The decision (the TLP read, the provider
allowed or refused) is recorded in the run's record. Embedding models and NER
models run in the process and send nothing out; they are not concerned.

### Audit (decided by this ADR)

Every state-changing action records the authenticated user: import, review
decision, finalize, export, delete, settings, policy, thresholds, user and
token changes, and sign-in failures. The records are JSON log lines on
standard output, which is enough for the organisation's log system to collect;
`docs/operations.md` documents the fields. The retention of what is kept in
the database is configurable.

### Monitoring and alerts (decided by this ADR)

- **`/metrics`**, in Prometheus format, reachable with an admin token or from
  loopback only. The signals: queue depth and wait, worker heartbeats, job
  failures, database reachability, free disk, and the last successful backup.
  Queue state, worker heartbeats and database reachability exist today
  (`/api/queue/status`, `worker_heartbeats`, `/api/health`). Free disk and
  the last backup are new, and so is a count of failed jobs as a metric (the
  job statuses are stored).
- **A Prometheus rules file** with alerts for: no live worker; queue wait above
  a threshold; repeated job failures; database down; disk nearly full; backup
  failed or too old. Each rule has a documented meaning and an operator
  procedure in `docs/operations.md`. Routing to people (Alertmanager, email,
  chat) is the operator's.

### Backups (decided by this ADR)

A `backup` service, in a Compose profile, runs the documented `pg_dump` and the
state archive on a schedule, to a mounted off-host target, keeps N copies, and
exposes its success or failure on `/metrics`. The operator sets the recovery
point objective (RPO) and the recovery time objective (RTO). The defaults the
documentation gives: a daily backup (RPO 24 h), and a restore whose duration
is the one the existing restore check measures (RTO = that duration). A
restore drill is part of the release qualification.

### Bounds (decided by this ADR)

- `GET /api/jobs` takes optional `limit` and `cursor`. A call without them
  keeps working.
- A job requeued after a lost lease more than `JOB_MAX_ATTEMPTS` times
  (default 3) is marked failed with the reason "quarantined after N attempts"
  instead of looping.
- An upload is refused when the free disk space is below a threshold.

### Fixed now, independent of the rest

The worker's "Database backup completed" line is removed (work item 21). The
call to `backup_db()` can go with it or stay as a pointer to the operator's
tool; the false success message goes either way.

### API contract (decided by this ADR)

Every operation gets an explicit response model, and the SSE event payloads
are described. The contract snapshot (ADR-0094 item 1) records them. On
2026-10-31 it recorded the response fields of 1 of the 60 operations (59
declare none, ADR-0094 item 1).

### Qualification additions (decided by this ADR)

- A load and failure recipe run on the candidate: a worker killed in the
  middle of a job, the LLM unavailable, the database down, the disk nearly
  full. Each case is checked for data integrity and for the alert it must
  raise.
- An end-to-end journey with a PDF import and a URL import, with the real
  models. ADR-0094 item 4 covers neither (it runs offline).

## Work items

They continue the table of ADR-0094 (items 1 to 13). None is started on
2026-11-08.

| # | Work | What it proves | State |
|---|---|---|---|
| 14 | Authentication and roles: OIDC and local accounts, the three roles, the permission table applied to every operation, `python -m api.admin create-admin`, the network posture (TLS and authentication off loopback, refused otherwise); a test that every operation has a minimum role and that a request without credentials gets 401 on all but health | a user is identified and limited by role | not started |
| 15 | Sessions and tokens: the server-side session and its cookie, the CSRF token, hashed revocable tokens with an expiry, the group-to-role mapping, Argon2id | the sign-in and the scripts' access are safe | not started |
| 16 | Egress policy: the TLP-to-provider rule in the text stages and in Stage 1f, a declared list of local addresses, the refusal and its reason, the decision in the run's record | AMBER and above never reach an external provider | not started |
| 17 | Audit: the authenticated user on every state-changing action, JSON log lines, retention, the documented fields | decisions are attributed | not started |
| 18 | Metrics and alert rules: `/metrics`, the Prometheus rules file, the procedure of each alert in `docs/operations.md` | an outage raises an alert | not started |
| 19 | Scheduled backups: the `backup` service, the schedule, the off-host target, N copies, the metric, the documented RPO and RTO | a backup exists and is known to | not started |
| 20 | Bounds: `GET /api/jobs` pagination, `JOB_MAX_ATTEMPTS`, the free-disk refusal of uploads | a list, a loop and a full disk do not take the service down | not started |
| 21 | The false backup log: remove "Database backup completed" from `api/worker.py` | the log says what happened | not started |
| 22 | Response models for every operation and the SSE payloads, recorded by the contract snapshot | the stable contract covers the responses | not started |
| 23 | Load and failure recipe on the candidate, each case checked for integrity and for its alert, and the restore drill | the service survives its failures | not started |
| 24 | End-to-end journey with a PDF and a URL import and the real models | the journey works with the models | not started |

**Order.** Items 21 and 16 first: they protect the single-analyst use too, and
item 21 is a few lines. Then 14 and 15, 17 and 20: the access layer, its audit
and its bounds. Then 18 and 19: the operations. Then 22, 23 and 24: the
contract and the qualification, which run on the finished candidate. Item 15
follows 14 because the session needs the roles. Item 17 follows 14 because the
audit needs a user. Item 23 needs 18 and 19, because it checks the alerts and
the restore. No date is promised.

## Consequences

- **A breaking API change.** Every route except `GET /api/health` needs
  authentication. Before 1.0 this is a minor version under ADR-0085 decision 8.
  The upgrade notes say: create the first admin, configure OIDC or local
  accounts, issue tokens for scripts.
- **1.0 is later.** The work items above join the thirteen of ADR-0094 as what
  gates the tag. Items 14 to 24 are new work, none started.
- **The single-analyst loopback mode stays,** with authentication off, and is
  unsupported for sharing. The start log says so.
- **ADR-0036 (Proposed).** It diagnosed the architecture and listed
  authentication and ownership as its Phase 4. This ADR decides the access and
  operations layer for one team. It does not rewrite the code, add a broker or
  use Kubernetes. Phase 4's per-user ownership (items 10, 12, 13 of ADR-0036)
  is team isolation, and stays after 1.0.
- **ADR-0048's rejection of `/metrics` is reversed** for the reason in
  *Context*. The status endpoint stays.
- **ADR-0094 is amended,** not rewritten: its action plan continues here, and
  `docs/support-policy.md` and `ROADMAP.md` point to this ADR.
- **Outbound data is limited.** A deployment with only an external provider
  can no longer process an AMBER, RED or unmarked report. It gets a refusal
  with a reason, not a silent send.
- **The default provider.** `anthropic` stays the default (ADR-0094 decision
  13). A report without a TLP marking is treated as AMBER, so on an install
  with only `anthropic` configured, an unmarked report is refused until its
  TLP is set.
- **More to run.** A host runs a reverse proxy, an identity provider or local
  accounts, a scraper and a backup target. One maintainer keeps the code; the
  operator keeps those.
- **What this ADR does not change today:** the code, the routes, the release
  workflow.

## Not covered

- **Isolation between teams:** an owner per report, filtered queries, the
  segregation of `uploads/` and `output/`, per-tenant policy and keys
  (ADR-0036 items 10, 12, 13). After 1.0.
- **High availability:** one host, one database, no failover.
- **Object storage** for uploads, outputs and backups.
- **An OpenCTI connector with retries.** Bundles are still imported by the
  analyst's tool.
- **SAML.** OIDC only.
