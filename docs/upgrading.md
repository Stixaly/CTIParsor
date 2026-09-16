# Upgrading to the container, PostgreSQL and worker layout

Runbook for an install that predates ADR-0044/0045/0046 (September 2026).
Each section says what changes for you, what you must do, and how to go back.

## Who this applies to

| You run… | Required action | Optional |
|---|---|---|
| a host install (`setup.sh`, `python run_api.py`) | **none** — `CTIPARSOR_ROLE` defaults to `all` and the job store stays in `cti_stix.db` | move the job store to PostgreSQL (§2); run the pipeline as a separate service (§3) |
| the first compose stack (ADR-0044, before PostgreSQL) | add `CTI_DB_PASSWORD`, rebuild, migrate the reports already in `cti_stix.db` (§4) | scale workers (§5) |
| nothing yet | follow the quick start in [docs/docker.md](docker.md) | — |

Prerequisites for the container sections: Docker Engine 24+, Compose v2.24+,
`.env` from `.env.example`, and a backup of what you have (§1).

## 1. Back up first

Host install:

```bash
cp cti_stix.db cti_stix.db.bak            # with the API stopped
```

Container stack from ADR-0044 (one volume, no database service yet):

```bash
docker compose down
docker run --rm -v ctiparsor_cti-state:/s -v "$PWD":/b alpine tar czf /b/cti-state-$(date +%F).tgz -C /s .
```

## 2. Host install: job store to PostgreSQL (optional)

1. Create a database and a role on your PostgreSQL server, `scram-sha-256`
   authentication. The schema needs `GENERATED … AS IDENTITY` (PostgreSQL 10+)
   and nothing newer; only PostgreSQL 17 has actually been tested (the
   version the compose stack runs), so treat an older server as unverified
   rather than unsupported.
2. In `.env`:

   ```dotenv
   DATABASE_URL=postgresql://ctiparsor@db.example.internal:5432/ctiparsor
   PGPASSWORD=...
   ```

3. Install the driver and copy the existing rows, dry run first:

   ```bash
   .venv/bin/pip install -r requirements-api.txt
   .venv/bin/python scripts/migrate_jobs_to_postgres.py --dry-run
   .venv/bin/python scripts/migrate_jobs_to_postgres.py
   ```

   The script copies the eight per-report tables in one transaction, keeps
   every id (the SSE resume point included), realigns the sequence, and
   refuses a target that already holds jobs unless you pass `--append`.
   It never modifies `cti_stix.db`.

4. Start the API. The rule corpus keeps living in `cti_stix.db`.

**Rollback:** remove the two variables. The SQLite file still holds every
report as of the migration; reports processed on PostgreSQL in between are
not copied back (there is no reverse script — `pg_dump` them first if it
matters).

## 3. Host install: the pipeline as its own service (optional)

Requires §2: with SQLite, the API and a worker would have to share one file
on one host, which works but gains little.

```ini
# ctiparsor-api.service      →  Environment=CTIPARSOR_ROLE=api
# ctiparsor-worker.service   →  Environment=CTIPARSOR_ROLE=worker
#                               ExecStart=/opt/ctiparsor/.venv/bin/python -m api.queue_loop
```

Both units need the same `.env`, the same `uploads/` and `output/`
directories, and the same `cti_stix.db` (rule store). Run as many worker
units as the machine's memory allows: 4.4 GB per report in flight.

**Rollback:** set the API back to `CTIPARSOR_ROLE=all` (or unset it) and stop
the worker units. A report a stopped worker was running is requeued after
`WORKER_LEASE_TIMEOUT_S` and resumes from its checkpoint.

## 4. Container stack: from the ADR-0044 layout

Your reports are in `cti_stix.db` on the `cti-state` volume; the new stack
keeps that file for the rule corpus and puts reports in PostgreSQL.

1. Password:

   ```bash
   echo "CTI_DB_PASSWORD=$(openssl rand -hex 24)" >> .env
   ```

2. Rebuild and start. The `postgres` and `worker` services are created; the
   app's schema migrations run at start.

   ```bash
   docker compose build
   docker compose up -d
   ```

3. Copy the reports you already had:

   ```bash
   docker compose run --rm app python scripts/migrate_jobs_to_postgres.py --sqlite /app/state/cti_stix.db --dry-run
   docker compose run --rm app python scripts/migrate_jobs_to_postgres.py --sqlite /app/state/cti_stix.db
   ```

   Expected: a table of source, inserted and target counts per table, then
   `[migrate] committed`. The job list in the UI shows the migrated reports.

4. Verify:

   ```bash
   bash scripts/docker_smoke.sh --no-build          # add --job for an end-to-end report
   ```

   Every line should read `PASS` except the known `WARN` on `re2`.

**Rollback:** `docker compose down`, check out the previous revision, `docker
compose up -d`. The old stack reads `cti_stix.db` as before, whose reports
are intact (the migration only reads it); reports created on the new stack
stay in the `pg-data` volume until you restore it forward again.

## 5. Container stack: scaling and sizing

```bash
docker compose up -d --scale worker=2
```

Each worker takes the limits in `compose.yaml` (4 CPUs, 6 GB for one report
in flight). Raise `CTI_WORKER_MEMORY` by 4.4 GB for each extra
`WORKER_MAX_CONCURRENT`, and set `CTI_APP_MEMORY` to at least 3 GB if you
rebuild the corpus from the Settings page. The sizing table is in
[docs/architecture.md §6](architecture.md#6-sizing).

## 6. Things that changed and might surprise you

- `WORKER_MAX_CONCURRENT` now means *per worker container*, not per stack.
- `requeue at startup` only happens in role `all`. A container API never
  requeues; a job stuck in `processing` is requeued by a worker once its
  lease expires (180 s by default).
- `backup_db()` copies the SQLite file only. With PostgreSQL, `pg_dump` the
  job store as well; both commands are in [docs/docker.md](docker.md#data-and-backups).
- The optional `re2` guard is absent from every current install; it is a
  pre-existing packaging problem, tracked separately.
- The bundle's recorded git revision comes from the image build argument in
  containers (`make docker-build` sets it).

## Escalation

If a step fails, collect `docker compose logs app worker postgres` (or the
systemd journals on a host install), the output of the migration script, and
the smoke test lines, and open an issue referencing the ADR number the step
belongs to.
