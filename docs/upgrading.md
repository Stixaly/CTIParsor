# Upgrading to the container, PostgreSQL and worker layout

Runbook for an install that predates ADR-0044/0045/0046/0053/0054 (September
2026). Each section says what changes for you, what you must do, and how to
go back — except §2, which as of ADR-0053 has no way back: CTIParsor no
longer supports SQLite at all, for either store.

**Docker is now the only supported destination (ADR-0054).** If you're on a
host (venv) install, §2's real destination is "move to the container stack"
(§4) — §2/§3 exist only to get an old host install's data safely onto
PostgreSQL first (they need a real `pip`/`python`, which the container image
already has baked in and a bare host may not), not to describe an
end-state anyone should stay on. `setup.sh` itself no longer creates a venv
at all, so §2/§3's commands assume one you set up yourself, on an older
checkout.

## Who this applies to

| You run… | Required action | Optional |
|---|---|---|
| a host install (`setup.sh`, `python run_api.py`) on the pre-ADR-0053 single-file layout | move both stores to PostgreSQL (§2), then move to the container stack (§4) — Docker is the only supported end state (ADR-0054) | — |
| the first compose stack (ADR-0044, before PostgreSQL) | add `CTI_DB_PASSWORD`, rebuild, migrate the reports and rules already in `cti_stix.db` (§4) | scale workers (§5) |
| the container stack on PostgreSQL 17 (volume `pg-data`, before 2026-10-04) | move the database to PostgreSQL 18 **before** `docker compose up` (§7) | — |
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

## 2. Host install: both stores to PostgreSQL (mandatory since ADR-0053)

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

3. Install the driver and copy the existing rows, dry run first — **both**
   scripts, they cover different tables:

   ```bash
   .venv/bin/pip install -r requirements.txt
   .venv/bin/python scripts/migrate_jobs_to_postgres.py --dry-run
   .venv/bin/python scripts/migrate_jobs_to_postgres.py
   .venv/bin/python scripts/migrate_rules_to_postgres.py --dry-run
   .venv/bin/python scripts/migrate_rules_to_postgres.py
   ```

   Each script copies its table set in one transaction, refuses a target
   that already holds rows unless you pass `--append`, and never modifies
   `cti_stix.db`. `migrate_jobs_to_postgres.py` additionally keeps every
   `progress_events` id (the SSE resume point) and realigns the sequence.

4. Start the API (`python run_api.py`) — it now refuses to start if
   `DATABASE_URL` is unset, with a message pointing back here.

**No rollback.** Unlike the pre-ADR-0053 state (where DATABASE_URL was
optional and PostgreSQL covered only the job store), CTIParsor has no SQLite
code path left to fall back to — `cti_stix.db` is read-only source material
for the two migration scripts above, nothing more. Keep it until you have
verified the PostgreSQL copy, then archive or delete it; there is no reverse
script, so `pg_dump` before making any further changes if you need a
point-in-time copy.

## 3. Host install: the pipeline as its own service (legacy)

**Prefer moving to the container stack instead (§4)** — it already ships a
`worker` service with this exact split built in (ADR-0046), scaled with
`docker compose up -d --scale worker=2` (§5), no systemd units to hand-write.
This section is kept only for a host install that has a specific reason to
stay off Docker a little longer; it is not a supported end state (ADR-0054).

Requires §2 (now unconditionally true — every host install is on PostgreSQL):
splitting the API and a worker across processes needs a datastore they can
both reach concurrently, which a local SQLite file never safely gave them.

```ini
# ctiparsor-api.service      →  Environment=CTIPARSOR_ROLE=api
# ctiparsor-worker.service   →  Environment=CTIPARSOR_ROLE=worker
#                               ExecStart=/opt/ctiparsor/.venv/bin/python -m api.queue_loop
```

Both units need the same `.env` (so the same `DATABASE_URL`) and the same
`uploads/` and `output/` directories. Run as many worker units as the
machine's memory allows: 4.4 GB per report in flight.

**Rollback:** set the API back to `CTIPARSOR_ROLE=all` (or unset it) and stop
the worker units. A report a stopped worker was running is requeued after
`WORKER_LEASE_TIMEOUT_S` and resumes from its checkpoint.

## 4. Container stack: from the ADR-0044 layout

Your reports and detection rules are both in `cti_stix.db` on the `cti-state`
volume; the new stack puts everything in PostgreSQL and no longer reads that
file at runtime (ADR-0053).

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

3. Copy the reports and rules you already had — **both** scripts:

   ```bash
   docker compose run --rm app python scripts/migrate_jobs_to_postgres.py --sqlite /app/state/cti_stix.db --dry-run
   docker compose run --rm app python scripts/migrate_jobs_to_postgres.py --sqlite /app/state/cti_stix.db
   docker compose run --rm app python scripts/migrate_rules_to_postgres.py --sqlite /app/state/cti_stix.db --dry-run
   docker compose run --rm app python scripts/migrate_rules_to_postgres.py --sqlite /app/state/cti_stix.db
   ```

   Expected: a table of source, inserted and target counts per table, then
   `[migrate] committed`. The job list in the UI shows the migrated reports;
   Settings → Detection Corpora shows the migrated rule counts.

4. Verify:

   ```bash
   bash scripts/docker_smoke.sh --no-build          # add --job for an end-to-end report
   ```

   Every line should read `PASS` except the known `WARN` on `re2`.

**Rollback:** `docker compose down`, check out the previous revision, `docker
compose up -d`. The old stack reads `cti_stix.db` as before, whose reports
and rules are intact (the migrations only read it); anything created on the
new stack stays in the `pg-data` volume until you restore it forward again.

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
- `backup_db()` no longer copies a file — both stores are PostgreSQL now
  (ADR-0053), so it just logs a reminder to `pg_dump`, which is the command
  in [docs/docker.md](docker.md#data-and-backups).
- The optional `re2` guard is absent from every current install; it is a
  pre-existing packaging problem, tracked separately.
- The bundle's recorded git revision comes from the image build argument in
  containers (`make docker-build` sets it).

## 7. Container stack: a new PostgreSQL major (`make db-upgrade`)

Every PostgreSQL major upgrade goes the same way since ADR-0077 part B:

```bash
git pull                                  # compose.yaml names the new major
docker compose stop app worker            # nothing writes during the move
make db-upgrade                           # dump, new cluster, restore, row counts
docker compose up -d                      # the app's start applies the schema history
```

`make db-upgrade` (`scripts/db_upgrade.sh`) finds the cluster to move: another
major's `/var/lib/postgresql/<major>/docker` in the stack's volume, or the old
17 volume `pg-data`. It stops whatever runs on it, then dumps it with a
throwaway server of its own major into `./backups/`. It then creates the new
major's cluster and restores into it, and stops if any table's row count
differs. The old cluster is never changed or deleted. Two things stop you
from starting on an empty database by mistake:

- **The image itself refuses.** PostgreSQL 18 on will not initialise beside
  another major's cluster in the same volume. Its log says "there appears to
  be PostgreSQL data in …": run `make db-upgrade`.
- **The app refuses.** Its state volume remembers which cluster the database
  was on (`db-identity.json`). An empty database on a new cluster where data
  had been migrated stops the start with `ClusterChanged`; this is the case
  where the data sits on another volume. If an empty database is really what
  you want, delete the entry the message names.

A major `db_upgrade.sh` has no pinned image for needs
`SOURCE_IMAGE=postgres:<major>-alpine@sha256:<digest>`. To check the procedure
itself: `scripts/check_db_upgrade.sh` (throwaway projects, nothing of yours).

### PostgreSQL 17 → 18 (ADR-0076)

**What changes.** The `postgres` service runs `postgres:18-alpine` on a new
volume, `pg-data-18`, mounted at `/var/lib/postgresql`. PostgreSQL 18's image
keeps its cluster in `/var/lib/postgresql/18/docker` and refuses to start with
a mount at the old `/var/lib/postgresql/data` path; and a 17 data directory
cannot be opened by 18 in any case. The old volume, `pg-data`, is no longer
declared by compose: it is not used, and `docker compose down -v` does not
delete it.

**What you must do,** after pulling, **before** `docker compose up`:

```bash
git pull
docker compose stop app worker            # nothing writes during the move
make db-upgrade                           # was scripts/upgrade_postgres_17_to_18.sh, which still works
docker compose up -d                      # or make docker-up
```

The script first stops the stack's own PostgreSQL 17 if it still runs on
`pg-data`, and refuses to go on while any other container uses that volume:
two servers on one data directory corrupt it, and inside containers
PostgreSQL's lock file does not stop the second. It then starts a throwaway PostgreSQL 17 on `pg-data`, dumps the database
with `pg_dump -Fc` into `./backups/` (kept, gitignored), creates the 18
cluster on `pg-data-18`, restores, and compares the row count of every table
between the two; it stops on any difference. Keep `CTI_DB_PASSWORD` as it
was: the 17 cluster must accept it. It refuses to restore into an 18 database
that already has tables (the app started on it first): rerun with `FORCE=1`
to replace them with the dump.

If you ran `docker compose up` first, the app is on an **empty** 18 database
and your reports are still in `pg-data`: stop app and worker, run the script
with `FORCE=1`, start again.

**How to go back.** Check out the previous commit: compose mounts `pg-data`
on `postgres:17-alpine` again, as it was at the move — what the app wrote on
18 since is not in it. Delete `pg-data` yourself
(`docker volume rm ctiparsor_pg-data`) once the app shows your reports on 18.

**A host database** (`DATABASE_URL` outside compose) is yours to upgrade with
PostgreSQL's own tools (`pg_upgrade`, or `pg_dump` / `pg_restore`); the
application runs on 17 and 18 alike (CI tests 18).

## Escalation

If a step fails, collect `docker compose logs app worker postgres` (or the
systemd journals on a host install), the output of the migration script, and
the smoke test lines, and open an issue referencing the ADR number the step
belongs to.
