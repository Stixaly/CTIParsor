# Upgrading CTIParsor

An install made from a release, as the [README's quick start](../README.md#quick-start)
makes it, moves to the next release as [the first section](#from-one-release-to-the-next)
shows. The sections after it are a runbook for an install that predates
ADR-0044/0045/0046/0053/0054 (September 2026).

## From one release to the next

Read the new release's notes first: its section of the
[CHANGELOG](../CHANGELOG.md) says what changed, and the notes give the digest
of its image.

1. **Back up**, in the directory of the installed release (`ctiparsor-0.1.0`
   below), with the commands of [docker.md, Data and
   backups](docker.md#data-and-backups), then check the backup as that section
   shows. The backup is the way back: the new release migrates the database at
   its first start, and the old one then refuses to start on it.
2. **Install the new release beside the old one and start it**, from the
   directory that holds `ctiparsor-0.1.0`. The first line names the release
   you have and the one you install, with its digest; the example moves 0.1.0
   to 0.2.0. An install made from a clone (the README's until 0.2.0) has no
   such directory: rename the clone first, for one at v0.2.0 `mv CTIParsor
   ctiparsor-0.2.0`, and work from its parent. `compose.yaml` names the Compose
   project `ctiparsor` whatever the directory is called, so the containers and
   volumes stay the same.

<!-- scripts/check_clean_install.sh: UPGRADE_COMMANDS -->
```bash
old=0.1.0 new=0.2.0 digest=sha256:f7ea0d3f9d44692b8b08ed31dae5b1738ab19a88bc1cce856d7a297320c95526
curl -fsSLO https://github.com/Stixaly/CTIParsor/releases/download/v$new/ctiparsor-$new.tar.gz
curl -fsSLO https://github.com/Stixaly/CTIParsor/releases/download/v$new/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
tar xzf ctiparsor-$new.tar.gz
cp ctiparsor-$old/.env ctiparsor-$new/
cd ctiparsor-$new
bash setup.sh
sed -i '/^CTI_IMAGE=/d' .env
echo "CTI_IMAGE=ghcr.io/stixaly/ctiparsor@$digest" >> .env
docker compose pull
docker compose up -d
docker compose --profile bootstrap run --rm bootstrap
```

`cp` brings your settings and the database password; `setup.sh` keeps
them and writes `.secrets/db_password` in the new directory. It copies `.env`
only: a `compose.override.yaml` of yours, and the proxy profile's
`docker/nginx/certs/` and `docker/nginx/htpasswd` (`compose.yaml` mounts both
from the release's directory), stay in the old one. If you have them, copy
them into `ctiparsor-$new` before `docker compose pull` (the directory exists
once `tar` has run), or afterwards and run `docker compose up -d` again
(`--profile proxy up -d` for the proxy). A setting the
new release adds takes its default: `diff ctiparsor-$old/.env.example
ctiparsor-$new/.env.example` lists them. Both directories are the same
Compose project, `ctiparsor` (the `name:` of `compose.yaml`), so `up -d`
from the new one replaces the containers and keeps the volumes, every
report with them. The first process to start on the new image applies the
new schema versions, under a lock the others wait for: `app`, `worker`, or
the `bootstrap` that follows them, whose output then shows `[db] schema
version 13 -> 14` (from 0.2.0) while `docker compose logs app worker` shows
`schema at version 14, nothing to migrate`. `bootstrap` runs after every
upgrade: it keeps the models already downloaded, fetches any the new
release adds, updates the detection corpora and rebuilds the rule store
(about 5 minutes on the clean install of [TESTING.md](../TESTING.md#clean-install-from-the-published-image),
most of it the rule store).

3. **Check**: `curl -fsS http://127.0.0.1:8000/api/health` (your `CTI_BIND`
   and `CTI_PORT`) answers `{"status":"ok"}`, and the web UI lists your
   reports, each bundle as you exported it. Keep the old directory and the
   backup until then.

**Going back.** There is no downgrade: the old release refuses a database the
new one migrated. Restore the backup taken at step 1 instead, from the old
directory, as [docker.md](docker.md#data-and-backups) shows ("Make the
restore the live install"); what the new release wrote since is not in it.

**From source**, the same steps with a clone instead of the archive: the
backup, then `git fetch --tags && git checkout v$new` (a release tag, not
`git pull` of `main`), `bash setup.sh`, `docker compose build`, `docker
compose up -d` and `bootstrap`.

---

The rest of this page is the runbook for an install that predates ADR-0044/0045/0046/0053/0054 (September
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
| a release, 0.1.0 or later | [from one release to the next](#from-one-release-to-the-next) | — |
| nothing yet | follow the [README's quick start](../README.md#quick-start) | — |

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

Container stack on PostgreSQL (every install since ADR-0045): the backup of
[docker.md, Data and backups](docker.md#data-and-backups), the database dump
and the `cti-state` archive taken together with `app` and `worker` stopped,
then checked as that section shows. The dump alone leaves out the uploaded
sources and the exported bundles.

## 2. Host install: both stores to PostgreSQL (mandatory since ADR-0053)

1. Create a database and a role on your PostgreSQL server, `scram-sha-256`
   authentication. The schema needs `GENERATED … AS IDENTITY` (PostgreSQL 10+)
   and nothing newer; only PostgreSQL 17 and 18 have actually been tested
   (the compose stack runs 18, CI tests 18), so treat an older server as
   unverified rather than unsupported.
2. In `.env`:

   ```dotenv
   DATABASE_URL=postgresql://ctiparsor@db.example.internal:5432/ctiparsor
   PGPASSWORD=...
   ```

3. Install the driver and copy the existing rows, dry run first — **both**
   scripts, they cover different tables:

   ```bash
   .venv/bin/pip install -r requirements/requirements.txt
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
- `WORKER_MAX_CONCURRENT` defaults to 1 in the code, as in `compose.yaml`; it
  was 10. A process that runs reports with the variable unset now runs one at a
  time and queues the rest: `python run_api.py`, `python -m api.queue_loop`, the
  image started without compose. Set the variable to run more
  ([deployment.md §5](deployment.md#5-workers-and-memory)).
- `requeue at startup` only happens in role `all`. A container API never
  requeues; a job stuck in `processing` is requeued by a worker once its
  lease expires (180 s by default).
- `backup_db()` no longer copies a file — both stores are PostgreSQL now
  (ADR-0053), so it just logs a reminder to `pg_dump`. A backup is that dump
  and an archive of `cti-state`, taken together
  ([docs/docker.md](docker.md#data-and-backups)).
- The optional `re2` guard is absent from every current install; it is a
  pre-existing packaging problem, tracked separately.
- The bundle's recorded git revision comes from the image build argument in
  containers (`make docker-build` sets it).
- Schema versions 12 (ADR-0086, bundle builds) and 13 (ADR-0090, STIX baselines)
  are new since v0.1.0. They apply at the first start of this code, by the API
  or by a worker, whichever starts first, with no action on your part. An older
  image then refuses the database ("an older image was started after a newer one
  migrated it", `api/migrate.py`). To go back, restore the backup taken before
  that start ([§1](#1-back-up-first)).
- STIX enrichment (ADR-0090) is on by default. `STIX_ENRICHMENT_ENABLED=false`
  turns it off, and the body budget of `POST /api/upload` then drops by the
  20 MB a baseline may weigh, to 50 MB plus the 64 KB form. The 50 MB limit on
  the report itself does not change.
- The ATT&CK 20.0 track ships in the image (`pipeline/data/attack/20.0/`), so
  `ATTACK_RELEASE=20.0` needs no download. The default stays 19.2 (ADR-0087;
  [configuration.md](configuration.md#attck-release)).

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
