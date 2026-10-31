# Running CTIParsor in containers

This guide covers installing, developing and deploying CTIParsor using
Docker Compose — the only supported way to do any of the three (ADR-0054).
`setup.sh` only prepares the environment (`.env`, secrets, a Docker check);
everything here happens through `docker compose`. Air-gapped installs are
also Docker-based now (ADR-0054 redesigned ADR-0040's bundle around
`docker save`/`load` — see the [README's offline section](../README.md#offline-air-gapped-installation)
and `scripts/package_offline_docker.sh`). See ADR-0044 for the architectural
decisions behind the containerization itself.

## What you get

- **Image**: `ctiparsor:local` (4.61 GB). Contains the React UI, Python 3.14 venv (torch CPU), and Chromium (optional).
- **Volumes** (Compose prefixes them with the project name, so `docker volume ls` shows `ctiparsor_cti-state` and so on):
  - `cti-state`: uploaded sources, exported bundles, `db-identity.json`, the private corpus overlay — back it up together with the database ([Data and backups](#data-and-backups)). No database file lives here any more (ADR-0053).
  - `pg-data-18`: the PostgreSQL 18 job store AND rule store (jobs, entities, relationships, progress, policy, figure and CVE caches, plus the detection-rule corpus since ADR-0053) — back it up together with `cti-state` ([Data and backups](#data-and-backups)).
  - `cti-cache`: HuggingFace models, Sigma/YARA/Suricata corpora — rebuildable with `bootstrap`.
  - `ollama-models`: (Only if using the `ollama` profile).
- **Services**: `app`, `worker`, `postgres` and `capture-proxy` always run. `app` only accepts and queues reports (`CTIPARSOR_ROLE=api`) and never loads a model; `worker` claims queued reports from the job store and runs each in an isolated subprocess, heartbeating the rows it owns so several workers can share the queue (ADR-0046) — scale it with `docker compose up -d --scale worker=2`; `postgres` is both stores (ADR-0045, ADR-0053: PostgreSQL 17, on the internal network only, running as the image's `postgres` user with every capability dropped and a read-only root; `CTI_DB_PASSWORD` in `.env` is required). `capture-proxy` is a Squid egress filter the URL-capture tab's Chromium goes through, so it can reach public addresses only (see *Security model*). Three optional profiles:
  - `bootstrap`: one-shot initialisation (models, corpora, rule store), same image and hardening as `app`.
  - `ollama`: a local LLM with no published port, reachable by `app` at `http://ollama:11434`.
  - `proxy`: TLS + password (`nginx-unprivileged`) in front of `app`; the only thing worth publishing on a network.
- **Not in the image**: the models (2.6 GB) and corpora (0.7 GB) are downloaded once into `cti-cache` by `bootstrap`, so a code change rebuilds in minutes. `docs/` and `tests/` are left out too.

Known limits: no GPU (torch is the CPU build); `git` has no repository inside the container, so bundle-staleness checks (ADR-0035) answer "undecidable" and the revision recorded in each bundle comes from the `GIT_REV` build argument (`make docker-build` sets it, a bare `docker compose build` records nothing). Docker Desktop on Windows and docker-ce inside WSL2 both work; the repository may live on the Windows drive, the named volumes live in the Linux VM.

```text
analyst ──https──> [proxy 8443] ──> [app :8000, role api] ──┐
analyst ──http (loopback)────────>        │                 │
                                          │ queue (jobs)    │ progress, review, export
                                          v                 │
                                   [postgres, job store] <──┤
                                          ^                 │
[worker x N, role worker] ── claim/heartbeat               │
      │  pipeline subprocess (models)                       │
      ├── uploads/output on cti-state <─────────────────────┘
      ├── models/corpora on cti-cache
      └── LLM: [ollama :11434] (profile) or a provider API
```

The full map with data flow and the reasoning is in [docs/architecture.md](architecture.md); moving an existing install here is [docs/upgrading.md](upgrading.md).

## Prerequisites

- Docker Engine 24+ with BuildKit (default).
- Docker Compose v2.24+ (`docker compose version`).
- Disk space: ~5 GB for the image, ~3.5 GB for volumes after bootstrap.
- RAM and CPU: every container declares a limit and a reservation in `compose.yaml`; the defaults below are measured for one report at a time and add up to about 10 GB and 8 CPUs for the always-on services. Override any of them in `.env` (`CTI_<SERVICE>_CPUS`, `CTI_<SERVICE>_MEMORY`).

| Service | CPUs | Memory limit | Reserved | Why |
|---|---|---|---|---|
| `app` | 2 | 3 GB | 512 MB | 130 MB idle; a Settings-page corpus rebuild parses 87 k rules in-process and peaked at 2.2 GB |
| `worker` | 4 | 6 GB | 4 GB | 4.4 GB per running report (ADR-0037) plus the supervisor; raise by 4.4 GB per extra `WORKER_MAX_CONCURRENT` |
| `postgres` | 1 | 512 MB | 128 MB | the job store is a few MB per report |
| `proxy` | 0.5 | 128 MB | — | nginx |
| `bootstrap` | 2 | 4 GB | — | model downloads and the same rule parse |
| `ollama` | 8 | 12 GB | — | a 7B model in Q4 on CPU; a 27B one needs ~18 GB and a GPU |

When the worker hits its limit the kernel's OOM killer takes the largest process in the container, the pipeline subprocess, and the report is marked `failed`; the supervisor and the API are unaffected.

## Pulling a pre-built image (ADR-0047)

Every push to `main` publishes the image to GHCR — skip the local build:

```dotenv
# .env
CTI_IMAGE=ghcr.io/stixaly/ctiparsor:latest
```
```bash
docker compose pull app worker bootstrap
docker compose up -d
```

`docker compose up` only builds a service when its image tag is not already
present locally — a prior `pull` is what makes it skip the build (verified
against this repo's own `compose.yaml`: a pre-existing tag went straight to
starting containers, no build step, in the log). `latest` tracks current
`main` and can change under you; pin `CTI_IMAGE` to an immutable `sha-<full
sha>` tag instead for anything you don't rebuild on every deploy — the same
tags list at `github.com/Stixaly/CTIParsor/pkgs/container/ctiparsor`.

Since the first release, 0.1.0 on 2026-10-17, `ghcr.io/stixaly/ctiparsor:X.Y.Z`
names a released image: the same digest as the `sha-` tag of the release's
commit, with nothing rebuilt (ADR-0085). `X.Y` is set too and follows the highest
patch release of that line. A registry tag name can be pushed again and a digest
cannot change, so the Release notes give the digest; see
[releasing.md](releasing.md).

```dotenv
# .env
CTI_IMAGE=ghcr.io/stixaly/ctiparsor:0.2.0
```

0.2.0, the latest release, is the image of commit ce59cfb, digest
`sha256:f7ea0d3f9d44692b8b08ed31dae5b1738ab19a88bc1cce856d7a297320c95526`; on
2026-10-30 the names `0.2.0`, `0.2` and `sha-ce59cfb7025daf46fcb661b71c1ac7cd23f3f16b`
all pointed to it. 0.1.0 is the image of commit 4bdfa8f, digest
`sha256:80aca36a7cf3fbf9319ee828f8d4811bf90e56d94120a99776ba8df4cc71a773`; on
2026-10-24 the names `0.1.0`, `0.1` and `sha-4bdfa8f9b2b3916486b87019a40148d5d15d9239`
all pointed to it. Moving from 0.1.0 migrates the database; back it up first
([upgrading.md](upgrading.md#1-back-up-first)).

To check that a pulled image was built by this repository's CI, run the
`gh attestation verify` commands in [Verifying a release](releasing.md#verifying-a-release).

**One manual step, once:** a new GHCR package is private by default
regardless of the repository's visibility. After the first push, a
maintainer sets it to the visibility you want in the package's own GitHub
settings (Package settings → Change visibility) — nothing in the workflow
does this for you.

## Quick start

```bash
bash setup.sh                   # writes .env + secrets, checks Docker — builds/starts nothing
nano .env                       # set your LLM provider / key
docker compose build            # or: make docker-build (stamps the git revision)
docker compose up -d            # http://127.0.0.1:8000
docker compose --profile bootstrap run --rm bootstrap   # once, 10-20 min: models, corpora, rule store
docker compose logs -f app
```

`docker compose up -d` only starts `app`, `worker` and `postgres` — starting
it does not by itself fetch or index the detection-rule corpora, which live
in the same PostgreSQL database as the job store now (ADR-0045, ADR-0053).
Skip the `bootstrap` line above and Settings → Detection Corpora will show 0
rules for every corpus. Bootstrap clones and indexes every corpus in one
process; syncing corpora individually from Settings → Redownload instead
works too, but only **one at a time** — each sync rebuilds the whole store
(`replace_corpus_rules` per corpus, then a global dedup pass), and two
overlapping ones contend for the same rows.

`bootstrap` takes `--no-models` (skip the model downloads), `--no-corpora` (skip
the corpus clone and the rule store) and `--strict`. With `--strict` it exits 1
when a model does not download, when the models do not load from the cache with
the network off (`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`), or when a corpus
does not sync. The air-gap packager runs it with `--strict`
([offline section of the README](../README.md#offline-air-gapped-installation)).

## Development

Two `profiles: [dev]` services replace the old venv-based dev loop (ADR-0054)
— neither starts with a plain `docker compose up -d`:

```bash
docker compose run --rm dev pytest -v                   # or: make test (make ci: every CI check)
docker compose run --rm dev cli input/report.pdf        # CLI, same as make run-dir
docker compose --profile dev up frontend-dev             # Vite HMR -> http://localhost:5173
```

`dev` is the Dockerfile's `dev` stage — the `app`/`worker` image plus the
lint, type-check and coverage tools CI uses (`requirements/requirements-dev.txt`) —
`read_only: false`, with the repo bind-mounted live over `/app`: edits on the
host need no rebuild, a dependency change does (`docker compose --profile dev
build dev`).  The stage is never shipped: a build without `--target` stops at
`runtime`.  An air-gapped install has the `app` image but not this one, so its
first `make test` needs the network once to build it.
`tests/` ships in this bind mount, not in the built image (`.dockerignore`
excludes it from `app`/`worker` on purpose). Bind-mounting `.` over `/app`
also replaces the image's `uploads`/`output`/`corpora` symlinks with this
repo's own directories, so `docker compose run --rm dev cli` reads/writes
those host paths directly. `frontend-dev` bind-mounts `frontend/` into a
plain `node:26-bookworm-slim` container and proxies `/api` to the `app`
service (`VITE_API_PROXY_TARGET=http://app:8000`, set in `compose.yaml`).
Its `node_modules` is a named volume (`frontend-node-modules`), so the
container's root-run `npm ci` never writes into the checkout's
`frontend/node_modules`.  `make frontend-check` runs the frontend's lint,
type check and tests there.

## Configuration

Configuration is managed via the `.env` file (passed to the container via `env_file`).

### Compose Interpolation Variables

| Variable | Default | Role |
|---|---|---|
| `CTI_IMAGE` | `ctiparsor:local` | Image name:tag |
| `CTI_GIT_REV` | empty | Build-arg `GIT_REV` |
| `CTI_INSTALL_CAPTURE` | `true` | Build-arg `INSTALL_CAPTURE` (Chromium) |
| `CTI_ENV_FILE` | `.env` | File passed as `env_file` |
| `CTI_BIND` | `127.0.0.1` | Host address for API |
| `CTI_PORT` | `8000` | Host port for API |
| `CTI_TLS_BIND` | `0.0.0.0` | Host address for TLS proxy |
| `CTI_TLS_PORT` | `8443` | Host port for TLS proxy |
| `WORKER_MAX_CONCURRENT` | `1` | Parallel reports (≈ 4.4 GB RAM each) |
| `CTI_DB_PASSWORD` | **required** | Password of the `postgres` service; `openssl rand -hex 24`. Compose refuses to start without it. |
| `CTI_DB_USER` | `ctiparsor` | PostgreSQL role created on first start; the app connects as it |
| `CTI_DB_NAME` | `ctiparsor` | Database created on first start |

The app receives `DATABASE_URL=postgresql://<CTI_DB_USER>@postgres:5432/<CTI_DB_NAME>` and `PGPASSWORD` from compose itself; a `DATABASE_URL` in `.env` is ignored inside the stack. Every connection authenticates with `scram-sha-256` (local socket included), the server publishes no port, and only the `app` service shares its network. Changing `CTI_DB_USER` or `CTI_DB_PASSWORD` after the `pg-data` volume exists does not alter the server's role: run `ALTER ROLE ... PASSWORD ...` through `docker compose exec postgres psql`, or start from a fresh volume.

### Forced Values

`compose.yaml` forces these values; they cannot be overridden by `.env`:
- `API_HOST=0.0.0.0`
- `API_PORT=8000`
- `API_RELOAD=0`

### LLM Endpoints

- **Anthropic**: Set `LLM_PROVIDER=anthropic` and `ANTHROPIC_API_KEY` in `.env`.
- **Ollama/LM Studio on Host**: Use `http://host.docker.internal:11434`. (`localhost` inside the container refers to the container itself).
- **Ollama Profile**: Set `OLLAMA_BASE_URL=http://ollama:11434` and run `docker compose exec ollama ollama pull mistral`.

## Data and backups

Data persists in named volumes. Two of them hold what you cannot rebuild: `cti-state` (uploaded sources, exported bundles, `db-identity.json`, the private corpus overlay) and `pg-data-18` (every report with its decisions, baseline and bundle, AND the detection-rule corpus, since ADR-0053). A backup is both, taken at one moment: a dump of the database and an archive of `cti-state`. It holds every report at its TLP: keep it as you keep the reports. It holds neither `.env` (your configuration and its secrets) nor, with the `proxy` profile, `docker/nginx/` (certificate, key, htpasswd): keep a copy of those apart, readable by you only. `cti-cache` (models, corpus clones) is not backed up: `bootstrap` downloads it again.

The database commands below need the password even on the local socket (`compose.yaml` sets `scram-sha-256` for it too). They read it inside the container from the mounted secret, so it never appears on the host's command line. They name the role and the database `ctiparsor`: with another `CTI_DB_USER` or `CTI_DB_NAME`, write yours in their place. The `cti-state` commands run `tar` in a one-off container of the `app` service, as the user the app runs as: Compose mounts the volume of the project it runs in, whatever the project's name, and a bind mount (below) the same way.

**Backup**, from the directory of `compose.yaml` and `.env`. `umask 077` makes the two files readable by you only, since they hold every report at its TLP; it stays set in that shell. `day` gives both files the same date, even past midnight. `app` and `worker` stop first, so that no report changes between the dump and the archive; a report in progress goes back to the queue and resumes when they start again. `postgres` keeps running for `pg_dump`. Not while `bootstrap` runs.

<!-- scripts/check_backup_restore_docker.sh: BACKUP_COMMANDS -->
```bash
umask 077
day=$(date +%F)
docker compose stop app worker
docker compose exec -T postgres sh -c 'PGPASSWORD="$(cat /run/secrets/db_password)" exec "$@"' sh pg_dump -U ctiparsor -d ctiparsor -Fc > ctiparsor-$day.dump
docker compose run --rm --no-deps -T --entrypoint tar app czf - -C /app/state . > cti-state-$day.tgz
docker compose start app worker
```

**Check a backup** before you count on it (YYYY-MM-DD: the backup's date). The first command prints how many tables the dump holds the rows of: every table of the database. The second prints how many files and directories the archive holds under `uploads/`. A damaged file stops either one with an error.

<!-- scripts/check_backup_restore_docker.sh: CHECK_COMMANDS -->
```bash
docker compose exec -T postgres pg_restore -l < ctiparsor-YYYY-MM-DD.dump | grep -c 'TABLE DATA'
tar tzf cti-state-YYYY-MM-DD.tgz | grep -c '^./uploads/.'
```

**Restore** into an empty project: on another machine, or on this one under another project name (`export COMPOSE_PROJECT_NAME=ctiparsor-restored` in the shell that runs the commands; stop the old stack first, or give the new one another `CTI_PORT`). The install you took the backup from stays as it is until the restored one works. Volumes are named after their project (`<project>_pg-data-18`, `<project>_cti-state`), so a new project starts with empty ones. You need `compose.yaml`, `.env` and the two files. On another machine, run `bash setup.sh` in the checkout first, with your `.env` in place (or `make .secrets/db_password`): it writes `.secrets/db_password` from `CTI_DB_PASSWORD`, which every service mounts. Without that file Compose creates a directory in its place and `postgres` does not start: delete that directory, then run `setup.sh`. Keep `CTI_DB_USER` and `CTI_DB_NAME` as they were: the dump recreates its tables under that role. Passwords are not in the dump: the new project's `CTI_DB_PASSWORD` is the one that counts. Run the release that took the backup, or a newer one, which migrates the database at its first start; an older one refuses it.

The database first, then `cti-state`, then the stack. An app started on the restored `cti-state` before its database finds an empty database where `db-identity.json` remembers one with data, and refuses to start; its message suggests `make db-upgrade`, but here the answer is to restore the database, then start the stack again.

**The target must be the new, empty project.** Before the first line, `docker compose ps -a` must list no container: if it lists one, this shell names a project that exists (check `COMPOSE_PROJECT_NAME`). `pg_restore --single-transaction` restores everything or nothing: into a database that already holds tables it stops with errors and writes nothing. It must exit 0 and print nothing; if it does not, stop there and do not run the `tar` line. Remove the new project's volumes (`docker compose down -v`, in that project only) and start again. `tar --keep-old-files` replaces no file that is already there: an error on a file means the volume was not empty. A bind mount for `cti-state` (below) is not named after the project: point the new project's at an empty directory first.

<!-- scripts/check_backup_restore_docker.sh: RESTORE_COMMANDS -->
```bash
docker compose up -d --wait postgres
docker compose exec -T postgres sh -c 'PGPASSWORD="$(cat /run/secrets/db_password)" exec "$@"' sh pg_restore -U ctiparsor -d ctiparsor --single-transaction < ctiparsor-YYYY-MM-DD.dump
docker compose run --rm --no-deps -T --entrypoint tar app xzf - --keep-old-files -C /app/state < cti-state-YYYY-MM-DD.tgz
docker compose up -d
```

Then check the restored install: `curl -fsS http://127.0.0.1:8000/api/health` (your `CTI_BIND` and `CTI_PORT`) answers `{"status":"ok"}`, and the web UI lists your reports. The first start records the new PostgreSQL cluster in `db-identity.json`: `docker compose logs app worker` shows `[db] postgres:5432/ctiparsor/public is now on cluster ... with its data: recorded`. `cti-cache` starts empty: `docker compose --profile bootstrap run --rm bootstrap --no-corpora` downloads the models again; the detection rules came back with the database.

**Remove a test project** once you are done with it: `docker compose -p ctiparsor-restored down -v` removes its containers, its networks and its volumes (`ctiparsor-restored_*`). `-v` deletes the volumes of the project `-p` names and of no other; read the name before you press Enter, since `-p ctiparsor` would delete the install itself.

**Make the restore the live install** on the same machine: restore the backup a second time, under the install's own project name, `ctiparsor`. The offline scripts (`scripts/package_offline_docker.sh`, `scripts/update_offline_corpora.sh`) and these docs name its volumes `ctiparsor_*`, so keep the install under that name rather than setting another one in `.env`. Once the restored project shows your reports, in a new shell where `COMPOSE_PROJECT_NAME` is not set: `docker compose down`, then `docker volume rm ctiparsor_pg-data-18 ctiparsor_cti-state` (the old install's database and files, for good; `cti-cache` stays), then the restore commands above. Until you remove it, the restored project still holds a copy of the data.

CI runs these commands as written here: `scripts/docker_smoke.sh --backup-restore` backs its stack up, checks the backup, restores it into a second, empty project, and compares every table and file (job `container-image`). `scripts/check_backup_restore.py` backs up a used install with the same `pg_dump`, `pg_restore` and `tar` flags, restores it into an empty database and directory, and compares every row, sequence, schema object and file (job `fast-tests`, ADR-0094 item 3).

**Moving an existing SQLite-based install onto PostgreSQL** (one that ran
before ADR-0045/ADR-0053 keeps its reports and its rule corpus in
`cti_stix.db` — this repo's historical single-file layout — on `cti-state`;
run both migration scripts, in order, since they cover different tables):
```bash
docker compose run --rm app python scripts/migrate_jobs_to_postgres.py --sqlite /app/state/cti_stix.db --dry-run
docker compose run --rm app python scripts/migrate_jobs_to_postgres.py --sqlite /app/state/cti_stix.db
docker compose run --rm app python scripts/migrate_rules_to_postgres.py --sqlite /app/state/cti_stix.db --dry-run
docker compose run --rm app python scripts/migrate_rules_to_postgres.py --sqlite /app/state/cti_stix.db
```

**Bind Mounts:**
If you replace the named volume with a bind mount (e.g., `./data/state:/app/state`), you must fix permissions:
```bash
sudo chown -R 1001:1001 ./data/state
```
Otherwise, the entrypoint fails with `ERROR: /app/state is not writable by uid 1001`.

## Reaching it from other machines

By default, the API is bound to `127.0.0.1`.

**Option 1: Expose API directly (Insecure)**
Set `CTI_BIND=0.0.0.0` in `.env`. This exposes the API without authentication. Only use on trusted networks. See `docs/deployment.md` §2.

**Option 2: TLS Proxy (Recommended)**
```bash
mkdir -p docker/nginx/certs
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout docker/nginx/certs/cti.key -out docker/nginx/certs/cti.crt \
  -subj '/CN=cti.example.internal'
htpasswd -nBC 12 alice > docker/nginx/htpasswd   # bcrypt, prompts for the password (apt install apache2-utils)
chmod 644 docker/nginx/certs/cti.crt docker/nginx/htpasswd
chmod 640 docker/nginx/certs/cti.key && sudo chown 0:101 docker/nginx/certs/cti.key   # nginx runs as uid 101
docker compose --profile proxy up -d       # https://<host>:8443
```

The `proxy` profile accepts a request body of up to 72 MB (`client_max_body_size`
in `docker/nginx/default.conf`). That covers the largest upload with enrichment
on: a 50 MB report, a 20 MB STIX baseline and the 64 KB form. A proxy in front of
the API must accept at least 70 MB plus 64 KB too. The API then holds each route
to its own budget and answers 413 past it ([api.md](api.md#how-large-a-request-may-be)).

No `htpasswd` on the host, or an old `$apr1$` (MD5-based) entry: see
[deployment.md, option C](deployment.md#option-c--tls--password-proxy-in-front).

Also set `FORWARDED_ALLOW_IPS=*` in `.env` when using this profile. `proxy` and
`app` are separate containers on the `frontend` bridge network, so `app` sees
`proxy`'s bridge IP as the TCP peer — not `127.0.0.1`. Uvicorn only trusts the
`X-Forwarded-For` header nginx sets (`docker/nginx/default.conf`) from peers in
`forwarded_allow_ips`, which defaults to `127.0.0.1`. Left unset here, every
request looks like it came from the proxy container: the per-IP upload rate
limit (`api/routes/upload.py`, `slowapi`) becomes one shared 10/minute quota
for every analyst combined instead of 10 each, and any future per-client
logic would misattribute the same way. `*` is safe in this specific topology
because `app`'s own port never leaves loopback/the internal network — nothing
but `proxy` (or a process already on the host) can ever present that header.
The host-install nginx setup in `docs/deployment.md` Option C does not need
this: there, nginx and the app share the same loopback interface, so the peer
already is `127.0.0.1` and the default applies.

## Security model

| Control | Prevents |
|---|---|
| Non-root user (uid 1001) | Parser/Chromium bugs do not yield root in container |
| `read_only: true` + `tmpfs` | Code/venv/browser cannot be modified; state lives on volumes |
| `cap_drop: [ALL]` | No Linux capabilities, even if process is compromised |
| `no-new-privileges` | Setuid binaries cannot elevate privileges |
| Seccomp profile (`docker/seccomp-chromium.json`) | Docker's default profile plus `clone`/`unshare`/`setns`/`chroot` without a capability requirement, so the Chromium **user-namespace sandbox stays on** instead of the usual `--no-sandbox` shortcut. Without it Chromium dies at launch (`Check failed: sys_chroot("/proc/self/fdinfo/")`) and the URL tab answers 503. The kernel still checks the capability in the caller's namespace: the container process has none, the sandbox zygote owns its own. |
| `pids_limit: 4096` | Fork bombs from hostile documents are stopped |
| Three networks, `backend` marked `internal` | The database has no route to the internet even if compromised; the proxy cannot reach the database or the LLM; the LLM cannot reach the database. Only `app` (and the one-shot `bootstrap`) sit on more than one network |
| `capture-proxy` (Squid, `docker/squid/squid.conf`) | Chromium's own traffic for the URL-capture tab is forced through an egress filter that blocks private/loopback/link-local/reserved destination ranges — an independent, network-layer re-check of `pipeline/web_capture.py`'s SSRF policy that closes the DNS-rebinding gap `_dns_pin_arg`'s docstring documents (a subresource on another host, resolved a second, uncoordinated time by Chromium itself) |
| Loopback bind by default | API reachable only from the host machine |
| Secrets via `env_file` | Image pushed to registry contains no keys or reports |
| Pinned base images, CPU-only torch | No `latest` tags, no unnecessary CUDA wheels |
| Log rotation (5 × 50 MB) | Disk does not fill up |

**What this does NOT do:**
- No application-level authentication (see `docs/deployment.md` §2).
- API keys are visible in `docker inspect` for anyone with Docker socket access.
- Database is stored in plaintext on the volume.

## Day-to-day operations

**Logs:**
```bash
docker compose logs -f app
```

**Update:**
```bash
git pull && docker compose build && docker compose up -d
```
*(Volumes are preserved; schema migrations run at the first start of the API or of a worker, whichever comes first.)*

**CLI Mode (No API):**
```bash
docker compose run --rm -v "$PWD/input":/input:ro app cli /input/report.pdf --output /app/output/report_bundle.json
```
*(Result is in the `cti-state` volume under `output/`.)*

**Diagnostic:**
```bash
docker compose run --rm app check
```

**Scaling the pipeline:**
```bash
docker compose up -d --scale worker=2          # two workers, each WORKER_MAX_CONCURRENT reports
```
Workers share the queue through the job store: each claims a report atomically, heartbeats it while it runs, and any worker requeues a report whose worker died. The API never runs a report itself (`CTIPARSOR_ROLE=api`), so it stays responsive while workers load models.

**Memory limits:**
Every service has one in `compose.yaml` (see *Prerequisites*); change them through the `CTI_<SERVICE>_MEMORY` / `CTI_<SERVICE>_CPUS` variables in `.env`. Each report runs in its own subprocess inside the worker, so when the worker's limit is hit the OOM killer takes the largest process in the container — the report's — and the supervisor marks that job `failed` (the same mechanism `api/worker.py` documents for systemd's `MemoryMax=`). Size the worker from `WORKER_MAX_CONCURRENT × 4.4 GB` plus 1 GB.

**Disk:**
`docker system df` shows what the stack holds. After a few rebuilds the BuildKit cache is the largest item (9.4 GB measured after two builds); `docker builder prune` reclaims it without touching images or volumes.

**GPU:**
Not supported in the image (torch CPU only).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `env file .env not found` | Missing `.env` | `cp .env.example .env` |
| `required variable CTI_DB_PASSWORD is missing a value` | No database password | `echo "CTI_DB_PASSWORD=$(openssl rand -hex 24)" >> .env` |
| `password authentication failed for user "ctiparsor"` | `CTI_DB_PASSWORD` changed after the `pg-data-18` volume was initialised | Restore the old value, or `docker compose down -v` to start a fresh database (deletes every report) |
| Reports (or detection rules) processed before the PostgreSQL move are gone from the list | They are still in `cti_stix.db` on `cti-state` | Run the migration commands in *Data and backups* |
| `docker compose pull` reports `denied` | The GHCR package is still private and you are not authenticated, or the first publish hasn't landed yet | `docker login ghcr.io`, or build locally with `docker compose build` |
| Backlog is unclear — is the queue actually backing up? | Watching logs is guesswork | `curl -s localhost:8000/api/queue/status \| python3 -m json.tool` — `queue.depth` against `queue.max_depth`, `queue.oldest_queued_seconds`, and each worker's `stale` flag (ADR-0048) |
| A report stays `queued` forever | No worker container is running (`docker compose ps worker`), or every worker is at `WORKER_MAX_CONCURRENT` | `docker compose up -d worker`, or `--scale worker=2`; watch `docker compose logs -f worker` |
| A report sits in `processing` after a worker crash | The lease has not expired yet | It is requeued automatically after `WORKER_LEASE_TIMEOUT_S` (180 s) and resumes from its Stage 3 checkpoint |
| `worker` is `unhealthy` | The supervisor loop has not touched its liveness file for two minutes | `docker compose logs worker`; usually the job store is unreachable |
| `ERROR: /app/state is not writable by uid 1001` | Bind mount not chowned | `sudo chown -R 1001:1001 ./data/state` |
| URL tab 503 / logs say `Chromium sandboxing failed` or `sys_chroot` | Seccomp profile not applied (`docker run` without `--security-opt seccomp=docker/seccomp-chromium.json`, or compose invoked from another directory), or the image was built with `INSTALL_CAPTURE=false` | Run compose from the repository root; rebuild with `CTI_INSTALL_CAPTURE=true` |
| `WARNING: ANTHROPIC_API_KEY is unset` | Missing key in `.env` | Edit `.env`, `docker compose up -d` |
| `Connection refused` on `localhost:11434` | `localhost` is the container | Use `host.docker.internal` or `ollama` profile |
| First report very slow | Bootstrap not run | Run bootstrap profile; set `HF_TOKEN` |
| Settings → Redownload fails or produces an inconsistent corpus | Two corpus syncs ran concurrently, contending for the same rows during the rebuild | Sync corpora one at a time, or re-run all of them at once with `docker compose --profile bootstrap run --rm bootstrap` |
| Report `failed`, subprocess killed | Out of Memory | Lower `WORKER_MAX_CONCURRENT`, increase Docker VM RAM |
| `port is already allocated` | Port conflict | Change `CTI_PORT` |
| Warning: `listening on 0.0.0.0:8000` | Normal in container | Ignore; `CTI_BIND` controls external exposure |

## Verifying an image

`scripts/docker_smoke.sh` builds the image, starts `app`, and checks: compose validity, health, the web UI is served, uid 1001, read-only root, writable volumes, the symlinks, the Python imports, `google-re2` availability (ADR-0049 — most Stage 2 regexes run in guaranteed linear time; 7 of 19 sub-patterns use lookaround RE2 can't parse and stay on stdlib `re`, verified not exploitable), Chromium present and **launching sandboxed** (the check that proves the seccomp profile is applied).

```bash
make docker-smoke                        # = bash scripts/docker_smoke.sh
bash scripts/docker_smoke.sh --no-build  # reuse the image you already built
bash scripts/docker_smoke.sh --job       # also upload tests/fixtures/sample_report.txt, wait for the job and check its stages
bash scripts/docker_smoke.sh --keep      # leave the stack running afterwards
bash scripts/docker_smoke.sh --clean     # docker compose down -v afterwards (DELETES the smoke project's volumes)
```

The smoke runs in a Compose project of its own, `ctiparsor-smoke`, not in your install's; the `COMPOSE_PROJECT_NAME` of `.env` is ignored. If your shell exports another one (the restore procedure above does), the smoke exits 2: it would start that project's `app` and `worker` on the image under test, which migrates its database, write a report into it with `--job`, and stop it at the end. To test an install on purpose, set `SMOKE_ALLOW_PROJECT` to its name as well, as `scripts/check_offline_bundle_docker.sh` does for a restored offline install. `--clean` and `--backup-restore` run only on `ctiparsor-smoke`, allowed project or not: `--clean` deletes the project's volumes, and `--backup-restore` writes a test report into it.

`--job` runs the whole pipeline, LLM stage included, with whatever `.env` configures — on a paid provider it costs one small report. It then reads the job's stage report and fails if a stage failed, or if a stage in `SMOKE_REQUIRED_STAGES` (default `2c 2d 2e 3`) did not run; a stage the configuration turned off is accepted. Set the variable to the stages your `.env` can run: without an LLM, `SMOKE_REQUIRED_STAGES="2c 2d 2e"`. CI runs the build and the non-job checks on every push.

## See also

- [docs/deployment.md](deployment.md) — bind address, what "no authentication" means, nginx, systemd
- [SECURITY.md](../SECURITY.md) — threat model
- [ADR-0044](adr/0044-container-images.md) — why one image and no database container; the hardening findings
- [ADR-0047](adr/0047-publish-image-to-ghcr.md) — the GHCR publish pipeline
- [ADR-0048](adr/0048-queue-status-endpoint.md) — the queue-status endpoint
- [ADR-0054](adr/0054-full-docker-installation.md) — Docker-only install/dev/air-gap, and why `setup.sh` shrank
- [ADR-0040](adr/0040-offline-installation-bundle.md) — the original (superseded) air-gap bundle mechanism
