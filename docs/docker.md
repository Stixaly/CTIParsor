# Running CTIParsor in containers

This guide covers deploying CTIParsor using Docker Compose. It replaces the manual `setup.sh` installation for standard environments. It does **not** replace the offline installation bundle (ADR-0040), which remains the required path for air-gapped systems. See ADR-0044 for the architectural decisions behind this containerization.

## What you get

- **Image**: `ctiparsor:local` (4.48 GB). Contains the React UI, Python 3.12 venv (torch CPU), and Chromium (optional).
- **Volumes** (Compose prefixes them with the project name, so `docker volume ls` shows `ctiparsor_cti-state` and so on):
  - `cti-state`: the SQLite rule store, uploads, outputs, backups — back it up.
  - `pg-data`: the PostgreSQL job store (jobs, entities, relationships, progress, policy, figure and CVE caches) — back it up with `pg_dump`.
  - `cti-cache`: HuggingFace models, Sigma/YARA/Suricata corpora — rebuildable with `bootstrap`.
  - `ollama-models`: (Only if using the `ollama` profile).
- **Services**: `app`, `worker` and `postgres` always run. `app` only accepts and queues reports (`CTIPARSOR_ROLE=api`) and never loads a model; `worker` claims queued reports from the job store and runs each in an isolated subprocess, heartbeating the rows it owns so several workers can share the queue (ADR-0046) — scale it with `docker compose up -d --scale worker=2`; `postgres` is the job store (ADR-0045: PostgreSQL 17, on the internal network only, running as the image's `postgres` user with every capability dropped and a read-only root; `CTI_DB_PASSWORD` in `.env` is required). Three optional profiles:
  - `bootstrap`: one-shot initialisation (models, corpora, rule store), same image and hardening as `app`.
  - `ollama`: a local LLM with no published port, reachable by `app` at `http://ollama:11434`.
  - `proxy`: TLS + password (`nginx-unprivileged`) in front of `app`; the only thing worth publishing on a network.
- **Not in the image**: the models (2.6 GB) and corpora (0.7 GB) are downloaded once into `cti-cache` by `bootstrap`, so a code change rebuilds in minutes. `docs/` and `tests/` are left out too.

Known limits: no GPU (torch is the CPU build); `git` has no repository inside the container, so bundle-staleness checks (ADR-0035) answer "undecidable" and the revision recorded in each bundle comes from the `GIT_REV` build argument (`make docker-build` sets it, a bare `docker compose build` records nothing). Docker Desktop on Windows and docker-ce inside WSL2 both work; the repository may live on the Windows drive, the named volumes live in the Linux VM, which is what keeps SQLite fast.

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

**One manual step, once:** a new GHCR package is private by default
regardless of the repository's visibility. After the first push, a
maintainer sets it to the visibility you want in the package's own GitHub
settings (Package settings → Change visibility) — nothing in the workflow
does this for you.

## Quick start

```bash
cp .env.example .env            # then set your LLM provider / key
docker compose build            # or: make docker-build (stamps the git revision)
docker compose up -d            # http://127.0.0.1:8000
docker compose --profile bootstrap run --rm bootstrap   # once, 10-20 min: models, corpora, rule store
docker compose logs -f app
```

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

Data persists in named volumes. Two of them hold what you cannot rebuild: `cti-state` (rule store, uploads, outputs) and `pg-data` (every report).

**Backup:**
```bash
docker run --rm -v ctiparsor_cti-state:/s -v "$PWD":/b alpine tar czf /b/cti-state-$(date +%F).tgz -C /s .
docker compose exec -T postgres pg_dump -U ctiparsor -d ctiparsor -Fc > ctiparsor-$(date +%F).dump
```

**Restore the job store** (into a fresh, empty `postgres` service):
```bash
docker compose exec -T postgres pg_restore -U ctiparsor -d ctiparsor --clean --if-exists < ctiparsor-YYYY-MM-DD.dump
```

**Moving an existing SQLite job store into the container's PostgreSQL** (an install that ran before ADR-0045 keeps its reports in `cti_stix.db` on `cti-state`):
```bash
docker compose run --rm app python scripts/migrate_jobs_to_postgres.py --sqlite /app/state/cti_stix.db --dry-run
docker compose run --rm app python scripts/migrate_jobs_to_postgres.py --sqlite /app/state/cti_stix.db
```

**Restore:**
*(Stop the app first)*
```bash
docker run --rm -v ctiparsor_cti-state:/s -v "$PWD":/b alpine sh -c 'cd /s && tar xzf /b/cti-state-YYYY-MM-DD.tgz'
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
printf 'alice:%s\n' "$(openssl passwd -apr1)" > docker/nginx/htpasswd   # prompts for the password
chmod 644 docker/nginx/certs/cti.crt docker/nginx/htpasswd
chmod 640 docker/nginx/certs/cti.key && sudo chown 0:101 docker/nginx/certs/cti.key   # nginx runs as uid 101
docker compose --profile proxy up -d       # https://<host>:8443
```

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
*(Volumes are preserved; schema migrations run at API startup.)*

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
| `password authentication failed for user "ctiparsor"` | `CTI_DB_PASSWORD` changed after the `pg-data` volume was initialised | Restore the old value, or `docker compose down -v` to start a fresh database (deletes every report) |
| Reports processed before the PostgreSQL move are gone from the list | They are still in `cti_stix.db` on `cti-state` | Run the migration command in *Data and backups* |
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
| Report `failed`, subprocess killed | Out of Memory | Lower `WORKER_MAX_CONCURRENT`, increase Docker VM RAM |
| `port is already allocated` | Port conflict | Change `CTI_PORT` |
| Warning: `listening on 0.0.0.0:8000` | Normal in container | Ignore; `CTI_BIND` controls external exposure |

## Verifying an image

`scripts/docker_smoke.sh` builds the image, starts `app`, and checks: compose validity, health, the web UI is served, uid 1001, read-only root, writable volumes, the symlinks, the Python imports, `google-re2` availability (ADR-0049 — most Stage 2 regexes run in guaranteed linear time; 7 of 19 sub-patterns use lookaround RE2 can't parse and stay on stdlib `re`, verified not exploitable), Chromium present and **launching sandboxed** (the check that proves the seccomp profile is applied).

```bash
make docker-smoke                        # = bash scripts/docker_smoke.sh
bash scripts/docker_smoke.sh --no-build  # reuse the image you already built
bash scripts/docker_smoke.sh --job       # also upload tests/fixtures/sample_report.txt and wait for the bundle
bash scripts/docker_smoke.sh --keep      # leave the stack running afterwards
bash scripts/docker_smoke.sh --clean     # docker compose down -v afterwards (DELETES the volumes)
```

`--job` runs the whole pipeline, LLM stage included, with whatever `.env` configures — on a paid provider it costs one small report. CI runs the build and the non-job checks on every push.

## See also

- [docs/deployment.md](deployment.md) — bind address, what "no authentication" means, nginx, systemd
- [SECURITY.md](../SECURITY.md) — threat model
- [ADR-0044](adr/0044-container-images.md) — why one image and no database container; the hardening findings
- [ADR-0047](adr/0047-publish-image-to-ghcr.md) — the GHCR publish pipeline
- [ADR-0048](adr/0048-queue-status-endpoint.md) — the queue-status endpoint
- [ADR-0040](adr/0040-offline-installation-bundle.md) — the air-gap bundle
