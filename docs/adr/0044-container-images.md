# ADR-0044 — Container images: one hardened application image, not a database tier

**Status:** Accepted (implemented and validated 2026-09-16)
**Date:** 2026-09-16
**Relates to:** [0002](0002-concurrent-report-ingestion.md) (in-process worker pool, no broker),
[0029](0029-pasted-text-and-captured-url-ingestion.md) (Chromium sandbox stays on),
[0036](0036-architecture-service-multi-utilisateur.md) / [0037](0037-scaling-to-30-40-users.md)
(SQLite stays; PostgreSQL deferred until authentication),
[0040](0040-offline-installation-bundle.md) (its Option C was "a container image")

## Context

CTIParsor installs two ways: `setup.sh`, which reaches twelve network sources,
or the 13 GB air-gap bundle of ADR-0040. Both put the product on the host's own
Python and leave the operator to run it as a service (`docs/deployment.md`).
The request was a third path — `docker compose up` — with images built from
files in the repository and a deployment that respects container security
practice.

The request came with a decomposition in mind, first "one container for the
database (PostgreSQL) and one for the rest", then "app / worker / Chromium /
database". Each was checked against what the code actually does:

| Component | What the code does today | Own container? |
|---|---|---|
| Database | One SQLite file, opened **in-process** by `api/db.py` (WAL, `busy_timeout`). No network protocol exists to put a container boundary on. ADR-0037 adopts PostgreSQL *only when authentication lands*. | **No** — a volume |
| Worker | `api/worker.py` spawns one `multiprocessing` (`spawn`) subprocess per report **from inside the uvicorn process**; the queue is the `jobs` table; ADR-0002 rejected Celery/RQ + Redis. A separate worker container needs a broker or a DB-polling loop — that is ADR-0036 work, not packaging. | **No** — same container |
| Chromium | Playwright launches it in-process (`pipeline/web_capture.py`), sandbox forced on. A remote browser (Playwright `run-server` + `chromium.connect()`) is possible but needs a code path that does not exist. | **Not yet** — Option D |
| LLM | An HTTP client on a URL (`OLLAMA_BASE_URL`, `LMSTUDIO_BASE_URL`, …). | **Yes, optional** |
| Reverse proxy | `docs/deployment.md` option C: nginx, TLS, basic auth. | **Yes, optional** |

Measured inputs for the image (this workstation, 2026-09-16):

| Item | Size |
|---|---|
| Tracked source tree (`git ls-files`) | 13 MB |
| HuggingFace models (Stage 2c/2d/2e) | 2.6 GB — re-fetchable |
| Detection corpora (`corpora/`) | 684 MB — re-fetchable |
| Local `cti_stix.db` | 586 MB — precious |
| `torch` from PyPI | pulls 15 `nvidia_*` CUDA wheels, 2.2 GB (ADR-0040) — useless on CPU |

Docker on this workstation: Engine 29.8 in WSL2 (Ubuntu 26.04, kernel 6.18,
cgroup v2, seccomp builtin), reachable as root only.

## Decision

**One application image, two named volumes, one compose file with three
optional profiles.** No database container.

```
Dockerfile (3 stages)
  ui       node:24-bookworm-slim      npm ci && npm run build      → /ui/dist
  builder  python:3.12-slim-bookworm  venv /opt/venv: torch (CPU index), requirements*.txt, playwright
  runtime  python:3.12-slim-bookworm  tesseract, poppler, libmagic1, git, tini, Chromium (--with-deps)
                                      /app root-owned; user ctiparsor 1001; HEALTHCHECK /api/health

compose.yaml
  app         always      the image, hardened (table below), port published on 127.0.0.1:8000
  bootstrap   profile     same image, one-shot: init_db, model warm-up, corpus sync, rule store
  ollama      profile     ollama/ollama:0.34.1, no published port, reachable at http://ollama:11434
  proxy       profile     nginxinc/nginx-unprivileged:1.28-alpine, TLS + htpasswd, port 8443
  networks    frontend (proxy ↔ app), backend (app ↔ ollama)
  volumes     cti-state  → /app/state   db, uploads, output, backups, corpus overlay   (back this up)
              cti-cache  → /app/cache   HF models, corpora                             (rebuildable)
```

The application opens fixed repository-relative paths. Rather than thread a data
directory through ten call sites, the image **symlinks** `/app/uploads`,
`/app/output`, `/app/db_backups`, `/app/corpora` and
`/app/detection_corpora.local.yaml` into the two volumes, and three small code
changes cover what a symlink cannot: `CTIPARSOR_DB_PATH` /
`CTIPARSOR_DB_BACKUP_DIR` (`api/db.py`, which now also creates the parent
directory), `CTIPARSOR_GIT_REV` as the fallback when `git rev-parse` has no
repository (`api/run_config.py`), and `scripts/check_stages.py` resolving its
files from the repository root instead of the working directory.

Models and corpora are **not baked in**: the image stays rebuildable in minutes
when code changes, and the cache volume survives image updates. An explicit
`docker compose --profile bootstrap run --rm bootstrap` fills it once; a
container started without it still works, it just downloads on the first
report, exactly as a host install does.

### Hardening applied to `app` and `bootstrap`

| Control | Why |
|---|---|
| user `ctiparsor` uid 1001 (Bitnami convention) | Chromium refuses its sandbox as root; a parser or renderer exploit does not get root |
| `/app` owned by root, `read_only: true`, `tmpfs` on `/tmp` and `/home/ctiparsor` | code, venv and browser cannot be modified at runtime; state is only on the volumes; tmpfs mounts are `noexec` by default and nothing needs to execute from them |
| `cap_drop: [ALL]` | measured: nothing in the pipeline needs a capability, including the Chromium sandbox (see Consequences §1) |
| `no-new-privileges:true` | no setuid path to escalation |
| seccomp `docker/seccomp-chromium.json` | Docker's default profile plus `clone`/`unshare`/`setns`/`chroot` without a capability requirement, so the Chromium **user-namespace sandbox stays on** instead of the usual `--no-sandbox` "fix" |
| `pids_limit: 4096` | a fork bomb from a hostile document stops there; the pipeline peaks well below (torch threads + Chromium processes) |
| port published on `${CTI_BIND:-127.0.0.1}` | the same loopback-by-default posture as `run_api.py`; exposure is an explicit `.env` change or the `proxy` profile |
| secrets via `env_file`, never in a layer | `.dockerignore` excludes `.env*`, `*.db*`, `uploads/`, `output/`, `corpora/`, `docker/nginx/certs/`, `docker/nginx/htpasswd`; an image pushed to a registry carries no key and no report |
| `API_HOST`, `API_PORT`, `API_RELOAD` forced in compose | a value in `.env` cannot bind the API to loopback inside the container (unreachable) or turn on the reloader |
| pinned base tags, CPU-only torch | no `latest`; the CUDA wheels never enter the image |
| json-file logging, 5 × 50 MB | bounded disk |
| `tini` as PID 1 | reaps Chromium and pipeline subprocesses |

## Options considered

### A — One image + SQLite on a volume

**Accepted.** It is the shape of the code: one process tree, one file. The
subprocess-per-report design already gives memory isolation inside the
container, and Docker's memory limit applies to the whole tree; the OOM killer
takes the largest process, which is the model subprocess, and the watcher marks
the job `failed` — the mechanism `api/worker.py` documents for systemd's
`MemoryMax=`.

### B — A PostgreSQL container

**Rejected.** There is no PostgreSQL client in the code, no driver in
`requirements*.txt`, and no table that would move. ADR-0037 already weighed this
and deferred it to the moment authentication makes concurrent writers and
per-user rows real. A database container today would run an empty server
beside an application that never connects to it. When ADR-0037's condition is
met, it becomes a fourth compose service and a third volume — nothing in this
layout has to be undone.

### C — A separate worker container

**Rejected for now.** The upload route calls `run_pipeline_async()` in-process;
there is no broker and no polling loop for a second container to consume.
Building one is the ARQ/Celery discussion ADR-0036 settled against for the
moment, and SQLite on a shared volume pins both containers to one host anyway,
so the split buys no scale-out. What it would buy — a memory limit on the
pipeline alone — the in-process subprocess already provides.

### D — A separate Chromium container

**Deferred; this is the next hardening step.** Playwright can drive a browser in
another container (`playwright run-server` there, `chromium.connect(ws_url)`
here), which would move the riskiest surface — rendering an attacker-chosen
page — out of the container that holds the database and the API keys.
It needs a connect mode in `pipeline/web_capture.py` and a way to pass the
launch options (sandbox on, the `_CHROMIUM_ARGS` list) across the wire. Until
then the sandbox is kept on inside the application container, which is what
the seccomp profile is for.

### E — Bake models and corpora into the image

**Rejected.** +3.3 GB per image, and every code change would republish it.
Volumes plus an explicit bootstrap keep the image at what the code needs.
Air-gapped sites keep ADR-0040's bundle; a registry mirror can carry the image
and the volumes can be filled from that bundle's `hf/` and `corpora.tar`.

### F — Docker secrets for the API keys

**Deferred.** The application reads environment variables and nothing else;
`*_FILE` variants would be new code. `env_file` keeps keys out of every layer,
which is the property that matters for an image that gets pushed. The residual
exposure — keys readable through `docker inspect` by anyone with the Docker
socket — is documented in `docs/docker.md`, not hidden.

## Consequences — what building and running it changed

1. **The stock Playwright seccomp profile is not enough once capabilities are
   dropped.** With `cap_drop: ALL` the sandboxed launch died with
   `Check failed: sys_chroot("/proc/self/fdinfo/") == 0` — the Chromium zygote
   `chroot`s inside its own user namespace, and the profile only allowed
   `chroot` when the container holds `CAP_SYS_CHROOT`. The profile shipped in
   `docker/seccomp-chromium.json` allows the syscall unconditionally; the kernel
   still checks the capability in the caller's namespace, which the container
   process lacks and the zygote (owner of its userns) has. Verified both ways:
   without the profile the launch fails, with it `chromium 153.0.8010.12`
   renders a page, and no capability is granted.
2. **`libmagic1` is not in `python:*-slim`.** `python-magic` is what validates
   upload MIME types; the import fails without the library, silently falling
   back to `filetype`. Added to the runtime packages.
3. **The optional `re2>=0.2.20` cannot be installed on Python 3.12.** The sdist
   `re2-0.2.24` uses `PyUnicode_AS_UNICODE`, removed in 3.12; the local 3.14
   venv has no `re2` either. `google-re2` ships wheels but is not a drop-in
   (`compile(pattern, options)` rejects `re` flags with
   `AttributeError: 'RegexFlag' object has no attribute 'max_mem'`). The image
   ships without re2 — the same state as every host install on a current
   Python — and the smoke test reports it as a warning. A follow-up task covers
   the shim.
4. **Compose resolves `seccomp=./docker/…` relative to the project directory.**
   The smoke test's sandboxed launch passes under compose, which is the proof;
   a plain `docker run` needs the `--security-opt` spelled out.
5. **What becomes harder.** `run_config.git_rev` depends on the build stamping
   `GIT_REV` (`make docker-build` does; a bare `docker build` records nothing);
   `bundle_revisions.is_ancestor()` answers "undecidable" in the container
   because there is no repository to ask; `docs/` and `tests/` are not in the
   image; the startup line from `run_api.py` warns about `0.0.0.0` even when
   compose publishes the port on loopback only.
6. **Measured.** Image **4.48 GB** (venv 2.07 GB, Chromium + libraries
   0.94 GB, system packages 0.20 GB, base 0.14 GB, source 11 MB, UI 4 MB);
   cold build **3 min 24 s**; the container is healthy **7 s** after
   `docker compose up`; `scripts/docker_smoke.sh` passes 13 of 13 checks with
   one warning (re2). Bootstrap and end-to-end job figures: see the
   validation section below.

## Validation record (2026-09-16, WSL2 / Docker 29.8)

| Step | Result |
|---|---|
| `docker build` (cold) | 3 min 24 s, exit 0 |
| `docker compose config` with every profile | valid |
| `scripts/docker_smoke.sh --keep` | 0 failures, 1 warning (re2) |
| Sandboxed Chromium, `cap_drop ALL` + profile | launches, renders |
| Sandboxed Chromium, `cap_drop ALL`, no profile | `sys_chroot` check fails (expected) |
| `proxy` profile with a throwaway cert + htpasswd | 401 without credentials, 200 with; TLS 1.3, HTTP/2; nginx runs as uid 101 on a read-only root; the UI is served through it |
| `docker compose run --rm app check` | 13 of 13 stages available inside the container, rule store visible through `CTIPARSOR_DB_PATH` |
| `ollama` profile | `docker compose --profile ollama config` valid; not started (3 GB image pull, not needed for this validation, which used an existing Ollama instance) |
| Full test suite on the host (`SKIP_HEAVY_MODELS=1`) | 1188 passed, 2 skipped; ruff clean; mypy clean on `pipeline/ api/ models/` |
| `bootstrap` (models + corpora + rule store), run against the live `app` | **13 min 3 s**, exit 0: 3 of 3 models cached (MiniLM, CyNER, GLiNER), 14 of 14 corpora synced, **87,480 rules** in the store, `check_stages` all green; volumes 3.6 GB afterwards |
| `scripts/docker_smoke.sh --no-build --job` (Stage 3 on an Ollama `qwen3.8` outside the compose stack) | **0 failures**: `tests/fixtures/sample_report.txt` uploaded through the API, job reached `for_review`, bundle exported with **63 STIX objects**, no traceback in the logs; **5 min 42 s** wall clock for the whole script, model loads and the LLM stage included |

## Files

- `Dockerfile`, `.dockerignore`, `compose.yaml`
- `docker/entrypoint.sh`, `docker/warm_models.py`, `docker/seccomp-chromium.json`, `docker/nginx/default.conf`
- `scripts/docker_smoke.sh`, `Makefile` (`docker-*` targets), `.github/workflows/ci.yml` (image build + smoke)
- `api/db.py`, `api/run_config.py`, `scripts/check_stages.py`, `tests/test_container_env.py`
- `docs/docker.md` (operator guide), `README.md`, `docs/deployment.md`, `.env.example`
