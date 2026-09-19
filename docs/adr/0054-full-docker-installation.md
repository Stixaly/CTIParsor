# ADR-0054 — Full-Docker installation: setup.sh becomes environment prep only

**Status:** Accepted (implemented 2026-09-19)
**Date:** 2026-09-19
**Relates to:** [setup.sh](../../setup.sh), [compose.yaml](../../compose.yaml),
[Makefile](../../Makefile), [scripts/offline_lib_docker.sh](../../scripts/offline_lib_docker.sh),
[scripts/package_offline_docker.sh](../../scripts/package_offline_docker.sh),
[scripts/check_offline_bundle_docker.sh](../../scripts/check_offline_bundle_docker.sh);
supersedes the installation mechanism (not the goal) of
[ADR-0040](0040-air-gapped-installation.md); builds on
[ADR-0044](0044-containerize-the-deployment.md), and re-examines the
bind-mount performance measurement from
[ADR-0037](0037-scaling-to-30-40-users.md); follows
[ADR-0053](0053-postgresql-only-sqlite-removed.md), which removed the last
reason a host install needed nothing but a single SQLite file.

## Context

CTIParsor supported two installation shapes side by side: a host install
(`bash setup.sh`, 1298 lines — created a venv, installed Python/Node/system
packages, downloaded NLP models, MITRE data and detection corpora, built the
frontend) and a container stack (`docker compose up`, with a `bootstrap`
profile doing the equivalent data-population steps inside a container,
ADR-0044). Docker already did everything `setup.sh` did, better isolated
(non-root, read-only root filesystem, seccomp-confined Chromium, resource
limits), so the two paths had been drifting duplicate logic since ADR-0044
landed. ADR-0053 removed the last reason the host path was materially
simpler than the container one — a host install now needs a reachable
PostgreSQL server too, exactly like the container path already provides via
`docker compose up -d postgres`.

The maintainer decided to make Docker the **only** supported way to install,
develop and run CTIParsor — not just end-user deployment, but the developer
loop (tests, pipeline iteration) and the air-gapped install (ADR-0040) as
well. `setup.sh` is reduced to environment preparation: create `.env`,
generate `CTI_DB_PASSWORD` and the `.secrets/db_password` file Compose
bind-mounts into every service, verify Docker/Compose are present and the
daemon is reachable, then print the next commands — it does not build,
download, or start anything itself.

## Decision

### `setup.sh` — environment prep only

Deleted: system-package installation, Node.js install, Python venv creation
and package install, MITRE data download, spaCy/CyNER/GLiNER
pre-download, frontend build. All of it is now either baked into the image
(`Dockerfile` already builds the venv, Node/frontend, system deps, Chromium)
or done by `docker compose --profile bootstrap run --rm bootstrap`
(`docker/entrypoint.sh::bootstrap()`). MITRE data files need no build step
at all — `pipeline/data/*.json`/`*.npy` are committed to git, not
gitignored, so `COPY . /app/` in the `Dockerfile` carries them automatically.

What the ~250-line replacement does: checks `docker`/`docker compose` (or
the `docker-compose` v1 fallback) are present and the daemon answers;
creates `.env` from `.env.example` if missing; generates `CTI_DB_PASSWORD`
if `.env` doesn't have one yet; writes `.secrets/db_password` from it
(mirroring the `Makefile`'s own `.secrets/db_password` target so the two
never disagree); prints the exact next commands
(`docker compose build`, `docker compose up -d`,
`docker compose --profile bootstrap run --rm bootstrap`) rather than running
them.

### Dev workflow: two new compose services, profile `dev`

Both reuse the existing app image (`&app-image` anchor) — no new
`Dockerfile` stage.

`dev` (`compose.yaml`): same image as `app`/`worker`, `read_only: false`
(needs to write `.pytest_cache`/`__pycache__`), the repo bind-mounted live
over `/app`. `tests/` is deliberately `.dockerignore`d from the built image
— it was never meant to ship in `app`/`worker` — so the bind mount is what
supplies it, and what makes source edits picked up with no rebuild.
Bind-mounting `.` over `/app` also replaces the image's
`uploads`/`output`/`corpora` symlinks with the repo's own real directories,
so `docker compose run --rm dev cli input/report.pdf` reads and writes
those host paths directly.

`frontend-dev`: a plain `node:24-bookworm-slim` service (the same base image
the `Dockerfile`'s own `ui` build stage uses), bind-mounts `frontend/`, runs
`npm run dev -- --host 0.0.0.0`, publishes Vite's port at
`127.0.0.1:5173`. `frontend/vite.config.ts`'s dev-server proxy target
becomes an env var (`VITE_API_PROXY_TARGET`) so it can point at
`http://localhost:8000` for a host-based `npm run dev` (unchanged default)
or `http://app:8000` (Compose service DNS) for the containerized one — a
container's own `localhost` never reaches a sibling container.

Both carry `profiles: [dev]`, like `bootstrap`/`ollama`/`proxy` already did,
so a plain `docker compose up -d` never starts them.

**Performance re-examination.** ADR-0037 measured that the WSL2 `/mnt/`
9p/DrvFs bridge pays real cost per page fault, and warned against
bind-mounting large working sets across it. That finding does not recur
here: it was about (a) SQLite doing random-access reads against a 644 MB
file — gone entirely after ADR-0053, PostgreSQL runs in its own container
unaffected by host bind-mount performance — and (b) Torch/HF imports
reading roughly 2 GB of `.so` files from `/mnt/c`. Neither applies to `dev`:
`/opt/venv` (the multi-gigabyte installed-package tree) stays baked inside
the image, never bind-mounted; only `.py`/`.tsx` source — a few hundred
small text files — crosses the bind mount, a fundamentally different I/O
profile than random-access reads against one large binary file.

### Air-gapped installation, redesigned around Docker

ADR-0040's bundle packaged wheels, `.deb`s, HF models, Chromium, MITRE/CAPEC
JSON, corpora, the frontend build, and an Ollama runtime — almost all of
which the Docker image now already contains after `docker compose build`.
The only things not in the image are what `bootstrap` populates into
volumes at runtime: NLP models and corpus clones in `cti-cache`, and the
job/rule store in `pg-data` (which, since ADR-0053, is no longer a file
that can simply be tarred up).

`scripts/offline_lib_docker.sh` replaces `scripts/offline_lib.sh`: 8
host-install staging functions (`offline_stage_models`/`browsers`/`data`/
`corpora`/`frontend`, `offline_install_debs`/`spacy_model`/`ollama`)
collapse into `docker load` (the image already carries Python/Node deps,
Chromium, the built frontend, and MITRE data) plus a generic tar-based
named-volume restore. The checksum-before-sourcing-`bundle.env` ordering
and the Zip-Slip tar guard (`offline_check_tar_safe`) carry over unchanged
— neither was ever venv-specific.

`scripts/package_offline_docker.sh` (run on a connected machine, same CPU
architecture as the target — Docker images are architecture-specific, no
cross-arch fallback): builds the app image, pulls the supporting images
(`postgres:17-alpine`, the `capture-proxy` image, `alpine` for the volume
restore step, optionally `ollama/ollama`), `docker save`s all of them into
one `images.tar.gz`, runs `bootstrap` locally to populate `cti-cache` and
the database for real, exports `cti-cache` via a throwaway `alpine`
container tarring the named volume (the same technique `docs/docker.md`'s
existing backup instructions already use), exports the job/rule store via
`pg_dump -Fc` — **not** a raw `pg-data` volume tar, since binary PostgreSQL
data directories are not reliably portable even between two instances of
the same version, and `pg_dump`/`pg_restore` is the mechanism this repo
already documents and tests for backup/restore — writes a `bundle.env`
manifest, computes `SHA256SUMS` over every staged file, and packs the whole
thing into `dist/cti-parsor-offline-docker-<rev>-<arch>.tar` plus a
whole-tarball `.sha256` (the same two-layer integrity scheme ADR-0040 used).

`setup.sh --offline=DIR`: validates the bundle (checksums first, then reads
`bundle.env`, then checks architecture), `docker load`s the images, restores
`cti-cache` (and `ollama-models` if present) from their tars, brings up
`postgres`, waits for it healthy, and `pg_restore`s the dump — literally the
same command `docs/docker.md`'s "Restore both stores" section already
documents. No `bootstrap` run is needed afterward: the data is already
restored. `.env`/`.secrets/db_password` prep runs first, shared with the
normal (non-offline) path.

`scripts/check_offline_bundle_docker.sh` replaces
`scripts/check_offline_bundle.sh`. The old checker's sudo/dpkg stubs and
network-blackhole subshell don't apply here — `docker load` and a volume
restore are offline by construction, there is nothing to prove absent the
way "did pip secretly reach the network" needed proving before. What is
worth verifying is that the restored stack actually works: the script does
the load+restore itself (a thin wrapper around the same
`offline_lib_docker.sh` functions `setup.sh --offline` uses), then hands off
to the existing `scripts/docker_smoke.sh` — confirmed by reading it
end-to-end that it never itself invokes
`docker compose --profile bootstrap run --rm bootstrap` (it starts `app`
and `worker` directly and assumes whatever state the volumes already hold),
so reusing it for the "does the stack actually work" half needs no changes.
An additional check not covered by `docker_smoke.sh` — polling
`/api/detection-corpora` for a non-zero rule count — is the one thing this
wrapper adds on top.

### Docs and Makefile

`README.md`'s "Quick start — CLI" and "Quick start — Web UI" (both
venv-based) collapse into one Docker-only quick start; its "Offline
(air-gapped) installation" section is rewritten for the new mechanism.
`CONTRIBUTING.md` and `TESTING.md` route every example through
`docker compose run --rm dev ...`, dropping the "two engines" framing that
ADR-0053 had already made half-obsolete. The `Makefile` drops every
venv-relative target (`install`, `api`, `api-dev`, the old venv
`frontend-dev`, …) in favor of a `DEV_RUN = docker compose run --rm dev`
variable used throughout, plus new `docker-test` and `docker-frontend-dev`
targets.

## Options considered

### A — Docker-only, dev workflow included (accepted)

Everything above. **Pros:** one installation path, one place bugs get fixed,
the container's hardening (non-root, read-only root filesystem, seccomp)
now also covers the day-to-day dev/test loop instead of only production.
**Cons:** every contributor needs Docker running, even for a single test
run; a bind-mounted dev container on Windows (not WSL2) would hit the
ADR-0037 filesystem-bridge cost for real, since the whole repo — not just
`.py` files — is the working directory there. Mitigated by the WSL2/Linux
filesystem check `setup.sh` already prints (copy the repo off `/mnt/` for
best performance), which applies to the Docker build context regardless of
this change.

### B — Docker for deployment, keep the venv path for development

Rejected — the user's explicit scoping decision. Keeping two paths is
exactly the drift this ADR exists to stop; a venv path that only
maintainers alive during the transition remember to keep working is worse
than no venv path.

### C — Keep ADR-0040's air-gap mechanism as-is, layer Docker on top

Rejected — also an explicit scoping decision. The old bundle's staging
functions (dpkg, HF cache copy, Playwright browser copy, frontend
`node_modules` tar) target a host install that no longer exists once
Docker is the only path; keeping them "just in case" would mean two
air-gap mechanisms, only one of which anyone tests.

## Consequences

- **What becomes easier.** One installation path to document, test, and keep
  working. The dev/test loop gets the same non-root, read-only-filesystem,
  seccomp-confined environment production runs in, instead of "whatever the
  contributor's host happens to have installed." The air-gap bundle shrinks
  from "everything a full OS+Python+Node install needs" to "an image plus
  two small runtime exports" — no more `.deb`/wheel/Chromium staging that
  had to track the host distribution's package versions.
- **What becomes harder.** Every contributor needs Docker (and, for decent
  build-context performance, a Linux-side filesystem if on WSL2) — there is
  no more "clone and run `python main.py`" zero-dependency path, not even
  for `main.py`'s batch CLI mode (which never touched either datastore, and
  so was the one thing the old venv path could still do that this one
  can't do without Docker running). A `docker compose run` invocation has
  more startup latency than a bare `python -m pytest` in an already-warm
  venv — acceptable for a full suite run, more noticeable for a
  single-test edit-run-edit loop; contributors who mind this can still run
  `pytest` directly on a host Python they set up themselves, unsupported.
- **Air-gap bundles are architecture-specific with no fallback.** ADR-0040's
  wheel-based bundle could in principle be rebuilt per-architecture from the
  same wheelhouse layout; a Docker image bundle has no equivalent — a bundle
  built on `x86_64` will not `docker load` on `aarch64`. This is treated as
  an acceptable trade for the operational simplicity gained, since air-gapped
  targets are typically fixed hardware known in advance.

## Validation record (2026-09-19)

| Check | Result |
|---|---|
| `bash -n` on `setup.sh`, `scripts/offline_lib_docker.sh`, `scripts/package_offline_docker.sh`, `scripts/check_offline_bundle_docker.sh` | clean |
| `docker compose config -q` (full file, all profiles resolvable) | clean |
| `docker compose build app` | clean build, image `ctiparsor:local` produced |
| `docker compose run --rm dev pytest tests/ --ignore=tests/eval_pipeline.py -q` | 1128 passed, 1 skipped, **249 errors** — all `psycopg.OperationalError: password authentication failed`, traced to a `pg-data` volume left over from an earlier session (created 2026-09-16) whose baked-in password predates the current `.secrets/db_password`; not a defect in this change (the same failure is already documented in `docs/docker.md`'s troubleshooting table, predating this ADR) — fixing it means dropping that volume, which needs the maintainer's confirmation (destructive) before it can be re-run to a clean pass |
| `docker compose run --rm dev cli input/<sample>.txt --output output/<name>.json` | **passed** — valid STIX bundle (46 objects) written to the host `./output/`, confirming the bind-mount-replaces-symlinks design; confirms ADR-0053's claim that `main.py` touches neither datastore, since this ran with `postgres` stopped |
| `docker compose --profile dev up -d frontend-dev` + browser check at `http://localhost:5173` | **passed** — Vite HMR WebSocket connected, every module/asset served 200 OK through the bind mount; the only failing request was `/api/jobs` → 500, expected since `app` was not started for this check (proves `VITE_API_PROXY_TARGET=http://app:8000` is wired, not a frontend-dev defect) |
| Full air-gap round trip (`package_offline_docker.sh` → transfer to a network-isolated machine → `setup.sh --offline=<dir>` → `check_offline_bundle_docker.sh`) | **not run** — needs a second, genuinely network-isolated machine, which this session does not have access to; the mechanism is implemented and each piece (`docker save`/`load`, the volume tar round trip, `pg_dump`/`pg_restore`) is individually a pattern already used and tested elsewhere in this repo, but the full chain has not been exercised end-to-end |

This record is intentionally honest about what has and has not been run —
the remaining pending items are tracked as immediate follow-up work, not
assumed to pass.
