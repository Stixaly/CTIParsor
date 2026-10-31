# Deploying CTIParsor for several analysts

This page covers putting CTIParsor on a Linux machine that more than one person
can reach. Docker is the only supported way to run it (ADR-0054) — this page
assumes `bash setup.sh` has run and `docker compose build` has produced the
image; see [docs/docker.md](docker.md) for the container reference.

Read [section 2](#2-what-no-authentication-actually-means) before you change the
bind address. It is short, and it is the part that decides which of the three
options below you should pick.

## What you are actually deploying

One process. `api/main.py` mounts the built React app at `/` and the API at
`/api/*`, so a single uvicorn process (inside the `app` container) serves the
whole product on a single port. The frontend calls the API with relative URLs.

Two consequences worth knowing up front:

- **There is no separate frontend server to deploy.** The image's build stage
  builds `frontend/dist/` and the `app` container serves it — nothing to build
  or ship separately.
- **There is no CORS to configure.** Same origin, always: `api/main.py`
  sets no CORS header at all (an earlier `allow_origins=["*"]` was removed),
  and the Vite dev server proxies `/api` so development is same-origin too.
- **The API answers only to the hosts in `API_ALLOWED_HOSTS`** (default
  `localhost,127.0.0.1,[::1]`) and refuses cross-site writes — the DNS
  rebinding and CSRF defences an app without authentication needs. Every
  option below that exposes the app on another name or address says what to
  put there; forgetting it shows as `400 Invalid host header`.

## 1. Choosing the bind address

The listen address is a compose variable, not an app one — `compose.yaml`
forces `API_HOST=0.0.0.0`/`API_PORT=8000` **inside** the container (see
[docs/docker.md §Forced Values](docker.md#forced-values)); what you actually
control is which host address/port the `app` service's port is published on:

```dotenv
# .env
CTI_BIND=0.0.0.0
CTI_PORT=8000
```

```bash
docker compose up -d
```

`CTI_BIND` defaults to `127.0.0.1` — reachable only from the machine itself.
`0.0.0.0` accepts connections on every interface; you can also name a single
interface address, e.g. `CTI_BIND=10.0.5.12`, which is usually what you want.
`docker compose logs -f app` shows where uvicorn is listening (always
`0.0.0.0:8000` inside the container) — the address that matters is the one
`CTI_BIND` publishes on the host, shown by `docker compose ps`.

## 2. What "no authentication" actually means

CTIParsor has no authentication, no sessions, and no per-user ownership of
anything. There is no `user_id` column, and no route checks who is calling.
Every analyst who can reach the port shares **one** workspace:

- every report, entity and relationship is visible to everyone
- anyone can edit, finalise or **delete** any job, including someone else's
- anyone can change the pipeline policy, which affects everyone's next run
- `POST /api/ingest/url` makes the server fetch a URL that the caller chooses
- `POST /api/settings/corpora` and `/sync` make the server clone git repos

This is not a bug list — it is what a single-user tool looks like once several
people can reach it. Whether that is acceptable depends entirely on who can
route to the port. Among trusted colleagues on a segmented network it is often
fine, and the shared workspace is arguably the point. On anything wider it is
not.

**Do not put this on the internet as-is.** Options B and C below are the two
ways to narrow who can reach it.

## 3. Three ways to run it

### Option A — stay on loopback, reach it over SSH

No configuration change at all. Leave `CTI_BIND=127.0.0.1` (the default) and
have each analyst forward the port:

```bash
ssh -N -L 8000:127.0.0.1:8000 analyst@cti-host
```

They then open `http://127.0.0.1:8000` on their own machine. Access is governed
by SSH, which you already administer, and nothing new listens on the network.

This is the safest option and the cheapest to set up. Its limit is comfort: each
analyst needs an SSH account and has to remember the tunnel.

### Option B — bind to a private interface, filter with the firewall

Pick the interface facing your analysts and restrict it to their subnet.

```dotenv
# .env
CTI_BIND=10.0.5.12
CTI_PORT=8000
```

```bash
docker compose up -d
sudo ufw allow from 10.0.5.0/24 to any port 8000 proto tcp
```

Simple, and it keeps the port off every other network. It is still plaintext
HTTP with no login, so anyone already inside that subnet has full access.

### Option C — TLS + password proxy in front

The practical answer for a small team, and already built into the compose
stack — the `proxy` profile (`nginx-unprivileged`) in front of `app`, both on
loopback until the proxy takes over the exposed port:

```dotenv
# .env
CTI_BIND=127.0.0.1
CTI_PORT=8000
FORWARDED_ALLOW_IPS=*
```

```bash
mkdir -p docker/nginx/certs
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout docker/nginx/certs/cti.key -out docker/nginx/certs/cti.crt \
  -subj '/CN=cti.example.internal'
htpasswd -nBC 12 alice > docker/nginx/htpasswd   # bcrypt, prompts for the password (apt install apache2-utils)
chmod 644 docker/nginx/certs/cti.crt docker/nginx/htpasswd
chmod 640 docker/nginx/certs/cti.key && sudo chown 0:101 docker/nginx/certs/cti.key
docker compose --profile proxy up -d       # https://<host>:8443
```

Without `htpasswd`, `printf 'alice:%s\n' "$(openssl passwd -6)"` writes a
salted SHA-512-crypt entry, which nginx also reads. Do not use
`openssl passwd -apr1`: APR1 is built on MD5. An existing `$apr1$` line still
works; replace it. TLS 1.2 offers only forward-secret ECDHE suites
(`docker/nginx/default.conf`); they need an RSA or ECDSA key, which the
command above makes.

This gives you TLS and a gate, and it is the only option here where the
credential is something other than "can you route to the port". Note what it
does *not* give you: nginx authenticates people, but the application still has
one shared workspace behind it. Everyone who logs in still sees, and can delete,
everyone else's reports. Real per-user isolation would need authentication
inside the application — a `user_id` on jobs and a check on every route. None of
that exists today.

The nginx config, with the SSE-buffering settings it needs (`proxy_buffering off`,
`proxy_read_timeout 3600s`), is `docker/nginx/default.conf`, already wired into
`compose.yaml`. The `FORWARDED_ALLOW_IPS` reasoning is in
[docs/docker.md §Reaching it from other machines](docker.md#reaching-it-from-other-machines).

The proxy accepts a request body of up to 72 MB (`client_max_body_size`). That covers
the largest upload with enrichment on: a 50 MB report, a 20 MB STIX baseline and the
64 KB form. A proxy in front of the API must accept at least 70 MB plus 64 KB too
([api.md](api.md#how-large-a-request-may-be)).

## 4. Running it as a service

Every compose service already declares `restart: unless-stopped` — `app`,
`worker` and `postgres` come back on their own after a crash or a host
reboot (as long as the Docker daemon itself is enabled at boot, the default
on most distributions: `sudo systemctl enable docker`). No systemd unit is
needed for the application itself:

```bash
docker compose up -d
```

If you want one anyway — e.g. to gate startup on something else, or to get
`systemctl status` for the whole stack — wrap `docker compose` rather than
the Python process directly:

```ini
# /etc/systemd/system/ctiparsor.service
[Unit]
Description=CTIParsor (docker compose)
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=true
WorkingDirectory=/opt/ctiparsor
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now ctiparsor
```

## 5. Workers and memory

Since ADR-0046 the pipeline can run in a process of its own. `CTIPARSOR_ROLE`
decides:

| Role | Who runs the pipeline | Use |
|---|---|---|
| `all` | the API process, through a queue loop in a background thread | one machine, one process — not used by the compose stack |
| `api` | nobody in this process; the routes only queue the report | `app`'s role in `compose.yaml` — reports are processed by separate `worker` containers |
| `worker` | this process, `python -m api.queue_loop`, in the foreground | the `worker` service's role in `compose.yaml`, one or more containers, each with its own memory budget |

The queue is the `jobs` table: a worker claims the oldest `queued` row with an
atomic conditional update, stamps it with its id, and refreshes
`heartbeat_at` every `WORKER_HEARTBEAT_S` (30 s) while the report runs. A
`processing` row whose stamp is older than `WORKER_LEASE_TIMEOUT_S` (180 s)
belonged to a worker that died and is requeued by whichever worker sees it
first; Stage 3 checkpoints make the restart cheap. Several workers therefore
share one PostgreSQL job store safely — a local SQLite file could not have
supported this, which is why the compose stack uses PostgreSQL (and, since
ADR-0053, why PostgreSQL is the only datastore CTIParsor supports at all).
All workers share the same `cti-state` volume as the API (uploads/output).

`app` and `worker` already carry the right `CTIPARSOR_ROLE` in
`compose.yaml` — nothing to configure. Scale workers with:

```bash
docker compose up -d --scale worker=2
```

`API_WORKERS` defaults to `1`. **Leave it there unless you have measured the
memory.**

The concurrent-job limit (`WORKER_MAX_CONCURRENT`) is a counter held in the
process, not in the database. With four workers you get four independent
counters, so the effective limit — and peak model memory, which is what actually
saturates the machine — is multiplied by four. The launcher prints a reminder
when you raise it.

More workers do not help the common case anyway: each report already runs in its
own subprocess, so the API process is not where the time goes.

**`WORKER_MAX_CONCURRENT` defaults to 1**, for a host install as for the
compose worker. Each concurrent report holds roughly 4.4 GB resident, almost all
of it the GLiNER weights: the former default of 10 asked for ~44 GB, and below
about 48 GB of host RAM the OS OOM killer set the real limit by killing the
workers. Raise it only from a measurement, and in the compose stack raise
`CTI_WORKER_MEMORY` by 4.4 GB per extra report.
`scripts/measure_cold_start.py` measures the figure on your host and suggests a
value:

```bash
docker compose run --rm dev python scripts/measure_cold_start.py
```

It exits non-zero and declines to suggest anything if a step fails — a partial
measurement understates the peak RSS and would recommend a pool several times
too large.

### What happens when every slot is busy

A report submitted while all slots are taken is **queued, not dropped**. It sits
at status `queued`; the loop claims it when a report finishes or on its next
poll (`WORKER_POLL_S`, 2 s). There is no broker: the table is the queue.

`API_QUEUE_MAX_DEPTH` (default 50, `0` = unbounded) caps the wait. Past it, the
upload is refused with HTTP 503 rather than accepted and quietly discarded — an
analyst who gets a 503 knows to retry, where a report accepted and never run
looks finished.

Jobs left `processing` by a crash or a redeploy: on a host install
(`CTIPARSOR_ROLE=all`), the API requeues those whose lease has expired when it
starts. In the container stack the API requeues nothing; a worker requeues the job
once its lease expires (`WORKER_LEASE_TIMEOUT_S`, 180 s by default). Either way, a
restart mid-report costs the run, not the submission.

## 6. Before you expose it

- [ ] `docker compose build` has run — it builds `frontend/dist/` as part of the image
- [ ] `.env` is not world-readable — it holds LLM API keys (`chmod 600 .env`)
- [ ] `DATABASE_URL` is set and reachable (mandatory since ADR-0053 — no
      SQLite fallback); if PostgreSQL's own data directory sits on a mounted
      Windows drive under WSL2, move it to native Linux storage the same way
      `cti_stix.db` used to need — every page fault across a 9p/DrvFs mount
      is paid at query time, and no amount of tuning recovers it
- [ ] You have decided which of options A/B/C applies, and everyone who can
      reach the port is someone you would let delete any report
- [ ] Backups: a dump of the database (both stores, ADR-0053) AND an archive
      of the `cti-state` volume (uploaded sources, exported bundles), taken
      together with `app` and `worker` stopped, and one restore tried into an
      empty project — see [docs/docker.md](docker.md#data-and-backups)

## 7. Air-gapped hosts

Nothing above assumes internet access at run time — the pipeline only calls
the LLM endpoint in `.env`, and the models, indexes and corpora are local
files (or reachable at `http://ollama:11434` when the `ollama` profile is
used, itself on no external network). What needs the network is the
*install*, and ADR-0054 packages it around Docker (supersedes ADR-0040's
wheel/deb bundle):

1. On a connected machine with Docker, the **same CPU architecture** as the
   target, in a clean checkout (no uncommitted changes), run
   `bash scripts/package_offline_docker.sh` (add `--with-llm[=MODEL[,MODEL...]]`
   to bundle local Ollama models, and `--with-proxy` to bundle the TLS front).
   It builds the image, saves every image the
   stack needs, runs `bootstrap --strict` locally to populate the NLP-model/corpus
   cache and the rule store, exports both (a volume tar and a `pg_dump`), and
   packs `dist/cti-parsor-offline-docker-<rev>-<arch>.tar` (+ `.sha256`).
   `--strict` stops the build when a model does not download or does not load
   from the cache with the network off, or when a corpus does not sync. The
   packager downloads even when `.env` says offline: it runs the build with
   `HF_HUB_OFFLINE=0` and `TRANSFORMERS_OFFLINE=0`. The `pg_dump` covers the
   `public` schema, without large objects. It has the schema of every table, but
   the data only of the six rule-store tables and of `schema_migrations`: the
   reports stay on the packaging machine. The packager stops if the table of
   contents of the dump shows the data of any other table, of another schema, or
   a large object. Then archive the source tree at the same commit:
   `git archive --format=tar.gz -o ctiparsor-src.tar.gz HEAD`.
2. Replay it before you carry it over, on a machine you're willing to cut
   network access to: `tar xf
   dist/cti-parsor-offline-docker-*.tar && bash
   scripts/check_offline_bundle_docker.sh offline` loads the images,
   restores the volumes/database, and runs `scripts/docker_smoke.sh` against
   the result plus a rule-count check. The check reads `.env` first, and it
   starts the `ollama` service and checks that each bundled model is in it.
   With a model in the bundle, `.env` must name it (`LLM_PROVIDER=ollama`,
   `OLLAMA_MODEL`, `OLLAMA_BASE_URL=http://ollama:11434`). Without one,
   `LLM_PROVIDER` must be `ollama`, `vllm` or `lmstudio`; `--allow-no-llm`
   lets a bundle with no model through, and then `--job` requires only stages
   2c, 2d and 2e. With `--job`, the job's stage report must show each stage in
   `SMOKE_REQUIRED_STAGES` (default `2c 2d 2e 3`) as run, unless the
   configuration turned it off. The restore refuses a database that holds a row
   outside the rule store, and `--job` leaves a job: a second run on the same host
   needs `docker compose down -v` first, or `OFFLINE_FORCE_RESTORE=1`.
3. On the target, with `ctiparsor-src.tar.gz` and the bundle in one
   directory, check the transfer with `sha256sum -c
   cti-parsor-offline-docker-*.tar.sha256`, then
   `mkdir ctiparsor && tar xzf ctiparsor-src.tar.gz -C ctiparsor`,
   `cd ctiparsor`, `tar xf ../cti-parsor-offline-docker-*.tar`, then
   `bash setup.sh --offline=offline`. Checksums and the image architecture are
   verified before anything is loaded; `docker compose up -d` is the only step
   left afterward — no `bootstrap` run needed, the data is already restored.
   The archives `cti-cache.tar.gz` and, when the bundle has a model,
   `ollama-models.tar.gz` are required: a missing one stops the install. The
   restore also stops on a database that holds a row outside the rule store (see
   below).
   The source tree must be at the bundle's revision (`BUNDLE_GIT_REV` in
   `offline/bundle.env`); nothing checks it.

On a host with the classic image store (overlay2 without the containerd
snapshotter), `setup.sh --offline` writes a `compose.override.yaml` next to
`compose.yaml` that names the plain tag of each service whose pinned image
came from the bundle, since `docker load` there restores the tag but not the
digest. Compose reads it on every run in that directory, so delete it once the
host can pull, to go back to the digest pins. `docker info` shows the store:
`driver-type: io.containerd.snapshotter.v1` under Storage Driver means the
containerd store, where no override is needed. A file the script did not write
is never overwritten; setup.sh stops and prints the lines to merge into it.

`setup.sh --offline` writes `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` into
`.env` when they are absent. The worker loads two Hugging Face models on every
report, and without these switches a Hub lookup there fails or stalls. Measured
on Docker 29.9.2, loading those two models took 20 s online, 156 s with the
connection refused, over 15 minutes (killed) with packets dropped, and 40 s
with packets dropped and the switches set.

The bundled Ollama model, if any, runs as the `ollama` compose profile
(`docker compose --profile ollama up -d`) — no separate systemd unit, no
host-installed `ollama` binary. Its CPU limit, context window and GPU settings
are in [docs/configuration.md](configuration.md#ollama-local-free). Models and
images are frozen at the bundle's build date (`offline/bundle.env` says when),
so a security update needs a new bundle.

`setup.sh --offline` does not restore over a database that holds a row outside the
rule store (a report, a review decision, an override, a cache): it stops before
the restore, because `pg_restore --clean` drops and recreates every table.
`OFFLINE_FORCE_RESTORE=1` overrides that and erases those rows in the database. The `cti-state` volume (uploads and outputs) is not touched. Images,
models and code have no in-place update that keeps the reports; the corpora do
(below). Back up first: the database dump and the `cti-state` archive of
[docs/docker.md](docker.md#data-and-backups); nothing merges that backup back
in.

Corpora can be refreshed without losing reports:
`scripts/package_offline_corpora.sh` on the connected machine, then
`scripts/update_offline_corpora.sh` on the target
(the commands are in the README's offline section). It replaces `corpora/` in
the `cti-cache` volume and rebuilds the rule store from the clones, reading them
from disk. The models and the job store are not touched. Run it while no report
is running, because the rebuild commits one statement at a time.

## 8. PostgreSQL for both stores

`DATABASE_URL` is mandatory (ADR-0053 removed SQLite support entirely — the
API and the CLI test suite both refuse to start without it). Point it at a
real PostgreSQL server:

```dotenv
DATABASE_URL=postgresql://ctiparsor@db.example.internal:5432/ctiparsor
PGPASSWORD=...
```

An install still on the pre-ADR-0053 single-file `cti_stix.db` layout copies
its existing rows once, with **both** scripts (they cover different tables —
job-store rows and rule-store rows respectively):

```bash
docker compose run --rm dev python scripts/migrate_jobs_to_postgres.py --dry-run    # counts only
docker compose run --rm dev python scripts/migrate_jobs_to_postgres.py              # one transaction, all or nothing
docker compose run --rm dev python scripts/migrate_rules_to_postgres.py --dry-run   # counts only
docker compose run --rm dev python scripts/migrate_rules_to_postgres.py             # one transaction, all or nothing
```

The detection-rule corpus now lives in the same PostgreSQL database as the
job store — `make detection-index` still rebuilds it, just against
PostgreSQL instead of a local SQLite file. Size the server's
`max_connections` for uvicorn's thread pool plus one connection per running
report; the default 100 is ample for one instance. The compose stack does
all of this for you with a hardened `postgres` service — see
[docs/docker.md](docker.md).

## See also

- [docs/docker.md](docker.md) — the container reference this page builds on
- [SECURITY.md](../SECURITY.md) — full security posture and threat model
- [docs/adr/](adr/) — architecture decisions, including the sandboxing posture
  for URL ingestion (ADR-0029) and the Docker-only install/dev/air-gap
  decision (ADR-0054)
