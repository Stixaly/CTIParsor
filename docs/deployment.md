# Deploying CTIParsor for several analysts

This page covers putting CTIParsor on a Linux machine that more than one person
can reach. It assumes `setup.sh` has already run successfully.

Read [section 2](#2-what-no-authentication-actually-means) before you change the
bind address. It is short, and it is the part that decides which of the three
options below you should pick.

## What you are actually deploying

One process. `api/main.py` mounts the built React app at `/` and the API at
`/api/*`, so a single uvicorn process serves the whole product on a single port.
The frontend calls the API with relative URLs.

Two consequences worth knowing up front:

- **There is no separate frontend server to deploy.** `make api` builds
  `frontend/dist/` and uvicorn serves it. If `frontend/dist/` is missing, the
  root URL returns a "not built" placeholder instead of the UI.
- **There is no CORS to configure.** Same origin, always. The
  `allow_origins=["*"]` in `api/main.py` exists for local development against
  the Vite dev server on a different port; it is not load-bearing in production.

## 1. Choosing the bind address

The listen address comes from `.env`:

```dotenv
API_HOST=0.0.0.0
API_PORT=8000
```

Then start it with the launcher, which reads `.env` before opening the socket:

```bash
make api
```

`API_HOST` defaults to `127.0.0.1` — reachable only from the machine itself.
`0.0.0.0` accepts connections on every interface; you can also name a single
interface address, e.g. `API_HOST=10.0.5.12`, which is usually what you want.

> **`uvicorn api.main:app` ignores `.env`.** uvicorn parses its own arguments
> before any `.env` is read, so it always binds to its own 127.0.0.1 default.
> Use `python run_api.py` (which is what `make api` runs), or pass `--host`
> yourself. This is why `API_HOST` exists at all.

Two details that matter once this runs as a service:

- **`.env` is found next to `run_api.py`, not in the working directory.** You
  can start it from anywhere and it still reads the repository's `.env`.
- **An already-set environment variable wins over `.env`.** `.env` fills in what
  the environment has not already said, so an `Environment=API_PORT=...` line in
  a systemd unit silently overrides the file. Pick one place and stay there.

On startup the launcher prints where it is listening, and prints a warning block
if that address is reachable from other machines.

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

No configuration change at all. Leave `API_HOST=127.0.0.1` and have each analyst
forward the port:

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
API_HOST=10.0.5.12
API_PORT=8000
```

```bash
sudo ufw allow from 10.0.5.0/24 to any port 8000 proto tcp
```

Simple, and it keeps the port off every other network. It is still plaintext
HTTP with no login, so anyone already inside that subnet has full access.

### Option C — nginx in front, with TLS and a password

The practical answer for a small team. Keep the app on loopback and let nginx
own the network:

```dotenv
API_HOST=127.0.0.1
API_PORT=8000
```

```nginx
server {
    listen 443 ssl;
    server_name cti.example.internal;

    ssl_certificate     /etc/ssl/certs/cti.crt;
    ssl_certificate_key /etc/ssl/private/cti.key;

    auth_basic           "CTIParsor";
    auth_basic_user_file /etc/nginx/cti.htpasswd;

    # Reports are uploaded whole; the API rejects anything over 50 MB itself.
    client_max_body_size 50m;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Pipeline progress is a Server-Sent Events stream and a run can take
        # many minutes. Without these, nginx buffers the stream and times the
        # connection out mid-job, so the UI freezes on a running report.
        proxy_buffering    off;
        proxy_read_timeout 3600s;
    }
}
```

Create the password file with `sudo htpasswd -c /etc/nginx/cti.htpasswd alice`.

This gives you TLS and a gate, and it is the only option here where the
credential is something other than "can you route to the port". Note what it
does *not* give you: nginx authenticates people, but the application still has
one shared workspace behind it. Everyone who logs in still sees, and can delete,
everyone else's reports. Real per-user isolation would need authentication
inside the application — a `user_id` on jobs and a check on every route. None of
that exists today.

`api/routes/progress.py` already sends `X-Accel-Buffering: no`, which nginx
honours, so SSE would survive even without `proxy_buffering off`. Both are set
because the header only helps for responses that actually reach nginx.

## 4. Running it as a service

`make api` runs in the foreground and dies with your shell. For anything shared,
use systemd:

```ini
# /etc/systemd/system/ctiparsor.service
[Unit]
Description=CTIParsor
After=network.target

[Service]
Type=simple
User=ctiparsor
WorkingDirectory=/opt/ctiparsor
ExecStart=/opt/ctiparsor/.venv/bin/python run_api.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now ctiparsor
```

Build the frontend once before enabling the unit — the service does not build
it:

```bash
make frontend-build
```

`run_api.py` resolves its own directory, so it works regardless of the working
directory systemd hands it.

## 5. Workers and memory

`API_WORKERS` defaults to `1`. **Leave it there unless you have measured the
memory.**

The concurrent-job limit (`WORKER_MAX_CONCURRENT`) is a counter held in the
process, not in the database. With four workers you get four independent
counters, so the effective limit — and peak model memory, which is what actually
saturates the machine — is multiplied by four. The launcher prints a reminder
when you raise it.

More workers do not help the common case anyway: each report already runs in its
own subprocess, so the API process is not where the time goes.

**Set `WORKER_MAX_CONCURRENT` from measured RAM, not from the default.** The
default of 10 overcommits badly: each concurrent report holds roughly 4.4 GB
resident, almost all of it the GLiNER weights, so ten in parallel ask for ~44 GB.
Below about 48 GB of host RAM the OS OOM killer sets the real limit for you.
`scripts/measure_cold_start.py` measures the figure on your host and suggests a
value:

```bash
python scripts/measure_cold_start.py
```

It exits non-zero and declines to suggest anything if a step fails — a partial
measurement understates the peak RSS and would recommend a pool several times
too large.

### What happens when every slot is busy

A report submitted while all slots are taken is **queued, not dropped**. It sits
at status `queued`, and the watcher thread of whichever report finishes next
claims it and starts it. Nothing polls; there is no broker and no second daemon.

`API_QUEUE_MAX_DEPTH` (default 50, `0` = unbounded) caps the wait. Past it, the
upload is refused with HTTP 503 rather than accepted and quietly discarded — an
analyst who gets a 503 knows to retry, where a report accepted and never run
looks finished.

Jobs left `processing` by a crash or a redeploy are returned to the queue when
the API starts, so a restart mid-report costs the run, not the submission.

## 6. Before you expose it

- [ ] `frontend/dist/` exists (`make frontend-build`)
- [ ] `.env` is not world-readable — it holds LLM API keys (`chmod 600 .env`)
- [ ] `cti_stix.db` sits on a native Linux filesystem, not a mounted Windows
      drive — every page fault across a 9p/DrvFs mount is paid at query time,
      and no amount of tuning recovers it
- [ ] You have decided which of options A/B/C applies, and everyone who can
      reach the port is someone you would let delete any report
- [ ] Backups: `cti_stix.db` holds every report and every bundle

## See also

- [SECURITY.md](../SECURITY.md) — full security posture and threat model
- [docs/adr/](adr/) — architecture decisions, including the sandboxing posture
  for URL ingestion (ADR-0029)
