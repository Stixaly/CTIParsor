import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

# Initialize logging before importing other modules
from api.logging_config import clear_request_id, get_logger, set_request_id, setup_logging
from pipeline.regex_safety import compile_pattern

setup_logging()
logger = get_logger(__name__)

from api.db import get_conn, init_db
from api.paths import output_dir, uploads_dir

# Rate limiter must be defined before routes are imported because
# api/routes/upload.py does `from api.main import limiter` at module level.
limiter = Limiter(key_func=get_remote_address)

from api.routes import (
    coverage,
    entities,
    ingest,
    jobs,
    overrides,
    policy,
    progress,
    queue,
    relationships,
    settings,
    thresholds,
    upload,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hook (replaces the deprecated @app.on_event("startup")).

    Startup: create the DB schema and ensure the working directories exist.
    Tests patch `api.main.init_db`; the patch still applies here because the
    name is resolved from the module namespace at call time.
    """
    # A bad STIX_TLP stops the process here, not at the first bundle — a
    # marking is never guessed (ADR-0073).
    from pipeline.stage4_stix_mapping import tlp_default
    logger.info("[startup] default TLP: %s", tlp_default())
    init_db()
    uploads_dir().mkdir(parents=True, exist_ok=True)
    output_dir().mkdir(parents=True, exist_ok=True)
    # Who runs the pipeline depends on CTIPARSOR_ROLE (ADR-0046).  `all`, the
    # host-install default: this process, through the queue loop in a background
    # thread — and a job left `processing` at boot is an orphan of a restart,
    # since nothing else could have been running it.  `api`: worker containers
    # own the queue; this process only enqueues, and must NOT requeue, because
    # a `processing` row is very likely a job a worker is running right now.
    from api import queue_loop
    _role = queue_loop.role()
    if _role == "all":
        # Unconditional requeue (touch every `processing` row, not just ones
        # whose lease expired) would only be safe if this were provably the
        # ONE process that could have left a job `processing`. PostgreSQL
        # (ADR-0045, ADR-0053) exists specifically so multiple independent
        # `role=all` replicas can share one DATABASE_URL -- this process can
        # never rule out a sibling still running a job on its own, so it
        # always falls back to the lease-based requeue (only touches a row
        # whose heartbeat has actually expired), the same requeue a
        # `worker`-role container's own startup uses.
        queue_loop.requeue_orphans()
        queue_loop.start_embedded()
    else:
        if _role == "worker":
            logger.warning("[startup] CTIPARSOR_ROLE=worker on the API process - treated as 'api'; "
                           "run `python -m api.queue_loop` for the worker")
        logger.info("[startup] CTIPARSOR_ROLE=%s - jobs are processed by worker containers", _role)
    # A filesystem check only, so a missing browser is a log line at boot
    # instead of a 500 on the first URL capture a user tries. Run off-thread:
    # Playwright's sync API refuses to run on a thread with a running asyncio
    # loop, which this coroutine is on — it would otherwise always fail with
    # "Sync API inside the asyncio loop" instead of the real answer.
    import asyncio

    from pipeline.web_capture import check_chromium_installed
    chromium_hint = await asyncio.to_thread(check_chromium_installed)
    if chromium_hint is not None:
        logger.warning("[startup] %s", chromium_hint)
    yield
    # Shutdown: stop the embedded queue loop (a no-op unless role `all` started
    # one); its running subprocesses are children of this process and end with
    # it, and the lease requeues their jobs for the next start.
    from api import queue_loop as _ql
    _ql.stop_embedded()


app = FastAPI(title="CTI to STIX", version="1.0.0", lifespan=lifespan)

# Add rate limiting middleware
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."},
    )

# Request ID middleware for tracing
_REQUEST_ID_RE = compile_pattern(r"^[a-zA-Z0-9\-_]{1,64}$")

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add a unique request ID to each request for tracing."""
    raw_id = request.headers.get("x-request-id", "")
    # Validate format before using in logs to prevent log injection via header
    request_id = raw_id if _REQUEST_ID_RE.fullmatch(raw_id) else None
    set_request_id(request_id)
    logger.debug(f"Request started: {request.method} {request.url}")

    try:
        response = await call_next(request)
        return response
    finally:
        clear_request_id()
        logger.debug(f"Request completed: {request.method} {request.url}")


# ---------------------------------------------------------------------------
# Who may talk to this API from a browser (audit B 8.2.1).
#
# The app has no authentication, and the same-origin policy below only stops a
# page on another origin from READING responses — it does not stop the
# browser from SENDING the request.  Two attacks follow from that alone:
#   * CSRF: a page the analyst visits submits a multipart form to /api/upload
#     (a "simple" request, no preflight) and a job is created — LLM cost,
#     a polluted workspace, a prompt-injection vector;
#   * DNS rebinding: the attacker's page points its own hostname at
#     127.0.0.1 and then calls this API as *same origin* — reads and edits
#     everything, TLP:RED reports included, even over an SSH tunnel.
# `TrustedHostMiddleware` closes rebinding: a request whose Host header is
# not one of API_ALLOWED_HOSTS gets 400 before any handler.  The write guard
# closes CSRF: a mutating request a browser marks as cross-site
# (`Sec-Fetch-Site`) or stamps with a foreign `Origin` gets 403.  Neither
# touches curl, scripts or the nginx `proxy` profile (which forwards Host),
# and a browser request from this app's own page carries a same-origin
# `Origin` or no `Origin` at all.
# ---------------------------------------------------------------------------

def allowed_hosts() -> list[str]:
    """Hostnames this API answers to: API_ALLOWED_HOSTS, comma-separated, port
    ignored; "*" disables the check (nothing safer than the network then).
    The public name behind a proxy, or the address API_HOST=0.0.0.0 is
    reached on, has to be listed — see docs/deployment.md."""
    raw = os.environ.get("API_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]")
    hosts = [h.strip().lower() for h in raw.split(",") if h.strip()]
    return hosts or ["localhost", "127.0.0.1", "[::1]"]


_ALLOWED_HOSTS = allowed_hosts()
_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _host_allowed(hostname: str | None) -> bool:
    if "*" in _ALLOWED_HOSTS:
        return True
    h = (hostname or "").lower()
    for pattern in _ALLOWED_HOSTS:
        if pattern.startswith("*.") and h.endswith(pattern[1:]):
            return True
        if h == pattern or (pattern.startswith("[") and h == pattern.strip("[]")):
            return True
    return False


@app.middleware("http")
async def refuse_cross_site_writes(request: Request, call_next):
    """A browser on another origin can still SEND a request (no CORS needed
    for a multipart POST); refuse it before any handler runs."""
    if request.method in _MUTATING:
        site = request.headers.get("sec-fetch-site")
        if site and site not in ("same-origin", "none"):
            return JSONResponse({"detail": "cross-site request refused"}, status_code=403)
        origin = request.headers.get("origin")
        if origin and origin != "null" and not _host_allowed(urlsplit(origin).hostname):
            return JSONResponse({"detail": "origin not allowed"}, status_code=403)
    return await call_next(request)


# Added last, so it runs first: an unknown Host is answered 400 before the
# request-id middleware or the write guard see it.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_ALLOWED_HOSTS, www_redirect=False)

# No CORSMiddleware: one uvicorn process serves both the API and the built
# React UI (see the SPA mount below), so the browser only ever calls this API
# from the same origin it loaded the page from -- there is no cross-origin
# caller to allow. `frontend/vite.config.ts` proxies `/api` through the Vite
# dev server for the same reason, so this holds in development too. Without
# this middleware the browser's own same-origin policy is what it is
# everywhere else: no `Access-Control-Allow-Origin` header means a page on
# any OTHER origin cannot read this API's responses, even though the app has
# no authentication of its own to stop the request from being sent. A
# previous `allow_origins=["*"]` here defeated that protection for every
# request with no offsetting benefit -- nothing in this codebase makes a
# cross-origin browser call to this API.


# API routes
app.include_router(jobs.router)
app.include_router(upload.router)
app.include_router(ingest.router)
app.include_router(entities.router)
app.include_router(relationships.router)
app.include_router(progress.router)
app.include_router(policy.router)
app.include_router(coverage.router)
app.include_router(settings.router)
app.include_router(queue.router)
app.include_router(thresholds.router)
app.include_router(overrides.router)


@app.get("/api/health")
def health():
    """Liveness AND readiness: the Docker HEALTHCHECK (and the equivalent host
    monitoring) only checks the HTTP status, so a DB outage must fail this
    with a non-200 rather than report "ok" while every real request 500s."""
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1")
    except Exception as exc:
        logger.error(f"[health] job store unreachable: {exc}")
        return JSONResponse({"status": "degraded", "detail": "job store unreachable"}, status_code=503)
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# SPA-aware static file server
# Starlette's stock StaticFiles returns 404 for unknown paths, which breaks
# React Router on hard-refresh (e.g. navigating to /jobs/123 directly).
# This subclass catches those 404s and falls back to index.html so the
# client-side router can take over.
# ---------------------------------------------------------------------------

class _SPAStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):  # type: ignore[override]
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404:
                # Fall back to the SPA entry point
                return await super().get_response("index.html", scope)
            raise


# Serve built frontend (production) — only mounted if dist/ exists
_dist = Path(__file__).parent.parent / "frontend" / "dist"
if _dist.exists():
    app.mount("/", _SPAStaticFiles(directory=str(_dist), html=True), name="static")
else:
    from fastapi.responses import HTMLResponse

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def frontend_not_built():
        return HTMLResponse("""
        <html><body style="font-family:monospace;padding:2rem;background:#0f172a;color:#94a3b8">
        <h2 style="color:#f8fafc">CTI → STIX API is running ✓</h2>
        <p>Frontend not built yet. Run:</p>
        <pre style="background:#1e293b;padding:1rem;border-radius:8px;color:#7dd3fc">
cd frontend && npm ci && npm run build && cd ..
python run_api.py</pre>
        <p>API docs: <a href="/docs" style="color:#60a5fa">/docs</a></p>
        </body></html>
        """, status_code=200)
