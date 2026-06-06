from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from api.db import init_db
from api.routes import jobs, upload, entities, relationships, progress, policy

# Rate limiter configuration
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="CTI to STIX", version="1.0.0")

# Add rate limiting middleware
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."},
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    # allow_credentials must be False when allow_origins=["*"];
    # the browser spec forbids credentials with a wildcard origin.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    # Add security headers
    allow_regular_options_preflight=True,
)

# Import JSONResponse for rate limit handler
from fastapi.responses import JSONResponse


@app.on_event("startup")
def on_startup():
    init_db()
    Path("uploads").mkdir(exist_ok=True)
    Path("output").mkdir(exist_ok=True)


# API routes
app.include_router(jobs.router)
app.include_router(upload.router)
app.include_router(entities.router)
app.include_router(relationships.router)
app.include_router(progress.router)
app.include_router(policy.router)


@app.get("/api/health")
def health():
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
cd frontend && npm install && npm run build && cd ..
uvicorn api.main:app --reload --app-dir .</pre>
        <p>API docs: <a href="/docs" style="color:#60a5fa">/docs</a></p>
        </body></html>
        """, status_code=200)
