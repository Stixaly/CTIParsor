"""Start the API server with the bind address taken from `.env`.

`uvicorn api.main:app` parses its own arguments before any `load_dotenv()` can
run, so the listen address could not be configured from `.env` at all — it was
hard-wired to uvicorn's 127.0.0.1 default. This entry point loads `.env` first,
then starts uvicorn programmatically, so the same file that configures the
pipeline also configures the socket.

    python run_api.py

The default stays 127.0.0.1: binding to every interface is opt-in, because the
application has no authentication of any kind.
"""
from __future__ import annotations

import os
from pathlib import Path

import uvicorn
from dotenv import load_dotenv

from pipeline.env_flags import env_bool

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

# Hosts that only ever accept connections from the machine itself. "0.0.0.0" and
# "::" are deliberately absent: they are the wildcards that expose the port.
LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})

# Absolute, because the launcher must work from any working directory: under
# systemd the cwd is not the repository. uvicorn's reload and multi-worker
# modes re-import the app in fresh processes, which need this on sys.path.
REPO_ROOT = str(Path(__file__).resolve().parent)


def _resolve_host() -> str:
    raw = os.getenv("API_HOST")
    if raw is None:
        return DEFAULT_HOST
    stripped = raw.strip()
    if not stripped:
        return DEFAULT_HOST
    return stripped


def _resolve_port() -> int:
    raw = os.getenv("API_PORT")
    if raw is None:
        return DEFAULT_PORT
    stripped = raw.strip()
    if not stripped:
        return DEFAULT_PORT
    try:
        port = int(stripped)
    except ValueError:
        raise SystemExit(f"API_PORT must be an integer between 1 and 65535, got: {raw!r}") from None
    if port < 1 or port > 65535:
        raise SystemExit(f"API_PORT must be an integer between 1 and 65535, got: {raw!r}")
    return port


def _resolve_workers() -> int:
    raw = os.getenv("API_WORKERS")
    if raw is None:
        return 1
    stripped = raw.strip()
    if not stripped:
        return 1
    try:
        workers = int(stripped)
    except ValueError:
        raise SystemExit(f"API_WORKERS must be an integer >= 1, got: {raw!r}") from None
    if workers < 1:
        raise SystemExit(f"API_WORKERS must be an integer >= 1, got: {raw!r}")
    return workers


def is_exposed(host: str) -> bool:
    """Return True if binding to *host* makes the port reachable from other machines."""
    h = host.strip().lower()
    if h in LOOPBACK_HOSTS:
        return False
    if h.startswith("127."):
        return False
    return True


def exposure_warning(host: str, port: int) -> list[str]:
    """Return warning lines if the bind exposes the port to other machines."""
    if not is_exposed(host):
        return []
    return [
        "",
        "  " + "=" * 68,
        f"  WARNING: listening on {host}:{port} — reachable from other machines.",
        "  " + "=" * 68,
        "  This application has no authentication, no sessions and no job",
        "  ownership. Anyone who can reach this port can read, edit, finalise and",
        "  delete every report, change the pipeline policy, and submit URLs for",
        "  the server to fetch.",
        "",
        "  Only do this on a trusted network. See docs/deployment.md.",
        "  " + "=" * 68,
        "",
    ]


def _worker_warning(workers: int) -> list[str]:
    if workers <= 1:
        return []
    return [
        f"  NOTE: API_WORKERS={workers}. The concurrent-job limit is a per-process",
        "  counter, so WORKER_MAX_CONCURRENT is multiplied by the worker count and",
        "  so is peak model memory. Raise workers only if you have measured the RAM.",
    ]


def main() -> int:
    """Load `.env`, resolve settings, print warnings, and start uvicorn."""
    load_dotenv()
    host = _resolve_host()
    port = _resolve_port()
    workers = _resolve_workers()
    reload = env_bool("API_RELOAD", default=False)
    if reload and workers > 1:
        workers = 1
        print("  NOTE: API_RELOAD is on, forcing API_WORKERS=1 (uvicorn cannot reload with multiple workers).")
    print(f"  CTIParsor API → http://{host}:{port}")
    for line in exposure_warning(host, port):
        print(line)
    for line in _worker_warning(workers):
        print(line)
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        workers=workers,
        reload=reload,
        app_dir=REPO_ROOT,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
