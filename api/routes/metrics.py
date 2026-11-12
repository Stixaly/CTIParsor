"""Prometheus metrics at GET /metrics (ADR-0097 item 18, ADR-0048 reversed).

Text format 0.0.4, rendered here with the standard library only: no
`prometheus_client`. The route is left out of the OpenAPI schema.

Access: a client on loopback (127.0.0.0/8 or ::1) gets the metrics. Any other
client gets 403, unless METRICS_TOKEN is set and it sends that token as a
bearer (see `_may_read`). Work item 14 adds the admin token next to it. See
docs/operations.md (*Monitoring and alerts*).

The endpoint answers when the database is down: `ctiparsor_database_up` is 0
and the metrics that need the database are left out. The backup metrics come
from the status file the `backup` service writes (BACKUP_STATUS_FILE); when
that file is missing or unreadable they are left out too.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import math
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import get_args

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from api.db import get_conn
from api.logging_config import get_logger
from api.paths import state_dir
from api.response_models.jobs import JobStatus
from api.routes.queue import _seconds_since, load_workers

router = APIRouter(tags=["metrics"])
logger = get_logger(__name__)

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
BACKUP_STATUS_ENV = "BACKUP_STATUS_FILE"
METRICS_TOKEN_ENV = "METRICS_TOKEN"  # noqa: S105 - the name of the setting, not a secret
DEFAULT_BACKUP_STATUS_FILE = "/app/backup-status/status.json"

# Every status a job can hold (api/response_models/jobs.py). Emitted even at 0,
# so a series does not disappear when its count falls to zero.
JOB_STATUSES: tuple[str, ...] = get_args(JobStatus)
WORKER_STATES = ("busy", "idle", "stale")


@dataclass
class Family:
    """One metric: its HELP text, its type, and its samples (labels, value)."""

    name: str
    help: str
    kind: str = "gauge"
    samples: list[tuple[dict[str, str], float]] = field(default_factory=list)

    def add(self, value: float, **labels: str) -> None:
        self.samples.append((labels, value))


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _escape_help(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\n", "\\n")


def _format_value(value: float) -> str:
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if float(value).is_integer():
        return str(int(value))
    return repr(float(value))


def render(families: list[Family]) -> str:
    """The exposition text: HELP and TYPE lines, then one line per sample."""
    lines: list[str] = []
    for family in families:
        lines.append(f"# HELP {family.name} {_escape_help(family.help)}")
        lines.append(f"# TYPE {family.name} {family.kind}")
        for labels, value in family.samples:
            if labels:
                inner = ",".join(f'{key}="{_escape_label(val)}"' for key, val in labels.items())
                lines.append(f"{family.name}{{{inner}}} {_format_value(value)}")
            else:
                lines.append(f"{family.name} {_format_value(value)}")
    return "\n".join(lines) + "\n"


def _is_loopback(host: str | None) -> bool:
    """True for a client address on loopback. A host name such as "testclient" is not."""
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def _job_families(conn) -> list[Family]:
    counts = {status: 0 for status in JOB_STATUSES}
    for row in conn.execute("SELECT status, COUNT(*) AS n FROM jobs GROUP BY status").fetchall():
        counts[row["status"]] = row["n"]

    jobs = Family("ctiparsor_jobs", "Jobs by status.")
    for status in JOB_STATUSES:
        jobs.add(counts[status], status=status)
    # The failed total is its own metric, for the alert on failures over time.
    failed = Family("ctiparsor_failed_jobs", "Jobs currently in status failed.")
    failed.add(counts["failed"])

    oldest = conn.execute(
        "SELECT created_at FROM jobs WHERE status='queued' ORDER BY created_at ASC LIMIT 1"
    ).fetchone()
    oldest_age = Family(
        "ctiparsor_oldest_queued_job_age_seconds",
        "Seconds since the oldest queued job was created; 0 when the queue is empty.",
    )
    age = _seconds_since(oldest["created_at"]) if oldest else None
    oldest_age.add(age or 0.0)

    workers = load_workers(conn)
    worker_family = Family(
        "ctiparsor_workers", "Worker loops by state: busy, idle, or stale (no heartbeat within the lease)."
    )
    for state in WORKER_STATES:
        worker_family.add(sum(1 for w in workers if w["state"] == state), state=state)

    return [jobs, failed, oldest_age, worker_family]


def _existing_directory(path: Path) -> Path | None:
    """The directory itself, or its nearest existing ancestor (a fresh install has no state dir yet)."""
    for candidate in (path, *path.parents):
        if candidate.is_dir():
            return candidate
    return None


def _disk_families() -> list[Family]:
    try:
        target = _existing_directory(state_dir())
        if target is None:
            return []
        usage = shutil.disk_usage(target)
    except OSError as exc:
        logger.warning(f"[metrics] free disk of the state directory unknown: {exc}")
        return []
    free = Family("ctiparsor_state_dir_free_bytes", "Free bytes on the filesystem holding the state directory.")
    free.add(usage.free)
    total = Family("ctiparsor_state_dir_total_bytes", "Size in bytes of the filesystem holding the state directory.")
    total.add(usage.total)
    return [free, total]


def _parse_timestamp(text: object) -> float | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).timestamp()


def _backup_families() -> list[Family]:
    """The backup metrics from the status file the `backup` service writes.

    A missing file means no backup is known, so the metrics are absent (the
    alert rules treat an absent metric as a missing backup). A file that does
    not parse is logged and treated the same way.
    """
    path = Path(os.environ.get(BACKUP_STATUS_ENV) or DEFAULT_BACKUP_STATUS_FILE)
    try:
        status = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        logger.warning(f"[metrics] backup status file unreadable: {exc}")
        return []
    if not isinstance(status, dict) or not isinstance(status.get("ok"), bool):
        logger.warning("[metrics] backup status file has no boolean 'ok'")
        return []

    families: list[Family] = []
    attempt = Family(
        "ctiparsor_backup_last_attempt_ok",
        "1 when the last backup attempt succeeded, 0 when it failed.",
    )
    attempt.add(1 if status["ok"] else 0)
    families.append(attempt)

    success_at = _parse_timestamp(status.get("last_success"))
    if success_at is not None:
        success = Family(
            "ctiparsor_backup_last_success_timestamp_seconds",
            "Unix time of the last successful backup.",
        )
        success.add(success_at)
        families.append(success)
    return families


def _collect() -> list[Family]:
    families: list[Family] = []
    database = Family("ctiparsor_database_up", "1 when PostgreSQL answers SELECT 1, 0 when it does not.")
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1").fetchone()
            job_families = _job_families(conn)
        database.add(1)
        families.extend(job_families)
    except Exception as exc:  # the endpoint still answers: that is the point of it
        logger.warning(f"[metrics] job store unreachable: {exc}")
        database.add(0)
    families.insert(0, database)
    families.extend(_disk_families())
    families.extend(_backup_families())
    return families


def _bearer_credential(request: Request) -> str | None:
    """The token of an `Authorization: Bearer <token>` header, or None."""
    scheme, _, credential = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer":
        return None
    return credential.strip()


def _may_read(request: Request) -> bool:
    """Loopback always; any address with the METRICS_TOKEN bearer.

    METRICS_TOKEN empty (the default) keeps the loopback rule alone, and the
    Authorization header is ignored. Once it is set, a bearer that does not
    match is refused from every address, even loopback. The comparison is in
    constant time. The token is never logged or put in a response.
    Work item 14 adds the admin token next to this one.
    """
    expected = os.environ.get(METRICS_TOKEN_ENV, "")
    if expected:
        credential = _bearer_credential(request)
        if credential is not None:
            return hmac.compare_digest(credential.encode("utf-8"), expected.encode("utf-8"))
    client = request.client.host if request.client else None
    return _is_loopback(client)


@router.get("/metrics", include_in_schema=False)
def get_metrics(request: Request):
    """Prometheus text format. Loopback clients, or a client with METRICS_TOKEN."""
    if not _may_read(request):
        return JSONResponse(
            {"detail": "metrics are served to loopback clients or with the metrics token"}, status_code=403
        )
    return PlainTextResponse(render(_collect()), media_type=CONTENT_TYPE)
