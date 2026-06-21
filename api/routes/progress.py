import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from api.db import get_conn

router = APIRouter(prefix="/api/jobs", tags=["progress"])

# Hard ceiling on how long a single SSE connection stays open.  Without it, a job
# wedged in a non-terminal status (e.g. the worker subprocess died without the
# watcher updating the row) keeps the generator polling — and the connection
# open — forever.  Sized above the default worker job timeout (1800 s) plus
# headroom so a legitimately long job still streams to completion.
_POLL_INTERVAL_SECONDS = 0.5
_MAX_STREAM_SECONDS = 2700  # 45 minutes


def _fetch_events_after(job_id: str, last_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, event_type, data FROM progress_events WHERE job_id=? AND id>? ORDER BY id",
            (job_id, last_id),
        ).fetchall()
    return [{"id": r["id"], "event_type": r["event_type"], "data": r["data"]} for r in rows]


def _fetch_job_status(job_id: str) -> str | None:
    with get_conn() as conn:
        row = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
    return row["status"] if row else None


def _parse_last_event_id(request: Request) -> int:
    """Resume point for a reconnecting EventSource.

    The browser replays the id of the last event it received via the
    Last-Event-ID header.  Without honouring it, a transient reconnect restarts
    the generator at 0 and re-streams every prior progress row — the client then
    appends them, producing duplicate progress entries in the UI.
    """
    raw = request.headers.get("last-event-id", "")
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 0


@router.get("/{job_id}/progress")
async def progress_stream(job_id: str, request: Request):
    async def generator():
        # Resume from the client's Last-Event-ID on reconnect (0 on first connect)
        last_id = _parse_last_event_id(request)
        done_sent = False
        # Send initial connection confirmation
        yield f"event: connected\ndata: {json.dumps({'job_id': job_id})}\n\n"

        # Bug 5 fix: the SSE client may connect fractionally before the job row
        # is committed (race between upload handler and the first SSE poll).
        # Retry a few times before treating a missing job as a hard 404.
        _not_found_retries = 0
        _MAX_NOT_FOUND = 6   # 6 × 0.5 s = 3 s grace window

        _elapsed = 0.0
        while True:
            events = _fetch_events_after(job_id, last_id)
            for ev in events:
                # Emit an SSE id: so the browser tracks its resume point and
                # sends it back as Last-Event-ID after a dropped connection.
                yield f"id: {ev['id']}\nevent: {ev['event_type']}\ndata: {ev['data']}\n\n"
                last_id = ev["id"]

                if ev["event_type"] == "done":
                    done_sent = True
                    return

            status = _fetch_job_status(job_id)
            if status in ("for_review", "completed", "failed"):
                if not done_sent:
                    yield f"event: done\ndata: {json.dumps({'status': status})}\n\n"
                return
            if status is None:
                _not_found_retries += 1
                if _not_found_retries >= _MAX_NOT_FOUND:
                    # Job genuinely does not exist — close the stream
                    yield f"event: done\ndata: {json.dumps({'status': 'failed', 'error': 'job not found'})}\n\n"
                    return
                # else: wait and retry — the row may not be committed yet

            # Hard timeout — a job stuck in a non-terminal state must not hold the
            # SSE connection open indefinitely.  Close with an explicit done event
            # so the client stops waiting and can re-poll the job status.
            if _elapsed >= _MAX_STREAM_SECONDS:
                yield (
                    "event: done\n"
                    f"data: {json.dumps({'status': status or 'processing', 'error': 'progress stream timed out'})}\n\n"
                )
                return

            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
            _elapsed += _POLL_INTERVAL_SECONDS

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
