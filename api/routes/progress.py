import asyncio
import json

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from api.db import get_conn

router = APIRouter(prefix="/api/jobs", tags=["progress"])


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


@router.get("/{job_id}/progress")
async def progress_stream(job_id: str):
    async def generator():
        last_id = 0
        done_sent = False
        # Send initial connection confirmation
        yield f"event: connected\ndata: {json.dumps({'job_id': job_id})}\n\n"

        # Bug 5 fix: the SSE client may connect fractionally before the job row
        # is committed (race between upload handler and the first SSE poll).
        # Retry a few times before treating a missing job as a hard 404.
        _not_found_retries = 0
        _MAX_NOT_FOUND = 6   # 6 × 0.5 s = 3 s grace window

        while True:
            events = _fetch_events_after(job_id, last_id)
            for ev in events:
                yield f"event: {ev['event_type']}\ndata: {ev['data']}\n\n"
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

            await asyncio.sleep(0.5)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
