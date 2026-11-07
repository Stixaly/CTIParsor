"""The progress stream reads the database off the event loop (issue #387).

The SSE generator polls every 0.5 s per client.  Its synchronous psycopg reads
used to run on the loop itself, so every poll stalled every other request and
stream.  The reads now run in a worker thread (asyncio.to_thread).
"""
from __future__ import annotations

import asyncio
import threading
import time

from starlette.requests import Request

from api.routes import progress


async def _collect(response) -> list[str]:
    chunks = []
    async for chunk in response.body_iterator:
        chunks.append(chunk if isinstance(chunk, str) else chunk.decode())
    return chunks


def _request() -> Request:
    return Request({"type": "http", "headers": []})


def test_progress_reads_run_off_the_event_loop_issue_387(monkeypatch):
    loop_thread = threading.get_ident()
    seen_threads: list[int] = []
    ticks = 0
    ticks_during_fetch: list[int] = []

    def slow_events(job_id, last_id):
        seen_threads.append(threading.get_ident())
        before = ticks
        time.sleep(0.3)                     # a slow database read
        ticks_during_fetch.append(ticks - before)
        return []

    def status(job_id):
        seen_threads.append(threading.get_ident())
        return "for_review"

    async def ticker():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    async def run():
        response = await progress.progress_stream("j1", _request())
        tick_task = asyncio.create_task(ticker())
        try:
            return await _collect(response)
        finally:
            tick_task.cancel()

    monkeypatch.setattr(progress, "_fetch_events_after", slow_events)
    monkeypatch.setattr(progress, "_fetch_job_status", status)

    chunks = asyncio.run(run())

    assert chunks[0].startswith("event: connected")
    assert chunks[-1].startswith("event: done")
    assert seen_threads and all(t != loop_thread for t in seen_threads)
    # The loop kept running while the slow read blocked its worker thread.
    assert ticks_during_fetch and ticks_during_fetch[0] >= 5


def test_progress_answers_the_same_events_as_before_issue_387(monkeypatch):
    rows = [{"id": 1, "event_type": "stage", "data": "{}"}, {"id": 2, "event_type": "done", "data": "{}"}]
    monkeypatch.setattr(progress, "_fetch_events_after", lambda job_id, last_id: rows)
    monkeypatch.setattr(progress, "_fetch_job_status", lambda job_id: "processing")

    async def run():
        response = await progress.progress_stream("j1", _request())
        return await _collect(response)

    chunks = asyncio.run(run())

    assert chunks[1] == "id: 1\nevent: stage\ndata: {}\n\n"
    assert chunks[2] == "id: 2\nevent: done\ndata: {}\n\n"
    assert len(chunks) == 3
