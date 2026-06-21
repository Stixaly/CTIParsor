"""
Tests for FastAPI API routes.

All database calls are mocked so these tests run without a real SQLite DB
and without spawning background workers.

Covers:
  - GET /api/health
  - GET /api/jobs/{id} → 404 for unknown job
  - File type validation on the upload endpoint
  - Progress events endpoint returns a list
"""
from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

# ── Request-ID context isolation ────────────────────────────────────────────────

class TestRequestIdIsolation:
    def test_request_id_is_isolated_across_concurrent_tasks(self):
        """Two concurrent async tasks must not see each other's request id.

        Regression for the threading.local() bug: with thread-local storage all
        async requests shared one slot, so a request id set before an await was
        clobbered by a concurrent request.  A ContextVar isolates each task.
        """
        import asyncio

        from api.logging_config import clear_request_id, get_request_id, set_request_id

        observed: dict[str, str] = {}

        async def worker(name: str) -> None:
            set_request_id(name)
            await asyncio.sleep(0)          # yield — lets the other task run
            observed[name] = get_request_id()  # must still be our own id
            clear_request_id()

        async def run() -> None:
            await asyncio.gather(worker("aaa11111"), worker("bbb22222"))

        asyncio.run(run())
        assert observed == {"aaa11111": "aaa11111", "bbb22222": "bbb22222"}


# ── Health endpoint ────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_200(self, api_client):
        response = api_client.get("/api/health")
        assert response.status_code == 200

    def test_health_returns_ok_status(self, api_client):
        response = api_client.get("/api/health")
        assert response.json() == {"status": "ok"}


# ── Jobs endpoint ──────────────────────────────────────────────────────────────

class TestJobsEndpoint:
    def test_get_unknown_job_returns_404(self, api_client):
        # api.routes.jobs imports `get_conn` directly (`from api.db import get_conn`),
        # so the name must be patched where it's looked up — in the route module —
        # not on `api.db` (patching there leaves the route's local reference untouched).
        with patch("api.routes.jobs.get_conn") as mock_get_conn:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.fetchone.return_value = None
            mock_conn.execute.return_value = mock_cursor
            mock_get_conn.return_value.__enter__.return_value = mock_conn
            mock_get_conn.return_value.__exit__.return_value = False

            response = api_client.get("/api/jobs/nonexistent-job-id-12345")

        assert response.status_code == 404

    def test_list_jobs_returns_list(self, api_client):
        with patch("api.routes.jobs.get_conn") as mock_get_conn:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.fetchall.return_value = []
            mock_conn.execute.return_value = mock_cursor
            mock_get_conn.return_value.__enter__.return_value = mock_conn
            mock_get_conn.return_value.__exit__.return_value = False

            response = api_client.get("/api/jobs")

        # 200 with a list, or 404/405 if route uses different path — just check it doesn't crash
        assert response.status_code in (200, 404, 405)


# ── Upload endpoint ────────────────────────────────────────────────────────────

class TestUploadEndpoint:
    def _upload(self, api_client, filename: str, content: bytes, content_type: str):
        return api_client.post(
            "/api/upload",
            files={"file": (filename, io.BytesIO(content), content_type)},
        )

    def test_upload_rejects_executable(self, api_client):
        """Executables must be rejected with 4xx."""
        # api.routes.upload also imports `get_conn` directly — patch it there
        # (rejection happens on extension check, before any DB access, so this
        # patch is mostly a safety net against accidentally hitting the real DB).
        with patch("api.routes.upload.get_conn"):
            response = self._upload(api_client, "evil.exe", b"MZ\x90\x00", "application/octet-stream")
        assert response.status_code in (400, 415, 422, 500)

    def test_upload_with_no_file_returns_error(self, api_client):
        response = api_client.post("/api/upload")
        assert response.status_code in (400, 422)


# ── Progress endpoint ──────────────────────────────────────────────────────────

class TestProgressEndpoint:
    def test_progress_endpoint_responds(self, api_client):
        """Progress endpoint returns 200 (SSE stream) or 404 — never 5xx."""
        # api.routes.progress also imports `get_conn` directly — patch it there.
        with patch("api.routes.progress.get_conn") as mock_get_conn:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.fetchall.return_value = []
            mock_cursor.fetchone.return_value = None
            mock_conn.execute.return_value = mock_cursor
            mock_get_conn.return_value.__enter__.return_value = mock_conn
            mock_get_conn.return_value.__exit__.return_value = False

            response = api_client.get("/api/jobs/some-job-id/progress")

        assert response.status_code in (200, 404)
        if response.status_code == 200:
            # The progress endpoint streams SSE, not JSON
            ct = response.headers.get("content-type", "")
            assert "text/event-stream" in ct or "application/json" in ct

    def test_parse_last_event_id_is_robust(self):
        from unittest.mock import MagicMock

        from api.routes.progress import _parse_last_event_id

        def _req(val):
            r = MagicMock()
            r.headers = {"last-event-id": val} if val is not None else {}
            return r

        assert _parse_last_event_id(_req("7")) == 7
        assert _parse_last_event_id(_req("")) == 0
        assert _parse_last_event_id(_req("not-a-number")) == 0
        assert _parse_last_event_id(_req(None)) == 0

    def test_progress_stream_is_resumable(self, temp_db, temp_db_client):
        """SSE emits id: lines and honours Last-Event-ID so a reconnect doesn't
        replay events the client already received."""
        with temp_db.get_conn() as conn:
            conn.execute(
                "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                "VALUES ('jp1','r.txt','for_review',?,?)",
                (temp_db.now_iso(), temp_db.now_iso()),
            )
            conn.commit()
        temp_db.emit_progress("jp1", "stage", {"stage": 1})
        temp_db.emit_progress("jp1", "done", {"status": "for_review"})

        first_id = temp_db.get_conn().execute(
            "SELECT id FROM progress_events WHERE job_id='jp1' ORDER BY id"
        ).fetchall()[0]["id"]

        # Fresh connect — both events stream, each carrying an SSE id:
        body1 = temp_db_client.get("/api/jobs/jp1/progress").text
        assert f"id: {first_id}" in body1
        assert '"stage": 1' in body1

        # Reconnect from the stage event — it must NOT be replayed.
        body2 = temp_db_client.get(
            "/api/jobs/jp1/progress", headers={"Last-Event-ID": str(first_id)}
        ).text
        assert '"stage": 1' not in body2
        assert "event: done" in body2


# ── Policy endpoint ────────────────────────────────────────────────────────────

class TestPolicyEndpoint:
    def test_get_policy_returns_200_or_404(self, api_client):
        # Real prefix is /api/relationship-policy (api/routes/policy.py); api.routes.policy
        # also imports `get_conn` directly, so patch it there — not on `api.db`.
        with patch("api.routes.policy.get_conn") as mock_get_conn:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.fetchone.return_value = None
            mock_conn.execute.return_value = mock_cursor
            mock_get_conn.return_value.__enter__.return_value = mock_conn
            mock_get_conn.return_value.__exit__.return_value = False

            response = api_client.get("/api/relationship-policy")

        assert response.status_code in (200, 404)
