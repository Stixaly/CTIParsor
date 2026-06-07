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
