"""
Shared pytest fixtures for CTIParsor test suite.

Provides:
  - sample_cti_text / sample_entities     — canonical test inputs
  - mock_llm_response / mock_llm          — patches _call_llm so no API key needed
  - storage                               — InMemoryJobStorage for worker tests
  - api_client                            — FastAPI TestClient with DB mocked out
"""
from __future__ import annotations

import json
import os
from unittest.mock import patch
from uuid import uuid4

import pytest

from api.storage import InMemoryJobStorage
from models.config import PipelineConfig
from models.schemas import EntityType, RawEntity

# ── Input fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture()
def config() -> PipelineConfig:
    return PipelineConfig()


@pytest.fixture()
def sample_cti_text() -> str:
    return (
        "APT29 deployed SUNBURST malware against SolarWinds targets. "
        "The threat actor used T1566.001 spearphishing and contacted "
        "185.220.101.45 and update.solarwinds[.]com for C2. "
        "CVE-2020-10148 was exploited for initial access. "
        "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


@pytest.fixture()
def sample_entities() -> list[RawEntity]:
    return [
        RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4, confidence=1.0),
        RawEntity(value="APT29", entity_type=EntityType.THREAT_ACTOR, confidence=0.9, source="gazetteer"),
        RawEntity(value="SUNBURST", entity_type=EntityType.MALWARE, confidence=0.9, source="gazetteer"),
    ]


# ── LLM mock fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _llm_provider_ready(monkeypatch):
    """
    Ensure pipeline.stage3_llm._provider_ready() returns True by default.

    enrich_chunk() short-circuits to an empty result when no provider is
    configured, which would make _call_llm mocks/patches in this suite
    silently go unused in environments (e.g. CI) without ANTHROPIC_API_KEY.
    Tests that specifically need the "not ready" path patch
    _provider_ready directly and are unaffected by this env var.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-for-pytest")


@pytest.fixture()
def mock_llm_response() -> dict:
    """Minimal valid LLM JSON response matching the LLMEnrichmentResult schema."""
    return {
        "threat_actors": ["APT29"],
        "malware_families": ["SUNBURST"],
        "tools": [],
        "ttps": [
            {
                "technique_name": "Spearphishing Attachment",
                "mitre_id": "T1566.001",
                "description": "APT29 used spearphishing emails with malicious attachments.",
            }
        ],
        "relationships": [
            {
                "source_value": "APT29",
                "relationship_type": "uses",
                "target_value": "SUNBURST",
                "confidence": 0.95,
                "evidence_text": "APT29 deployed SUNBURST malware against SolarWinds targets.",
                "evidence_label": "observed",
            }
        ],
        "ioc_associations": [
            {
                "ioc_value": "185.220.101.45",
                "malware_name": "SUNBURST",
                "relationship_type": "indicates",
            }
        ],
        "targeted_sectors": ["government", "technology"],
        "targeted_countries": ["United States"],
        "campaign_name": "SolarWinds Supply Chain",
        "course_of_action": ["Patch SolarWinds Orion immediately.", "Rotate all credentials."],
    }


@pytest.fixture()
def mock_llm(mock_llm_response):
    """
    Patch pipeline.stage3_llm._call_llm so no API key is required.
    Returns a Mock so tests can assert call counts / args.
    """
    with patch("pipeline.stage3_llm._call_llm") as mock:
        mock.return_value = json.dumps(mock_llm_response)
        yield mock


@pytest.fixture()
def mock_llm_empty():
    """Patch _call_llm to return an empty response (simulates provider not ready)."""
    with patch("pipeline.stage3_llm._call_llm", return_value="") as mock:
        yield mock


@pytest.fixture()
def mock_llm_bad_json():
    """Patch _call_llm to return unparseable text."""
    with patch("pipeline.stage3_llm._call_llm", return_value="not json at all") as mock:
        yield mock


# ── Storage fixture ────────────────────────────────────────────────────────────

@pytest.fixture()
def storage() -> InMemoryJobStorage:
    return InMemoryJobStorage()


# ── Isolated SQLite database ────────────────────────────────────────────────────

@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """Point api.db at a throwaway SQLite file and run migrations.

    Resets the thread-local connection cache before and after so the temp path
    is actually used and the next test reconnects to the real DB_PATH (which
    monkeypatch restores). Lets worker/route tests write rows without touching
    the developer's cti_stix.db.

    With CTIPARSOR_TEST_DATABASE_URL set (a postgresql:// URL) the JOB store is
    created in a disposable PostgreSQL schema named `t_<12 hex>` and dropped
    afterwards; the rule store stays in the temp SQLite file, exactly as in
    production with DATABASE_URL.
    """
    import api.db as db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip() or None

    if url:
        schema = "t_" + uuid4().hex[:12]
        monkeypatch.setattr(db, "DATABASE_URL", url)
        monkeypatch.setattr(db, "_PG_SCHEMA", schema)
        import psycopg
        admin = psycopg.connect(url, autocommit=True)
        admin.execute(f'CREATE SCHEMA "{schema}"')
        admin.close()
    else:
        monkeypatch.setattr(db, "DATABASE_URL", None)
        monkeypatch.setattr(db, "_PG_SCHEMA", None)

    db.reset_connections()
    db.init_db()
    yield db
    db.reset_connections()

    if url:
        import psycopg
        admin = psycopg.connect(url, autocommit=True)
        try:
            admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
        finally:
            admin.close()


@pytest.fixture()
def temp_db_client(temp_db):
    """FastAPI TestClient bound to the isolated temp database."""
    from fastapi.testclient import TestClient

    import api.main

    with patch("api.main.init_db"), patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app, raise_server_exceptions=True) as client:
            yield client


# ── FastAPI test client ────────────────────────────────────────────────────────

@pytest.fixture()
def api_client():
    """
    FastAPI TestClient with database initialisation mocked out.

    api.main must be imported before the patch so that `api.main` is present
    in sys.modules (mock.patch resolves the target lazily on __enter__).

    Also mocks `api.queue_loop.start_embedded`: the lifespan hook starts it
    unconditionally in role `all` (the default, and no test sets
    CTIPARSOR_ROLE), which is a REAL background thread that polls the
    database and claims/requeues `jobs` rows — including ones a test inserts
    a moment later, racing its own assertions. `requeue_orphans` is left
    real: it is a one-time synchronous call that completes, on whatever rows
    exist *before* the TestClient's `__enter__` returns, before any test body
    or fixture caller can insert anything — there is no window for it to race.
    """
    from fastapi.testclient import TestClient

    import api.main  # ensure module is loaded before patching its attribute

    with patch("api.main.init_db"), patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app, raise_server_exceptions=True) as client:
            yield client
