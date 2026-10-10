"""
Shared pytest fixtures for CTIParsor test suite.

Provides:
  - sample_cti_text / sample_entities     — canonical test inputs
  - mock_llm_response / mock_llm          — patches _call_llm so no API key needed
  - storage                               — InMemoryJobStorage for worker tests
  - api_client                            — FastAPI TestClient with DB mocked out

and keeps every test's uploads and bundles out of the working tree.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest

# The API answers only to the hosts in API_ALLOWED_HOSTS (api/main.py, read at
# import); Starlette's TestClient presents itself as `testserver`.
os.environ.setdefault("API_ALLOWED_HOSTS", "testserver,localhost,127.0.0.1,[::1]")

from api.storage import InMemoryJobStorage  # noqa: E402
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


@pytest.fixture(autouse=True)
def _llm_checks_at_their_defaults(monkeypatch):
    """Stages 3d and 3f run as their defaults (off), as in CI, whatever the
    developer's `.env` says: `pipeline.stage3_llm` loads it at import, and
    both modules read their switch once.  `mock_llm` answers every call with
    the extraction JSON, which a verifier cannot parse — and an unparseable
    verification holds its claims for review (ADR-0082) — so with a local
    `ENABLE_STIX_VERIFICATION=true` the Stage 3 tests lost their relationship.
    A test about verification turns it on itself."""
    monkeypatch.setattr("pipeline.stage3d_verify._VERIFY_ENABLED", False)
    monkeypatch.setattr("pipeline.stage3f_ttp_verify._VERIFY_ENABLED", False)


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


@pytest.fixture(autouse=True)
def _forget_store_backed_caches():
    """pipeline.thresholds and pipeline.overrides read the job store once per
    process and cache it (a worker subprocess lives for one job).  A test that
    wrote rows through temp_db must not leave them cached for the next test,
    which may run against a different temp store — or none at all."""
    yield
    from pipeline import overrides, thresholds

    thresholds.reload()
    overrides.reload()


# ── Uploads and bundles stay in tmp_path ───────────────────────────────────────

@pytest.fixture(autouse=True)
def _files_stay_in_tmp_path(tmp_path, monkeypatch):
    """Uploaded sources and exported bundles go under this test's tmp_path
    (api/paths.py), not into the checkout's uploads/ and output/.  Finalizing
    a job writes a bundle file: whether a test passes must not depend on that
    directory being writable, and a run must not leave files behind in it."""
    monkeypatch.setenv("CTIPARSOR_UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("CTIPARSOR_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setenv("CTIPARSOR_STATE_DIR", str(tmp_path / "state"))


_REPO = Path(__file__).resolve().parent.parent
_GUARDED_DIRS = ("uploads", "output")
_FILES_BEFORE = pytest.StashKey[set[Path]]()


def _guarded_files() -> set[Path]:
    return {p for d in _GUARDED_DIRS if (_REPO / d).is_dir()
            for p in (_REPO / d).rglob("*") if p.is_file()}


def pytest_sessionstart(session):
    session.config.stash[_FILES_BEFORE] = _guarded_files()


def pytest_sessionfinish(session, exitstatus):
    """Name any file the run added to uploads/ or output/: a path the fixture
    above does not cover yet.  Fails the run in CI; only warns elsewhere,
    since an API started from this checkout writes there too."""
    new = sorted(_guarded_files() - session.config.stash.get(_FILES_BEFORE, set()))
    if not new:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_sep("=", "files written into the working tree", red=True)
        for p in new:
            reporter.write_line(f"  {p.relative_to(_REPO)}")
        reporter.write_line("Route them through api/paths.py or tmp_path (tests/conftest.py).")
    if os.environ.get("CI"):
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


# ── A missing test dependency fails where it is required ────────────────────
# pytest.importorskip skips quietly, which is right on a laptop without
# yara-python and wrong in CI: the OpenCTI pattern gates (ADR-0067, ADR-0070)
# went untested there because the job never installed their parsers.
# CTIPARSOR_REQUIRE_TEST_DEPS=1 (the fast CI job) makes such a skip a failure.

_MISSING_IMPORT = "could not import"        # pytest.importorskip's skip reason


def _missing_import_is_a_failure(report) -> None:
    if (os.environ.get("CTIPARSOR_REQUIRE_TEST_DEPS") == "1" and report.skipped
            and _MISSING_IMPORT in str(report.longrepr)):
        report.outcome = "failed"


@pytest.hookimpl(tryfirst=True)
def pytest_collectreport(report):
    """A module-level importorskip skips the whole file at collection."""
    _missing_import_is_a_failure(report)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    _missing_import_is_a_failure(report)
    return report


# ── Storage fixture ────────────────────────────────────────────────────────────

@pytest.fixture()
def storage() -> InMemoryJobStorage:
    return InMemoryJobStorage()


# ── Isolated PostgreSQL schema ───────────────────────────────────────────────────

@pytest.fixture()
def temp_db(monkeypatch):
    """Point api.db at a disposable PostgreSQL schema and run migrations.

    ADR-0053: SQLite is gone, so this is now a single path rather than a
    branch — CTIPARSOR_TEST_DATABASE_URL (a postgresql:// URL) is required.
    A schema named `t_<12 hex>` holds BOTH the job store and the rule store
    (they are the same database now — see api.db.get_conn/get_rule_conn),
    created before the test and dropped after. Resets the thread-local
    connection cache before and after so the schema is actually used and the
    next test reconnects cleanly.
    """
    import api.db as db

    url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip() or None
    if not url:
        pytest.fail(
            "CTIPARSOR_TEST_DATABASE_URL is required — CTIParsor no longer "
            "supports SQLite (ADR-0053). Point it at a disposable PostgreSQL "
            "server, e.g. postgresql://ctiparsor:ci@127.0.0.1:5432/ctiparsor"
        )

    schema = "t_" + uuid4().hex[:12]
    monkeypatch.setattr(db, "DATABASE_URL", url)
    monkeypatch.setattr(db, "_PG_SCHEMA", schema)
    import psycopg
    admin = psycopg.connect(url, autocommit=True)
    admin.execute(f'CREATE SCHEMA "{schema}"')
    admin.close()

    db.reset_connections()
    db.init_db()
    yield db
    db.reset_connections()

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
