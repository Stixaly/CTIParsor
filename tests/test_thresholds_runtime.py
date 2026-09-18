"""pipeline.thresholds — the runtime read of calibrated cutoffs (ADR-0051).

Locks the fail-soft contract: no store, no table, or the kill switch all mean
"the stage default", and asking never creates a job store as a side effect.
"""
from __future__ import annotations

import pytest

import api.db as db
import pipeline.thresholds as thresholds
from pipeline import calibration as cal


@pytest.fixture(autouse=True)
def _fresh_cache():
    thresholds.reload()
    yield
    thresholds.reload()


def test_default_when_there_is_no_store_and_none_is_created(monkeypatch, tmp_path):
    missing = tmp_path / "absent" / "cti_stix.db"
    monkeypatch.setattr(db, "DB_PATH", missing)
    monkeypatch.setattr(db, "DATABASE_URL", None)
    db.reset_connections()

    assert thresholds.get_threshold("gliner", "malware", 0.40) == 0.40
    assert thresholds.overrides_for("gliner") == {}
    assert not missing.exists(), "a CLI run asking for a cutoff must not create a job store"


def test_default_when_the_table_is_missing(temp_db):
    conn = temp_db.get_conn()
    conn.execute("DROP TABLE model_thresholds")
    conn.commit()
    assert thresholds.get_threshold("cyner", "malware", 0.70) == 0.70


def test_stored_row_overrides_the_default_for_that_pair_only(temp_db):
    cal.set_override(temp_db.get_conn(), "gliner", "identity", 0.55, temp_db.now_iso())
    thresholds.reload()
    assert thresholds.get_threshold("gliner", "identity", 0.40) == 0.55
    assert thresholds.get_threshold("gliner", "location", 0.40) == 0.40
    assert thresholds.get_threshold("cyner", "identity", 0.70) == 0.70


def test_the_read_is_cached_until_reload(temp_db):
    assert thresholds.get_threshold("gliner", "identity", 0.40) == 0.40
    cal.set_override(temp_db.get_conn(), "gliner", "identity", 0.55, temp_db.now_iso())
    assert thresholds.get_threshold("gliner", "identity", 0.40) == 0.40     # still the cached view
    thresholds.reload()
    assert thresholds.get_threshold("gliner", "identity", 0.40) == 0.55


def test_kill_switch_ignores_every_stored_row(temp_db, monkeypatch):
    cal.set_override(temp_db.get_conn(), "gliner", "identity", 0.55, temp_db.now_iso())
    monkeypatch.setenv("THRESHOLD_CALIBRATION_ENABLED", "false")
    thresholds.reload()
    assert thresholds.calibration_enabled() is False
    assert thresholds.get_threshold("gliner", "identity", 0.40) == 0.40
