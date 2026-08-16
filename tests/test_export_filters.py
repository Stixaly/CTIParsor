import io
import json
import zipfile
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def temp_db_client(temp_db):
    """Provide a TestClient with the temporary database context."""
    from api.main import app
    with TestClient(app) as client:
        yield client


def _seed(db, job_id: str) -> None:
    """Seed a job, one accepted technique, and 6 rules spanning format/licence/severity.

    Techniques live in `entities` with entity_type='technique' and are resolved by
    job_technique_ids — there is no ttp/job_ttp table. `db` is the api.db module
    fixture, which also supplies now_iso().
    """
    conn = db.get_conn()
    ts = db.now_iso()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)",
        (job_id, "test_report.pdf", "reviewing", ts, ts),
    )
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), job_id, "T1059", "technique", "T1059", 1, "llm"),
    )

    rules = [
        ("r1", "sigma", "sigmahq", "DRL-1.1", "high", "Rule 1", "raw1"),
        ("r2", "sigma", "mthcht", "none", "low", "Rule 2", "raw2"),
        ("r3", "suricata", "et-open", "BSD-3-Clause", "high", "Rule 3", "raw3"),
        ("r4", "suricata", "et-open", "BSD-3-Clause", "informational", "Rule 4", "raw4"),
        ("r5", "yara", "signature-base", "DRL-1.1", "unknown", "Rule 5", "raw5"),
        ("r6", "sigma", "sigmahq", "DRL-1.1", "medium", "Rule 6", "raw6"),
    ]
    for rid, fmt, corpus, lic, sev, title, raw in rules:
        conn.execute(
            "INSERT INTO detection_rules "
            "(id, corpus, native_key, title, license, source_ref, raw, format, severity, is_canonical) "
            "VALUES (?,?,?,?,?,?,?,?,?,1)",
            (rid, corpus, f"key_{rid}", title, lic, f"src_{rid}", raw, fmt, sev),
        )
        conn.execute(
            "INSERT INTO rule_techniques (rule_id, technique_id) VALUES (?,?)",
            (rid, "T1059"),
        )
    conn.commit()


def test_facets_reports_totals_and_axes(temp_db_client: TestClient, temp_db):
    """Verify facets endpoint returns correct totals and axis counts."""
    job_id = "job1"
    _seed(temp_db, job_id)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export/facets")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 6
    assert "format" in data
    assert "corpus" in data
    assert "license" in data
    assert "severity" in data
    assert sum(item["rules"] for item in data["format"]) == 6


def test_facets_empty_job_is_not_404(temp_db_client: TestClient, temp_db):
    """Ensure empty job returns 200 with zero totals, not 404."""
    job_id = "job_empty"
    conn = temp_db.get_conn()
    ts = temp_db.now_iso()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)", (job_id, "empty.pdf", "reviewing", ts, ts),
    )
    conn.commit()

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export/facets")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0


def test_export_unfiltered_contains_all(temp_db_client: TestClient, temp_db):
    """Verify unfiltered export contains all 6 rules."""
    job_id = "job2"
    _seed(temp_db, job_id)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export")
    assert resp.status_code == 200

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf, "r") as zf:
        files = [f for f in zf.namelist() if f.startswith("rules/")]
        assert len(files) == 6


def test_extension_per_format(temp_db_client: TestClient, temp_db):
    """Verify file extensions match the rule format (sigma=.yml, suricata=.rules, yara=.yar)."""
    job_id = "job3"
    _seed(temp_db, job_id)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export")
    assert resp.status_code == 200

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf, "r") as zf:
        for name in zf.namelist():
            if name.startswith("rules/"):
                if "/sigma/" in name:
                    assert name.endswith(".yml")
                elif "/suricata/" in name:
                    assert name.endswith(".rules")
                elif "/yara/" in name:
                    assert name.endswith(".yar")


def test_filter_by_format(temp_db_client: TestClient, temp_db):
    """Verify filtering by format=sigma returns only 3 sigma rules."""
    job_id = "job4"
    _seed(temp_db, job_id)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export?format=sigma")
    assert resp.status_code == 200

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf, "r") as zf:
        files = [f for f in zf.namelist() if f.startswith("rules/")]
        assert len(files) == 3
        for f in files:
            assert "/sigma/" in f


def test_filter_by_license_excludes_all_rights_reserved(temp_db_client: TestClient, temp_db):
    """Verify filtering by license excludes 'none' (all rights reserved) corpus mthcht."""
    job_id = "job5"
    _seed(temp_db, job_id)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export?license=DRL-1.1&license=BSD-3-Clause")
    assert resp.status_code == 200

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf, "r") as zf:
        for name in zf.namelist():
            if name.startswith("rules/"):
                assert "mthcht" not in name


def test_filters_combine_with_and(temp_db_client: TestClient, temp_db):
    """Verify combined filters (format=sigma & severity=high) return exactly 1 rule."""
    job_id = "job6"
    _seed(temp_db, job_id)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export?format=sigma&severity=high")
    assert resp.status_code == 200

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf, "r") as zf:
        files = [f for f in zf.namelist() if f.startswith("rules/")]
        assert len(files) == 1


def test_filter_matching_nothing_returns_404(temp_db_client: TestClient, temp_db):
    """Verify filter matching no rules returns 404."""
    job_id = "job7"
    _seed(temp_db, job_id)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export?format=snort")
    assert resp.status_code == 404


def test_manifest_records_filters_and_excluded(temp_db_client: TestClient, temp_db):
    """Verify manifest records filters and excluded counts correctly."""
    job_id = "job8"
    _seed(temp_db, job_id)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export?format=sigma")
    assert resp.status_code == 200

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf, "r") as zf:
        manifest = json.loads(zf.read("MANIFEST.json"))
        assert manifest["filters"]["format"] == ["sigma"]
        assert manifest["excluded"]["total"] == 3
        assert manifest["excluded"]["format"].get("suricata") == 2
        assert manifest["excluded"]["format"].get("yara") == 1


def test_manifest_excluded_plus_included_equals_total(temp_db_client: TestClient, temp_db):
    """Verify rule_count + excluded.total equals total rules (6)."""
    job_id = "job9"
    _seed(temp_db, job_id)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export?format=sigma")
    assert resp.status_code == 200

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf, "r") as zf:
        manifest = json.loads(zf.read("MANIFEST.json"))
        assert manifest["rule_count"] + manifest["excluded"]["total"] == 6


def test_readme_lists_only_present_licenses(temp_db_client: TestClient, temp_db):
    """Verify README lists only licenses present in the filtered archive."""
    job_id = "job10"
    _seed(temp_db, job_id)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export?format=suricata")
    assert resp.status_code == 200

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf, "r") as zf:
        readme = zf.read("README.txt").decode("utf-8")
        listed = readme.split("Licenses present:", 1)[1]
        assert "BSD-3-Clause" in listed
        # Scoped to the listing: the explanatory sentence above it
        # ("a license of 'none' means ALL RIGHTS RESERVED") is prose we want
        # in every README, so a bare substring check would always trip.
        assert "none" not in listed


def test_archive_name_is_not_sigma_specific(temp_db_client: TestClient, temp_db):
    """Verify Content-Disposition uses _detection_rules.zip, not _sigma_."""
    job_id = "job11"
    _seed(temp_db, job_id)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/detections/export")
    assert resp.status_code == 200

    cd = resp.headers.get("Content-Disposition", "")
    assert "_detection_rules.zip" in cd
    assert "_sigma_" not in cd


def test_case_insensitive_filter_values(temp_db_client: TestClient, temp_db):
    """Verify filter values are case-insensitive (SIGMA == sigma)."""
    job_id = "job12"
    _seed(temp_db, job_id)

    resp1 = temp_db_client.get(f"/api/jobs/{job_id}/detections/export?format=sigma")
    resp2 = temp_db_client.get(f"/api/jobs/{job_id}/detections/export?format=SIGMA")

    assert resp1.status_code == 200
    assert resp2.status_code == 200

    buf1 = io.BytesIO(resp1.content)
    buf2 = io.BytesIO(resp2.content)

    with zipfile.ZipFile(buf1, "r") as zf1, zipfile.ZipFile(buf2, "r") as zf2:
        files1 = [f for f in zf1.namelist() if f.startswith("rules/")]
        files2 = [f for f in zf2.namelist() if f.startswith("rules/")]
        assert len(files1) == len(files2) == 3
