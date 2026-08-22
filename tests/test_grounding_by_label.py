"""Tests for ADR-0024 Phase C: grounding scoring by evidence label."""

from pathlib import Path

from tests.eval_pipeline import (
    _EVIDENTIAL_LABELS,
    _SYNTHESISED_LABELS,
    _stix_display_name,
    load_grounding_from_bundle,
)


def _make_db(tmp_path: Path, report_text: str, objects: list) -> Path:
    """Create a throwaway cti_stix.db-shaped database with one job."""
    import json
    import sqlite3

    db = tmp_path / "test.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE jobs (id TEXT, report_text TEXT, bundle_json TEXT)"
    )
    conn.execute(
        "INSERT INTO jobs VALUES (?, ?, ?)",
        (
            "job-1234abcd",
            report_text,
            json.dumps({"type": "bundle", "objects": objects}),
        ),
    )
    conn.commit()
    conn.close()
    return db


def test_stix_display_name_prefers_name_then_value() -> None:
    """_stix_display_name returns the first non-empty field in priority order."""
    assert _stix_display_name({"name": "APT29"}) == "APT29", (
        "name field should take priority"
    )
    assert _stix_display_name({"value": "evil.com"}) == "evil.com", (
        "value field should be used when name is absent"
    )
    assert _stix_display_name({"hashes": {"SHA-256": "abc"}}) == "abc", (
        "first hash value should be used when name and value are absent"
    )
    assert _stix_display_name({"path": "/tmp/x"}) == "/tmp/x", (
        "path field should be used when name, value, and hashes are absent"
    )
    assert _stix_display_name({"id": "malware--1"}) == "malware--1", (
        "id should be the last resort"
    )
    assert _stix_display_name({}) == "", (
        "empty dict should return empty string"
    )
    assert _stix_display_name(None) == "", (
        "None should return empty string"
    )
    assert _stix_display_name(42) == "", (
        "non-dict should return empty string"
    )


def test_census_counts_every_label_including_unlabelled(tmp_path: Path) -> None:
    """Census counts all relationship objects by their x_evidence_label."""
    objects = [
        {"id": "malware--1", "type": "malware", "name": "Malware A"},
        {"id": "indicator--1", "type": "indicator", "name": "Ind A"},
        {"id": "rel--1", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1",
         "x_evidence_label": "observed"},
        {"id": "rel--2", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1",
         "x_evidence_label": "assessed"},
        {"id": "rel--3", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1",
         "x_evidence_label": "inferred"},
        {"id": "rel--4", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1"},
    ]
    db = _make_db(tmp_path, "some report text", objects)
    samples, census = load_grounding_from_bundle(db, "all")
    assert census == {
        "observed": 1,
        "assessed": 1,
        "inferred": 1,
        "(unlabelled)": 1,
    }, "census must count every label including unlabelled"


def test_only_evidential_edges_are_scored(tmp_path: Path) -> None:
    """Only observed/reported edges appear in the sample's relationships."""
    objects = [
        {"id": "malware--1", "type": "malware", "name": "Malware A"},
        {"id": "indicator--1", "type": "indicator", "name": "Ind A"},
        {"id": "rel--1", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1",
         "x_evidence_label": "observed"},
        {"id": "rel--2", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1",
         "x_evidence_label": "assessed"},
        {"id": "rel--3", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1",
         "x_evidence_label": "inferred"},
        {"id": "rel--4", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1"},
    ]
    db = _make_db(tmp_path, "some report text", objects)
    samples, _ = load_grounding_from_bundle(db, "all")
    assert len(samples) == 1, "exactly one sample expected"
    assert len(samples[0].relationships) == 1, (
        "assessed/inferred edges are assertions, not claims about the text "
        "-- scoring them measures nothing"
    )
    assert samples[0].relationships[0][2] == "Malware A", (
        "the scored edge must be the observed one"
    )


def test_rel_evidence_stays_aligned(tmp_path: Path) -> None:
    """rel_evidence list has the same length as relationships, with '' for missing."""
    objects = [
        {"id": "malware--1", "type": "malware", "name": "Malware A"},
        {"id": "indicator--1", "type": "indicator", "name": "Ind A"},
        {"id": "rel--1", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1",
         "x_evidence_label": "observed", "x_evidence_text": "quote one"},
        {"id": "rel--2", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1",
         "x_evidence_label": "reported"},
    ]
    db = _make_db(tmp_path, "some report text", objects)
    samples, _ = load_grounding_from_bundle(db, "all")
    assert len(samples) == 1
    assert len(samples[0].rel_evidence) == len(samples[0].relationships), (
        "rel_evidence must be aligned index-by-index with relationships"
    )
    assert samples[0].rel_evidence[0] == "quote one", (
        "first evidence should be the provided quote"
    )
    assert samples[0].rel_evidence[1] == "", (
        "missing x_evidence_text should yield empty string"
    )


def test_edges_with_unresolvable_endpoints_are_skipped_but_counted(
    tmp_path: Path,
) -> None:
    """Edges with unresolvable refs are excluded from scoring but counted in census."""
    objects = [
        {"id": "malware--1", "type": "malware", "name": "Malware A"},
        {"id": "rel--1", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "nonexistent--999",
         "x_evidence_label": "reported"},
    ]
    db = _make_db(tmp_path, "some report text", objects)
    samples, census = load_grounding_from_bundle(db, "all")
    assert census.get("reported", 0) == 1, (
        "edge must be counted in census even if endpoint is unresolvable"
    )
    assert len(samples) == 1
    assert len(samples[0].relationships) == 0, (
        "edge with unresolvable endpoint must not appear in relationships"
    )


def test_malformed_bundle_json_is_skipped(tmp_path: Path) -> None:
    """Malformed bundle_json is skipped without raising."""
    import sqlite3

    db = tmp_path / "test.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE jobs (id TEXT, report_text TEXT, bundle_json TEXT)"
    )
    conn.execute(
        "INSERT INTO jobs VALUES (?, ?, ?)",
        ("job-1234abcd", "some report text", "{not valid json"),
    )
    conn.commit()
    conn.close()

    samples, census = load_grounding_from_bundle(db, "all")
    assert samples == [], "malformed bundle should yield no samples"
    assert census == {}, "malformed bundle should yield empty census"


def test_bundle_without_objects_list_is_skipped(tmp_path: Path) -> None:
    """Bundle without 'objects' key is skipped without raising."""
    import json
    import sqlite3

    db = tmp_path / "test.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE jobs (id TEXT, report_text TEXT, bundle_json TEXT)"
    )
    conn.execute(
        "INSERT INTO jobs VALUES (?, ?, ?)",
        ("job-1234abcd", "some report text", json.dumps({"type": "bundle"})),
    )
    conn.commit()
    conn.close()

    samples, census = load_grounding_from_bundle(db, "all")
    assert samples == [], "bundle without objects should yield no samples"
    assert census == {}, "bundle without objects should yield empty census"


def test_evidential_and_synthesised_sets_are_disjoint() -> None:
    """The two label sets must be disjoint."""
    assert _EVIDENTIAL_LABELS & _SYNTHESISED_LABELS == frozenset(), (
        "evidential and synthesised label sets must be disjoint"
    )
