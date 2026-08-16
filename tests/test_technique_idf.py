"""Tests for ADR-0018 technique IDF weighting."""

from __future__ import annotations

import sqlite3

import pytest

from pipeline.detection.relevance import idf
from pipeline.detection.store import (
    technique_counts_for_rules,
    technique_document_frequency,
)


def _db() -> sqlite3.Connection:
    """In-memory store with detection_rules + rule_techniques."""
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE detection_rules (
            id TEXT PRIMARY KEY,
            corpus TEXT NOT NULL DEFAULT 'c',
            is_canonical INTEGER DEFAULT 1
        );
        CREATE TABLE rule_techniques (
            rule_id TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            PRIMARY KEY (rule_id, technique_id)
        );
        """
    )
    return conn


def _rule(conn: sqlite3.Connection, rule_id: str, techniques: list[str], canonical: bool = True) -> None:
    """Insert a rule and its techniques."""
    conn.execute(
        "INSERT INTO detection_rules (id, is_canonical) VALUES (?, ?)",
        (rule_id, 1 if canonical else 0),
    )
    for tech in techniques:
        conn.execute(
            "INSERT INTO rule_techniques (rule_id, technique_id) VALUES (?, ?)",
            (rule_id, tech),
        )


class TestTechniqueDocumentFrequency:
    def test_counts_rules_per_technique(self) -> None:
        """3 rules with T1059, 1 with T1027 -> correct counts."""
        conn = _db()
        _rule(conn, "R1", ["T1059"])
        _rule(conn, "R2", ["T1059"])
        _rule(conn, "R3", ["T1059"])
        _rule(conn, "R4", ["T1027"])
        result = technique_document_frequency(conn, ["T1059", "T1027"])
        assert result == {"T1059": 3, "T1027": 1}

    def test_non_canonical_rules_excluded(self) -> None:
        """Non-canonical rules are excluded from the count."""
        conn = _db()
        _rule(conn, "R1", ["T1059"], canonical=True)
        _rule(conn, "R2", ["T1059"], canonical=False)
        _rule(conn, "R3", ["T1059"], canonical=False)
        result = technique_document_frequency(conn, ["T1059"])
        assert result == {"T1059": 1}

    def test_unknown_technique_absent_from_result(self) -> None:
        """Unknown technique is not present in the result dict."""
        conn = _db()
        _rule(conn, "R1", ["T1059"])
        result = technique_document_frequency(conn, ["T9999"])
        assert "T9999" not in result

    def test_empty_input_returns_empty(self) -> None:
        """Empty input returns empty dict."""
        conn = _db()
        result = technique_document_frequency(conn, [])
        assert result == {}

    def test_blank_and_non_string_ids_ignored(self) -> None:
        """Blank and non-string IDs are ignored without raising."""
        conn = _db()
        _rule(conn, "R1", ["T1059"])
        result = technique_document_frequency(conn, ["", "  ", None, "T1059"])
        assert result == {"T1059": 1}

    def test_chunking_over_limit(self) -> None:
        """250 distinct techniques with chunk=10 are all counted correctly."""
        conn = _db()
        techniques = [f"T{i:04d}" for i in range(250)]
        for i, tech in enumerate(techniques):
            _rule(conn, f"R{i}", [tech])
        result = technique_document_frequency(conn, techniques, chunk=10)
        assert len(result) == 250
        for tech in techniques:
            assert result[tech] == 1


class TestTechniqueCountsForRules:
    def test_counts_techniques_per_rule(self) -> None:
        """Rule A with 3 techniques, B with 1 -> correct counts."""
        conn = _db()
        _rule(conn, "A", ["T1059", "T1027", "T1070"])
        _rule(conn, "B", ["T1059"])
        result = technique_counts_for_rules(conn, ["A", "B"])
        assert result == {"A": 3, "B": 1}

    def test_rule_without_techniques_absent(self) -> None:
        """Rule without techniques is absent from the result."""
        conn = _db()
        _rule(conn, "A", [])
        result = technique_counts_for_rules(conn, ["A"])
        assert "A" not in result

    def test_includes_non_canonical(self) -> None:
        """Non-canonical rules are included when explicitly requested."""
        conn = _db()
        _rule(conn, "A", ["T1059"], canonical=False)
        result = technique_counts_for_rules(conn, ["A"])
        assert result == {"A": 1}

    def test_empty_input_returns_empty(self) -> None:
        """Empty input returns empty dict."""
        conn = _db()
        result = technique_counts_for_rules(conn, [])
        assert result == {}


class TestIdfBehaviour:
    def test_common_technique_scores_lower_than_rare(self) -> None:
        """Common technique (df=358) scores lower than rare (df=1)."""
        assert idf(358, 6349) < idf(1, 6349)

    @pytest.mark.parametrize("df", [0, 1, 100, 6349, 99999])
    def test_idf_is_bounded_0_1(self, df: int) -> None:
        """IDF is always in [0.0, 1.0] for various df values."""
        result = idf(df, 6349)
        assert 0.0 <= result <= 1.0

    @pytest.mark.parametrize("df", [0, 1, 100, 6349, 99999])
    def test_idf_never_exceeds_one_so_term_stays_capped(self, df: int) -> None:
        """0.30 * idf(df, 6349) <= 0.30, keeping the term under strong evidence weight."""
        assert 0.30 * idf(df, 6349) <= 0.30
