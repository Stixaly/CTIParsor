from __future__ import annotations

import sqlite3

from pipeline.detection.dedup import FOLDING_RELATIONS, dedupe_store


def _db() -> sqlite3.Connection:
    """In-memory store with the three tables dedupe_store reads."""
    conn = sqlite3.connect(":memory:")
    # executescript, not execute: execute() runs exactly one statement.
    conn.executescript(
        """
        CREATE TABLE detection_rules (
            id TEXT PRIMARY KEY, corpus TEXT NOT NULL, native_key TEXT NOT NULL,
            dedup_key TEXT DEFAULT '', content_hash TEXT DEFAULT '',
            is_canonical INTEGER DEFAULT 1
        );
        CREATE TABLE rule_techniques (
            rule_id TEXT NOT NULL, technique_id TEXT NOT NULL,
            PRIMARY KEY (rule_id, technique_id)
        );
        CREATE TABLE rule_related (
            rule_id TEXT NOT NULL, related_key TEXT NOT NULL, rel_type TEXT NOT NULL,
            PRIMARY KEY (rule_id, related_key, rel_type)
        );
        """
    )
    conn.commit()
    return conn


def _add(
    conn: sqlite3.Connection, rule_id: str, corpus: str, native_key: str,
    dedup_key: str = "", content_hash: str = "",
) -> None:
    conn.execute(
        "INSERT INTO detection_rules (id, corpus, native_key, dedup_key, content_hash) VALUES (?, ?, ?, ?, ?)",
        (rule_id, corpus, native_key, dedup_key, content_hash),
    )
    conn.commit()


def _relate(conn: sqlite3.Connection, rule_id: str, related_key: str, rel_type: str) -> None:
    """Declare a provenance edge from *rule_id* to a bare Sigma id."""
    conn.execute(
        "INSERT INTO rule_related (rule_id, related_key, rel_type) VALUES (?, ?, ?)",
        (rule_id, related_key, rel_type),
    )
    conn.commit()


def _canonical(conn: sqlite3.Connection) -> set[str]:
    """Ids currently flagged canonical."""
    rows = conn.execute("SELECT id FROM detection_rules WHERE is_canonical = 1").fetchall()
    return {r[0] for r in rows}


def test_dedup_key_clustering_still_works() -> None:
    """Two rules sharing dedup_key collapse to the lower-priority corpus."""
    conn = _db()
    _add(conn, "r1", "a", "key1", "shared")
    _add(conn, "r2", "b", "key2", "shared")
    dedupe_store(conn, priority={"a": 10, "b": 95})
    assert _canonical(conn) == {"r1"}
    conn.close()


def test_distinct_dedup_keys_stay_separate() -> None:
    """Rules with different dedup_keys and no related stay canonical."""
    conn = _db()
    _add(conn, "r1", "a", "key1", "dedup1")
    _add(conn, "r2", "b", "key2", "dedup2")
    dedupe_store(conn, priority={"a": 10, "b": 95})
    assert _canonical(conn) == {"r1", "r2"}
    conn.close()


def test_empty_dedup_key_does_not_pool() -> None:
    """Empty dedup_key rules do not collapse together."""
    conn = _db()
    _add(conn, "r1", "a", "key1", "", "hash1")
    _add(conn, "r2", "b", "key2", "", "hash2")
    _add(conn, "r3", "c", "key3", "", "hash3")
    dedupe_store(conn, priority={"a": 10, "b": 20, "c": 30})
    assert _canonical(conn) == {"r1", "r2", "r3"}
    conn.close()


def test_derived_folds_under_referent() -> None:
    """Derived relation folds the higher-priority rule under the referent."""
    conn = _db()
    _add(conn, "sig1", "sigmahq", "sig:1", "dedup_sig")
    _add(conn, "hay1", "hayabusa", "hay:1", "dedup_hay")
    _relate(conn, "hay1", "sig:1", "derived")
    conn.commit()
    dedupe_store(conn, priority={"sigmahq": 10, "hayabusa": 95})
    assert _canonical(conn) == {"sig1"}
    conn.close()


def test_renamed_folds() -> None:
    """Renamed relation also folds under the referent."""
    conn = _db()
    _add(conn, "sig1", "sigmahq", "sig:1", "dedup_sig")
    _add(conn, "hay1", "hayabusa", "hay:1", "dedup_hay")
    _relate(conn, "hay1", "sig:1", "renamed")
    conn.commit()
    dedupe_store(conn, priority={"sigmahq": 10, "hayabusa": 95})
    assert _canonical(conn) == {"sig1"}
    conn.close()


def test_similar_does_not_fold() -> None:
    """Similar relation does not fold; both remain canonical."""
    conn = _db()
    _add(conn, "sig1", "sigmahq", "sig:1", "dedup_sig")
    _add(conn, "hay1", "hayabusa", "hay:1", "dedup_hay")
    _relate(conn, "hay1", "sig:1", "similar")
    conn.commit()
    dedupe_store(conn, priority={"sigmahq": 10, "hayabusa": 95})
    assert _canonical(conn) == {"sig1", "hay1"}
    conn.close()


def test_obsolete_does_not_fold() -> None:
    """Obsolete relation does not fold; both remain canonical."""
    conn = _db()
    _add(conn, "sig1", "sigmahq", "sig:1", "dedup_sig")
    _add(conn, "hay1", "hayabusa", "hay:1", "dedup_hay")
    _relate(conn, "hay1", "sig:1", "obsolete")
    conn.commit()
    dedupe_store(conn, priority={"sigmahq": 10, "hayabusa": 95})
    assert _canonical(conn) == {"sig1", "hay1"}
    conn.close()


def test_merged_does_not_fold() -> None:
    """Merged relation does not fold; both remain canonical."""
    conn = _db()
    _add(conn, "sig1", "sigmahq", "sig:1", "dedup_sig")
    _add(conn, "hay1", "hayabusa", "hay:1", "dedup_hay")
    _relate(conn, "hay1", "sig:1", "merged")
    conn.commit()
    dedupe_store(conn, priority={"sigmahq": 10, "hayabusa": 95})
    assert _canonical(conn) == {"sig1", "hay1"}
    conn.close()


def test_relation_type_is_case_insensitive() -> None:
    """Uppercase rel_type 'DERIVED' still folds."""
    conn = _db()
    _add(conn, "sig1", "sigmahq", "sig:1", "dedup_sig")
    _add(conn, "hay1", "hayabusa", "hay:1", "dedup_hay")
    _relate(conn, "hay1", "sig:1", "DERIVED")
    conn.commit()
    dedupe_store(conn, priority={"sigmahq": 10, "hayabusa": 95})
    assert _canonical(conn) == {"sig1"}
    conn.close()


def test_dangling_reference_is_ignored() -> None:
    """A derived reference to a non-existent rule is ignored."""
    conn = _db()
    _add(conn, "hay1", "hayabusa", "hay:1", "dedup_hay")
    _relate(conn, "hay1", "nonexistent", "derived")
    conn.commit()
    dedupe_store(conn, priority={"hayabusa": 95})
    assert _canonical(conn) == {"hay1"}
    conn.close()


def test_self_reference_ignored() -> None:
    """A rule declaring derived of its own native_key stays canonical."""
    conn = _db()
    _add(conn, "hay1", "hayabusa", "hay:1", "dedup_hay")
    _relate(conn, "hay1", "hay:1", "derived")
    conn.commit()
    dedupe_store(conn, priority={"hayabusa": 95})
    assert _canonical(conn) == {"hay1"}
    conn.close()


def test_chain_collapses_to_one_cluster() -> None:
    """A->B->C derived chain collapses to the lowest-priority rule."""
    conn = _db()
    _add(conn, "A", "corpusA", "keyA", "dedupA")
    _add(conn, "B", "corpusB", "keyB", "dedupB")
    _add(conn, "C", "corpusC", "keyC", "dedupC")
    _relate(conn, "A", "keyB", "derived")
    _relate(conn, "B", "keyC", "derived")
    conn.commit()
    dedupe_store(conn, priority={"corpusA": 30, "corpusB": 20, "corpusC": 10})
    assert _canonical(conn) == {"C"}
    conn.close()


def test_two_rules_same_native_key_both_merge() -> None:
    """Two hayabusa rules derived from the same sigmahq key both demote."""
    conn = _db()
    _add(conn, "sig1", "sigmahq", "sig:1", "dedup_sig")
    _add(conn, "hay1", "hayabusa", "hay:1", "dedup_hay1")
    _add(conn, "hay2", "hayabusa", "hay:2", "dedup_hay2")
    _relate(conn, "hay1", "sig:1", "derived")
    _relate(conn, "hay2", "sig:1", "derived")
    conn.commit()
    dedupe_store(conn, priority={"sigmahq": 10, "hayabusa": 95})
    assert _canonical(conn) == {"sig1"}
    conn.close()


def test_missing_rule_related_table_falls_back() -> None:
    """Missing rule_related table does not raise; dedup_key logic still works."""
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE detection_rules (
            id TEXT PRIMARY KEY, corpus TEXT NOT NULL, native_key TEXT NOT NULL,
            dedup_key TEXT DEFAULT '', content_hash TEXT DEFAULT '',
            is_canonical INTEGER DEFAULT 1
        )
        """
    )
    conn.execute("INSERT INTO detection_rules (id, corpus, native_key, dedup_key) VALUES ('r1', 'a', 'k1', 'shared')")
    conn.execute("INSERT INTO detection_rules (id, corpus, native_key, dedup_key) VALUES ('r2', 'b', 'k2', 'shared')")
    conn.commit()
    dedupe_store(conn, priority={"a": 10, "b": 95})
    assert _canonical(conn) == {"r1"}
    conn.close()


def test_summary_keys_present() -> None:
    """Returned dict has all 6 expected keys and canonical+duplicates==total."""
    conn = _db()
    _add(conn, "r1", "a", "key1", "dedup1")
    _add(conn, "r2", "b", "key2", "dedup2")
    result = dedupe_store(conn, priority={"a": 10, "b": 95})
    expected_keys = {"total", "clusters", "canonical", "duplicates", "provenance_edges", "merged_by_provenance"}
    assert expected_keys.issubset(result.keys())
    assert result["canonical"] + result["duplicates"] == result["total"]
    conn.close()


def test_merged_by_provenance_counts_reduction() -> None:
    """Derived fold reduces cluster count by 1, reflected in merged_by_provenance."""
    conn = _db()
    _add(conn, "sig1", "sigmahq", "sig:1", "dedup_sig")
    _add(conn, "hay1", "hayabusa", "hay:1", "dedup_hay")
    _relate(conn, "hay1", "sig:1", "derived")
    conn.commit()
    result = dedupe_store(conn, priority={"sigmahq": 10, "hayabusa": 95})
    assert result["merged_by_provenance"] == 1
    conn.close()


def test_folding_relations_constant() -> None:
    """FOLDING_RELATIONS contains exactly derived and renamed."""
    assert FOLDING_RELATIONS == {"derived", "renamed"}
    assert "similar" not in FOLDING_RELATIONS


def test_deterministic_across_runs() -> None:
    """Two consecutive dedupe_store calls yield the same canonical set."""
    conn = _db()
    _add(conn, "sig1", "sigmahq", "sig:1", "dedup_sig")
    _add(conn, "hay1", "hayabusa", "hay:1", "dedup_hay")
    _relate(conn, "hay1", "sig:1", "derived")
    conn.commit()
    dedupe_store(conn, priority={"sigmahq": 10, "hayabusa": 95})
    first = _canonical(conn)
    dedupe_store(conn, priority={"sigmahq": 10, "hayabusa": 95})
    second = _canonical(conn)
    assert first == second
    conn.close()
