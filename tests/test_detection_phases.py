import sqlite3

import pytest

from pipeline.detection.phases import (
    TACTIC_ORDER,
    _technique_index,
    covered_phases,
    phase_band,
    report_phases,
)


def _create_test_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE rule_techniques (
            rule_id TEXT,
            technique_id TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE detection_rules (
            id TEXT PRIMARY KEY,
            corpus TEXT,
            is_canonical INTEGER
        )
    """)
    conn.commit()
    return conn


def _skip_if_no_index():
    index = _technique_index()
    if not index:
        pytest.skip("MITRE index is empty or unavailable")


def test_enterprise_technique_lands_in_its_tactic_column():
    _skip_if_no_index()
    # T1190 is "Exploit Public-Facing Application" -> initial-access
    result = report_phases(["T1190"])
    col = next(c for c in result["columns"] if c["tactic"] == "initial-access")
    assert "T1190" in col["techniques"]
    assert result["on_matrix_total"] == 1


def test_subtechnique_uses_its_own_tactics():
    _skip_if_no_index()
    # T1071.003 is "Domain Name System" -> command-and-control
    result = report_phases(["T1071.003"])
    c2_col = next(c for c in result["columns"] if c["tactic"] == "command-and-control")
    assert "T1071.003" in c2_col["techniques"]
    assert result["on_matrix_total"] == 1


def test_multi_tactic_technique_appears_in_every_column_but_counts_once():
    _skip_if_no_index()
    # T1059 "Command and Scripting Interpreter" is often multi-tactic (Execution, Defense Evasion)
    # Let's verify T1059 in the index
    index = _technique_index()
    if "T1059" not in index:
        pytest.skip("T1059 not in index")

    tactics = index["T1059"].get("tactics", [])
    if len(tactics) < 2:
        pytest.skip("T1059 is not multi-tactic in this index version")

    result = report_phases(["T1059"])
    assert result["on_matrix_total"] == 1

    # Check it appears in all its tactics
    for tactic in tactics:
        if tactic in TACTIC_ORDER:
            col = next(c for c in result["columns"] if c["tactic"] == tactic)
            assert "T1059" in col["techniques"]


def test_mobile_technique_is_off_matrix_not_a_column():
    _skip_if_no_index()
    # T1417 is "Network Denial of Service" (Mobile)
    result = report_phases(["T1417"])
    assert "T1417" in [o["technique_id"] for o in result["off_matrix"]]
    off_entry = next(o for o in result["off_matrix"] if o["technique_id"] == "T1417")
    assert off_entry["domain"] == "mobile-attack"
    assert result["on_matrix_total"] == 0


def test_ics_technique_is_off_matrix():
    _skip_if_no_index()
    # T0873 is "Inhibit Response Function" (ICS)
    result = report_phases(["T0873"])
    assert "T0873" in [o["technique_id"] for o in result["off_matrix"]]
    off_entry = next(o for o in result["off_matrix"] if o["technique_id"] == "T0873")
    assert off_entry["domain"] == "ics-attack"
    assert result["on_matrix_total"] == 0


def test_tactic_id_is_off_matrix_with_unknown_domain():
    # TA0042 is a tactic ID, not a technique
    result = report_phases(["TA0042"])
    assert "TA0042" in [o["technique_id"] for o in result["off_matrix"]]
    off_entry = next(o for o in result["off_matrix"] if o["technique_id"] == "TA0042")
    assert off_entry["domain"] == "unknown"
    assert result["on_matrix_total"] == 0


def test_capec_id_is_off_matrix():
    # CAPEC-175
    result = report_phases(["CAPEC-175"])
    assert "CAPEC-175" in [o["technique_id"] for o in result["off_matrix"]]
    off_entry = next(o for o in result["off_matrix"] if o["technique_id"] == "CAPEC-175")
    assert off_entry["domain"] == "capec"
    assert result["on_matrix_total"] == 0


def test_all_tactic_columns_always_present():
    result = report_phases([])
    assert len(result["columns"]) == len(TACTIC_ORDER)
    for col in result["columns"]:
        assert col["techniques"] == []
    assert result["on_matrix_total"] == 0
    assert result["off_matrix_total"] == 0


def test_covered_phases_counts_distinct_rules_not_pairs():
    conn = _create_test_db()
    # One rule carrying two techniques that both land in command-and-control:
    # T1071.003 (DNS) and T1102 (Web Service). The column must count the RULE
    # once, not once per (rule, technique) pair.
    cur = conn.cursor()
    cur.execute("INSERT INTO detection_rules (id, corpus, is_canonical) VALUES ('rule1', 'test', 1)")
    cur.execute("INSERT INTO rule_techniques (rule_id, technique_id) VALUES ('rule1', 'T1102')")
    cur.execute("INSERT INTO rule_techniques (rule_id, technique_id) VALUES ('rule1', 'T1071.003')")
    conn.commit()

    result = covered_phases(conn, ["rule1"])

    c2_col = next(c for c in result["columns"] if c["tactic"] == "command-and-control")
    assert c2_col["rules"] == 1  # Distinct rules, not pairs
    assert "T1102" in c2_col["techniques"]
    assert "T1071.003" in c2_col["techniques"]
    assert result["rules_total"] == 1
    assert result["rules_placed"] == 1
    assert result["rules_untagged"] == 0
    conn.close()


def test_rule_with_only_off_matrix_tags_counts_as_untagged():
    conn = _create_test_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO detection_rules (id, corpus, is_canonical) VALUES ('rule2', 'test', 1)")
    # T1417 is mobile (off-matrix)
    cur.execute("INSERT INTO rule_techniques (rule_id, technique_id) VALUES ('rule2', 'T1417')")
    conn.commit()

    result = covered_phases(conn, ["rule2"])
    assert result["rules_total"] == 1
    assert result["rules_placed"] == 0
    assert result["rules_untagged"] == 1
    conn.close()


def test_covered_phases_empty_input_does_not_query():
    # Create a closed connection to ensure no query is attempted
    conn = sqlite3.connect(":memory:")
    conn.close()

    # This should not raise an exception
    result = covered_phases(conn, [])
    assert result["rules_total"] == 0
    assert result["rules_placed"] == 0
    assert result["rules_untagged"] == 0
    assert len(result["columns"]) == len(TACTIC_ORDER)


def test_gap_juxtaposes_both_rows():
    conn = _create_test_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO detection_rules (id, corpus, is_canonical) VALUES ('rule1', 'test', 1)")
    cur.execute("INSERT INTO rule_techniques (rule_id, technique_id) VALUES ('rule1', 'T1190')")
    conn.commit()

    result = phase_band(conn, ["T1190"], ["rule1"])

    assert "report" in result
    assert "covered" in result
    assert "gap" in result

    # Check gap structure. T1190 is initial-access on both rows: the report
    # names it, and the matched rule is tagged with it.
    assert len(result["gap"]) == len(TACTIC_ORDER)
    gap = next(g for g in result["gap"] if g["tactic"] == "initial-access")
    assert gap["report_techniques"] == 1
    assert gap["covered_rules"] == 1
    conn.close()


def test_every_enterprise_tactic_in_the_index_has_a_column():
    """The column list must be derived from the shipped ATT&CK index, not copied.

    This locks the defect that shipped in the frontend's TACTIC_ORDER: that list
    has fourteen classic columns including `defense-evasion`, while this index
    renamed TA0005 to `stealth` and added TA0112 `defense-impairment`. The
    mismatch silently pushed 204 enterprise techniques off the matrix.
    """
    from pipeline.detection.phases import ENTERPRISE_DOMAIN, TACTIC_LABEL, TACTIC_ORDER
    from pipeline.mitre_db import get_techniques

    techniques = get_techniques()
    if not techniques:
        pytest.skip("MITRE index is empty or unavailable")

    used: set[str] = set()
    for entry in techniques:
        if entry.get("domain") != ENTERPRISE_DOMAIN:
            continue
        for tactic in entry.get("tactics") or []:
            used.add(tactic)

    missing = sorted(used - set(TACTIC_ORDER))
    assert missing == [], f"enterprise tactics with no column: {missing}"
    assert set(TACTIC_ORDER) <= set(TACTIC_LABEL), "every column needs a label"
