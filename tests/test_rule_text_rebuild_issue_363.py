"""rebuild_store refills the rule_text title index it used to erase (#363).

Replacing a corpus deletes its rules, and their rule_text rows go with them
(foreign key). The builder never wrote rule_text back, so after a Rebuild index
the CVE and brand title matches were gone until scripts/build_rule_text.py ran.
"""
from pipeline.detection.brands import cve_evidence
from pipeline.detection.builder import rebuild_store

_CVE_RULE = (
    "title: Exploit for CVE-2024-3400 on PAN-OS\n"
    "logsource: {product: windows}\n"
    "detection:\n"
    "  selection: {Image: gamma-marker}\n"
    "  condition: selection\n"
)


def _clone(tmp_path, name, text):
    """A corpus clone holding one Sigma rule file."""
    clone = tmp_path / name
    clone.mkdir()
    (clone / "rule.yml").write_text(text, encoding="utf-8")
    return clone


def _corpus(tmp_path, *corpora):
    """A registry file with one Sigma corpus per (name, clone, priority)."""
    config = tmp_path / "detection_corpora.yaml"
    lines = ["corpora:\n"]
    for name, clone, priority in corpora:
        lines.append(
            f"  - name: {name}\n"
            "    adapter: sigma\n"
            f"    path: {clone.as_posix()}\n"
            "    license: proprietary\n"
            "    enabled: true\n"
            f"    priority: {priority}\n"
        )
    config.write_text("".join(lines), encoding="utf-8")
    return config


def _rule_text_ids(conn) -> list[str]:
    return sorted(r[0] for r in conn.execute("SELECT rule_id FROM rule_text").fetchall())


def test_rebuild_store_keeps_the_cve_title_match_issue_363(temp_db, tmp_path):
    clone = _clone(tmp_path, "clone", _CVE_RULE)
    config = _corpus(tmp_path, ("demo", clone, 1))
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()

    summary = rebuild_store(conn, config)
    assert summary["rule_text"] == {"rows": 1, "empty_bodies": 0}
    rule_id = conn.execute("SELECT id FROM detection_rules").fetchone()[0]
    assert set(cve_evidence(conn, ["CVE-2024-3400"])) == {rule_id}

    # The same corpus again: the rule is replaced with its rule_text row, and the
    # rebuild indexes it again rather than leaving the store without a match.
    summary = rebuild_store(conn, config)
    assert summary["rule_text"] == {"rows": 1, "empty_bodies": 0}
    assert _rule_text_ids(conn) == [rule_id]
    assert set(cve_evidence(conn, ["CVE-2024-3400"])) == {rule_id}


def test_a_rule_demoted_by_dedup_is_not_indexed_issue_363(temp_db, tmp_path):
    # Same detection block, different titles: dedup folds them into one cluster,
    # and the higher-priority corpus (lower number) keeps the canonical rule.
    high = _clone(tmp_path, "high", _CVE_RULE.replace("Exploit for", "High copy of"))
    low = _clone(tmp_path, "low", _CVE_RULE.replace("Exploit for", "Low copy of"))
    config = _corpus(tmp_path, ("high", high, 1), ("low", low, 2))
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()

    rebuild_store(conn, config)
    canonical = {r[0] for r in conn.execute("SELECT id FROM detection_rules WHERE is_canonical=1").fetchall()}
    demoted = {r[0] for r in conn.execute("SELECT id FROM detection_rules WHERE is_canonical=0").fetchall()}
    assert len(canonical) == 1 and len(demoted) == 1

    assert _rule_text_ids(conn) == sorted(canonical)
    assert set(cve_evidence(conn, ["CVE-2024-3400"])) == canonical
