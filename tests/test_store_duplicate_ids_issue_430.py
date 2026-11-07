"""replace_corpus_rules keeps one row per rule id when a batch repeats it (#430).

`detection_rules` took the last rule written with a repeated id (`DO UPDATE`), but
the child tables used `ON CONFLICT DO NOTHING`, so the surviving row carried the
atoms and techniques of every rule that shared the id. A Sigma `id:` written twice
and a Suricata `gid:sid` repeated are the two ways a real corpus gets there (#375
removed the id-less Sigma case).
"""
from __future__ import annotations

import logging

from models.detection import DetectionRule
from pipeline.detection.builder import rebuild_store
from pipeline.detection.store import replace_corpus_rules

_SIGMA_SAME_ID = (
    "title: First rule\n"
    "id: dup-sigma-id\n"
    "logsource: {product: windows}\n"
    "tags: [attack.t1059.001]\n"
    "detection:\n"
    "  selection: {Image: alpha-marker}\n"
    "  condition: selection\n"
    "---\n"
    "title: Second rule\n"
    "id: dup-sigma-id\n"
    "logsource: {product: windows}\n"
    "tags: [attack.t1027]\n"
    "detection:\n"
    "  selection: {Image: beta-marker}\n"
    "  condition: selection\n"
)

_SURICATA_SAME_SID = (
    'alert tcp any any -> any 80 (msg:"First rule"; content:"alpha-marker"; sid:1; gid:1; rev:1;)\n'
    'alert tcp any any -> any 80 (msg:"Second rule"; content:"beta-marker"; sid:1; gid:1; rev:1;)\n'
)


def _corpus(tmp_path, clone, adapter):
    """A one-corpus registry file pointing at `clone`."""
    config = tmp_path / "detection_corpora.yaml"
    config.write_text(
        "corpora:\n"
        "  - name: demo\n"
        f"    adapter: {adapter}\n"
        f"    path: {clone.as_posix()}\n"
        "    license: proprietary\n"
        "    enabled: true\n",
        encoding="utf-8",
    )
    return config


def _values(conn, table, rule_id, column) -> set[str]:
    return {r[column] for r in conn.execute(
        f"SELECT {column} FROM {table} WHERE rule_id=?", (rule_id,)
    ).fetchall()}


def _rule(key, title, atom, technique):
    return DetectionRule(
        id=f"core:{key}", corpus="core", format="sigma", title=title,
        technique_ids=[technique], atoms=[("process", atom)],
        license="proprietary", raw=f"title: {title}\n",
    )


def test_repeated_sigma_id_keeps_only_the_last_rule_issue_430(temp_db, tmp_path, caplog):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "pair.yml").write_text(_SIGMA_SAME_ID, encoding="utf-8")
    config = _corpus(tmp_path, clone, "sigma")
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()

    with caplog.at_level(logging.WARNING):
        summary = rebuild_store(conn, config)
    assert summary["total"] == 1

    rows = conn.execute("SELECT id, title FROM detection_rules").fetchall()
    assert [r["title"] for r in rows] == ["Second rule"]
    rid = rows[0]["id"]
    atoms = _values(conn, "rule_atoms", rid, "value")
    assert "beta-marker" in atoms
    assert "alpha-marker" not in atoms
    assert _values(conn, "rule_techniques", rid, "technique_id") == {"T1027"}
    assert "demo:dup-sigma-id" in caplog.text


def test_repeated_suricata_sid_keeps_only_the_last_rule_issue_430(temp_db, tmp_path, caplog):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "local.rules").write_text(_SURICATA_SAME_SID, encoding="utf-8")
    config = _corpus(tmp_path, clone, "suricata")
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()

    with caplog.at_level(logging.WARNING):
        summary = rebuild_store(conn, config)
    assert summary["total"] == 1

    rows = conn.execute("SELECT id, title FROM detection_rules").fetchall()
    assert [r["title"] for r in rows] == ["Second rule"]
    atoms = _values(conn, "rule_atoms", rows[0]["id"], "value")
    assert "beta-marker" in atoms
    assert "alpha-marker" not in atoms
    assert "demo:1:1" in caplog.text


def test_distinct_ids_in_one_batch_are_written_unchanged_issue_430(temp_db, caplog):
    conn = temp_db.get_rule_conn()
    rules = [
        _rule("a", "Rule A", "alpha-marker", "T1059"),
        _rule("b", "Rule B", "beta-marker", "T1027"),
    ]

    with caplog.at_level(logging.WARNING):
        written = replace_corpus_rules(conn, "core", rules)
    assert written == 2
    assert "duplicate" not in caplog.text

    for key, atom, technique in (("a", "alpha-marker", "T1059"), ("b", "beta-marker", "T1027")):
        rid = f"core:{key}"
        assert _values(conn, "rule_atoms", rid, "value") == {atom}
        assert _values(conn, "rule_techniques", rid, "technique_id") == {technique}
