"""rebuild_store keeps two Sigma rules without an `id` that share one file (#375).

Both documents used to take the file hash as their storage id, so the second one
replaced the first in `detection_rules` and its atoms were mixed up with it. Each
rule now has its own row and its own atoms.
"""
from pipeline.detection.builder import rebuild_store

_PAIR = (
    "title: First rule\n"
    "logsource: {product: windows}\n"
    "detection:\n"
    "  selection: {Image: alpha-marker}\n"
    "  condition: selection\n"
    "---\n"
    "title: Second rule\n"
    "logsource: {product: windows}\n"
    "detection:\n"
    "  selection: {Image: beta-marker}\n"
    "  condition: selection\n"
)


def _corpus(tmp_path, clone):
    """A one-corpus registry file pointing at `clone`."""
    config = tmp_path / "detection_corpora.yaml"
    config.write_text(
        "corpora:\n"
        "  - name: demo\n"
        "    adapter: sigma\n"
        f"    path: {clone.as_posix()}\n"
        "    license: proprietary\n"
        "    enabled: true\n",
        encoding="utf-8",
    )
    return config


def _rule_id_by_title(conn) -> dict[str, str]:
    return {r["title"]: r["id"] for r in conn.execute("SELECT id, title FROM detection_rules").fetchall()}


def test_two_documents_without_id_become_two_rows_with_their_own_atoms_issue_375(temp_db, tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "pair.yml").write_text(_PAIR, encoding="utf-8")
    config = _corpus(tmp_path, clone)
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()

    summary = rebuild_store(conn, config)
    assert summary["total"] == 2
    assert summary["file_errors"] == {}

    rows = conn.execute("SELECT id, title FROM detection_rules ORDER BY title").fetchall()
    assert [r["title"] for r in rows] == ["First rule", "Second rule"]
    assert rows[0]["id"] != rows[1]["id"]

    ids = _rule_id_by_title(conn)
    atoms = {(r["rule_id"], r["value"]) for r in conn.execute("SELECT rule_id, value FROM rule_atoms").fetchall()}
    assert (ids["First rule"], "alpha-marker") in atoms
    assert (ids["Second rule"], "beta-marker") in atoms
    assert (ids["First rule"], "beta-marker") not in atoms
    assert (ids["Second rule"], "alpha-marker") not in atoms


def test_rebuilding_the_same_corpus_keeps_both_rules_issue_375(temp_db, tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "pair.yml").write_text(_PAIR, encoding="utf-8")
    config = _corpus(tmp_path, clone)
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()

    rebuild_store(conn, config)
    first = _rule_id_by_title(conn)
    summary = rebuild_store(conn, config)
    assert summary["total"] == 2
    assert _rule_id_by_title(conn) == first
    assert conn.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0] == 2
