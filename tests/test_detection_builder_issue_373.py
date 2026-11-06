"""rebuild_store reports the files it could not fully read (#373).

A broken YAML document after a valid rule used to drop that rule without a word:
the rebuild wrote the incomplete corpus and its summary looked like a clean run.
The corpus is still replaced (the valid rules are kept), but the summary now lists
the files in `file_errors`.
"""
from pipeline.detection.builder import rebuild_store
from pipeline.detection.store import corpus_counts


def _rule(title: str, rule_id: str) -> str:
    return (
        f"title: {title}\n"
        f"id: {rule_id}\n"
        "logsource: {product: windows}\n"
        "detection:\n"
        f"  selection: {{Image: {title}-marker}}\n"
        "  condition: selection\n"
    )


_BROKEN_TAIL = "---\ntitle: [unterminated\n"


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


def _written(conn) -> dict[str, int]:
    return {row["corpus"]: row["rules"] for row in corpus_counts(conn)}


def test_broken_document_after_a_valid_rule_keeps_the_store_and_is_reported_issue_373(temp_db, tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "a.yml").write_text(_rule("alpha", "11111111-0000-0000-0000-000000000001"), encoding="utf-8")
    (clone / "b.yml").write_text(_rule("beta", "11111111-0000-0000-0000-000000000002"), encoding="utf-8")
    config = _corpus(tmp_path, clone)
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()

    summary = rebuild_store(conn, config)
    assert summary["total"] == 2
    assert summary["file_errors"] == {}

    # Step 2 of the issue: a broken document appended to the first file.
    (clone / "a.yml").write_text(
        _rule("alpha", "11111111-0000-0000-0000-000000000001") + _BROKEN_TAIL, encoding="utf-8",
    )
    summary = rebuild_store(conn, config)
    assert summary["total"] == 2                          # the valid rule of a.yml is kept
    assert _written(conn) == {"demo": 2}
    assert [e["path"] for e in summary["file_errors"]["demo"]] == ["a.yml"]
    assert "partially imported" in summary["file_errors"]["demo"][0]["error"]

    # Step 4: the same change in the second file. Both rules survive, both files are listed.
    (clone / "b.yml").write_text(
        _rule("beta", "11111111-0000-0000-0000-000000000002") + _BROKEN_TAIL, encoding="utf-8",
    )
    summary = rebuild_store(conn, config)
    assert summary["total"] == 2
    assert _written(conn) == {"demo": 2}
    assert sorted(e["path"] for e in summary["file_errors"]["demo"]) == ["a.yml", "b.yml"]


def test_file_that_is_not_utf8_is_listed_by_its_path_under_the_corpus_root_issue_373(temp_db, tmp_path):
    clone = tmp_path / "clone"
    (clone / "sub").mkdir(parents=True)
    (clone / "ok.yml").write_text(_rule("alpha", "11111111-0000-0000-0000-000000000003"), encoding="utf-8")
    (clone / "sub" / "bad.yml").write_bytes(b"\xff")
    config = _corpus(tmp_path, clone)
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()

    summary = rebuild_store(conn, config)
    assert summary["total"] == 1
    assert _written(conn) == {"demo": 1}
    assert [e["path"] for e in summary["file_errors"]["demo"]] == ["sub/bad.yml"]
    assert "UTF-8" in summary["file_errors"]["demo"][0]["error"]
