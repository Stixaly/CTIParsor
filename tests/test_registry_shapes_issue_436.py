"""A registry or corpus entry of an unexpected shape does not crash the rebuild (#436).

A registry whose root is a YAML list raised AttributeError, an entry that is not a
mapping did the same, and `priority: null` raised TypeError in rebuild_store. The
registry now treats a file of the wrong shape as unreadable (as a YAML error does),
skips a bad entry with a warning, and falls back to the default priority with a
warning.
"""
import pytest

from pipeline.detection.builder import rebuild_store
from pipeline.detection.registry import _merged, load_corpora

_CVE_RULE = (
    "title: Exploit for CVE-2024-3400 on PAN-OS\n"
    "logsource: {product: windows}\n"
    "detection:\n"
    "  selection: {Image: gamma-marker}\n"
    "  condition: selection\n"
)


@pytest.mark.parametrize("text", [
    "- name: demo\n  adapter: sigma\n  path: /x\n",   # a YAML list as the root
    "just a string\n",                                # a scalar as the root
    "corpora: 5\n",                                   # `corpora` is not a list
])
def test_a_registry_of_the_wrong_shape_is_unreadable_issue_436(tmp_path, caplog, text):
    config = tmp_path / "detection_corpora.yaml"
    config.write_text(text, encoding="utf-8")

    assert load_corpora(config) == []
    assert _merged(config) == []
    assert "could not parse" in caplog.text


def test_an_entry_that_is_not_a_mapping_is_skipped_issue_436(tmp_path, caplog):
    config = tmp_path / "detection_corpora.yaml"
    config.write_text(
        "corpora:\n"
        "  - 5\n"
        "  - null\n"
        "  - name: demo\n"
        "    adapter: sigma\n"
        "    path: /x\n"
        "    enabled: true\n",
        encoding="utf-8",
    )

    # The valid entry after the bad ones still loads: a control for the skip.
    assert [c["name"] for c in load_corpora(config)] == ["demo"]
    assert caplog.text.count("not a mapping") == 2


@pytest.mark.parametrize("priority_line", ["    priority: null\n", "    priority: high\n"])
def test_a_bad_priority_falls_back_to_the_default_issue_436(temp_db, tmp_path, caplog, priority_line):
    # Two corpora carry the same detection block. `good` has an explicit priority of
    # 999, under the default of 1000, so it must win the election: a `bad` corpus
    # that fell back to a different default would take it instead.
    bad_clone = tmp_path / "bad"
    bad_clone.mkdir()
    (bad_clone / "rule.yml").write_text(_CVE_RULE.replace("Exploit for", "Bad copy of"), encoding="utf-8")
    good_clone = tmp_path / "good"
    good_clone.mkdir()
    (good_clone / "rule.yml").write_text(_CVE_RULE.replace("Exploit for", "Good copy of"), encoding="utf-8")
    config = tmp_path / "detection_corpora.yaml"
    config.write_text(
        "corpora:\n"
        "  - name: bad\n"
        "    adapter: sigma\n"
        f"    path: {bad_clone.as_posix()}\n"
        "    license: proprietary\n"
        "    enabled: true\n"
        f"{priority_line}"
        "  - name: good\n"
        "    adapter: sigma\n"
        f"    path: {good_clone.as_posix()}\n"
        "    license: proprietary\n"
        "    enabled: true\n"
        "    priority: 999\n",
        encoding="utf-8",
    )
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()

    summary = rebuild_store(conn, config)

    assert summary["written"] == {"bad": 1, "good": 1}
    canonical = conn.execute("SELECT corpus FROM detection_rules WHERE is_canonical=1").fetchall()
    assert canonical == [("good",)]
    # Settings writes `priority: null` for an empty field: that one is silent.
    assert ("priority" in caplog.text) == ("null" not in priority_line)
