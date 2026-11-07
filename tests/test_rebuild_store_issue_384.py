"""rebuild_store re-indexes rule_text when the rebuild fails part-way (#384).

Replacing a corpus deletes its rule_text rows (foreign key). When a later corpus
raised, the loop stopped before rebuild_rule_text ran, so the title index stayed
empty until someone ran scripts/build_rule_text.py. The index is now rebuilt on
the way out, and the error still goes up.
"""
import pytest

from pipeline.detection.brands import cve_evidence
from pipeline.detection.builder import rebuild_store
from pipeline.detection.sigma import SigmaAdapter

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


def test_a_failure_mid_rebuild_keeps_the_title_index_issue_384(temp_db, tmp_path, monkeypatch):
    good = _clone(tmp_path, "good", _CVE_RULE)
    boom = _clone(tmp_path, "boom", _CVE_RULE.replace("Exploit for", "Other copy of"))
    config = _corpus(tmp_path, ("good", good, 1), ("boom", boom, 2))
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()

    rebuild_store(conn, config)
    assert len(_rule_text_ids(conn)) == 1

    # The next rebuild replaces `good` (its rule_text rows go with it), then `boom`
    # raises while its files are read.
    real_parse = SigmaAdapter.parse

    def parse(self, root, **kwargs):
        if kwargs["corpus"] == "boom":
            raise RuntimeError("unexpected failure while reading boom")
        return real_parse(self, root, **kwargs)

    monkeypatch.setattr(SigmaAdapter, "parse", parse)
    with pytest.raises(RuntimeError, match="unexpected failure"):
        rebuild_store(conn, config)

    canonical = {r[0] for r in conn.execute("SELECT id FROM detection_rules WHERE is_canonical=1").fetchall()}
    assert len(canonical) == 1
    assert _rule_text_ids(conn) == sorted(canonical)
    assert set(cve_evidence(conn, ["CVE-2024-3400"])) == canonical
