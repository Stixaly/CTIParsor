"""Tests for cross-corpus rule deduplication (ADR-0010).

Covers the adapter's normalized dedup_key, the dedupe_store election pass, the
registry `subdir` scoping, and an end-to-end hayabusa-vs-sigmahq overlap fixture
asserting that a duplicated corpus does not inflate coverage.
"""
from uuid import uuid4

from pipeline.detection.coverage import compute_for_job
from pipeline.detection.dedup import dedupe_store
from pipeline.detection.registry import corpus_root
from pipeline.detection.sigma import SigmaAdapter
from pipeline.detection.store import (
    corpus_counts,
    replace_corpus_rules,
    rule_refs_for_techniques,
    rules_for_technique,
)

# A SigmaHQ-style rule and the "same" rule as a hayabusa conversion: reordered
# selection keys, reformatted whitespace, different title/id/author. Same logic.
_SIGMAHQ = """\
title: Suspicious PowerShell Encoded Command
id: 11111111-2222-3333-4444-555555555555
author: SigmaHQ
description: Detects powershell -EncodedCommand usage.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
"""

_HAYABUSA_CONVERTED = """\
title: PowerShell EncodedCommand (converted)
id: 99999999-8888-7777-6666-555555555555
author: Yamato Security
description: Converted rule.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: '-EncodedCommand'
    Image|endswith: '\\powershell.exe'
  condition: selection
level: high
tags:
  - attack.t1059.001
  - attack.execution
"""

# A genuinely different rule that also covers T1059.001 — must NOT be folded.
_INDEPENDENT = """\
title: PowerShell Download Cradle
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'DownloadString'
  condition: selection
level: high
tags:
  - attack.t1059.001
"""


# ── Adapter: normalized dedup_key ─────────────────────────────────────────────

def _parse(text, corpus):
    import pathlib
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "r.yml").write_text(text, encoding="utf-8")
    return list(SigmaAdapter().parse(d, corpus=corpus, license="x"))[0]


def test_dedup_key_ignores_metadata_and_field_order():
    a = _parse(_SIGMAHQ, "sigmahq")
    b = _parse(_HAYABUSA_CONVERTED, "hayabusa")
    assert a.dedup_key and a.dedup_key == b.dedup_key   # same logic → same key
    assert a.content_hash != b.content_hash             # but not byte-identical


def test_dedup_key_differs_for_different_logic():
    a = _parse(_SIGMAHQ, "sigmahq")
    c = _parse(_INDEPENDENT, "indie")
    assert a.dedup_key != c.dedup_key


# ── dedupe_store election ─────────────────────────────────────────────────────

def test_dedupe_elects_canonical_by_priority(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sigmahq", [_parse(_SIGMAHQ, "sigmahq")])
    replace_corpus_rules(conn, "hayabusa", [_parse(_HAYABUSA_CONVERTED, "hayabusa")])

    summary = dedupe_store(conn, {"sigmahq": 10, "hayabusa": 95})
    assert summary == {"total": 2, "clusters": 1, "canonical": 1, "duplicates": 1}

    # both rows survive (lossless) — only the flag differs; sigmahq wins (lower priority)
    rows = dict(conn.execute(
        "SELECT corpus, is_canonical FROM detection_rules"
    ).fetchall())
    assert rows == {"sigmahq": 1, "hayabusa": 0}


def test_dedupe_keeps_independent_rules(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sigmahq", [_parse(_SIGMAHQ, "sigmahq")])
    replace_corpus_rules(conn, "indie", [_parse(_INDEPENDENT, "indie")])
    summary = dedupe_store(conn, {"sigmahq": 10, "indie": 50})
    assert summary["canonical"] == 2 and summary["duplicates"] == 0


def test_dedupe_no_priority_is_deterministic(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "zeta", [_parse(_SIGMAHQ, "zeta")])
    replace_corpus_rules(conn, "alpha", [_parse(_HAYABUSA_CONVERTED, "alpha")])
    dedupe_store(conn, {})  # no priorities → tie broken by corpus name
    canon = conn.execute(
        "SELECT corpus FROM detection_rules WHERE is_canonical=1"
    ).fetchone()[0]
    assert canon == "alpha"


# ── End-to-end: a duplicate corpus must not inflate coverage ──────────────────

def _job_with_technique(temp_db, conn, job_id, technique):
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)", (job_id, "r.txt", "reviewing", temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), job_id, technique, "technique", technique, 1, "llm"),
    )
    conn.commit()


def test_duplicate_corpus_does_not_raise_score(temp_db):
    conn = temp_db.get_conn()
    # SigmaHQ alone covers T1059.001 → score 2 (single corpus)
    replace_corpus_rules(conn, "sigmahq", [_parse(_SIGMAHQ, "sigmahq")])
    dedupe_store(conn, {"sigmahq": 10})
    _job_with_technique(temp_db, conn, "j-dup", "T1059.001")
    assert compute_for_job(conn, "j-dup")["cells"][0]["score"] == 2

    # Adding hayabusa's *copy* must not bump it to 3 — it's the same logical rule
    replace_corpus_rules(conn, "hayabusa", [_parse(_HAYABUSA_CONVERTED, "hayabusa")])
    dedupe_store(conn, {"sigmahq": 10, "hayabusa": 95})
    cell = compute_for_job(conn, "j-dup")["cells"][0]
    assert cell["score"] == 2          # still single effective corpus
    assert cell["corpora"] == ["sigmahq"]

    # An independent rule, however, legitimately corroborates → score 3
    replace_corpus_rules(conn, "indie", [_parse(_INDEPENDENT, "indie")])
    dedupe_store(conn, {"sigmahq": 10, "hayabusa": 95, "indie": 50})
    assert compute_for_job(conn, "j-dup")["cells"][0]["score"] == 3


def test_drilldown_preserves_duplicate_provenance(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sigmahq", [_parse(_SIGMAHQ, "sigmahq")])
    replace_corpus_rules(conn, "hayabusa", [_parse(_HAYABUSA_CONVERTED, "hayabusa")])
    dedupe_store(conn, {"sigmahq": 10, "hayabusa": 95})

    rules = rules_for_technique(conn, "T1059.001")
    assert len(rules) == 1                      # one canonical rule shown
    assert rules[0]["corpus"] == "sigmahq"
    assert rules[0]["also_in"] == ["hayabusa"]  # the folded copy is still credited

    # coverage refs are canonical-only
    refs = rule_refs_for_techniques(conn, ["T1059.001"])
    assert {c for _t, c, _k in refs} == {"sigmahq"}


def test_corpus_counts_reports_total_and_canonical(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sigmahq", [_parse(_SIGMAHQ, "sigmahq")])
    replace_corpus_rules(conn, "hayabusa", [_parse(_HAYABUSA_CONVERTED, "hayabusa")])
    dedupe_store(conn, {"sigmahq": 10, "hayabusa": 95})
    counts = {c["corpus"]: c for c in corpus_counts(conn)}
    assert counts["hayabusa"]["rules"] == 1 and counts["hayabusa"]["canonical"] == 0
    assert counts["sigmahq"]["rules"] == 1 and counts["sigmahq"]["canonical"] == 1


# ── Registry subdir scoping ───────────────────────────────────────────────────

def test_corpus_root_applies_subdir(tmp_path):
    assert corpus_root({"path": str(tmp_path)}) == tmp_path
    assert corpus_root({"path": str(tmp_path), "subdir": "sigma"}) == tmp_path / "sigma"
    assert corpus_root({"path": str(tmp_path), "subdir": ""}) == tmp_path
