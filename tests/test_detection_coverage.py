"""Tests for detection coverage scoring + store + API (ADR-0006)."""
import io
import json
import zipfile
from uuid import uuid4

from models.detection import DetectionRule, Severity
from pipeline.detection.coverage import (
    DETECTION_FORMATS,
    compute_for_job,
    rule_bodies_for_job,
    rules_for_job,
    score_techniques,
)
from pipeline.detection.store import (
    corpus_counts,
    replace_corpus_rules,
    rule_refs_for_techniques,
    rules_for_technique,
)

# ── Scoring policy (pure) ─────────────────────────────────────────────────────

def test_independent_corpora_corroborate_to_3():
    refs = [("T1059", "core", "k1"), ("T1059", "cloud", "k2")]
    cell = score_techniques(["T1059"], refs)[0]
    assert cell.score == 3
    assert cell.corpora == ["cloud", "core"]
    assert cell.rule_count == 2


def test_forked_rule_does_not_inflate_score():
    # same native_key in two corpora = one logical rule (a fork) → score 2, not 3
    refs = [("T1059", "core", "k1"), ("T1059", "cloud", "k1")]
    cell = score_techniques(["T1059"], refs)[0]
    assert cell.score == 2
    assert cell.corpora == ["core"]   # first-seen corpus owns the shared rule
    assert cell.rule_count == 1


def test_single_corpus_scores_2():
    assert score_techniques(["T1059"], [("T1059", "core", "k1")])[0].score == 2


def test_no_rules_scores_0():
    assert score_techniques(["T1003"], [])[0].score == 0


def test_telemetry_only_scores_1():
    cell = score_techniques(["T1003"], [], telemetry_techniques={"T1003"})[0]
    assert cell.score == 1


# ── Store round-trip + compute_for_job (temp DB) ──────────────────────────────

def _rule(corpus, key, techniques, *, raw=None, license="proprietary"):
    return DetectionRule(
        id=f"{corpus}:{key}", corpus=corpus, title=f"rule {key}",
        technique_ids=techniques, severity=Severity.HIGH, license=license,
        raw=raw if raw is not None else f"title: rule {key}\nlogsource: {corpus}\n",
    )


def test_store_replace_and_query(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [_rule("core", "k1", ["T1059", "T1027"])])
    replace_corpus_rules(conn, "cloud", [_rule("cloud", "k2", ["T1059"])])

    refs = rule_refs_for_techniques(conn, ["T1059"])
    assert {(c, k) for _t, c, k, _f in refs} == {("core", "k1"), ("cloud", "k2")}
    assert {r["corpus"]: r["rules"] for r in corpus_counts(conn)} == {"core": 1, "cloud": 1}

    # replace is idempotent — re-running one corpus doesn't duplicate
    replace_corpus_rules(conn, "core", [_rule("core", "k1", ["T1059", "T1027"])])
    assert {r["corpus"]: r["rules"] for r in corpus_counts(conn)}["core"] == 1


def test_compute_for_job_scores_accepted_techniques(temp_db):
    conn = temp_db.get_conn()
    # two independent corpora cover T1059; nothing covers T1003
    replace_corpus_rules(conn, "core", [_rule("core", "k1", ["T1059"])])
    replace_corpus_rules(conn, "cloud", [_rule("cloud", "k2", ["T1059"])])

    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES ('j1','r.txt','reviewing',?,?)", (temp_db.now_iso(), temp_db.now_iso()),
    )
    for mid, accepted in (("T1059", 1), ("T1003", 1), ("T1110", 0)):  # T1110 rejected → excluded
        conn.execute(
            "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
            "VALUES (?,?,?,?,?,?,?)",
            (str(uuid4()), "j1", mid, "technique", mid, accepted, "llm"),
        )
    conn.commit()

    result = compute_for_job(conn, "j1")
    cells = {c["technique_id"]: c for c in result["cells"]}
    assert set(cells) == {"T1059", "T1003"}          # rejected T1110 excluded
    assert cells["T1059"]["score"] == 3               # corroborated
    assert cells["T1003"]["score"] == 0               # no rules
    assert result["validated"] is False               # readiness, not validation


def test_parent_rule_covers_subtechnique(temp_db):
    """A rule tagged with the parent technique (T1059) must credit a report's
    sub-technique (T1059.001); a sibling sub-technique rule (T1059.003) must not."""
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [_rule("core", "k1", ["T1059"])])         # parent rule
    replace_corpus_rules(conn, "sibling", [_rule("sibling", "k2", ["T1059.003"])])  # sibling sub

    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES ('jp','r.txt','reviewing',?,?)", (temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), "jp", "PowerShell", "technique", "T1059.001", 1, "llm"),
    )
    conn.commit()

    cells = {c["technique_id"]: c for c in compute_for_job(conn, "jp")["cells"]}
    assert set(cells) == {"T1059.001"}
    # Covered by the parent rule (score 2 — one corpus), NOT by the sibling sub.
    assert cells["T1059.001"]["score"] == 2
    assert cells["T1059.001"]["corpora"] == ["core"]


# ── API ───────────────────────────────────────────────────────────────────────

def test_coverage_api(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [_rule("core", "k1", ["T1059"])])
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES ('j2','r.txt','reviewing',?,?)", (temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), "j2", "PowerShell", "technique", "T1059", 1, "llm"),
    )
    conn.commit()

    resp = temp_db_client.get("/api/jobs/j2/coverage")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["techniques_total"] == 1
    assert body["cells"][0]["technique_id"] == "T1059" and body["cells"][0]["score"] == 2

    assert temp_db_client.get("/api/jobs/does-not-exist/coverage").status_code == 404
    assert temp_db_client.get("/api/detection-corpora").json()["corpora"][0]["corpus"] == "core"


# ── Sigma export ────────────────────────────────────────────────────────────

def _job_with_technique(temp_db, job_id, mitre_id, *, accepted=1):
    conn = temp_db.get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)", (job_id, "r.txt", "reviewing", temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), job_id, mitre_id, "technique", mitre_id, accepted, "llm"),
    )
    conn.commit()


def test_rule_bodies_for_job_returns_raw_and_techniques(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [_rule("core", "k1", ["T1059"], raw="detection: powershell")])
    _job_with_technique(temp_db, "jb", "T1059")

    bodies = rule_bodies_for_job(conn, "jb")
    assert len(bodies) == 1
    assert bodies[0]["raw"] == "detection: powershell"
    assert bodies[0]["techniques"] == ["T1059"]
    assert bodies[0]["corpus"] == "core"


def test_export_detections_zip(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [
        _rule("core", "k1", ["T1059"], raw="title: ps\ndetection: a", license="DRL-1.1"),
        _rule("core", "k2", ["T1059"], raw="title: cmd\ndetection: b", license="DRL-1.1"),
    ])
    _job_with_technique(temp_db, "jz", "T1059")

    resp = temp_db_client.get("/api/jobs/jz/detections/export")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/zip"
    assert "jz" not in resp.headers["content-disposition"]  # named after the report, not the id
    # ADR-0020 renamed the archive: it is no longer Sigma-only, and a mixed export
    # labelled "_sigma_rules" would misdescribe its contents.
    assert resp.headers["content-disposition"].endswith('_detection_rules.zip"')

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    rule_files = [n for n in names if n.startswith("rules/")]
    assert len(rule_files) == 2
    assert "MANIFEST.json" in names and "README.txt" in names

    manifest = json.loads(zf.read("MANIFEST.json"))
    assert manifest["rule_count"] == 2
    assert {r["license"] for r in manifest["rules"]} == {"DRL-1.1"}
    # raw bodies are actually written
    assert zf.read(rule_files[0]).decode().startswith("title:")


def test_export_detections_404_when_no_rules(temp_db, temp_db_client):
    _job_with_technique(temp_db, "jn", "T1003")  # nothing covers T1003
    resp = temp_db_client.get("/api/jobs/jn/detections/export")
    assert resp.status_code == 404

    assert temp_db_client.get("/api/jobs/missing/detections/export").status_code == 404


# ── Per-format breakdown + drill-down query shape (ADR-0022) ──────────────────

def _fmt_rule(corpus, key, techniques, fmt, *, dedup_key="", license="proprietary"):
    return DetectionRule(
        id=f"{corpus}:{key}", corpus=corpus, title=f"rule {key}",
        technique_ids=techniques, severity=Severity.HIGH, license=license,
        format=fmt, dedup_key=dedup_key,
        raw=f"title: rule {key}\nlogsource: {corpus}\n",
    )


def test_rule_refs_carry_format(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "net", [_fmt_rule("net", "s1", ["T1190"], "suricata")])
    replace_corpus_rules(conn, "sig", [_fmt_rule("sig", "g1", ["T1190"], "sigma")])

    refs = rule_refs_for_techniques(conn, ["T1190"])
    assert len(refs) == 2
    for ref in refs:
        assert len(ref) == 4
    assert {(r[1], r[3]) for r in refs} == {("net", "suricata"), ("sig", "sigma")}


def test_blank_format_reads_back_as_sigma(temp_db):
    """A blank format must not drop a rule out of every format lane.

    `detection_rules.format` is `NOT NULL DEFAULT 'sigma'`, so NULL cannot occur
    and is not tested here; an empty string is the only reachable blank, and the
    live store holds none. The fallback is therefore defensive, and matches the
    one `_load_rules` applies on the export path.
    """
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [_fmt_rule("sig", "g1", ["T1190"], "sigma")])

    conn.execute("UPDATE detection_rules SET format = ''")
    conn.commit()
    assert rule_refs_for_techniques(conn, ["T1190"])[0][3] == "sigma"
    assert rules_for_technique(conn, "T1190")[0]["format"] == "sigma"


def test_rules_for_technique_exposes_format_and_key_order(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "yarahq", [_fmt_rule("yarahq", "y1", ["T1486"], "yara")])

    rules = rules_for_technique(conn, "T1486")
    assert rules[0]["format"] == "yara"
    # Key order is part of the contract — the frontend CoverageRule type mirrors it.
    assert list(rules[0].keys()) == [
        "id", "corpus", "title", "severity", "license",
        "source_ref", "format", "bytes", "also_in",
    ]


def test_also_in_excludes_own_corpus_after_batching(temp_db):
    conn = temp_db.get_conn()
    for corpus in ("alpha", "beta", "gamma"):
        replace_corpus_rules(
            conn, corpus,
            [_fmt_rule(corpus, "r1", ["T1190"], "sigma", dedup_key="dk1")],
        )
    conn.execute(
        "UPDATE detection_rules SET is_canonical = 0 WHERE corpus IN ('beta','gamma')"
    )
    conn.commit()

    rules = rules_for_technique(conn, "T1190")
    assert len(rules) == 1
    assert rules[0]["also_in"] == ["beta", "gamma"]
    assert "alpha" not in rules[0]["also_in"]


def test_also_in_empty_when_dedup_key_missing(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "alpha", [_fmt_rule("alpha", "r1", ["T1190"], "sigma")])
    replace_corpus_rules(conn, "beta", [_fmt_rule("beta", "r2", ["T1190"], "sigma")])

    rules = rules_for_technique(conn, "T1190")
    assert len(rules) == 2
    for rule in rules:
        assert rule["also_in"] == []


def test_rules_for_technique_does_not_query_per_rule(temp_db):
    """The `also_in` lookup must be one sweep, not one query per rule.

    The pre-ADR-0022 implementation issued one sub-query per rule — 31 statements
    for 30 rules, measured at 871-1227 ms each against the real store, which is
    what made the drill-down endpoint take hours. The batched sweep issues one
    statement per 400 dedup keys, so 30 rules cost at most 2; the bound of 3
    leaves room for the outer query without admitting an N+1.
    """
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [
        _fmt_rule("core", f"k{i}", ["T1059"], "sigma", dedup_key=f"dk{i}")
        for i in range(30)
    ])

    stmts = []
    conn.set_trace_callback(stmts.append)
    out = rules_for_technique(conn, "T1059")
    conn.set_trace_callback(None)

    assert len(out) == 30
    assert len(stmts) <= 3


def test_also_in_sweep_pins_the_dedup_index(temp_db):
    """The sweep must pin `idx_detection_dedup` via INDEXED BY.

    Asserting on the *executed statement* rather than on EXPLAIN QUERY PLAN is
    deliberate. A plan assertion passes for the wrong reason here: on a fixture
    holding a handful of rows SQLite picks the dedup index anyway, so the test
    stayed green with the directive deleted — verified by re-introducing the
    defect. Only the statement text distinguishes "pinned" from "happened to be
    chosen", and pinning is what holds at 86k rows (ADR-0022).
    """
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [
        _fmt_rule("core", "k1", ["T1059"], "sigma", dedup_key="dk1"),
    ])

    stmts: list[str] = []
    conn.set_trace_callback(stmts.append)
    rules_for_technique(conn, "T1059")
    conn.set_trace_callback(None)

    sweep = [s for s in stmts if "dedup_key" in s and "is_canonical=0" in s]
    assert sweep, "the also_in sweep did not run"
    assert all("INDEXED BY idx_detection_dedup" in s for s in sweep)

    # And the outer query must not be the JOIN form that enters via idx_detection_canon.
    outer = [s for s in stmts if "rule_techniques" in s]
    assert outer and all("EXISTS" in s for s in outer)


def test_score_without_formats_is_unchanged():
    """Backward-compatibility lock: no `formats` argument, no behaviour change."""
    cell = score_techniques(
        ["T1059"], [("T1059", "core", "k1"), ("T1059", "cloud", "k2")]
    )[0]
    assert cell.score == 3
    assert cell.rule_count == 2
    assert cell.by_format == {}


def test_by_format_splits_counts_and_corpora():
    refs = [
        ("T1190", "sig", "k1"),
        ("T1190", "sig", "k2"),
        ("T1190", "net", "k3"),
    ]
    formats = {"k1": "sigma", "k2": "sigma", "k3": "suricata"}
    cell = score_techniques(["T1190"], refs, formats=formats)[0]

    assert cell.score == 3
    assert cell.rule_count == 3
    assert cell.by_format["sigma"] == {"rule_count": 2, "corpora": ["sig"]}
    assert cell.by_format["suricata"] == {"rule_count": 1, "corpora": ["net"]}
    assert cell.by_format["yara"] == {"rule_count": 0, "corpora": []}
    assert set(cell.by_format) == set(DETECTION_FORMATS)


def test_by_format_sums_to_rule_count():
    refs = [
        ("T1190", "sig", "k1"), ("T1190", "sig", "k2"),
        ("T1190", "net", "k3"), ("T1190", "net", "k4"),
        ("T1190", "sb", "k5"), ("T1190", "sb", "k6"),
    ]
    formats = {
        "k1": "sigma", "k2": "sigma",
        "k3": "suricata", "k4": "suricata",
        "k5": "yara", "k6": "yara",
    }
    cell = score_techniques(["T1190"], refs, formats=formats)[0]

    assert cell.rule_count == 6
    # Holds because a native_key never spans two formats — a failure here means
    # that assumption broke, not that the arithmetic did.
    assert sum(
        cell.by_format[f]["rule_count"] for f in DETECTION_FORMATS
    ) == cell.rule_count


def test_by_format_corpora_use_first_seen_owner():
    """If the panel counted each ref's own corpus instead of the owning corpus, it
    would show two corpora where the score sees one, and the UI would claim more
    corroboration than the score does."""
    refs = [
        ("T1190", "core", "k1"),
        ("T1190", "cloud", "k1"),
        ("T1190", "core", "k2"),
    ]
    formats = {"k1": "sigma", "k2": "sigma"}
    cell = score_techniques(["T1190"], refs, formats=formats)[0]

    assert cell.score == 2
    assert cell.rule_count == 2
    assert cell.by_format["sigma"]["corpora"] == ["core"]


def test_unknown_format_counts_in_total_but_no_bucket():
    """A format outside DETECTION_FORMATS still counts toward the cell total."""
    cell = score_techniques(["T1190"], [("T1190", "core", "k1")], formats={"k1": "snort"})[0]

    assert cell.rule_count == 1
    for fmt in DETECTION_FORMATS:
        assert cell.by_format[fmt]["rule_count"] == 0
    assert set(cell.by_format) == set(DETECTION_FORMATS)


def test_compute_for_job_emits_by_format(temp_db):
    conn = temp_db.get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES ('jf','r.txt','reviewing',?,?)", (temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), "jf", "T1190", "technique", "T1190", 1, "llm"),
    )
    conn.commit()

    replace_corpus_rules(conn, "sig", [_fmt_rule("sig", "g1", ["T1190"], "sigma")])
    replace_corpus_rules(conn, "net", [
        _fmt_rule("net", "s1", ["T1190"], "suricata"),
        _fmt_rule("net", "s2", ["T1190"], "suricata"),
    ])

    cells = {c["technique_id"]: c for c in compute_for_job(conn, "jf")["cells"]}
    cell = cells["T1190"]
    assert set(cell["by_format"]) == set(DETECTION_FORMATS)
    assert cell["by_format"]["sigma"]["rule_count"] == 1
    assert cell["by_format"]["suricata"]["rule_count"] == 2
    assert cell["by_format"]["yara"] == {"rule_count": 0, "corpora": []}


# ── Rule-id export + byte sizes + proposal formats (ADR-0022, step 2) ─────────

def test_export_selection_zip(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [
        _fmt_rule("sig", "s1", ["T1059"], "sigma"),
        _fmt_rule("sig", "s2", ["T1059"], "sigma"),
    ])
    replace_corpus_rules(conn, "net", [_fmt_rule("net", "n1", ["T1059"], "suricata")])
    _job_with_technique(temp_db, "js", "T1059")

    resp = temp_db_client.post(
        "/api/jobs/js/detections/export",
        json={"rule_ids": ["sig:s1", "net:n1"]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/zip"
    assert resp.headers["content-disposition"].endswith('_detection_rules.zip"')

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    rule_files = [n for n in names if n.startswith("rules/")]
    assert len(rule_files) == 2

    sigma_files = [n for n in rule_files if n.startswith("rules/sigma/")]
    suricata_files = [n for n in rule_files if n.startswith("rules/suricata/")]
    assert len(sigma_files) == 1 and sigma_files[0].endswith(".yml")
    assert len(suricata_files) == 1 and suricata_files[0].endswith(".rules")

    manifest = json.loads(zf.read("MANIFEST.json"))
    assert manifest["rule_count"] == 2
    assert manifest["excluded"]["total"] == 1
    assert manifest["filters"]["rule_ids"] == 2
    assert {r["id"] for r in manifest["rules"]} == {"sig:s1", "net:n1"}


def test_export_selection_ignores_rules_outside_the_report(temp_db, temp_db_client):
    """Ids are intersected with the report's linkable set — the export must never
    become a generic store-dump endpoint keyed by arbitrary ids."""
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [
        _fmt_rule("sig", "s1", ["T1059"], "sigma"),
        _fmt_rule("sig", "zz", ["T1486"], "sigma"),   # technique NOT in the job
    ])
    _job_with_technique(temp_db, "jo", "T1059")

    resp = temp_db_client.post(
        "/api/jobs/jo/detections/export",
        json={"rule_ids": ["sig:s1", "sig:zz"]},
    )
    assert resp.status_code == 200, resp.text

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    rule_files = [n for n in zf.namelist() if n.startswith("rules/")]
    assert len(rule_files) == 1

    manifest = json.loads(zf.read("MANIFEST.json"))
    assert {r["id"] for r in manifest["rules"]} == {"sig:s1"}


def test_export_selection_400_on_empty_ids(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [_fmt_rule("sig", "s1", ["T1059"], "sigma")])
    _job_with_technique(temp_db, "je", "T1059")

    assert temp_db_client.post(
        "/api/jobs/je/detections/export", json={"rule_ids": []},
    ).status_code == 400
    # Blank ids are filtered out before the emptiness check.
    assert temp_db_client.post(
        "/api/jobs/je/detections/export", json={"rule_ids": ["  ", ""]},
    ).status_code == 400


def test_export_selection_404_when_nothing_matches(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [_fmt_rule("sig", "s1", ["T1059"], "sigma")])
    _job_with_technique(temp_db, "jm", "T1059")

    assert temp_db_client.post(
        "/api/jobs/jm/detections/export", json={"rule_ids": ["ghost:x"]},
    ).status_code == 404
    assert temp_db_client.post(
        "/api/jobs/missing/detections/export", json={"rule_ids": ["sig:s1"]},
    ).status_code == 404


def test_export_get_and_post_share_the_layout(temp_db, temp_db_client):
    """The two routes share `_zip_export`; this locks the invariant that they can
    never drift in archive layout."""
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [
        _fmt_rule("sig", "s1", ["T1059"], "sigma"),
        _fmt_rule("sig", "s2", ["T1059"], "sigma"),
    ])
    _job_with_technique(temp_db, "jp2", "T1059")

    resp_get = temp_db_client.get("/api/jobs/jp2/detections/export")
    assert resp_get.status_code == 200, resp_get.text
    resp_post = temp_db_client.post(
        "/api/jobs/jp2/detections/export",
        json={"rule_ids": ["sig:s1", "sig:s2"]},
    )
    assert resp_post.status_code == 200, resp_post.text

    zf_get = zipfile.ZipFile(io.BytesIO(resp_get.content))
    zf_post = zipfile.ZipFile(io.BytesIO(resp_post.content))
    assert set(zf_get.namelist()) == set(zf_post.namelist())

    manifest_get = json.loads(zf_get.read("MANIFEST.json"))
    manifest_post = json.loads(zf_post.read("MANIFEST.json"))
    assert manifest_get["rule_count"] == manifest_post["rule_count"]


def test_rules_for_technique_exposes_bytes(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [_fmt_rule("sig", "s1", ["T1190"], "sigma")])

    result = rules_for_technique(conn, "T1190")
    assert len(result) == 1
    assert result[0]["bytes"] == len("title: rule s1\nlogsource: sig\n")
    assert list(result[0].keys()) == [
        "id", "corpus", "title", "severity", "license", "source_ref", "format",
        "bytes", "also_in",
    ]


def test_proposals_carry_format(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "net", [_fmt_rule("net", "n1", ["T1059"], "suricata")])
    _job_with_technique(temp_db, "jf2", "T1059")

    resp = temp_db_client.get("/api/jobs/jf2/detections/proposals")
    assert resp.status_code == 200, resp.text
    proposals = resp.json().get("proposals", [])
    assert len(proposals) > 0
    assert all("format" in p for p in proposals)
    net_n1 = next((p for p in proposals if p["id"] == "net:n1"), None)
    assert net_n1 is not None and net_n1["format"] == "suricata"


# ── Flat rules_for_job sweep + body-restricted export (ADR-0022, perf) ────────

def _job_with_techniques(temp_db, job_id, mitre_ids):
    conn = temp_db.get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)", (job_id, "r.txt", "reviewing", temp_db.now_iso(), temp_db.now_iso()),
    )
    for mid in mitre_ids:
        conn.execute(
            "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
            "VALUES (?,?,?,?,?,?,?)",
            (str(uuid4()), job_id, mid, "technique", mid, 1, "llm"),
        )
    conn.commit()


def test_rules_for_job_flat_rewrite_keeps_parent_rollup(temp_db):
    """The flat sweep must reproduce the per-technique form exactly, including the
    parent→sub roll-up that credits a T1059-tagged rule to T1059.001."""
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [
        _fmt_rule("sig", "s1", ["T1059"], "sigma"),
        _fmt_rule("sig", "s2", ["T1059"], "sigma"),
    ])
    replace_corpus_rules(conn, "net", [_fmt_rule("net", "n1", ["T1059.001"], "suricata")])
    replace_corpus_rules(conn, "yr", [_fmt_rule("yr", "y1", ["T1486"], "yara")])
    _job_with_techniques(temp_db, "jflat", ["T1059", "T1059.001"])

    out = rules_for_job(conn, "jflat")
    groups = {g["technique_id"]: {r["id"] for r in g["rules"]} for g in out["techniques"]}

    assert set(groups) == {"T1059", "T1059.001"}
    assert groups["T1059"] == {"sig:s1", "sig:s2"}
    # The parent-tagged sigma rules also cover the sub-technique.
    assert groups["T1059.001"] == {"net:n1", "sig:s1", "sig:s2"}
    assert out["rule_total"] == 3           # distinct ids, not group memberships
    assert "yr:y1" not in {r for ids in groups.values() for r in ids}

    for g in out["techniques"]:
        for r in g["rules"]:
            assert list(r.keys()) == [
                "id", "corpus", "title", "severity", "license", "source_ref",
                "format", "bytes", "also_in",
            ]
            # Sizes must be real, not a silent zero: they come from the
            # `rule_bytes` side table, and a store missing that join would
            # render "0 B" everywhere in the selection UI rather than fail.
            assert r["bytes"] == len(f"title: rule {r['id'].split(':', 1)[1]}"
                                     f"\nlogsource: {r['corpus']}\n")


def test_rules_for_job_query_count_is_flat(temp_db):
    """The pre-rewrite form issued two statements per technique — 34 techniques
    cost 68+ round trips and 26.3 s. The flat sweep is one id query, one metadata
    batch per 400 ids and one also_in batch per 400 keys."""
    conn = temp_db.get_conn()
    for i, tech in enumerate(("T1001", "T1002", "T1003")):
        replace_corpus_rules(conn, f"c{i}", [
            _fmt_rule(f"c{i}", f"k{i}_{k}", [tech], "sigma", dedup_key=f"d{i}_{k}")
            for k in range(10)
        ])
    _job_with_techniques(temp_db, "jcount", ["T1001", "T1002", "T1003"])

    stmts = []
    conn.set_trace_callback(stmts.append)
    out = rules_for_job(conn, "jcount")
    conn.set_trace_callback(None)

    assert len(out["techniques"]) == 3
    assert out["rule_total"] == 30
    assert len(stmts) <= 8


def test_export_selection_packages_only_the_selected_rules(temp_db, temp_db_client):
    """Output correctness only. The body-loading *restriction* is locked by
    `test_rule_bodies_for_job_body_ids_restricts_raw_only` — this archive looks
    identical whether or not the other bodies were read, so it cannot stand in
    for that check."""
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [
        _rule("sig", f"e{k}", ["T1059"], raw=f"body-{k}") for k in range(6)
    ])
    _job_with_technique(temp_db, "jbody", "T1059")

    resp = temp_db_client.post(
        "/api/jobs/jbody/detections/export",
        json={"rule_ids": ["sig:e0", "sig:e1"]},
    )
    assert resp.status_code == 200, resp.text

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    rule_files = [n for n in zf.namelist() if n.startswith("rules/")]
    assert len(rule_files) == 2
    assert {zf.read(n).decode() for n in rule_files} == {"body-0", "body-1"}

    manifest = json.loads(zf.read("MANIFEST.json"))
    assert manifest["rule_count"] == 2
    # The other four are still counted, without ever loading their bodies.
    assert manifest["excluded"]["total"] == 4


def test_rule_bodies_for_job_body_ids_restricts_raw_only(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [
        _rule("sig", "b1", ["T1059"], raw="raw-b1"),
        _rule("sig", "b2", ["T1059"], raw="raw-b2"),
    ])
    _job_with_technique(temp_db, "jraw", "T1059")

    full = rule_bodies_for_job(conn, "jraw")
    assert len(full) == 2 and all(r["raw"] for r in full)

    none_loaded = rule_bodies_for_job(conn, "jraw", body_ids=set())
    assert {r["id"] for r in none_loaded} == {"sig:b1", "sig:b2"}
    assert all(r["raw"] == "" for r in none_loaded)

    partial = rule_bodies_for_job(conn, "jraw", body_ids={"sig:b1"})
    by_id = {r["id"]: r for r in partial}
    assert by_id["sig:b1"]["raw"] == "raw-b1"
    assert by_id["sig:b2"]["raw"] == ""
    # Metadata survives for the body-less entries — the manifest still needs it.
    assert by_id["sig:b2"]["corpus"] == "sig" and by_id["sig:b2"]["title"]
