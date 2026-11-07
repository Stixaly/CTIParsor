"""Detection and TTP retrieval fixes: #515, #516, #518, #522, #523.

#515 merge_by_technique(limit=0) returns every candidate instead of none.
#516 rules_for_job(evidence_only=False) drops the evidence-admitted untagged rules.
#518 domains taken from URLs, emails and file names skip the www./trailing-dot normalisation.
#522 job_technique_ids keeps mixed-case duplicates of one technique id.
#523 score_artifacts takes display and entity_type from a different observable than artifact_class.
"""
from uuid import uuid4

from models.detection import DetectionRule, Severity
from pipeline import ttp_retrieval as tr
from pipeline.detection.artifacts import score_artifacts
from pipeline.detection.coverage import job_technique_ids, rules_for_job
from pipeline.detection.observables import Observable, observables_from_entities
from pipeline.detection.store import replace_corpus_rules, replace_rule_atoms

# ── #515 merge_by_technique(limit=0) ─────────────────────────────────────────

def test_merge_by_technique_limit_zero_returns_no_candidates():
    """limit=0 caps the output at zero candidates, not "no cap" (#515)."""
    cands = [
        tr.TtpCandidate(attack_id="T1059", fused_rank=1),
        tr.TtpCandidate(attack_id="T1566", fused_rank=2),
    ]
    assert tr.merge_by_technique(cands, limit=0) == []


def test_merge_by_technique_no_limit_keeps_every_candidate():
    """limit=None still means no cap (#515)."""
    cands = [
        tr.TtpCandidate(attack_id="T1059", fused_rank=1),
        tr.TtpCandidate(attack_id="T1566", fused_rank=2),
    ]
    assert [c.attack_id for c in tr.merge_by_technique(cands)] == ["T1059", "T1566"]


class _FixedRetriever:
    """Every passage gets the same five techniques, best first (#515 caller check)."""

    def rank(self, passages, k):
        return [
            [tr.TtpCandidate(attack_id=f"T10{i:02d}", fused_rank=i + 1) for i in range(5)]
            for _ in passages
        ]


def test_chunk_candidates_with_zero_cap_still_means_no_cap():
    """The caller turns a 0 per-chunk cap into None, so 0 keeps meaning "no cap" (#515).

    chunk_candidates_with and the evaluation spec both pass `max_per_chunk or None`;
    the fix to merge_by_technique must not change what they get back.
    """
    text = "Operators dump credentials from memory. They then pivot to other hosts."
    uncapped = tr.chunk_candidates_with(
        _FixedRetriever(), [text], k_per_passage=5, max_per_chunk=0 or None, keyword_gate=False,
    )
    capped = tr.chunk_candidates_with(
        _FixedRetriever(), [text], k_per_passage=5, max_per_chunk=2, keyword_gate=False,
    )
    assert len(uncapped[0]) == 5
    assert len(capped[0]) == 2


# ── #516 rules_for_job(evidence_only=False) keeps evidence-admitted untagged rules ──

def _fmt_rule(corpus, key, techniques, fmt):
    return DetectionRule(
        id=f"{corpus}:{key}", corpus=corpus, title=f"rule {key}",
        technique_ids=techniques, severity=Severity.HIGH, license="proprietary",
        format=fmt, dedup_key="",
        raw=f"title: rule {key}\nlogsource: {corpus}\n",
    )


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


def _add_observable(temp_db, job_id, value, entity_type):
    conn = temp_db.get_conn()
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), job_id, value, entity_type, None, 1, "llm"),
    )
    conn.commit()


def _panel_ids(out):
    return {r["id"] for g in out["techniques"] for r in g["rules"]}


def test_evidence_only_false_keeps_an_untagged_rule_reached_by_evidence(temp_db):
    """With evidence_only=False the untagged YARA rule with evidence still reaches
    the panel under (untagged), as it does with evidence_only=True (#516)."""
    job_id = str(uuid4())
    _job_with_techniques(temp_db, job_id, ["T1059"])
    _add_observable(temp_db, job_id, "Sandworm2024", "malware")
    replace_corpus_rules(temp_db.get_rule_conn(), "yr", [_fmt_rule("yr", "y1", [], "yara")])
    replace_corpus_rules(temp_db.get_rule_conn(), "sig", [_fmt_rule("sig", "s1", ["T1059"], "sigma")])
    replace_rule_atoms(temp_db.get_rule_conn(), [("yr:y1", "strlit", "sandworm2024")])

    out = rules_for_job(temp_db.get_rule_conn(), job_id, evidence_only=False,
                        jobs_conn=temp_db.get_conn())
    untagged = [g for g in out["techniques"] if g["technique_id"] == "(untagged)"]
    assert len(untagged) == 1, "the (untagged) group is missing with evidence_only=False"
    assert [r["id"] for r in untagged[0]["rules"]] == ["yr:y1"]
    assert "sig:s1" in _panel_ids(out)
    assert out["rule_total"] == 2


def test_evidence_only_false_lists_each_rule_once_per_group(temp_db):
    """An admitted untagged rule is listed once in (untagged) and the total counts it once (#516)."""
    job_id = str(uuid4())
    _job_with_techniques(temp_db, job_id, ["T1059"])
    _add_observable(temp_db, job_id, "Sandworm2024", "malware")
    replace_corpus_rules(temp_db.get_rule_conn(), "yr", [_fmt_rule("yr", "y1", [], "yara")])
    replace_rule_atoms(temp_db.get_rule_conn(), [("yr:y1", "strlit", "sandworm2024")])

    out = rules_for_job(temp_db.get_rule_conn(), job_id, evidence_only=False,
                        jobs_conn=temp_db.get_conn())
    untagged = next(g for g in out["techniques"] if g["technique_id"] == "(untagged)")
    ids = [r["id"] for r in untagged["rules"]]
    assert ids == ["yr:y1"]
    assert out["rule_total"] == len(_panel_ids(out)) == 1


# ── #518 www. and trailing dot on hosts taken from URLs, emails and files ──────

def _domains(rows):
    return {o.value for o in observables_from_entities(rows) if o.obs_class == "domain"}


def test_url_host_loses_www_prefix():
    """A URL's host is normalised like a bare domain: no www. (#518)."""
    assert _domains([{"entity_type": "url", "value": "https://www.evil.com/path"}]) == {"evil.com"}


def test_url_host_loses_trailing_dot():
    """A URL's host with a trailing dot still yields its domain (#518)."""
    assert _domains([{"entity_type": "url", "value": "https://bad.com./payload"}]) == {"bad.com"}


def test_url_and_bare_domain_of_one_host_fold_into_one_observable():
    """`www.evil.com` as a URL and `evil.com` as a domain give one domain observable (#518)."""
    obs = observables_from_entities([
        {"entity_type": "url", "value": "https://www.evil.com/path"},
        {"entity_type": "domain", "value": "evil.com"},
    ])
    assert [(o.obs_class, o.value) for o in obs if o.obs_class == "domain"] == [("domain", "evil.com")]


def test_email_host_loses_www_prefix_and_trailing_dot():
    """An email's host is normalised like a bare domain (#518)."""
    assert _domains([{"entity_type": "email", "value": "ops@www.evil.com."}]) == {"evil.com"}


def test_file_named_like_a_host_loses_www_prefix():
    """A file entity naming a host yields the normalised domain, not the raw www. form (#518)."""
    obs = observables_from_entities([{"entity_type": "file", "value": "www.evil.com"}])
    assert [(o.obs_class, o.value) for o in obs] == [("domain", "evil.com")]


def test_file_named_like_a_host_with_trailing_dot_yields_the_domain():
    """A host-shaped file entity with a trailing dot yields the domain (#518)."""
    obs = observables_from_entities([{"entity_type": "file", "value": "bad.com."}])
    assert [(o.obs_class, o.value) for o in obs] == [("domain", "bad.com")]


def test_a_path_in_a_file_entity_is_still_a_file():
    """A file with a path separator keeps its path: normalisation only touches hosts (#518)."""
    obs = observables_from_entities([{"entity_type": "file", "value": "www.evil.com/a/tool.exe"}])
    assert ("file", "www.evil.com/a/tool.exe") in {(o.obs_class, o.value) for o in obs}


# ── #522 mixed-case duplicate technique ids ──────────────────────────────────

def test_job_technique_ids_dedupes_mixed_case_ids(temp_db):
    """`t1059` and `T1059` on one job give one canonical `T1059` (#522)."""
    job_id = str(uuid4())
    _job_with_techniques(temp_db, job_id, ["t1059", "T1059"])
    assert job_technique_ids(temp_db.get_conn(), job_id) == ["T1059"]


def test_rules_for_job_has_one_group_per_mixed_case_technique(temp_db):
    """Mixed-case entities for one technique do not duplicate its group (#522)."""
    job_id = str(uuid4())
    _job_with_techniques(temp_db, job_id, ["t1059", "T1059"])
    replace_corpus_rules(temp_db.get_rule_conn(), "sig", [_fmt_rule("sig", "s1", ["T1059"], "sigma")])

    out = rules_for_job(temp_db.get_rule_conn(), job_id, evidence_only=False,
                        jobs_conn=temp_db.get_conn())
    labels = [g["technique_id"] for g in out["techniques"]]
    assert labels.count("T1059") == 1


# ── #523 artifact_class and tier agree with display and entity_type ──────────

def test_artifact_display_and_entity_type_follow_the_representative_class(temp_db):
    """The name observable (tier 4) comes first, the image observable (tier 3) second:
    the artifact is an image, so its display and entity_type come from the image (#523)."""
    obs_name = Observable(obs_class="name", value="nircmd.exe", entity_type="tool", display="NirCmd.exe")
    obs_image = Observable(obs_class="image", value="nircmd.exe", entity_type="file",
                           display="C:/Tools/nircmd.exe")
    artifacts = score_artifacts(temp_db.get_rule_conn(), [obs_name, obs_image])
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.artifact_class == "image"
    assert art.tier == 3
    assert art.display == "C:/Tools/nircmd.exe"
    assert art.entity_type == "file"
