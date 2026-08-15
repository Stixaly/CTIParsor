"""Tests for observable-driven detection proposals (ADR-0014).

Covers the three new pure modules (atoms, observables, relevance scoring) and
the end-to-end ranking against an isolated store.
"""
from uuid import uuid4

import pytest

from models.detection import DetectionRule, Severity
from pipeline.detection.atoms import extract_atoms, rule_platform
from pipeline.detection.observables import observables_from_entities, report_platform
from pipeline.detection.relevance import (
    combine,
    idf,
    platform_factor,
    propose_for_job,
    rank_rules,
    tier_of,
)
from pipeline.detection.store import (
    atom_document_frequency,
    atom_hits,
    replace_corpus_rules,
)

# ── Atom extraction (pure) ────────────────────────────────────────────────────

def _doc(detection: dict, logsource: dict | None = None) -> dict:
    return {"title": "t", "logsource": logsource or {}, "detection": detection}


def test_atoms_map_fields_to_classes():
    atoms = extract_atoms(_doc({
        "selection": {
            "Image|endswith": "\\meshagent64.exe",
            "CommandLine|contains": "sshpass -p",
            "TargetObject": "HKLM\\Software\\Run",
            "DestinationHostname": "evil.example",
        },
        "condition": "selection",
    }))
    by_class = {c: v for c, v in atoms}
    assert by_class["cmdline"] == "sshpass -p"
    assert by_class["registry"] == "hklm/software/run"
    assert by_class["domain"] == "evil.example"
    # a path yields both the full path and the basename
    assert ("image", "meshagent64.exe") in atoms


def test_atoms_reject_interior_wildcards_but_strip_edge_ones():
    atoms = extract_atoms(_doc({"selection": {
        "Image": "*\\rundll32.exe",          # edge wildcard stripped → kept
        "CommandLine": "foo*bar",             # interior wildcard → dropped
    }}))
    values = {v for _c, v in atoms}
    assert "rundll32.exe" in values
    assert "foo*bar" not in values
    assert not any(v.startswith("*") for v in values)


def test_atoms_split_composite_hashes():
    atoms = extract_atoms(_doc({"selection": {
        "Hashes": ["MD5=" + "a" * 32 + ",SHA256=" + "b" * 64],
    }}))
    assert set(atoms) == {("hash", "a" * 32), ("hash", "b" * 64)}


def test_atoms_skip_condition_and_short_values():
    atoms = extract_atoms(_doc({
        "selection": {"CommandLine": "ab"},   # under the 4-char floor
        "condition": "selection",
    }))
    assert atoms == []


def test_atoms_respect_the_cap():
    """Generated keyword corpora list thousands of values under one field."""
    doc = _doc({"selection": {"CommandLine": [f"value-{i:04d}" for i in range(500)]}})
    assert len(extract_atoms(doc, max_atoms=25)) == 25


def test_atoms_never_raise_on_malformed_rules():
    assert extract_atoms(None) == []
    assert extract_atoms({"detection": "not-a-dict"}) == []
    assert extract_atoms(_doc({"selection": {3: "x", "Image": None}})) == []


def test_rule_platform_from_product_service_and_list_category():
    assert rule_platform(_doc({}, {"product": "windows"})) == "windows"
    assert rule_platform(_doc({}, {"product": "linux"})) == "linux"
    # no product — a Windows-only service still identifies the platform
    assert rule_platform(_doc({}, {"service": "sysmon"})) == "windows"
    # some corpora write category as a list
    assert rule_platform(_doc({}, {"category": ["registry_set", "network"]})) == "windows"
    # platform-agnostic (proxy/cloud) rules stay unlabelled
    assert rule_platform(_doc({}, {"category": "proxy"})) == ""
    assert rule_platform(None) == ""


# ── Report observables (pure) ────────────────────────────────────────────────

def test_observables_expand_url_and_executables():
    obs = observables_from_entities([
        {"value": "hxxps://bad[.]example/a?b=/c", "entity_type": "url"},
        {"value": "/opt/app/meshagent64.exe", "entity_type": "file"},
    ])
    pairs = {(o.obs_class, o.value) for o in obs}
    assert ("url", "https://bad.example/a?b=/c") in pairs     # refanged
    assert ("domain", "bad.example") in pairs                  # host extracted
    assert ("file", "/opt/app/meshagent64.exe") in pairs
    assert ("file", "meshagent64.exe") in pairs                # basename
    assert ("image", "meshagent64.exe") in pairs               # executable suffix


def test_observables_ignore_non_technical_entities():
    obs = observables_from_entities([
        {"value": "APT29", "entity_type": "threat_actor"},
        {"value": "Spearphishing", "entity_type": "ttp"},
        {"value": "not-a-hash", "entity_type": "sha256"},
        {"value": "", "entity_type": "domain"},
        {"entity_type": "domain"},
    ])
    assert obs == []


def test_observables_drop_values_that_can_never_be_indicators():
    """Guards IDF cannot provide: `/dev/null` and `127.0.0.1` are *rare* as whole
    rule-field values, so they read as specific and rank spurious rules high."""
    obs = observables_from_entities([
        {"value": "/dev/null", "entity_type": "file"},
        {"value": "/proc/self/environ", "entity_type": "file"},
        {"value": "127.0.0.1", "entity_type": "ipv4"},
        {"value": "0.0.0.0", "entity_type": "ipv4"},
        {"value": "169.254.169.254", "entity_type": "ipv4"},
        {"value": "::1", "entity_type": "ipv6"},
    ])
    assert obs == []

    # …but a routable address, and an internal pivot target, are real content
    kept = observables_from_entities([
        {"value": "142.11.200.186", "entity_type": "ipv4"},
        {"value": "10.0.0.5", "entity_type": "ipv4"},
        {"value": "/etc/hosts", "entity_type": "file"},
    ])
    assert {o.value for o in kept} >= {"142.11.200.186", "10.0.0.5", "/etc/hosts"}


def test_observables_deduplicate_on_class_and_value():
    obs = observables_from_entities([
        {"value": "evil.example", "entity_type": "domain"},
        {"value": "EVIL.example", "entity_type": "domain"},
    ])
    assert len(obs) == 1
    assert obs[0].display == "evil.example"   # first spelling wins


@pytest.mark.parametrize("values,expected", [
    ([("file", "/etc/cron.d/x"), ("file", "/usr/bin/pv"), ("file", "/var/tmp/a")], "linux"),
    ([("file", "c:/windows/system32/a.exe"), ("registry_key", "HKLM\\Run")], "windows"),
    ([], ""),
])
def test_report_platform(values, expected):
    obs = observables_from_entities(
        [{"value": v, "entity_type": t} for t, v in values]
    )
    assert report_platform(obs) == expected


def test_report_platform_is_multi_when_evidence_is_mixed():
    obs = observables_from_entities([
        {"value": "/etc/hosts", "entity_type": "file"},
        {"value": "/usr/bin/pv", "entity_type": "file"},
        {"value": "c:/a/x.exe", "entity_type": "file"},
        {"value": "c:/a/y.dll", "entity_type": "file"},
    ])
    assert report_platform(obs) == "multi"


# ── Scoring primitives (pure) ────────────────────────────────────────────────

def test_idf_separates_generic_from_specific_values():
    total = 11000
    assert idf(0, total) == pytest.approx(1.0, abs=0.01)   # in no other rule
    assert idf(3000, total) < 0.20                          # `cmd.exe`-grade noise
    assert idf(1, total) > idf(500, total) > idf(5000, total)


def test_combine_saturates_and_favours_one_strong_match():
    assert combine([]) == 0.0
    assert combine([1.0, 0.5]) == 1.0
    # ten weak matches must not outrank one near-certain one
    assert combine([0.05] * 10) < combine([0.95])
    assert 0 <= combine([0.4, 0.4]) <= 1


def test_platform_factor_demotes_only_a_known_mismatch():
    assert platform_factor("windows", "windows") == 1.0
    assert platform_factor("", "linux") == 1.0            # agnostic rule
    assert platform_factor("windows", "multi") == 1.0     # mixed report
    assert platform_factor("windows", "") == 1.0          # unknown report
    assert platform_factor("windows", "linux") < 1.0


def test_tier_of():
    assert tier_of(True, False, False) == "direct"
    assert tier_of(False, True, True) == "behavioural"
    assert tier_of(False, True, False) == "weak"


# ── Ranking against a store (temp DB) ────────────────────────────────────────

_HASH = "d" * 64


def _rule(corpus, key, techniques, *, atoms=(), platform="", title=None):
    return DetectionRule(
        id=f"{corpus}:{key}", corpus=corpus, title=title or f"rule {key}",
        technique_ids=techniques, severity=Severity.HIGH, license="proprietary",
        platform=platform, atoms=list(atoms), raw=f"title: rule {key}\n",
    )


def _seed_job(db, job_id, entities):
    conn = db.get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,'r.pdf','reviewing',?,?)", (job_id, db.now_iso(), db.now_iso()),
    )
    for value, etype, mitre in entities:
        conn.execute(
            "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
            "VALUES (?,?,?,?,?,1,'llm')",
            (str(uuid4()), job_id, value, etype, mitre),
        )
    conn.commit()


def test_store_round_trips_atoms_and_platform(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [
        _rule("core", "k1", ["T1059"], atoms=[("hash", _HASH), ("image", "pv")], platform="linux"),
    ])
    assert atom_hits(conn, [_HASH]) == [("core:k1", "hash", _HASH)]
    assert atom_document_frequency(conn, [_HASH]) == {_HASH: 1}

    # re-ingesting the corpus replaces atoms rather than accumulating them
    replace_corpus_rules(conn, "core", [_rule("core", "k1", ["T1059"], atoms=[("hash", _HASH)])])
    assert len(atom_hits(conn, [_HASH, "pv"])) == 1


def test_ioc_match_outranks_a_bare_technique_match(temp_db):
    """The whole point of ADR-0014: a rule that names the report's hash must beat
    the 500 rules that merely share its technique tag."""
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "ioc", [
        _rule("ioc", "hit", ["T1059"], atoms=[("hash", _HASH)]),
    ])
    replace_corpus_rules(conn, "generic", [
        _rule("generic", f"g{i}", ["T1059"]) for i in range(20)
    ])

    _seed_job(temp_db, "j1", [
        (_HASH, "sha256", None),
        ("Command and Scripting Interpreter", "ttp", "T1059"),
    ])

    result = propose_for_job(conn, "j1")
    top = result["proposals"][0]
    assert top["id"] == "ioc:hit"
    assert top["tier"] == "direct"
    assert top["score"] > result["proposals"][1]["score"]
    assert result["counts"]["direct"] == 1
    assert result["counts"]["behavioural"] == 20
    # the evidence says *why* it ranked first
    assert top["matches"][0]["value"] == _HASH
    assert top["matches"][0]["field"] == "hash"
    assert top["matches"][0]["exact"] is True


def test_untagged_rule_surfaces_through_an_observable(temp_db):
    """1049 rules in the real store carry no ATT&CK tag and were unreachable."""
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "ioc", [
        _rule("ioc", "untagged", [], atoms=[("domain", "azurenetfiles.net")]),
    ])
    _seed_job(temp_db, "j2", [("azurenetfiles.net", "domain", None)])

    ids = [p["id"] for p in propose_for_job(conn, "j2")["proposals"]]
    assert ids == ["ioc:untagged"]


def test_off_platform_rule_is_demoted_not_dropped(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "win", [_rule("win", "w", ["T1059"], platform="windows")])
    replace_corpus_rules(conn, "nix", [_rule("nix", "l", ["T1059"], platform="linux")])

    _seed_job(temp_db, "j3", [
        ("/etc/cron.d/x", "file", None),
        ("/usr/bin/pv", "file", None),
        ("/var/tmp/stage", "file", None),
        ("Unix Shell", "ttp", "T1059"),
    ])

    result = propose_for_job(conn, "j3")
    assert result["platform"] == "linux"
    by_id = {p["id"]: p for p in result["proposals"]}
    assert by_id["nix:l"]["score"] > by_id["win:w"]["score"]
    assert by_id["nix:l"]["tier"] == "behavioural"
    assert by_id["win:w"]["tier"] == "weak"          # kept, just demoted


def test_generic_value_is_discounted_by_idf(temp_db):
    """A value present in most rules carries almost no signal."""
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "noise", [
        _rule("noise", f"n{i}", [], atoms=[("image", "cmd.exe")]) for i in range(40)
    ])
    replace_corpus_rules(conn, "rare", [
        _rule("rare", "r", [], atoms=[("image", "meshagent64-v2.exe")]),
    ])
    _seed_job(temp_db, "j4", [
        ("cmd.exe", "file", None),
        ("meshagent64-v2.exe", "file", None),
    ])

    proposals = propose_for_job(conn, "j4")["proposals"]
    assert proposals[0]["id"] == "rare:r"
    assert proposals[0]["score"] > 3 * proposals[-1]["score"]


def test_extension_fragments_do_not_count_as_matches(temp_db):
    """Rules hold bare fragments (".exe", "http"). Plain containment linked every
    campaign binary to any rule downloading *some* .exe, and — because the report
    value is itself in no rule — IDF handed that match a perfect weight."""
    conn = temp_db.get_conn()
    # Both rules share the report's technique, so both are candidates and the
    # only thing separating them is the quality of their substring overlap.
    replace_corpus_rules(conn, "browser", [
        _rule("browser", "dl", ["T1105"], atoms=[("cmdline", ".exe"), ("cmdline", "http")]),
    ])
    replace_corpus_rules(conn, "tool", [
        _rule("tool", "mesh", ["T1105"], atoms=[("image", "meshagent64.exe")]),
    ])
    # IDF is relative to the store: in a two-rule corpus nothing is rare, so a
    # match would legitimately weigh 0. Fill it out to a realistic size.
    replace_corpus_rules(conn, "filler", [_rule("filler", f"f{i}", []) for i in range(40)])
    _seed_job(temp_db, "jfrag", [
        ("meshagent", "tool", None),                 # inside "meshagent64.exe"
        ("meshagent64-v2.exe", "file", None),        # only shares ".exe" with the other rule
        ("Ingress Tool Transfer", "ttp", "T1105"),
    ])

    by_id = {p["id"]: p for p in propose_for_job(conn, "jfrag")["proposals"]}
    assert by_id["browser:dl"]["matches"] == []          # ".exe" fragment rejected
    assert by_id["browser:dl"]["tier"] == "behavioural"  # technique only
    assert by_id["tool:mesh"]["tier"] == "direct"        # real overlap kept
    assert by_id["tool:mesh"]["matches"][0]["exact"] is False
    assert by_id["tool:mesh"]["score"] > by_id["browser:dl"]["score"]


def test_one_entity_scores_once_across_its_derived_observables(temp_db):
    """A path is emitted as `file` *and* `image` and may also hit a `cmdline`
    atom — counting all three let one artifact saturate the noisy-OR to 1.0."""
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "c", [
        _rule("c", "multi", [], atoms=[
            ("file", "/opt/x/agent64.exe"), ("image", "/opt/x/agent64.exe"),
            ("cmdline", "/opt/x/agent64.exe"),
        ]),
    ])
    _seed_job(temp_db, "jdup", [("/opt/x/agent64.exe", "file", None)])

    top = propose_for_job(conn, "jdup")["proposals"][0]
    assert len(top["matches"]) == 1
    assert top["score"] < 1.0


def test_rank_rules_on_an_empty_store_is_harmless(temp_db):
    result = rank_rules(temp_db.get_conn(), [], [])
    assert result["proposals"] == []
    assert result["candidate_total"] == 0
    assert result["atom_index_built"] is False


# ── API ──────────────────────────────────────────────────────────────────────

def test_proposals_endpoint(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "ioc", [
        _rule("ioc", "hit", ["T1059"], atoms=[("domain", "azurenetfiles.net")]),
    ])
    _seed_job(temp_db, "japi", [("azurenetfiles.net", "domain", None)])

    r = temp_db_client.get("/api/jobs/japi/detections/proposals")
    assert r.status_code == 200
    body = r.json()
    assert body["job_id"] == "japi"
    assert body["proposals"][0]["id"] == "ioc:hit"
    assert body["proposals"][0]["matches"][0]["display"] == "azurenetfiles.net"

    assert temp_db_client.get("/api/jobs/nope/detections/proposals").status_code == 404


def test_proposals_endpoint_limit_is_bounded(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "g", [_rule("g", f"k{i}", ["T1059"]) for i in range(30)])
    _seed_job(temp_db, "jlim", [("Shell", "ttp", "T1059")])

    body = temp_db_client.get("/api/jobs/jlim/detections/proposals?limit=5").json()
    assert len(body["proposals"]) == 5
    assert body["candidate_total"] == 30
    assert body["returned"] == 5
