"""dedupe_store marks the techniques it gives a canonical rule from its cluster (#432).

`_propagate_techniques` wrote them into `rule_techniques` like the rule's own
tags, so a technique inherited from a corpus that was removed, or from a cluster
that split, stayed on the canonical rule until that rule's own corpus was
rewritten. They are now `propagated = 1`, deleted and computed again at every pass.
"""
from __future__ import annotations

from models.detection import DetectionRule
from pipeline.detection.dedup import dedupe_store
from pipeline.detection.store import replace_corpus_rules

_PRIORITY = {"alpha": 10, "beta": 95}


def _rule(corpus, key, technique, dedup_key):
    return DetectionRule(
        id=f"{corpus}:{key}", corpus=corpus, title=f"{corpus} {key}",
        technique_ids=[technique], atoms=[("process", key)],
        license="proprietary", dedup_key=dedup_key, raw=f"title: {key}\n",
    )


def _techniques(conn, rule_id) -> dict[str, int]:
    """technique_id -> propagated, for one rule."""
    return {r["technique_id"]: r["propagated"] for r in conn.execute(
        "SELECT technique_id, propagated FROM rule_techniques WHERE rule_id=?", (rule_id,)
    ).fetchall()}


def _two_corpora(conn):
    """alpha (priority 10) wins the cluster; beta's T1027 is inherited by alpha:a1."""
    replace_corpus_rules(conn, "alpha", [_rule("alpha", "a1", "T1059", "shared")])
    replace_corpus_rules(conn, "beta", [_rule("beta", "b1", "T1027", "shared")])


def test_an_inherited_technique_is_marked_propagated_issue_432(temp_db):
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()
    _two_corpora(conn)

    summary = dedupe_store(conn, _PRIORITY)
    assert summary["techniques_propagated"] == 1
    assert _techniques(conn, "alpha:a1") == {"T1059": 0, "T1027": 1}

    # Running the pass again regenerates the same rows: nothing doubles, nothing is kept twice.
    again = dedupe_store(conn, _PRIORITY)
    assert again["techniques_propagated"] == 1
    assert _techniques(conn, "alpha:a1") == {"T1059": 0, "T1027": 1}


def test_an_inherited_technique_goes_when_its_corpus_is_removed_issue_432(temp_db):
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()
    _two_corpora(conn)
    dedupe_store(conn, _PRIORITY)

    replace_corpus_rules(conn, "beta", [])          # beta is removed from the store
    dedupe_store(conn, _PRIORITY)

    assert _techniques(conn, "alpha:a1") == {"T1059": 0}


def test_an_inherited_technique_goes_when_its_cluster_splits_issue_432(temp_db):
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()
    _two_corpora(conn)
    dedupe_store(conn, _PRIORITY)

    # beta's rule changes its detection logic: it no longer clusters with alpha's.
    replace_corpus_rules(conn, "beta", [_rule("beta", "b1", "T1027", "other-logic")])
    summary = dedupe_store(conn, _PRIORITY)

    assert summary["techniques_propagated"] == 0
    assert _techniques(conn, "alpha:a1") == {"T1059": 0}
    assert _techniques(conn, "beta:b1") == {"T1027": 0}


def test_a_technique_the_winner_has_of_its_own_is_not_taken_over_issue_432(temp_db):
    temp_db.get_conn()          # job store
    conn = temp_db.get_rule_conn()
    replace_corpus_rules(conn, "alpha", [_rule("alpha", "a1", "T1027", "shared")])
    replace_corpus_rules(conn, "beta", [_rule("beta", "b1", "T1027", "shared")])

    summary = dedupe_store(conn, _PRIORITY)
    assert summary["techniques_propagated"] == 0       # already its own: nothing added
    assert _techniques(conn, "alpha:a1") == {"T1027": 0}

    replace_corpus_rules(conn, "beta", [])
    dedupe_store(conn, _PRIORITY)
    assert _techniques(conn, "alpha:a1") == {"T1027": 0}   # its own tag survives the removal
