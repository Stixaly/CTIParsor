"""evaluation/annoctr.load — the general-only lot and the gold entities (#459, #458).

#459: `include_general_only` excludes the cyber ids of the requested splits only,
so a train or test report came back as a general-only document beside a dev run.
#458: two gold entities of one type whose labels read the same (a no-break space
in the text) were two gold entities, so one prediction left the other a false
negative.  Distinct spans that merely overlap (`Europe`, `Eastern Europe`) stay
distinct: the scorer already matches them one to one."""
from __future__ import annotations

import json

from evaluation import annoctr
from evaluation.metrics import score_entities


def _write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _bio(doc_id, tokens, tags):
    return json.dumps({"id": f"{doc_id}__0", "tokens": tokens, "ne_tags": tags})


def _mini_annoctr(root):
    """Three cyber splits (one report each), and two general-only reports in all/."""
    cyber = {"train": "intel471_2021-01-01_train-report", "dev": "lab52_2021-02-02_dev-report",
             "test": "zscaler_2021-03-03_test-report"}
    general = ["proofpoint_2020-01-01_general-one", "quointelligence_2020-02-02_general-two"]
    for split, doc_id in cyber.items():
        _write(root / "text" / split / f"{doc_id}.txt", f"Report of {split}.")
        _write(root / "all" / "text" / f"{doc_id}.txt", f"Report of {split}.")
    for doc_id in general:
        _write(root / "all" / "text" / f"{doc_id}.txt", "A general report.")
    return cyber, general


# ── #459 ────────────────────────────────────────────────────────────────────

def test_general_only_excludes_the_cyber_reports_of_every_split_issue_459(tmp_path):
    cyber, general = _mini_annoctr(tmp_path / "AnnoCTR")
    docs = annoctr.load(tmp_path / "AnnoCTR", splits=("dev",), include_general_only=True)

    by_id = {d.doc_id: d for d in docs}
    assert set(by_id) == {cyber["dev"], *general}           # no train or test report
    assert by_id[cyber["dev"]].split == "dev"
    assert sorted(d.doc_id for d in docs if d.split == annoctr.GENERAL_ONLY) == sorted(general)


def test_general_only_with_every_split_still_lists_only_the_general_reports_issue_459(tmp_path):
    """Control: the full load already excluded all three splits."""
    cyber, general = _mini_annoctr(tmp_path / "AnnoCTR")
    docs = annoctr.load(tmp_path / "AnnoCTR", include_general_only=True)

    assert len(docs) == 3 + len(general)
    assert sorted(d.doc_id for d in docs if d.split == annoctr.GENERAL_ONLY) == sorted(general)
    assert all(d.layers == frozenset({"general", "cyber"}) for d in docs if d.split != annoctr.GENERAL_ONLY)


# ── #458 ────────────────────────────────────────────────────────────────────

def test_two_gold_locations_that_read_the_same_are_one_entity_issue_458(tmp_path):
    root = tmp_path / "AnnoCTR"
    cyber, _ = _mini_annoctr(root)
    doc_id = cyber["dev"]
    # "Middle East" in the text, and once with a no-break space: the same entity.
    _write(root / "ner_json" / "dev.json", "\n".join([
        _bio(doc_id, ["Middle", "East", "and", "Chinese"], ["B-LOC", "I-LOC", "O", "B-LOC"]),
        _bio(doc_id, ["Middle\xa0East"], ["B-LOC"]),
    ]))
    [doc] = [d for d in annoctr.load(root, splits=("dev",)) if d.doc_id == doc_id]

    locations = [e for e in doc.entities.values() if e.etype == "location"]
    assert sorted(e.label for e in locations) == ["Chinese", "Middle East"]
    merged = next(e for e in locations if e.label == "Middle East")
    assert merged.surfaces == {"Middle East", "Middle\xa0East"}


def test_the_scorer_finds_one_match_for_that_entity_issue_458(tmp_path):
    """The false negative: one prediction for the entity, one gold entry left over."""
    root = tmp_path / "AnnoCTR"
    cyber, _ = _mini_annoctr(root)
    doc_id = cyber["dev"]
    _write(root / "ner_json" / "dev.json", "\n".join([
        _bio(doc_id, ["Middle", "East"], ["B-LOC", "I-LOC"]),
        _bio(doc_id, ["Middle\xa0East"], ["B-LOC"]),
    ]))
    [doc] = [d for d in annoctr.load(root, splits=("dev",)) if d.doc_id == doc_id]
    gold = [(e.etype, e.label, e.surfaces) for e in doc.entities.values()]

    counts = score_entities([("location", "Middle East")], gold)["location"]
    assert (counts.tp, counts.fp, counts.fn) == (1, 0, 0)


def test_overlapping_distinct_locations_stay_two_entities_issue_458(tmp_path):
    """Control: `Europe` inside `Eastern Europe` is two spans, not a duplicate."""
    root = tmp_path / "AnnoCTR"
    cyber, _ = _mini_annoctr(root)
    doc_id = cyber["dev"]
    _write(root / "ner_json" / "dev.json", "\n".join([
        _bio(doc_id, ["Eastern", "Europe", "and", "Europe"], ["B-LOC", "I-LOC", "O", "B-LOC"]),
    ]))
    [doc] = [d for d in annoctr.load(root, splits=("dev",)) if d.doc_id == doc_id]

    assert sorted(e.label for e in doc.entities.values() if e.etype == "location") == ["Eastern Europe", "Europe"]
    counts = score_entities([("location", "Europe")], [(e.etype, e.label, e.surfaces) for e in doc.entities.values()])
    assert counts["location"].tp == 1 and counts["location"].fn == 1
