"""scripts/relation_fp_breakdown.py on a synthetic run folder.

The run has one document: a bundle with a threat actor, a malware and a victim,
two relationships with the same triple (one counted), a `based-on` edge (not
counted), a stated link (true positive), a link the gold lacks (false positive)
and a gold link the bundle lacks (false negative).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts import relation_fp_breakdown as rfp

DOC = "doc1"


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _relationship(rid: str, rtype: str, src: str, tgt: str, **extra: object) -> dict:
    obj = {"type": "relationship", "id": f"relationship--{rid}", "relationship_type": rtype,
           "source_ref": src, "target_ref": tgt, "x_evidence_label": "reported"}
    obj.update(extra)
    return obj


def _make_run(tmp_path: Path, score_tp: int = 2) -> tuple[Path, Path]:
    gold_dir = tmp_path / "inhouse"
    _write_json(gold_dir / DOC / "gold.json", {
        "doc_id": DOC, "status": "gold", "layers": ["relations"],
        "entities": [
            {"type": "threat_actor", "value": "APT-Test", "aliases": ["Alias-T"]},
            {"type": "malware", "value": "MalA", "aliases": []},
            {"type": "identity", "value": "Victim Co", "aliases": []},
        ],
        "relations": [
            {"source": "APT-Test", "type": "uses", "target": "MalA", "quote": "APT-Test uses MalA."},
            {"source": "APT-Test", "type": "targets", "target": "Victim Co", "quote": "APT-Test hit Victim Co."},
            {"source": "MalA", "type": "drops", "target": "Victim Co", "quote": "MalA dropped on Victim Co."},
        ],
    })
    (gold_dir / DOC / "source.txt").write_text("text", encoding="utf-8")

    run_dir = tmp_path / "run"
    objects = [
        {"type": "threat-actor", "id": "threat-actor--1", "name": "APT-Test", "aliases": ["Alias-T"]},
        {"type": "malware", "id": "malware--1", "name": "MalA"},
        {"type": "identity", "id": "identity--1", "name": "Victim Co"},
        _relationship("r1", "uses", "threat-actor--1", "malware--1", x_evidence_text="APT-Test uses MalA.",
                      confidence=90),
        _relationship("r1b", "uses", "threat-actor--1", "malware--1", x_evidence_text="APT-Test uses MalA.",
                      confidence=90),
        _relationship("r2", "targets", "threat-actor--1", "identity--1", confidence=80,
                      description="**APT-Test** `targets` **Victim Co**\n\n**Why:** The report names **APT-Test** "
                                  "as a threat actor and **Victim Co** as a target. CTIParsor links every threat "
                                  "actor of the report to every target it names, so the report may not say so.\n"),
        _relationship("r3", "related-to", "malware--1", "threat-actor--1", x_evidence_label="inferred",
                      x_inference_rule="transitive:uses+uses"),
        _relationship("r4", "based-on", "threat-actor--1", "malware--1"),
    ]
    bundle_bytes = json.dumps({"type": "bundle", "id": "bundle--1", "objects": objects}).encode("utf-8")
    (run_dir / "bundles").mkdir(parents=True)
    (run_dir / "bundles" / f"{DOC}.json").write_bytes(bundle_bytes)
    bundle_relations = [
        {"source": "APT-Test", "type": "uses", "target": "MalA", "evidence_label": "reported", "policy_rule": None},
        {"source": "APT-Test", "type": "uses", "target": "MalA", "evidence_label": "reported", "policy_rule": None},
        {"source": "APT-Test", "type": "targets", "target": "Victim Co", "evidence_label": "reported",
         "policy_rule": None},
        {"source": "MalA", "type": "related-to", "target": "APT-Test", "evidence_label": "inferred",
         "policy_rule": None},
        {"source": "APT-Test", "type": "based-on", "target": "MalA", "evidence_label": "reported",
         "policy_rule": None},
    ]
    _write_json(run_dir / "docs" / f"{DOC}.json", {
        "doc_id": DOC, "validation": "validated", "bundle_file": f"bundles/{DOC}.json",
        "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "relations": [{"source": "APT-Test", "type": "uses", "target": "MalA",
                       "evidence_text": "APT-Test uses MalA.", "evidence_label": "reported"}],
        "rel_review": [], "bundle_relations": bundle_relations,
    })
    _write_json(run_dir / "run.json", {"name": "test-run", "format": 2, "manifest": {}})
    _write_json(run_dir / "score-bundle.json", {
        "format": "inhouse-score/2", "documents_unscored": {},
        "per_document": {DOC: {"relations": {"tp": score_tp, "fp": 1, "fn": 1}}},
        "micro": {"relations": {"tp": score_tp, "fp": 1, "fn": 1}},
    })
    return run_dir, gold_dir


def test_counts_equal_the_score_file_and_attributes_are_right(tmp_path: Path) -> None:
    run_dir, gold_dir = _make_run(tmp_path)
    result = rfp.analyse(run_dir, gold_dir)
    assert result["scorer_check"]["ok"], result["scorer_check"]["problems"]
    assert result["totals"]["found"] == 3
    assert result["totals"]["tp"] == 2
    assert result["totals"]["fp"] == 1
    assert result["totals"]["gold"] == 3
    assert result["totals"]["fn"] == 1
    assert result["raw_relationships"] == 4          # based-on not counted
    assert result["duplicates_collapsed"] == 1       # the two `uses` share a triple

    [fp] = result["false_positives"]
    assert (fp["relationship_type"], fp["source"], fp["target"]) == ("related-to", "MalA", "APT-Test")
    assert fp["inference_rule"] == "transitive"
    assert fp["gold_link"] == "reversed pair in gold"
    assert fp["pair"] == "malware->threat-actor"

    assert result["by_attribute"]["why"]["every threat actor x every target"]["tp"] == 1
    assert result["by_attribute"]["stage3"]["stage3 row"] == {"found": 1, "tp": 1, "fp": 0,
                                                             "precision": 1.0, "share_of_fp": 0.0}
    assert result["false_negatives"]["relationship_type"] == {"drops": 1}


def test_main_writes_the_breakdown_and_exits_zero(tmp_path: Path) -> None:
    run_dir, gold_dir = _make_run(tmp_path)
    out = tmp_path / "out" / "breakdown.json"
    code = rfp.main(["--run-dir", str(run_dir), "--gold-dir", str(gold_dir), "--out", str(out)])
    assert code == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["totals"]["found"] == 3


def test_mismatch_with_the_score_file_exits_one(tmp_path: Path, capsys) -> None:
    run_dir, gold_dir = _make_run(tmp_path, score_tp=3)
    score_path = run_dir / "score-bundle.json"
    before = score_path.read_bytes()
    code = rfp.main(["--run-dir", str(run_dir), "--gold-dir", str(gold_dir)])
    assert code == 1
    err = capsys.readouterr().err
    assert "MISMATCH" in err and "tp" in err
    assert score_path.read_bytes() == before        # the score file is never rewritten
