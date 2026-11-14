"""Regression tests for the tooling bugs #836 to #841, and #837 (hardening).

#836: the runner's bundle relations keep the based-on plumbing and name an
Indicator by its pattern, a registry key or an ASN by its UUID.  #838: a negative
relation without a whole triple raises in inhouse.score.  #839: run_directory
takes a file for a folder.  #840: --batch 0 migrates nothing and exits 0.
#841: the OpenCTI report needs its --out-dir to exist.  #837: run_api reads the
.env of the repository, whatever the working directory.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import main
import run_api
from evaluation import __main__ as ev
from evaluation import inhouse
from scripts import migrate_jobs_to_postgres as migrate_jobs
from scripts import migrate_rules_to_postgres as migrate_rules
from scripts import opencti_expectations as x
from tests.test_opencti_expectations import check_record, run_record

U = "00000000-0000-4000-8000-0000000000{:02d}"


def _id(kind: str, n: int) -> str:
    return f"{kind}--{U.format(n)}"


class _Bundle:
    """What _bundle_relations reads from a stix2 bundle: its serialisation."""

    def __init__(self, objects: list[dict]) -> None:
        self.objects = objects

    def serialize(self) -> str:
        return json.dumps({"type": "bundle", "id": _id("bundle", 0), "objects": self.objects})


def _rel(n: int, src: str, rtype: str, tgt: str) -> dict:
    return {"type": "relationship", "id": _id("relationship", n), "relationship_type": rtype,
            "source_ref": src, "target_ref": tgt}


# ── #836 ─────────────────────────────────────────────────────────────────────

def test_based_on_is_not_a_bundle_relation_and_objects_are_named_by_their_value_836():
    ipv4 = {"type": "ipv4-addr", "id": _id("ipv4-addr", 1), "value": "1.2.3.4"}
    key = {"type": "windows-registry-key", "id": _id("windows-registry-key", 2),
           "key": "HKLM\\Software\\Run\\evil"}
    asn = {"type": "autonomous-system", "id": _id("autonomous-system", 3), "number": 64496}
    malware = {"type": "malware", "id": _id("malware", 4), "name": "WellMess"}
    ind_ip = {"type": "indicator", "id": _id("indicator", 5), "name": "ip",
              "pattern": "[ipv4-addr:value = '1.2.3.4']", "pattern_type": "stix"}
    ind_key = {"type": "indicator", "id": _id("indicator", 6), "name": "key",
               "pattern": "[windows-registry-key:key = 'HKLM\\\\Software\\\\Run\\\\evil']", "pattern_type": "stix"}
    ind_asn = {"type": "indicator", "id": _id("indicator", 7), "name": "asn",
               "pattern": "[autonomous-system:number = 64496]", "pattern_type": "stix"}
    objects = [ipv4, key, asn, malware, ind_ip, ind_key, ind_asn,
               _rel(10, ind_ip["id"], "based-on", ipv4["id"]),
               _rel(11, ind_key["id"], "based-on", key["id"]),
               _rel(12, ind_asn["id"], "based-on", asn["id"]),
               _rel(13, ind_ip["id"], "indicates", malware["id"]),
               _rel(14, malware["id"], "uses", key["id"]),
               _rel(15, malware["id"], "communicates-with", asn["id"])]

    out = ev._bundle_relations(_Bundle(objects))

    assert len(out) == 3
    assert {(r["source"], r["type"], r["target"]) for r in out} == {
        ("1.2.3.4", "indicates", "WellMess"),
        ("WellMess", "uses", "HKLM\\Software\\Run\\evil"),
        ("WellMess", "communicates-with", "64496"),
    }


# ── #838 ─────────────────────────────────────────────────────────────────────

def test_a_negative_relation_without_a_whole_triple_is_ignored_838():
    gold = {"status": "gold", "negatives": [
        {"kind": "relation"},
        {"kind": "relation", "triple": ["APT29", "uses"]},
        {"kind": "relation", "triple": ["APT29", "uses", "X"]},
    ]}
    doc = inhouse.InhouseDoc("doc", Path("source.txt"), gold, frozenset())
    pred = {"ttp_ids": [], "entities": [], "relations": [{"source": "APT29", "type": "uses", "target": "X"}],
            "bundle_relations": None}

    out = inhouse.score(doc, pred, lambda t: None)

    # The whole triple is the one violation; the two incomplete ones are neither.
    assert out["negatives"]["cases"] == 3
    assert out["negatives"]["violated"] == 1
    assert out["negatives"]["violations"] == [{"kind": "relation", "triple": ["APT29", "uses", "X"]}]


# ── #839 ─────────────────────────────────────────────────────────────────────

def test_run_directory_refuses_a_file_instead_of_a_folder_839(tmp_path, capsys):
    report = tmp_path / "report.txt"
    report.write_text("a report", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main.run_directory(str(report), str(tmp_path / "out"))

    assert exc.value.code == 1
    assert "Pas un dossier" in capsys.readouterr().out


# ── #840 ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("module", [migrate_jobs, migrate_rules])
def test_a_batch_below_one_is_a_usage_error_840(module):
    with pytest.raises(SystemExit) as exc:
        module.parse_args(["--batch", "0"])
    assert exc.value.code == 2
    assert module.parse_args(["--batch", "1"]).batch == 1


# ── #841 ─────────────────────────────────────────────────────────────────────

def test_the_report_creates_a_missing_out_dir_841(tmp_path):
    (tmp_path / "run.json").write_text(json.dumps(run_record()), encoding="utf-8")
    (tmp_path / "check.json").write_text(json.dumps(check_record(True)), encoding="utf-8")
    out = tmp_path / "new" / "deeper"

    assert x.main(["report", "--run", str(tmp_path / "run.json"), "--check", str(tmp_path / "check.json"),
                   "--out-dir", str(out)]) == 0

    assert (out / "report.json").exists()
    assert (out / "report.md").exists()


# ── #837 ─────────────────────────────────────────────────────────────────────

def test_run_api_loads_the_repository_env_whatever_the_cwd_837(monkeypatch, tmp_path):
    seen: list[tuple] = []

    def fake_load_dotenv(*args, **kwargs):
        seen.append(args)
        raise SystemExit("stop before uvicorn")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_api, "load_dotenv", fake_load_dotenv)

    with pytest.raises(SystemExit):
        run_api.main()

    assert seen == [(Path(run_api.__file__).resolve().parent / ".env",)]
