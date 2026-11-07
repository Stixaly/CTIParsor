"""scripts/build_indexes.py `--only revoked` (issue #464): the revoked-name index is
Enterprise's, so a Mobile technique bearing the name of a revoked Enterprise
technique must not hide it.

Small synthetic bundles; nothing reads the real ATT&CK files.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from scripts import build_indexes


def ref(source: str, external_id: str) -> list[dict]:
    return [{"source_name": source, "external_id": external_id}]


def technique(key: str, external_id: str, name: str, source: str = "mitre-attack", **extra) -> dict:
    return {"type": "attack-pattern", "id": f"attack-pattern--{key}", "name": name,
            "external_references": ref(source, external_id), **extra}


def relationship(key: str, verb: str, source: str, target: str) -> dict:
    return {"type": "relationship", "id": f"relationship--{key}", "relationship_type": verb,
            "source_ref": source, "target_ref": target}


def write_bundle(path: Path, objects: list[dict]) -> Path:
    path.write_text(json.dumps({"type": "bundle", "id": "bundle--1", "objects": objects}),
                    encoding="utf-8")
    return path


def run_revoked(monkeypatch, out_dir: Path, *bundle_args: str) -> dict:
    """Run `build_indexes.py --only revoked` through main() and read the file it wrote."""
    monkeypatch.setattr(build_indexes, "_find_bundle", lambda key: None)
    monkeypatch.setattr(sys, "argv", ["build_indexes.py", "--out-dir", str(out_dir),
                                      "--only", "revoked", *bundle_args])
    build_indexes.main()
    return json.loads((out_dir / "attack_revoked.json").read_text(encoding="utf-8"))


def test_mobile_active_name_does_not_hide_enterprise_revoked_name_issue_464(tmp_path, monkeypatch):
    # Enterprise T1562 "Impair Defenses" is revoked for T1685; Mobile T1629 bears the same name.
    enterprise = write_bundle(tmp_path / "enterprise-attack.json", [
        technique("e1", "T1685", "Disable or Modify Tools"),
        technique("e2", "T1562", "Impair Defenses", revoked=True),
        relationship("1", "revoked-by", "attack-pattern--e2", "attack-pattern--e1"),
    ])
    mobile = write_bundle(tmp_path / "mobile-attack.json", [
        technique("m1", "T1629", "Impair Defenses", "mitre-mobile-attack"),
    ])

    built = run_revoked(monkeypatch, tmp_path / "out", "--enterprise", str(enterprise),
                        "--mobile", str(mobile))

    assert built["names"]["impair defenses"] == "T1685"
    assert built["revoked_by"] == {"T1562": "T1685"}


def test_enterprise_alone_keeps_the_revoked_name_control_issue_464(tmp_path, monkeypatch):
    enterprise = write_bundle(tmp_path / "enterprise-attack.json", [
        technique("e1", "T1685", "Disable or Modify Tools"),
        technique("e2", "T1562", "Impair Defenses", revoked=True),
        relationship("1", "revoked-by", "attack-pattern--e2", "attack-pattern--e1"),
    ])

    built = run_revoked(monkeypatch, tmp_path / "out", "--enterprise", str(enterprise))

    assert built["names"]["impair defenses"] == "T1685"
    assert built["revoked_by"] == {"T1562": "T1685"}


def test_an_enterprise_active_name_still_hides_the_revoked_name_issue_464(tmp_path, monkeypatch):
    # The masking inside Enterprise itself is unchanged: an active Enterprise
    # technique that keeps the name leaves no entry in `names`.
    enterprise = write_bundle(tmp_path / "enterprise-attack.json", [
        technique("e1", "T1685", "Disable or Modify Tools"),
        technique("e2", "T1562", "Impair Defenses", revoked=True),
        technique("e3", "T1700", "Impair Defenses"),
        relationship("1", "revoked-by", "attack-pattern--e2", "attack-pattern--e1"),
    ])

    built = run_revoked(monkeypatch, tmp_path / "out", "--enterprise", str(enterprise))

    assert "impair defenses" not in built["names"]
    assert built["revoked_by"] == {"T1562": "T1685"}
