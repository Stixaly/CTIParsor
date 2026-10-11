"""Stage 3c resolves a revoked ATT&CK id to its replacement, and a shared name
to the Enterprise technique.

Found in the 50 quotes judged on 2026-10-11: a report's table said T1562
*Impair Defenses*, revoked for T1685 in ATT&CK 2026 and absent from the
index; resolving by name found the Mobile T1629, the only technique left with
that name, and the bundle carried a Mobile technique for a Windows intrusion.
"""
from __future__ import annotations

import json
from pathlib import Path

from pipeline import mitre_db
from pipeline.stage3c_mitre import _resolve

REVOKED = Path(mitre_db.__file__).parent / "data" / "attack_revoked.json"


def test_a_revoked_id_is_its_replacement():
    assert _resolve("Impair Defenses", "T1562")[:2] == ("Disable or Modify Tools", "T1685")
    assert _resolve("Disable or Modify Tools: Disable Windows Defender", "T1562.001")[1] == "T1685"


def test_a_revoked_name_without_an_id_is_its_replacement_not_mobile():
    assert _resolve("Impair Defenses", None)[1] == "T1685"


def test_a_name_several_domains_share_is_the_enterprise_one():
    # "Phishing": T1566 (Enterprise), T1660 (Mobile), CAPEC-98.
    assert _resolve("Phishing", None)[1] == "T1566"


def test_an_id_still_decides():
    assert _resolve("Phishing", "T1660")[1] == "T1660"
    assert _resolve("Exploit Public-Facing Application", "T1190")[1] == "T1190"


def test_the_table_is_built_from_attack_and_points_at_active_techniques():
    data = json.loads(REVOKED.read_text(encoding="utf-8"))
    assert data["sources"], "which bundles it was built from"
    assert data["revoked_by"]["T1562"] == "T1685"
    known = {t["id"] for t in mitre_db.get_techniques()}
    assert set(data["revoked_by"].values()) <= known
    assert not set(data["revoked_by"]) & known, "a revoked id is not in the index"
