"""Issue #377: a technique name shared by several MITRE domains resolves to the
Enterprise one, as in Stage 3c, not to whichever domain the index lists first
(the CAPEC entries come first in mitre_index.json)."""
import pytest

from pipeline.aliases import technique_id_for, technique_name_for


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Phishing", "T1566"),          # Enterprise; CAPEC-98 and Mobile T1660 share the name
        ("Kerberoasting", "T1558.003"),  # Enterprise; CAPEC-509 shares the name
        ("Brute Force", "T1110"),        # Enterprise; CAPEC-112 shares the name
        ("PHISHING", "T1566"),           # case-insensitive, as before
    ],
)
def test_shared_name_resolves_to_enterprise_issue_377(name, expected):
    assert technique_id_for(name) == expected


def test_shared_name_resolves_like_stage3c_issue_377():
    """The same name gives the same id here and in Stage 3c's index."""
    from pipeline.stage3c_mitre import _load_index

    index = _load_index()
    assert index is not None
    for name in ("Phishing", "Kerberoasting", "Brute Force"):
        assert technique_id_for(name) == index[name.lower()]["id"]


def test_capec_only_name_still_resolves_to_capec_issue_377():
    """A name no ATT&CK technique carries keeps its CAPEC id (control)."""
    assert technique_id_for("Session Sidejacking") == "CAPEC-102"


def test_spearphishing_link_control_issue_377():
    """Two Enterprise entries share this name (T1566.002, T1598.003): the first
    one in the file still wins, as before the change."""
    assert technique_id_for("Spearphishing Link") == "T1566.002"
    assert technique_name_for("T1566") == "Phishing"
