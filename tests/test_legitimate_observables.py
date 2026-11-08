"""A legitimate observable is never an Indicator (ADR-0095).

The in-house gold of 2026-11-07 (decision A6) moved the values a report names
without accusing them out of its IoCs: `rundll32.exe` and `comsvcs.dll` in the
cert-ua table, `chkdsk.exe` and `kernel32.dll` in apt44's YARA strings, a
standard registry key, `.bash_history`, a Telegram handle, a GUID.  Their
observable ships; an Indicator on one would match every machine.  The analyst
kept the HKLM\\SYSTEM, SECURITY and SAM hives as IoCs (decision B1).
"""
from __future__ import annotations

import json

import pytest
import stix2

from models.schemas import EntityType, RawEntity
from pipeline import benign
from pipeline import stage4_stix_mapping as s4
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import IoCAssociation, LLMEnrichmentResult

T = EntityType
WIN = "legitimate_file:windows"
UNIX = "legitimate_file:unix"
KEY = "legitimate_registry_key"


@pytest.mark.parametrize("etype, value, reason", [
    # The gold's own observables.
    (T.FILE, "rundll32.exe", WIN),
    (T.FILE, r"C:\Windows\System32\rundll32.exe", WIN),
    (T.FILE, r"C:\windows\System32\comsvcs.dll", WIN),
    (T.FILE, "chkdsk.exe", WIN),
    (T.FILE, "xpsp2res.dll", WIN),
    (T.FILE, "kernel32.dll", WIN),
    (T.FILE, "SCHTASKS.EXE", WIN),
    (T.FILE, ".bash_history", UNIX),
    (T.FILE, r"\\.\EPMNTDRV", "no_ioc_type:device"),
    (T.FILE, "79A87EBB-4DF6-4541-9530-CAD8BEE8A7AD", "no_ioc_type:guid"),
    (T.REGISTRY_KEY, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", KEY),
    (T.REGISTRY_KEY, r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList", KEY),
    (T.USER_ACCOUNT, "@lilymihalyk", "no_ioc_type:messenger_handle"),
    # Other spellings of a standard place.
    (T.FILE, r"%SystemRoot%\System32\cmd.exe", WIN),
    (T.FILE, r"%windir%\SysWOW64\rundll32.exe", WIN),
    (T.FILE, r"\??\C:\Windows\System32\svchost.exe", WIN),
    (T.FILE, "C:/Windows/System32/certutil.exe", WIN),
    (T.FILE, r"System32\rundll32.exe", WIN),
    (T.FILE, r"C:\Windows\explorer.exe", WIN),
    (T.FILE, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", WIN),
    (T.FILE, r"C:\Windows\System32\wbem\WMIC.exe", WIN),
    (T.FILE, "/home/bob/.bash_history", UNIX),
    (T.FILE, "/root/.bash_history", UNIX),
    (T.FILE, "~/.bash_history", UNIX),
    (T.FILE, "/usr/bin/curl", UNIX),
    (T.FILE, "{79a87ebb-4df6-4541-9530-cad8bee8a7ad}", "no_ioc_type:guid"),
    (T.REGISTRY_KEY, r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", KEY),
    (T.REGISTRY_KEY, r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\\", KEY),
    (T.REGISTRY_KEY, r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\RunOnce", KEY),
    (T.REGISTRY_KEY, r"HKLM\SYSTEM\ControlSet001\Services", KEY),
    # The hives an attacker saves are IoCs (decision B1).
    (T.REGISTRY_KEY, r"HKLM\SYSTEM", None),
    (T.REGISTRY_KEY, r"HKLM\SECURITY", None),
    (T.REGISTRY_KEY, r"HKLM\SAM", None),
    (T.REGISTRY_KEY, r"HKEY_LOCAL_MACHINE\SAM", None),
    # Exact match only: a subkey is the attacker's, a near name is a masquerade.
    (T.REGISTRY_KEY, r"HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc", None),
    (T.REGISTRY_KEY, r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater", None),
    (T.FILE, "schtask.exe", None),
    (T.FILE, "svch0st.exe", None),
    # A system name outside its directory is a masquerade (T1036.005).
    (T.FILE, r"C:\Users\Public\svchost.exe", None),
    (T.FILE, r"C:\Windows\Temp\rundll32.exe", None),
    (T.FILE, r"C:\Windows\rundll32.exe", None),
    (T.FILE, r"C:\Windows\System32\explorer.exe", None),
    (T.FILE, r"%APPDATA%\kernel32.dll", None),
    (T.FILE, r"\\fileserver\share\rundll32.exe", None),
    (T.FILE, r"\\%DOMAIN%\sysvol\%DOMAIN%\Policies\%GPO ID%\Machine\zrada.exe", None),
    (T.FILE, "/tmp/.bash_history", None),
    (T.FILE, "/tmp/curl", None),
    (T.FILE, "/var/log/wobf.sh", None),
    # What the attacker took stays an IoC.
    (T.FILE, "/etc/shadow", None),
    (T.FILE, "ntds.dit", None),
    (T.FILE, "lsass.DMP", None),
    (T.FILE, r"C:\Users\Public\sam.reg", None),
    # An account name is not a handle.
    (T.USER_ACCOUNT, "svc_backup", None),
    (T.USER_ACCOUNT, "admin@corp.example", None),
])
def test_why_a_value_is_not_an_indicator(etype, value, reason):
    assert benign.benign_reason(etype, value) == reason


def test_the_filter_turns_the_lists_off_too(monkeypatch):
    monkeypatch.setenv("BENIGN_IOC_FILTER", "false")
    assert benign.benign_reason(T.FILE, "rundll32.exe") is None


def _data() -> dict:
    return json.loads(benign._LEGIT_PATH.read_text(encoding="utf-8"))


def test_no_list_names_what_an_attacker_takes():
    data = _data()
    never = data["never_listed"]
    keys = {benign.registry_path(k) for k in data["windows_registry_keys"]}
    assert not keys & {benign.registry_path(k) for k in never["windows_registry_keys"]}
    names = {n.lower() for family in ("windows_files", "unix_files")
             for group in data[family] for n in group["names"]}
    assert not names & {n.lower() for n in never["files"]}


@pytest.mark.parametrize("family", ["windows_files", "unix_files"])
def test_a_file_is_listed_once(family):
    # One name may sit in two directories (/usr/bin/crontab, /etc/crontab).
    files = [(n.lower(), d) for group in _data()[family] for n in group["names"] for d in group["dirs"]]
    assert len(files) == len(set(files))


def test_registry_keys_are_written_in_their_normal_form():
    keys = _data()["windows_registry_keys"]
    assert keys == sorted(keys) and all(benign.registry_path(k) == k for k in keys)


def test_an_unreadable_list_makes_nothing_legitimate(monkeypatch, tmp_path):
    monkeypatch.setattr(benign, "_LEGIT_PATH", tmp_path / "missing.json")
    benign._legit.cache_clear()
    try:
        assert benign.benign_reason(T.FILE, "rundll32.exe") is None
        assert benign.benign_reason(T.FILE, r"\\.\EPMNTDRV") == "no_ioc_type:device"
    finally:
        benign._legit.cache_clear()


def test_a_hash_or_a_mutex_is_never_judged_by_its_name():
    assert s4._benign(stix2.File(name="rundll32.exe", hashes={"SHA-256": "a" * 64})) is None
    assert s4._benign(stix2.File(name="rundll32.exe")) == WIN
    assert s4._benign(stix2.Mutex(name="79A87EBB-4DF6-4541-9530-CAD8BEE8A7AD")) is None


def _build(entities, llm=None):
    ledger = MappingLedger()
    bundle = s4.build_stix_bundle(entities, llm or LLMEnrichmentResult(), "r",
                                  report_text="text", ledger=ledger)
    return bundle, ledger.to_dict()


CERT_UA = [
    RawEntity(value=r"C:\Windows\System32\rundll32.exe", entity_type=T.FILE),
    RawEntity(value=r"C:\Users\Public\mem.dmp", entity_type=T.FILE),
    RawEntity(value=r"HKLM\SAM", entity_type=T.REGISTRY_KEY),
    RawEntity(value=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList",
              entity_type=T.REGISTRY_KEY),
    RawEntity(value="@lilymihalyk", entity_type=T.USER_ACCOUNT),
]


def test_legitimate_values_ship_as_observables_without_an_indicator():
    bundle, ledger = _build(CERT_UA)
    patterns = {o["pattern"] for o in bundle.objects if o["type"] == "indicator"}
    assert patterns == {r"[file:name = 'C:\\Users\\Public\\mem.dmp']",
                        r"[windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\SAM']"}
    names = {o.get("name") for o in bundle.objects if o["type"] == "file"}
    assert {r"C:\Windows\System32\rundll32.exe", r"C:\Users\Public\mem.dmp"} <= names
    assert any(o["type"] == "user-account" and o["user_id"] == "@lilymihalyk" for o in bundle.objects)
    assert sum(o["type"] == "windows-registry-key" for o in bundle.objects) == 2
    marked = sorted(info.get("benign") for info in ledger["objects"].values()
                    if info.get("no_indicator") == "benign")
    assert marked == [WIN, KEY, "no_ioc_type:messenger_handle"]

    cov = s4.verify_ioc_coverage(CERT_UA, bundle)
    assert cov["ok"] and cov["with_indicator"] == 2 and len(cov["benign"]) == 3


def test_an_association_with_a_legitimate_file_builds_no_indicator():
    llm = LLMEnrichmentResult(malware_families=["CaddyWiper"], ioc_associations=[
        IoCAssociation(ioc_value="rundll32.exe", malware_name="CaddyWiper")])
    bundle, ledger = _build([RawEntity(value="rundll32.exe", entity_type=T.FILE)], llm)
    assert not [o for o in bundle.objects if o["type"] == "indicator"]
    [entry] = [e for e in ledger["entities"] if e["value"] == "rundll32.exe" and e["outcome"] == "dropped"]
    assert entry["reason"] == "benign" and entry["benign"] == WIN


# ── The in-house score (evaluation/inhouse.py) ──────────────────────────────

def _gold_doc(tmp_path, gold):
    from evaluation import inhouse
    folder = tmp_path / "r1"
    folder.mkdir()
    (folder / "source.txt").write_text("report", encoding="utf-8")
    (folder / "gold.json").write_text(json.dumps(gold), encoding="utf-8")
    [doc] = inhouse.load(tmp_path)
    return inhouse, doc


GOLD = {"status": "gold", "layers": ["iocs"],
        "iocs": [{"type": "file", "value": r"C:\Users\Public\mem.dmp"}],
        "observables": [
            {"type": "file", "value": r"C:\Windows\System32\rundll32.exe", "why": "legitimate", "quote": "q"},
            {"type": "registry_key", "value": r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
             "why": "legitimate", "quote": "q"},
            {"type": "telegram_handle", "value": "@lilymihalyk", "why": "no-ioc-type", "quote": "q"}]}


def test_an_extracted_observable_is_neither_a_hit_nor_a_false_positive(tmp_path):
    inhouse, doc = _gold_doc(tmp_path, GOLD)
    pred = {"entities": [{"type": "file", "value": r"C:\Users\Public\mem.dmp"},
                         {"type": "file", "value": r"c:\windows\system32\RUNDLL32.exe"},
                         {"type": "file", "value": "invented.exe"}],
            "ttp_ids": []}
    s = inhouse.score(doc, pred, lambda t: t)
    assert (s["iocs"].tp, s["iocs"].fp, s["iocs"].fn) == (1, 1, 0)
    assert s["observables"] == {"cases": 3, "as_indicator": None, "items": []}  # no bundle recorded


def test_the_score_counts_the_observables_the_bundle_gives_an_indicator(tmp_path):
    from evaluation.__main__ import _bundle_indicated
    inhouse, doc = _gold_doc(tmp_path, GOLD)
    # The registry key's hive is spelled out by Stage 4; the gold omits it.
    indicated = [{"type": "windows-registry-key",
                  "value": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"},
                 {"type": "file", "value": r"C:\Users\Public\mem.dmp"}]
    s = inhouse.score(doc, {"entities": [], "ttp_ids": [], "bundle_indicated": indicated}, lambda t: t)
    assert s["observables"]["as_indicator"] == 1
    assert [o["type"] for o in s["observables"]["items"]] == ["registry_key"]

    # What the pipeline records: with ADR-0095, only the IoC is indicated.
    bundle, _ = _build(CERT_UA)
    assert sorted((i["type"], i["value"]) for i in _bundle_indicated(bundle)) == [
        ("file", r"C:\Users\Public\mem.dmp"), ("windows-registry-key", r"HKEY_LOCAL_MACHINE\SAM")]
    s = inhouse.score(doc, {"entities": [], "ttp_ids": [], "bundle_indicated": _bundle_indicated(bundle)},
                      lambda t: t)
    assert s["observables"]["as_indicator"] == 0
    assert _bundle_indicated(None) is None
