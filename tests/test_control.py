# tests/test_control.py
from pipeline.detection.control import (
    DISCRIMINATING,
    UBIQUITOUS,
    _host,
    _stem,
    discrimination,
)


def test_hash_and_cve_always_discriminate():
    assert discrimination("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == DISCRIMINATING
    assert discrimination("cve", "cve-2023-1234") == DISCRIMINATING


def test_lolbin_never_corroborates():
    values = [
        "certutil",
        "certutil.exe",
        "C:\\Windows\\System32\\certutil.exe",
        "powershell.exe",
        "schtasks",
        "tasklist",
        "netstat",
        "ping",
        "systeminfo",
    ]
    for v in values:
        assert discrimination("name", v) == UBIQUITOUS
        assert discrimination("image", v) == UBIQUITOUS


def test_the_values_document_frequency_kept_are_now_stripped():
    # certutil(df=15), ping(10), tasklist(7), netstat(9), systeminfo(14), schtasks(16)
    assert discrimination("name", "certutil") == UBIQUITOUS
    assert discrimination("name", "ping") == UBIQUITOUS
    assert discrimination("name", "tasklist") == UBIQUITOUS
    assert discrimination("name", "netstat") == UBIQUITOUS
    assert discrimination("name", "systeminfo") == UBIQUITOUS
    assert discrimination("name", "schtasks") == UBIQUITOUS


def test_the_value_document_frequency_stripped_still_corroborates():
    # api.telegram.org (df=60) was excluded by ADR-0025 threshold but must discriminate
    assert discrimination("domain", "api.telegram.org") == DISCRIMINATING


def test_campaign_domain_discriminates():
    assert discrimination("domain", "ms365-live.com") == DISCRIMINATING
    assert discrimination("domain", "wa-connect.eu") == DISCRIMINATING
    # Registrable is verify-drive.com, not google.com
    assert discrimination("domain", "drive.google.verify-drive.com") == DISCRIMINATING


def test_free_mail_domain_does_not_corroborate():
    assert discrimination("domain", "gmail.com") == UBIQUITOUS
    assert discrimination("domain", "mail.google.com") == UBIQUITOUS


def test_url_is_classified_on_its_host():
    assert discrimination("url", "https://api.telegram.org/bot123/sendMessage") == DISCRIMINATING
    assert discrimination("url", "https://gmail.com/x") == UBIQUITOUS


def test_category_word_is_not_an_identity():
    assert discrimination("name", "wiper") == UBIQUITOUS
    assert discrimination("name", "stealer") == UBIQUITOUS
    assert discrimination("name", "backdoor") == UBIQUITOUS
    assert discrimination("name", "solar") == UBIQUITOUS
    assert discrimination("name", "atomic") == UBIQUITOUS
    assert discrimination("name", "mimikatz") == DISCRIMINATING
    assert discrimination("name", "cobaltstrike") == DISCRIMINATING
    assert discrimination("name", "atomicstealer") == DISCRIMINATING


def test_public_resolver_does_not_corroborate():
    assert discrimination("ip", "8.8.8.8") == UBIQUITOUS
    assert discrimination("ip", "1.1.1.1") == UBIQUITOUS
    assert discrimination("ip", "107.189.18.7") == DISCRIMINATING


def test_private_range_still_corroborates():
    assert discrimination("ip", "192.168.1.50") == DISCRIMINATING
    assert discrimination("ip", "10.0.0.5") == DISCRIMINATING


def test_run_key_prefix_is_ubiquitous_with_either_separator():
    assert discrimination("registry", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil") == UBIQUITOUS
    assert discrimination("registry", "HKLM/Software/Microsoft/Windows/CurrentVersion/Run/Evil") == UBIQUITOUS
    assert discrimination("registry", "HKLM\\Software\\Campaign\\Key") == DISCRIMINATING


def test_exact_system_path_only():
    assert discrimination("file", "/etc/passwd") == UBIQUITOUS
    assert discrimination("file", "/tmp/payload.elf") == DISCRIMINATING


def test_builtin_principal_does_not_corroborate():
    assert discrimination("user", "SYSTEM") == UBIQUITOUS
    assert discrimination("user", "Administrator") == UBIQUITOUS
    assert discrimination("user", "NT AUTHORITY\\SYSTEM") == UBIQUITOUS
    assert discrimination("user", "svc-backup-prod") == DISCRIMINATING


def test_port_never_corroborates():
    assert discrimination("port", "443") == UBIQUITOUS
    assert discrimination("port", "4444") == UBIQUITOUS


def test_malformed_input_never_raises():
    assert discrimination("name", None) == UBIQUITOUS
    assert discrimination("name", 42) == UBIQUITOUS
    assert discrimination("name", []) == UBIQUITOUS
    assert discrimination("name", "") == UBIQUITOUS
    assert discrimination("name", "   ") == UBIQUITOUS
    assert discrimination(None, "value") == DISCRIMINATING
    assert discrimination(123, "value") == DISCRIMINATING


def test_stem_strips_one_extension_only():
    assert _stem("archive.tar.gz") == "archive.tar"
    assert _stem("C:\\Windows\\System32\\certutil.exe") == "certutil"
    assert _stem("/usr/bin/curl") == "curl"


def test_host_cuts_at_leftmost_delimiter():
    assert _host("host?a=/b") == "host"
    assert _host("http://user:pass@h.example.com:8080/p") == "h.example.com"
