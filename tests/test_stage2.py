from pipeline.stage2_extraction import extract_entities, _deduplicate, refang
from pipeline.stage1_ingestion import _join_hyphen_linebreaks
from models.schemas import EntityType, RawEntity

SAMPLE_TEXT = """
APT29 used Cobalt Strike for C2 communications.
The malware contacted 185.220.101.45 and evil-c2-domain.ru.
Also seen resolving to isolated-domain.com.
Download URL: https://evil-c2-domain.ru/payload.exe
Phishing email: phishing@malicious-domain.com
File hash SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
CVE-2021-40444 was exploited for initial access.
Technique T1566.001 (Spearphishing Attachment) was observed.
"""

DEFANGED_TEXT = """
The actor communicated with hxxps://malicious[.]domain[.]com/path
C2 server at 192[.]168[.]1[.]1 contacted via hxxp://c2[.]evil[.]ru
Email: attacker[@]evil[.]org
"""


def test_extracts_ipv4():
    entities = extract_entities(SAMPLE_TEXT)
    ipv4s = [e for e in entities if e.entity_type == EntityType.IPV4]
    assert any("185.220.101.45" in e.value for e in ipv4s)


def test_extracts_cve():
    entities = extract_entities(SAMPLE_TEXT)
    cves = [e for e in entities if e.entity_type == EntityType.CVE]
    assert any("CVE-2021-40444" in e.value for e in cves)


def test_extracts_mitre_ttp():
    entities = extract_entities(SAMPLE_TEXT)
    ttps = [e for e in entities if e.entity_type == EntityType.TTP]
    assert any("T1566.001" in e.value for e in ttps)


def test_extracts_sha256():
    entities = extract_entities(SAMPLE_TEXT)
    sha256s = [e for e in entities if e.entity_type == EntityType.SHA256]
    assert len(sha256s) >= 1


def test_extracts_url():
    entities = extract_entities(SAMPLE_TEXT)
    urls = [e for e in entities if e.entity_type == EntityType.URL]
    assert len(urls) >= 1


def test_extracts_email():
    entities = extract_entities(SAMPLE_TEXT)
    emails = [e for e in entities if e.entity_type == EntityType.EMAIL]
    assert len(emails) >= 1


def test_extracts_domain():
    entities = extract_entities(SAMPLE_TEXT)
    domains = [e for e in entities if e.entity_type == EntityType.DOMAIN]
    assert len(domains) >= 1


def test_refang_hxxps():
    assert refang("hxxps://evil.com") == "https://evil.com"
    assert refang("hxxp://evil.com") == "http://evil.com"


def test_refang_dotted():
    assert refang("evil[.]com") == "evil.com"
    assert refang("192[.]168[.]1[.]1") == "192.168.1.1"


def test_defanged_iocs_extracted():
    entities = extract_entities(DEFANGED_TEXT)
    types = {e.entity_type for e in entities}
    assert EntityType.URL in types or EntityType.DOMAIN in types
    assert EntityType.IPV4 in types


def test_no_duplicates():
    entities = extract_entities(SAMPLE_TEXT + SAMPLE_TEXT)
    seen = set()
    for e in entities:
        key = (e.value.lower(), e.entity_type)
        assert key not in seen, f"Doublon trouvé : {e.value}"
        seen.add(key)


def test_deduplicate_function():
    entities = [
        RawEntity(value="192.168.1.1", entity_type=EntityType.IPV4),
        RawEntity(value="192.168.1.1", entity_type=EntityType.IPV4),
        RawEntity(value="192.168.1.2", entity_type=EntityType.IPV4),
    ]
    result = _deduplicate(entities)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Extended defang tests — ADR-005
# ---------------------------------------------------------------------------

class TestRefangProtocols:
    def test_hxxps(self):
        assert refang("hxxps://evil.com") == "https://evil.com"

    def test_hxxp(self):
        assert refang("hxxp://evil.com") == "http://evil.com"

    def test_h_tt_ps(self):
        assert refang("h[tt]ps://evil.com") == "https://evil.com"

    def test_h_tt_p(self):
        assert refang("h[tt]p://evil.com") == "http://evil.com"

    def test_https_bracket_s(self):
        assert refang("http[s]://evil.com") == "https://evil.com"

    def test_http_bracket_colon(self):
        assert refang("http[:]//evil.com") == "http://evil.com"

    def test_https_bracket_colon(self):
        assert refang("https[:]//evil.com") == "https://evil.com"

    def test_fxxp(self):
        assert refang("fxxp://files.evil.com") == "ftp://files.evil.com"

    def test_fxp(self):
        assert refang("fxp://files.evil.com") == "ftp://files.evil.com"


class TestRefangDots:
    def test_square_bracket_dot(self):
        assert refang("evil[.]com") == "evil.com"

    def test_paren_dot(self):
        assert refang("evil(.)com") == "evil.com"

    def test_curly_dot(self):
        assert refang("evil{.}com") == "evil.com"

    def test_word_dot_square(self):
        assert refang("evil[dot]com") == "evil.com"

    def test_word_dot_paren(self):
        assert refang("evil(dot)com") == "evil.com"

    def test_word_dot_case_insensitive(self):
        assert refang("evil[DOT]com") == "evil.com"

    def test_space_padded_dot(self):
        assert refang("evil [.] com") == "evil.com"

    def test_dot_in_path(self):
        # Matches the real-world case: transformers[.]pyz
        assert refang("transformers[.]pyz") == "transformers.pyz"

    def test_full_url_combined(self):
        # Real example from the failing report
        result = refang("hxxps://git-anstack[.]com/transformers[.]pyz")
        assert result == "https://git-anstack.com/transformers.pyz"


class TestRefangAtSign:
    def test_bracket_at(self):
        assert refang("user[@]evil.com") == "user@evil.com"

    def test_bracket_at_word(self):
        assert refang("user[at]evil.com") == "user@evil.com"

    def test_paren_at_word(self):
        assert refang("user(at)evil.com") == "user@evil.com"

    def test_at_case_insensitive(self):
        assert refang("user[AT]evil.com") == "user@evil.com"


class TestRefangColonSlash:
    def test_bracket_colon(self):
        assert refang("http[:]//evil.com") == "http://evil.com"

    def test_paren_colon(self):
        assert refang("http(:)//evil.com") == "http://evil.com"

    def test_bracket_double_slash(self):
        assert refang("http:[//]evil.com") == "http://evil.com"


# ---------------------------------------------------------------------------
# IoC appendix / list patterns — ADR-004 P1-C (Croquet Thorne 2025 findings)
# These tests verify that IoCs in "Indicators" appendix sections are correctly
# extracted even when they appear as:
#   • comma-separated lists
#   • pipe-separated tables
#   • one-per-line bulleted lists
#   • with mixed live + defanged forms in the same text
# ---------------------------------------------------------------------------

class TestIoCAppendixPatterns:
    """IoCs in structured list/appendix sections (common in real CTI PDFs)."""

    def test_comma_separated_defanged_ips(self):
        text = "C2 servers: 10[.]0[.]0[.]1, 192[.]168[.]1[.]100, 172[.]16[.]0[.]50"
        entities = extract_entities(text)
        ipv4s = {e.value for e in entities if e.entity_type == EntityType.IPV4}
        assert "10.0.0.1" in ipv4s
        assert "192.168.1.100" in ipv4s
        assert "172.16.0.50" in ipv4s

    def test_one_per_line_indicator_section(self):
        text = (
            "Indicators of Compromise\n"
            "- 185[.]220[.]101[.]45\n"
            "- evil-c2[.]ru\n"
            "- hxxps://malware[.]example[.]com/payload\n"
            "- e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        )
        entities = extract_entities(text)
        types = {e.entity_type for e in entities}
        assert EntityType.IPV4 in types
        assert EntityType.SHA256 in types
        assert EntityType.URL in types or EntityType.DOMAIN in types

    def test_mixed_live_and_defanged_same_text(self):
        """A report using defanging inconsistently — some IoCs live, some defanged."""
        text = (
            "The actor used 8.8.8.8 (live) and 1.1.1[.]1 (defanged) as DNS resolvers. "
            "The C2 was hxxps://evil[.]com/stage2 and also https://backup-c2.net/api."
        )
        entities = extract_entities(text)
        ipv4s  = {e.value for e in entities if e.entity_type == EntityType.IPV4}
        urls   = {e.value for e in entities if e.entity_type == EntityType.URL}
        assert "8.8.8.8" in ipv4s
        assert "1.1.1.1" in ipv4s
        assert any("evil.com" in u for u in urls)
        assert any("backup-c2.net" in u for u in urls)

    def test_pipe_table_format(self):
        """IoC table with pipe separators (common in DOCX/PDF exports)."""
        text = (
            "| Type    | Value                     |\n"
            "| IP      | 192[.]0[.]2[.]1            |\n"
            "| Domain  | malicious[.]example[.]com  |\n"
            "| SHA256  | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |\n"
        )
        entities = extract_entities(text)
        ipv4s   = {e.value for e in entities if e.entity_type == EntityType.IPV4}
        sha256s = {e.value for e in entities if e.entity_type == EntityType.SHA256}
        assert "192.0.2.1" in ipv4s
        assert any(
            "e3b0c44298fc1c149afbf4c8996fb924" in h for h in sha256s
        )

    def test_uppercase_defanging(self):
        """Some analysts write HXXPS:// or [DOT] in uppercase."""
        text = "Download from HXXPS://EVIL[DOT]COM/payload"
        entities = extract_entities(text)
        types = {e.entity_type for e in entities}
        assert EntityType.URL in types or EntityType.DOMAIN in types

    def test_multiple_hashes_same_line(self):
        """Multiple hash types on the same line (triage sheet format)."""
        text = (
            "MD5=d41d8cd98f00b204e9800998ecf8427e "
            "SHA1=da39a3ee5e6b4b0d3255bfef95601890afd80709 "
            "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        entities = extract_entities(text)
        md5s   = [e for e in entities if e.entity_type == EntityType.MD5]
        sha1s  = [e for e in entities if e.entity_type == EntityType.SHA1]
        sha256s = [e for e in entities if e.entity_type == EntityType.SHA256]
        assert len(md5s)    >= 1
        assert len(sha1s)   >= 1
        assert len(sha256s) >= 1

    def test_defanged_url_with_path_and_query(self):
        """Full URL with path, query string, and fragment — all defanged."""
        url = "hxxps://sub[.]evil[.]com/path/file[.]php?id=1&token=abc#section"
        result = refang(url)
        assert result == "https://sub.evil.com/path/file.php?id=1&token=abc#section"
        entities = extract_entities(url)
        urls = [e for e in entities if e.entity_type == EntityType.URL]
        assert len(urls) >= 1
        assert "sub.evil.com" in urls[0].value

    def test_ipv4_with_port_defanged(self):
        """IP:port notation after defanging."""
        text = "Beacon connected to 10[.]10[.]10[.]10:4444"
        entities = extract_entities(text)
        ipv4s = [e for e in entities if e.entity_type == EntityType.IPV4]
        assert any("10.10.10.10" in e.value for e in ipv4s)


class TestHyphenLinebreaks:
    def test_single_newline(self):
        text = "git-\ntanstack.com"
        assert _join_hyphen_linebreaks(text) == "git-tanstack.com"

    def test_double_newline(self):
        # PDF column/page break
        text = "git-\n\ntanstack[.]com"
        assert _join_hyphen_linebreaks(text) == "git-tanstack[.]com"

    def test_with_spaces(self):
        text = "git-  \n  tanstack.com"
        assert _join_hyphen_linebreaks(text) == "git-tanstack.com"

    def test_no_change_non_hyphen(self):
        text = "hello\n\nworld"
        assert _join_hyphen_linebreaks(text) == "hello\n\nworld"

    def test_full_pipeline_tanstack(self):
        # Simulates the exact failing text from the report
        raw = "hxxps://git-\n\ntanstack[.]com/transformers[.]pyz"
        joined = _join_hyphen_linebreaks(raw)
        refanged = refang(joined)
        assert refanged == "https://git-tanstack.com/transformers.pyz"
