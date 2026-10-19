"""`\\d`, `\\w` and `\\b` mean the same with RE2 or without (ADR-0049, 2026-10-18).

google-re2 (CI, the container image) reads all three as ASCII; the stdlib `re`
that `compile_pattern` falls back to (a dev venv without re2) reads them as
Unicode.  So production cut "o@evil.com" out of "joão@evil.com" and gave the
alias list the anchor "Group" for "Müller Group (aka Berserk Bear)", while a
dev run shipped "T١٠٥٩" as an ATT&CK id and "８.８.８.８" as an address.

An IoC is ASCII: its patterns say [0-9], and a pattern that says `\\b` passes
re.ASCII, RE2's own reading.  Where a letter glued to a match means it was cut
out of a word, the caller drops it (`regex_safety.glued_to_a_word`: a letter of
a script with case, or a digit; Chinese text glues words to an IoC and keeps
it).  Names and numbers read every script:
`regex_safety.PY_DIGIT`, `PY_NON_ASCII_WORD`, and the alias list's mask.

Each case passes under both engines; each failed under one of them before.
`test_a_new_word_digit_or_boundary_is_reviewed` keeps the list closed.
"""
from __future__ import annotations

import ast
import importlib
import re
from pathlib import Path
from re import _constants as _sre

import pytest

from models.schemas import EntityType
from pipeline import regex_safety
from pipeline.regex_safety import PY_DIGIT, PY_NON_ASCII_WORD, compile_pattern
from tests.test_unicode_whitespace import _LEADING_FLAGS, _module_level_patterns, _uses

ARABIC_INDIC = str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩")
FULLWIDTH = str.maketrans("0123456789", "０１２３４５６７８９")


def _found(text: str, etype: EntityType) -> set[str]:
    from pipeline.stage2_extraction import extract_entities
    return {e.value for e in extract_entities(text) if e.entity_type == etype}


# ── The building blocks ───────────────────────────────────────────────────────

def test_the_generated_classes_are_pythons_own():
    """[PY_DIGIT] is `re`'s `\\d` and [A-Za-z0-9_PY_NON_ASCII_WORD] its `\\w`, for
    every character, read by RE2 when it is installed; none lies past U+3FFFF,
    where regex_safety stops reading the Unicode tables."""
    every = "".join(chr(c) for c in range(0x110000) if not 0xD800 <= c < 0xE000)
    for ours, pythons in ((f"[{PY_DIGIT}]+", r"\d+"),
                          (f"[A-Za-z0-9_{PY_NON_ASCII_WORD}]+", r"\w+")):
        assert ([m.span() for m in compile_pattern(ours).finditer(every)]
                == [m.span() for m in re.finditer(pythons, every)]), pythons
    assert re.search(r"[\w\d]", "".join(map(chr, range(0x40000, 0x110000)))) is None


def test_re_ascii_is_re2s_own_reading():
    """re.ASCII needs no inline flag: RE2 compiles the pattern, `re` gets the flag."""
    rx = compile_pattern(r"\bT[0-9]{4}\b", re.ASCII)
    if regex_safety._RE2_AVAILABLE:
        assert type(rx).__module__ == "re2"
    else:
        assert rx.flags & re.ASCII
    assert [m.group() for m in rx.finditer("使用T1059技术, éT1234é, xT9999")] == ["T1059", "T1234"]


def test_glued_to_a_word():
    from pipeline.regex_safety import glued_to_a_word
    text = "joão@evil.com x@evil.com"
    assert glued_to_a_word(text, 3, 13)                 # "o@evil.com" after "ã"
    assert not glued_to_a_word(text, 14, 24)            # "x@evil.com", at the end
    assert not glued_to_a_word("evil.com", 0, 8)
    assert glued_to_a_word("ΔAS1", 1, 4) and glued_to_a_word("AS1٣", 0, 3)   # Greek; a digit
    assert not glued_to_a_word("网络AS1网络", 2, 5)        # Chinese writes no spaces


# ── IoCs are ASCII ────────────────────────────────────────────────────────────

# (module, attribute, a string it matches): with the digits of another script
# it matches nothing.  Under `re` each one used to.
ASCII_DIGITS = [
    ("pipeline.stage2_extraction", "_CVE_PATTERN", "CVE-2021-44228"),
    ("pipeline.stage2_extraction", "_IPV4_PATTERN", "8.8.8.8"),
    ("pipeline.stage2_extraction", "_ASN_PATTERN", "AS15169"),
    ("pipeline.stage2_extraction", "_MITRE_TTP_PATTERN", "T1059.001"),
    ("pipeline.stage2c_ttp_semantic", "_LIST_NUMBER", "1. They sent"),
    ("pipeline.stage2c_ttp_semantic", "_TABLE_CAPTION_PATTERN", "Table 3"),
    ("pipeline.ttp_retrieval", "_LIST_NUMBER", "1. They sent"),
    ("pipeline.stage2f_cve_enrichment", "_CVE_PATTERN", "CVE-2021-44228"),
    ("pipeline.stage3c_mitre", "_MITRE_ID_RE", "t1059.001"),
    ("pipeline.stage3f_ttp_select", "_ID_RE", "T1059.001"),
    ("pipeline.stage4_stix_mapping", "_PATTERN_NUM_RE", "[autonomous-system:number = 15169]"),
    ("pipeline.stage4b_graph_completion", "_IOC_GUARD", "CVE-2021-44228"),
    ("pipeline.stage1_ingestion", "_PDF_DATE_RE", "D:20230315120000"),
    ("pipeline.stage1_ingestion", "_IOC_SHAPED", "10.0.0.1:443"),
    ("pipeline.network_traffic", "_PORT", "port 443"),
    ("pipeline.network_traffic", "_HOST_PORT", "evil.com:443"),
    ("pipeline.temporal", "_R_ISO_DAY", "2024-03-12"),
    ("pipeline.temporal", "_R_D_M_Y", "12 march 2024"),
    ("pipeline.temporal", "_R_NUMERIC_ANY", "12/03/2024"),
    ("pipeline.temporal", "_R_YEAR_RANGE", "2019 - 2024"),
    ("pipeline.detection.observables", "_CVE_RE", "cve-2021-44228"),
    ("pipeline.detection.sigma", "_TECHNIQUE_RE", "attack.t1059.001"),
    ("pipeline.detection.sigma", "_GROUP_SOFTWARE_RE", "g0016"),
    ("pipeline.detection.sigma", "_TACTIC_ID_RE", "ta0001"),
    ("pipeline.detection.suricata", "_IP_RE", "10.0.0.1"),
    ("pipeline.detection.suricata_atoms", "_RE_IP", "10.0.0.1"),
    ("pipeline.detection.suricata_atoms", "_RE_MITRE", "T1059.001"),
    ("pipeline.detection.synth_sigma", "_IPV4_RE", "10.0.0.1"),
    ("pipeline.detection.yara", "_TECHNIQUE_RE", "T1059"),
    ("pipeline.detection.yara_atoms", "_RE_IP", "10.0.0.1"),
]


@pytest.mark.parametrize("module, attr, sample", ASCII_DIGITS, ids=[f"{m}.{a}" for m, a, _ in ASCII_DIGITS])
def test_an_ioc_pattern_reads_ascii_digits(module, attr, sample):
    rx = getattr(importlib.import_module(module), attr)
    assert rx.search(sample)
    for digits in (ARABIC_INDIC, FULLWIDTH):
        assert not rx.search(sample.translate(digits)), sample.translate(digits)


def test_a_markdown_list_item_is_numbered_in_ascii():
    import api.main  # noqa: F401  (the routes import it back)
    from api.routes.ingest import _MARKDOWN_RE
    [ordered] = [rx for rx in _MARKDOWN_RE if "[0-9]+" in rx.pattern]
    assert ordered.search("intro\n1. first item")
    assert not ordered.search("intro\n١. first item")


def test_extracted_iocs_have_ascii_digits():
    text = ("T١٠٥٩ and T１０５９, CVE-٢٠٢١-٤٤٢٢٨ and CVE－２０２１－４４２２８, "
            "beacon to ８.８.８.８ and 8.8.8.8١, ASN ١٥١٦٩.")
    for etype in (EntityType.TTP, EntityType.CVE, EntityType.IPV4, EntityType.ASN):
        assert _found(text, etype) == set(), etype
    assert _found("CVE－2021－44228", EntityType.CVE) == {"CVE-2021-44228"}   # the dash is folded


# A `\b` beside an ASCII identifier: Chinese text glues words to it.
@pytest.mark.parametrize("text, etype, value", [
    ("攻击者使用T1059技术", EntityType.TTP, "T1059"),
    ("网卡é00:1A:2B:3C:4D:5E地址", EntityType.MAC_ADDR, "00:1a:2b:3c:4d:5e"),
    ("注册表HKLM\\Software\\Run", EntityType.REGISTRY_KEY, "HKLM\\Software\\Run"),
])
def test_an_ascii_identifier_glued_to_another_script_is_found(text, etype, value):
    assert _found(text, etype) == {value}


def test_ascii_boundaries_elsewhere():
    from pipeline.detection.yara import _TECHNIQUE_RE
    from pipeline.stage2c_ttp_semantic import _is_advisory_noise
    from pipeline.stage4b_graph_completion import _IOC_GUARD
    assert _TECHNIQUE_RE.findall("mitre=T1059.001,攻击T1027") == ["T1059.001", "T1027"]
    assert _IOC_GUARD.search("使用CVE-2021-44228")          # never merged into another name
    assert _is_advisory_noise("见Table 3 lists the indicators")


# A letter of another script glued to the match: it was cut out of a word.
@pytest.mark.parametrize("text, etype, values", [
    ("joão@evil.com wrote", EntityType.EMAIL, set()),            # RE2: "o@evil.com"
    ("joão@evil.com wrote", EntityType.DOMAIN, {"evil.com"}),
    ("contact: müller@evil.com", EntityType.EMAIL, set()),       # RE2: "ller@evil.com"
    ("write to x@evil.comunicação", EntityType.EMAIL, set()),    # RE2: "x@evil.comunica"
    ("write to x@evil.com, joão", EntityType.EMAIL, {"x@evil.com"}),
    ("mail josé.perez@evil.com now", EntityType.EMAIL, set()),   # the cut is before the dot
    ("mail é.x@evil.com now", EntityType.EMAIL, set()),
    ("ÚLTIMOS DÍAS 2024", EntityType.ASN, set()),                # RE2: AS2024
    ("AS15169 and ASN 13335", EntityType.ASN, {"AS15169", "AS13335"}),
])
def test_a_match_cut_out_of_a_word_is_dropped(text, etype, values):
    assert _found(text, etype) == values


# Chinese and Japanese write no spaces: an IoC glued to their words stays one.
@pytest.mark.parametrize("text, etype, values", [
    ("使用attacker@evil.com发送", EntityType.EMAIL, {"attacker@evil.com"}),
    ("该IP属于AS4134网络", EntityType.ASN, {"AS4134"}),
    ("ロシアのAS4134ネットワーク", EntityType.ASN, {"AS4134"}),
    ("C:\\Windows\\System32\\cmd.exe执行了命令", EntityType.FILE, {"C:\\Windows\\System32\\cmd.exe"}),
])
def test_an_ioc_glued_to_an_unspaced_script_is_kept(text, etype, values):
    assert _found(text, etype) == values


def test_a_windows_path_extension_does_not_run_into_another_script():
    from pipeline.stage2_extraction import _extract_file_paths

    def paths(text: str) -> set[str]:
        return {e.value for e in _extract_file_paths(text)}
    assert paths("saved C:\\Users\\x\\relatório.comunicação") == set()   # RE2: "...relatório.comunica"
    assert paths("saved C:\\Users\\José\\évil.exe today") == {"C:\\Users\\José\\évil.exe"}


def test_a_port_is_not_read_out_of_a_word():
    from pipeline.network_traffic import parse_network_traffic
    assert parse_network_traffic("198.51.100.7 téléport 443").port is None
    assert parse_network_traffic("198.51.100.7 port ٤٤٣ over tcp").port is None
    assert parse_network_traffic("198.51.100.7 téléport 22, port 443 over tcp").port == 443
    assert parse_network_traffic("198.51.100.7 通过tcp/443连接").port == 443


def test_a_date_is_read_in_ascii_digits():
    from pipeline.temporal import header_candidates, normalize
    assert normalize("12 March 2024").value == "2024-03-12"
    for text in ("٢٠٢٤-٠٣-١٢", "12 March ٢٠٢٤", "２０２４-０３-１２"):
        assert normalize(text).value is None, text
    assert header_candidates("Published: ٢٠٢٤-٠٣-١٢") == []


def test_detection_grammars_are_ascii():
    import api.main  # noqa: F401  (the routes import it back)
    from api.routes.settings import _UNSAFE_REMOTE_RE
    from pipeline.detection.atoms import _COND_TOKEN
    from pipeline.detection.yara_atoms import _RE_META_LINE, _RE_STRING_DECL, split_rules
    assert _COND_TOKEN.findall("not ١ of filter_*") == ["not", "of", "filter_*"]
    assert _RE_META_LINE.match("  author = x") and not _RE_META_LINE.match("  clé = x")
    assert _RE_STRING_DECL.match('  $s1 = "x"') and not _RE_STRING_DECL.match('  $café = "x"')
    [rule] = split_rules('import "pé"\n\nrule a {\n  condition: true\n}\n')
    assert rule.imports == ()
    # What git reads as a transport helper (transport.c), and RE2's `\w+`.
    for remote in ("-u", "ext::sh -c x", "fd::0", "a-b::x", "a.b::x", "x+y::z", "_x::y"):
        assert _UNSAFE_REMOTE_RE.match(remote), remote
    for remote in ("https://github.com/x/y", "é::x", "git@host:x"):
        assert not _UNSAFE_REMOTE_RE.match(remote), remote


# ── Names and numbers read every script ───────────────────────────────────────

def test_a_yara_rule_with_a_non_ascii_name_is_found():
    """YARA refuses it; found, it is left out with a reason in the ledger."""
    from pipeline.detection.yara_atoms import split_rules
    [rule] = split_rules("rule café {\n  condition: true\n}\n")
    assert rule.name == "café"


def test_a_version_number_in_any_digits_is_not_a_name():
    from pipeline.stage2_extraction import _VERSION_PATTERN
    from pipeline.stage2d_cyner import _VERSION_RE
    for value in ("1.2.3", "١.٢.٣", "１.２-３"):
        assert _VERSION_PATTERN.fullmatch(value) and _VERSION_RE.match(value), value
    for value in ("v1.2", "1.2.", "1"):
        assert not _VERSION_PATTERN.fullmatch(value) and not _VERSION_RE.match(value), value


@pytest.mark.parametrize("text, expected", [
    ("Müller Group (aka Berserk Bear, Ghost Blizzard) was seen.",
     {"Müller Group", "Berserk Bear", "Ghost Blizzard"}),                  # RE2: "Group"
    ("Static Tundra, also known as Berserk Bear and Ghøst Blizzard.",
     {"Static Tundra", "Berserk Bear", "Ghøst Blizzard"}),                 # RE2: no "Ghøst Blizzard"
    ("Static Tundra (aka Cléand Bear, Dragonfly)",
     {"Static Tundra", "Cléand Bear", "Dragonfly"}),                       # RE2 split "Clé|and Bear"
    ("𝔘 wrote: Müller Group (aka Berserk Bear) was seen.",                  # one astral character first
     {"Müller Group", "Berserk Bear"}),
    ("Static Tundra (áka Berserk Bear) was seen.", set()),               # the mask does not read "aka"
    ("Static Tundra, also known ás Berserk Bear.", set()),
    ("Static Tundra (aka Berserk Bear, Ánd Ghost Blizzard)",              # nor "and"
     {"Static Tundra", "Berserk Bear", "Ánd Ghost Blizzard"}),
])
def test_alias_names_keep_their_letters(text, expected):
    from pipeline.stage2g_alias_list import extract_alias_list_entities
    assert {e.value for e in extract_alias_list_entities(text)} == expected


def test_aliases_split_where_the_masked_text_splits():
    from pipeline.stage2g_alias_list import _masked, _split_aliases
    raw = ", Berserk Bear,, Dragonfly and Ghost Blizzard/ or Sandworm Team,"
    assert _split_aliases(raw, raw) == ["Berserk Bear", "Dragonfly", "Ghost Blizzard", "Sandworm Team"]
    raw = "Cléand Bear and Dragonfly"
    assert _split_aliases(raw, _masked(raw)) == ["Cléand Bear", "Dragonfly"]
    assert len(_masked("𝔘 Müller")) == len("𝔘 Müller") and _masked("Ünd café") == "znd cafz"


# ── Every module-level `\w`, `\d` and `\b` is reviewed ───────────────────────

_ROOT = Path(__file__).resolve().parent.parent
_WORD_DIGIT = frozenset({_sre.CATEGORY_WORD, _sre.CATEGORY_NOT_WORD,
                         _sre.CATEGORY_DIGIT, _sre.CATEGORY_NOT_DIGIT})
_BOUNDARY = frozenset({_sre.AT_BOUNDARY, _sre.AT_NON_BOUNDARY})
_SPACE = frozenset({_sre.CATEGORY_SPACE, _sre.CATEGORY_NOT_SPACE})

# Where `\w`, `\d` or `\b` stays without re.ASCII.  (module, start of the pattern
# after any leading inline flags) -> why; a whole module when the reason covers
# every pattern in it.
REVIEWED: dict[tuple[str, str | None], str] = {
    ("pipeline.stage2g_alias_list", r"(?P<anchor>(?:[A-Z][\w'&.-]*"):
        "both alias patterns read _masked() text, where no non-ASCII word character "
        "is left for `\\w` and `\\b` to read differently",
    ("pipeline.stage2g_alias_list", r",|/|\band\b|\bor\b"): "splits _masked() text, as above",
}


def _assignment(module: str, attr: str) -> ast.expr | None:
    path = _ROOT.joinpath(*module.split(".")).with_suffix(".py")
    value = None
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        targets = (node.targets if isinstance(node, ast.Assign)
                   else [node.target] if isinstance(node, ast.AnnAssign) else [])
        if any(isinstance(t, ast.Name) and t.id == attr for t in targets):
            value = node.value
    return value


def _calls_compile_pattern(value: ast.expr) -> bool:
    return any(isinstance(n, ast.Call)
               and (getattr(n.func, "id", None) or getattr(n.func, "attr", "")).endswith("compile_pattern")
               for n in ast.walk(value))


def _passes_re_ascii(value: ast.expr) -> bool:
    return any(isinstance(n, ast.Attribute) and n.attr == "ASCII"
               and isinstance(n.value, ast.Name) and n.value.id == "re" for n in ast.walk(value))


def _unreviewed() -> tuple[list[tuple[str, str, str]], set[tuple[str, str]], set[str]]:
    from tests.test_re2_fallbacks import LISTED  # lookarounds: `re`, so Unicode, under both
    patterns, checked = _module_level_patterns()
    problems: list[tuple[str, str, str]] = []
    found: set[tuple[str, str]] = set()
    for module, attr, rx in patterns:
        pattern = _LEADING_FLAGS.sub("", rx.pattern)
        word_digit, boundary = _uses(pattern, _WORD_DIGIT), _uses(pattern, ats=_BOUNDARY)
        if not (word_digit or boundary):
            continue
        value = _assignment(module, attr)
        if value is None or not _calls_compile_pattern(value):
            continue                                # re.compile: `re` under both
        if any(module == m and pattern.startswith(prefix) for m, prefix in LISTED):
            continue
        found.add((module, pattern))
        if (module, None) in REVIEWED or any(module == m and prefix is not None
                                             and pattern.startswith(prefix) for m, prefix in REVIEWED):
            continue
        if word_digit:
            problems.append((module, attr, "says \\w or \\d: write [A-Za-z0-9_] or [0-9], "
                                           "or regex_safety.PY_DIGIT / PY_NON_ASCII_WORD"))
        elif not _passes_re_ascii(value):
            problems.append((module, attr, "says \\b without re.ASCII"))
        elif _uses(pattern, _SPACE):
            problems.append((module, attr, "says \\s with re.ASCII, whose \\s has \\v and RE2's not"))
    return problems, found, checked


def test_a_new_word_digit_or_boundary_is_reviewed():
    problems, found, checked = _unreviewed()
    assert problems == [], (
        "RE2 reads \\w, \\d and \\b as ASCII and `re` as Unicode: write the class "
        "(a `\\b` takes re.ASCII, and a check in Python if a letter of another "
        "script must not touch the match), or list the pattern in REVIEWED with "
        f"the reason it is safe: {problems}")
    stale = sorted(key for key in REVIEWED if key[0] in checked
                   and not any(m == key[0] and (key[1] is None or p.startswith(key[1])) for m, p in found))
    assert stale == [], f"listed but no longer says \\w, \\d or \\b, unlist: {stale}"


def test_the_guard_sees_word_digit_and_boundary():
    assert _uses(r"a\db", _WORD_DIGIT) and _uses(r"[^\s\w]+", _WORD_DIGIT) and _uses(r"(?:x|\D)*", _WORD_DIGIT)
    assert _uses(r"(?:x\b)+", ats=_BOUNDARY) and _uses(r"\Bx", ats=_BOUNDARY)
    assert not _uses(r"a\\db[0-9]", _WORD_DIGIT) and not _uses(r"a\\b", ats=_BOUNDARY)
    value = ast.parse('X = compile_pattern(r"\\bx", re.IGNORECASE | re.ASCII)').body[0].value
    assert _calls_compile_pattern(value) and _passes_re_ascii(value)
