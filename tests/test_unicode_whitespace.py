"""`\\s` means what Python means, with RE2 or without (ADR-0049).

google-re2 (CI, the container image) reads `\\s` as ASCII whitespace only; the
stdlib `re` that `compile_pattern` falls back to (a dev venv without re2) reads
it as `str.isspace()`.  A PDF or an HTML page puts no-break and thin spaces
between words, so a pattern that relied on `\\s` there did one thing in local
runs and another in production.  The patterns that read such text say
`regex_safety.PY_WHITESPACE` or split with `str.split()`.

Every case passes under both engines; under RE2 each one failed before the fix.
`test_a_new_backslash_s_is_reviewed` keeps the list closed: a new module-level
pattern that uses `\\s` fails it until it is rewritten or listed with a reason.
"""
from __future__ import annotations

import importlib
import re
import re._parser as _sre_parse
from pathlib import Path
from re import _constants as _sre
from typing import Any

import pytest

from models.schemas import EntityType

# No-break space (HTML's &nbsp;), thin space, narrow no-break space (French
# typography before ":" and in "15 000").
BLANKS = ["\xa0", "\u2009", "\u202f"]


# ── The patterns fixed ────────────────────────────────────────────────────────

@pytest.mark.parametrize("b", BLANKS)
def test_generic_vocabulary_is_generic_across_any_blank(b):
    """ADR-0050's filter, and ADR-0052's promote gate that reuses it: "malware
    family" stays out of the gazetteer however the analyst's copy spaced it."""
    from pipeline.promotion import validate_promote_term
    from pipeline.stage2d_cyner import _is_generic_fragment
    assert _is_generic_fragment(f"malware{b}family")
    assert _is_generic_fragment(f"threat{b}actor-group")
    assert not _is_generic_fragment(f"Sandworm{b}Team")
    assert validate_promote_term(f"malware{b}family") is not None


@pytest.mark.parametrize("b", BLANKS)
def test_asn_after_a_no_break_space(b):
    from pipeline.stage2_extraction import extract_entities
    for text in (f"AS{b}15169", f"ASN{b}15169"):
        asns = {e.value for e in extract_entities(text) if e.entity_type == EntityType.ASN}
        assert "AS15169" in asns, f"failed for {text!r}"


@pytest.mark.parametrize("b", BLANKS)
def test_a_spaced_defang_takes_its_blanks(b):
    from pipeline.stage2_extraction import refang
    assert refang(f"update{b}[.]{b}example{b}(.){b}net") == "update.example.net"


@pytest.mark.parametrize("b", BLANKS)
def test_a_windows_path_stops_at_any_blank(b):
    from pipeline.stage2_extraction import _extract_file_paths
    for text in (f"dropped C:\\Users\\Public\\Program{b}Data\\evil.dll today",
                 f"dropped C:\\Windows\\Temp\\evil.dll{b}and more",
                 f"copied to \\\\file{b}srv\\share\\evil.dll today"):
        got = {e.value for e in _extract_file_paths(text)}
        assert got == {e.value for e in _extract_file_paths(text.replace(b, " "))}
        assert not any(b in v for v in got), got


@pytest.mark.parametrize("b", BLANKS)
def test_alias_markers_across_any_blank(b):
    from pipeline.stage2g_alias_list import extract_alias_list_entities
    for text, expected in (
            (f"Static Tundra{b}(aka{b}Berserk Bear) was seen.", {"Berserk Bear"}),
            (f"Static Tundra ({b}aka Berserk Bear,{b}Ghost Blizzard) was seen.", {"Berserk Bear", "Ghost Blizzard"}),
            (f"Static Tundra, also{b}known{b}as Berserk Bear and Dragonfly.", {"Berserk Bear", "Dragonfly"}),
            (f"Static Tundra,{b}also known as{b}Berserk Bear and Dragonfly.", {"Berserk Bear", "Dragonfly"}),
            (f"Static Tundra, also known as Berserk Bear{b}and{b}Dragonfly.", {"Berserk Bear", "Dragonfly"}),
    ):
        names = {e.value for e in extract_alias_list_entities(text)}
        assert names == {"Static Tundra"} | expected, f"failed for {text!r}: {names}"


@pytest.mark.parametrize("b", BLANKS)
def test_a_numbered_list_item_after_any_blank(b):
    from pipeline.stage2c_ttp_semantic import _unwrap_hard_linebreaks
    from pipeline.ttp_retrieval import split_passages
    text = f"The operators took these steps\n1.{b}They sent spearphishing emails to staff"
    assert _unwrap_hard_linebreaks(text) == text          # a list item is not a hard wrap
    # ("1." itself is a sentence end, and too short a passage)
    assert [p.text for p in split_passages(text)] == [
        "The operators took these steps", "They sent spearphishing emails to staff"]


@pytest.mark.parametrize("b", BLANKS)
def test_a_table_caption_after_any_blank(b):
    from pipeline.stage2c_ttp_semantic import _is_advisory_noise
    assert _is_advisory_noise(f"Table{b}3 lists the indicators of compromise")


@pytest.mark.parametrize("b", BLANKS)
def test_passage_and_attack_text_collapse_any_blank(b):
    from pipeline.ttp_retrieval import clean_attack_text, split_passages
    [p] = split_passages(f"The actor sent{b}spearphishing{b}{b}emails to the staff.")
    assert p.text == "The actor sent spearphishing emails to the staff."
    assert clean_attack_text(f" APT28 has used{b}rundll32.{b}") == "APT28 has used rundll32."


@pytest.mark.parametrize("b", BLANKS)
def test_a_selection_quote_is_found_across_any_blank(b):
    """Stage 3f keeps a technique only if its quote is in the report."""
    from pipeline.stage3f_ttp_select import _clip, _norm
    assert _norm("sent spear phishing links") in _norm(f"They sent spear{b}phishing{b}links.")
    assert _clip(f"a{b}{b}b ", 10) == "a b"


@pytest.mark.parametrize("b", BLANKS)
def test_a_port_after_any_blank(b):
    from pipeline.network_traffic import parse_network_traffic
    d = parse_network_traffic(f"198.51.100.7 port{b}443 over tcp")
    assert d is not None and d.port == 443


@pytest.mark.parametrize("b", BLANKS)
def test_observable_refang_of_a_spaced_dot(b):
    from pipeline.detection.observables import _refang
    assert _refang(f"evil{b}[dot]{b}com") == "evil.com"


@pytest.mark.parametrize("b", BLANKS)
def test_yara_import_declared_after_any_blank(b):
    """A report that declares `import "pe"` outside the rule: Stage 4 adds it to
    the rule, which then compiles (ADR-0067)."""
    from pipeline.detection.yara_atoms import split_rules
    [rule] = split_rules(f'import{b}"pe"\n\nrule a {{\n  condition: pe.is_pe\n}}\n')
    assert rule.imports == ("pe",)


@pytest.mark.parametrize("b", BLANKS)
def test_yara_rule_header_and_lines_across_any_blank(b):
    """YARA refuses a no-break space outside a string, so such a rule does not
    ship either way; it is still found, so the ledger says why it was left out."""
    from pipeline.detection.yara_atoms import _classify_literal, extract_atoms, split_rules
    md5, sha1 = "d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    [rule] = split_rules(
        f'rule a{b}{{\n meta:\n{b}hash = "{md5}{b}{sha1}"\n strings:\n'
        f'{b}$s = "kernel32"\n condition: $s\n}}\n')
    assert rule.name == "a"
    assert rule.meta == {"hash": f"{md5}{b}{sha1}"}
    assert {v for c, v in extract_atoms(rule) if c == "hash"} == {md5, sha1}
    assert len(rule.strings) == 1
    # "contains no spaces" is what makes a literal a path
    assert _classify_literal(f"c:\\program{b}files\\x.exe") == _classify_literal("c:\\program files\\x.exe")


@pytest.mark.parametrize("b", BLANKS)
def test_a_sigma_rule_ends_where_the_next_title_starts(b):
    """Without the boundary the two rules ship as one Indicator pattern."""
    from pipeline.stage4_stix_mapping import _find_embedded_sigma_rules
    rule_a = ("title: Rule A\nlogsource:\n  product: windows\n"
              "detection:\n  sel:\n    Image: a.exe\n  condition: sel\n")
    rule_b = (f"title{b}: Rule B\nlogsource:\n  product: linux\n"
              "detection:\n  sel:\n    Image: b\n  condition: sel\n")
    found = _find_embedded_sigma_rules(rule_a + "\n" + rule_b)
    assert [doc["title"] for _, doc in found] == ["Rule A"]   # B's key is "title\xa0" to YAML
    assert "Rule B" not in found[0][0]


# ── The patterns left as they are ─────────────────────────────────────────────

def test_dates_are_folded_before_any_pattern_reads_them():
    from pipeline.temporal import header_candidates, normalize
    assert normalize("27\xa0February\u20092020").value == "2020-02-27"
    assert normalize("Q3\xa02024").value == normalize("Q3 2024").value
    assert [c["value"] for c in header_candidates("Published:\xa012\u202fMarch\xa02024")] == ["2024-03-12"]


# ── Every module-level `\s` is reviewed ───────────────────────────────────────

_ROOT = Path(__file__).resolve().parent.parent

# Where `\s` stays: the text it reads cannot hold a non-ASCII blank, or its
# grammar is ASCII.  (module, start of the pattern after any leading inline
# flags) -> why.  A whole module when the reason covers every pattern in it.
REVIEWED: dict[tuple[str, str | None], str] = {
    ("pipeline.temporal", None):
        "every input goes through fold(), which turns any str.isspace() into ' '",
    ("pipeline.stage1_ingestion", r"^(?:[0-9a-fA-F]{32,128}"):
        "_join_cell matches it only on lines without any str.isspace() character",
    ("pipeline.stage2d_cyner", r"^(the|a|an)\s+"):
        "CyNER's `word` is decoded by DeBERTa's NFKC tokenizer; a non-ASCII value "
        "is dropped by _has_boundary_artifact",
    ("pipeline.stage2d_cyner", r"^[a-z]\s"): "as above",
    ("pipeline.stage2d_cyner", r"\.\s"): "as above",
    ("pipeline.stage4_stix_mapping", r"=\s*([0-9]+)\s*\]"): "reads the STIX patterns Stage 4 wrote",
    ("pipeline.ttp_retrieval", r"\[([^\]]{1,200})\]\((https?://attack"):
        "ATT&CK's own text at corpus build; a URL holds no blank",
    ("api.routes.ingest", r"<"): "sniffs HTML, whose blanks are ASCII",
    ("api.routes.ingest", r"^\#{1,6}\s+\S"): "sniffs Markdown, whose blanks are space and tab",
    ("api.routes.ingest", r"^\s{0,3}([-*+]|[0-9]+\.)\s+\S"): "as above",
    ("api.routes.ingest", r"^\s*```"): "as above",
    ("api.routes.ingest", r"^\s*\|.+\|\s*$"): "as above",
}
_LEADING_FLAGS = re.compile(r"^(?:\(\?[aiLmsux]+\))+")      # RE2 takes the flags inline


def _uses(pattern: str, categories: frozenset = frozenset(), ats: frozenset = frozenset()) -> bool:
    """`pattern` says one of `categories` (`\\s`, `\\S`, `\\d`... as the parser
    names them) or one of the zero-width `ats` (`\\b`, `\\B`), at any depth.
    tests/test_unicode_word_digit.py walks with it too."""
    found = False

    def walk(items) -> None:
        nonlocal found
        for op, av in items:
            if op is _sre.IN:
                found |= any(sop is _sre.CATEGORY and av2 in categories for sop, av2 in av)
            elif op is _sre.CATEGORY:
                found |= av in categories
            elif op is _sre.AT:
                found |= av in ats
            elif op is _sre.SUBPATTERN:
                walk(av[-1])
            elif op in (_sre.MAX_REPEAT, _sre.MIN_REPEAT, getattr(_sre, "POSSESSIVE_REPEAT", None)):
                walk(av[2])
            elif op is _sre.BRANCH:
                for branch in av[1]:
                    walk(branch)
            elif op in (_sre.ASSERT, _sre.ASSERT_NOT):
                walk(av[1])
            elif op is getattr(_sre, "ATOMIC_GROUP", None):
                walk(av)
            elif op is _sre.GROUPREF_EXISTS:
                walk(av[1])
                if av[2]:
                    walk(av[2])

    walk(_sre_parse.parse(pattern))
    return found


def _uses_backslash_s(pattern: str) -> bool:
    return _uses(pattern, frozenset({_sre.CATEGORY_SPACE, _sre.CATEGORY_NOT_SPACE}))


def _patterns_in(value, depth: int = 0):
    if hasattr(value, "finditer") and isinstance(getattr(value, "pattern", None), str):
        yield value
    elif depth < 2 and isinstance(value, (tuple, list, frozenset, set)):
        for item in value:
            yield from _patterns_in(item, depth + 1)
    elif depth < 2 and isinstance(value, dict):
        for item in value.values():
            yield from _patterns_in(item, depth + 1)


def _module_level_patterns() -> tuple[list[tuple[str, str, Any]], set[str]]:
    """(module, attribute, compiled pattern) of every compiled pattern a module
    that calls compile_pattern holds at its top level and defines itself, and the
    modules that could be imported here."""
    found: list[tuple[str, str, Any]] = []
    checked: set[str] = set()
    for path in sorted([*(_ROOT / "pipeline").rglob("*.py"), *(_ROOT / "api").rglob("*.py")]):
        source = path.read_text(encoding="utf-8")
        if "compile_pattern(" not in source or path.name == "regex_safety.py":
            continue
        name = ".".join(path.relative_to(_ROOT).with_suffix("").parts)
        try:
            module = importlib.import_module(name)
        except ImportError as exc:        # an optional dependency absent here; CI has them all
            print(f"not checked: {name}: {exc}")
            continue
        checked.add(name)
        for attr, value in vars(module).items():
            if not re.search(rf"^{re.escape(attr)}\s*[:=]", source, re.MULTILINE):
                continue                  # imported from another module
            found.extend((name, attr, rx) for rx in _patterns_in(value))
    return found, checked


def _module_level_backslash_s() -> tuple[set[tuple[str, str]], set[str]]:
    """(module, pattern) of every module-level pattern that says `\\s`."""
    patterns, checked = _module_level_patterns()
    stripped = {(name, _LEADING_FLAGS.sub("", rx.pattern)) for name, _, rx in patterns}
    return {(name, pattern) for name, pattern in stripped if _uses_backslash_s(pattern)}, checked


def _reviewed(module: str, pattern: str) -> bool:
    from tests.test_re2_fallbacks import LISTED  # lookarounds: always `re`, Unicode \s
    return (any(module == m and pattern.startswith(prefix) for m, prefix in LISTED)
            or (module, None) in REVIEWED
            or any(module == m and prefix is not None and pattern.startswith(prefix)
                   for m, prefix in REVIEWED))


def test_a_new_backslash_s_is_reviewed():
    found, checked = _module_level_backslash_s()
    unreviewed = sorted((m, p[:80]) for m, p in found if not _reviewed(m, p))
    assert unreviewed == [], (
        "RE2's \\s is ASCII only: write regex_safety.PY_WHITESPACE in the class "
        "(or str.split()), or list the pattern in REVIEWED with the reason it is safe")
    stale = sorted(key for key in REVIEWED if key[0] in checked
                   and not any(m == key[0] and (key[1] is None or p.startswith(key[1])) for m, p in found))
    assert stale == [], f"listed but no longer uses \\s, unlist: {stale}"


def test_the_guard_sees_backslash_s():
    assert _uses_backslash_s(r"a\sb") and _uses_backslash_s(r"[^\S\d]+") and _uses_backslash_s(r"(?:x|\s)*")
    assert not _uses_backslash_s(r"a\\sb") and not _uses_backslash_s("[\t\xa0 ]")
