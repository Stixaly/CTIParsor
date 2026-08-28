"""Sigma negated selections must never become atoms (bug-hunt 2026-08)."""
from __future__ import annotations

from pipeline.detection.atoms import (
    _expand_selector,
    _negated_selections,
    extract_atoms,
)


def _rule(condition, **selections) -> dict:
    """Build a minimal Sigma document with the given detection block."""
    detection = dict(selections)
    if condition is not None:
        detection["condition"] = condition
    return {"detection": detection}


def test_plain_not_excludes_the_named_selection() -> None:
    """Real condition: 'selection and not filter'."""
    rule = _rule(
        "selection and not filter",
        selection={"Image": "\\\\evil.exe"},
        filter={"Image": "\\\\teams.exe"},
    )
    atoms = extract_atoms(rule)
    values = {v for _c, v in atoms}
    assert "evil.exe" in values
    assert "teams.exe" not in values


def test_one_of_pattern_excludes_every_matching_selection() -> None:
    """Real condition: 'selection and not 1 of filter_*'."""
    rule = _rule(
        "selection and not 1 of filter_*",
        selection={"Image": "\\\\evil.exe"},
        filter_a={"Image": "\\\\teams.exe"},
        filter_b={"Image": "\\\\onedrive.exe"},
    )
    atoms = extract_atoms(rule)
    values = {v for _c, v in atoms}
    assert "evil.exe" in values
    assert "teams.exe" not in values
    assert "onedrive.exe" not in values


def test_all_of_pattern_is_also_a_quantifier() -> None:
    """Real condition: 'selection and not all of filter_*'."""
    rule = _rule(
        "selection and not all of filter_*",
        selection={"Image": "\\\\evil.exe"},
        filter_a={"Image": "\\\\teams.exe"},
        filter_b={"Image": "\\\\onedrive.exe"},
    )
    atoms = extract_atoms(rule)
    values = {v for _c, v in atoms}
    assert "evil.exe" in values
    assert "teams.exe" not in values
    assert "onedrive.exe" not in values


def test_negated_parenthesis_excludes_every_name_inside() -> None:
    """Real condition: 'selection and not (exclude_a or exclude_b)'."""
    rule = _rule(
        "selection and not (exclude_a or exclude_b)",
        selection={"Image": "\\\\evil.exe"},
        exclude_a={"Image": "\\\\teams.exe"},
        exclude_b={"Image": "\\\\onedrive.exe"},
    )
    atoms = extract_atoms(rule)
    values = {v for _c, v in atoms}
    assert "evil.exe" in values
    assert "teams.exe" not in values
    assert "onedrive.exe" not in values


def test_negation_does_not_depend_on_the_name_filter() -> None:
    """Real sigmahq:18739897 — 'legitimate_executable and not legitimate_process_path'."""
    rule = _rule(
        "legitimate_executable and not legitimate_process_path",
        legitimate_executable={"Image": "\\\\evil.exe"},
        legitimate_process_path={"Image": "c:\\\\windows\\\\system32\\\\"},
    )
    atoms = extract_atoms(rule)
    values = {v for _c, v in atoms}
    assert "evil.exe" in values
    assert not any("system32" in v for v in values)


def test_positively_used_filter_selection_is_kept() -> None:
    """Real sigmahq:340ee172 — 'selection and filter' (filter used positively)."""
    rule = _rule(
        "selection and filter",
        selection={"Image": "\\\\evil.exe"},
        filter={"CommandLine": "install something here"},
    )
    atoms = extract_atoms(rule)
    values = {v for _c, v in atoms}
    assert "evil.exe" in values
    assert "install something here" in values


def test_wholly_negated_rule_yields_no_atoms() -> None:
    """Real sigmahq:1fc0809e — 'not selection'."""
    rule = _rule("not selection", selection={"Image": "\\\\evil.exe"})
    assert extract_atoms(rule) == []


def test_negation_nested_in_parentheses_only_excludes_its_operand() -> None:
    """Real sigmahq:c52a914f — nested negation inside parentheses."""
    rule = _rule(
        "selection_execve and (keywords_truncate or (keywords_dd and not keywords_filter))",
        selection_execve={"Image": "\\\\evil.exe"},
        keywords_truncate={"CommandLine": "truncate the file now"},
        keywords_dd={"CommandLine": "dd if=/dev/zero of=/tmp/x"},
        keywords_filter={"CommandLine": "benign filter phrase"},
    )
    atoms = extract_atoms(rule)
    values = {v for _c, v in atoms}
    assert "evil.exe" in values
    assert "truncate the file now" in values
    assert "dd if=/dev/zero of=/tmp/x" in values
    assert "benign filter phrase" not in values


def test_condition_absent_excludes_nothing() -> None:
    """No condition key: nothing is negated."""
    rule = _rule(None, selection={"Image": "\\\\evil.exe"})
    atoms = extract_atoms(rule)
    values = {v for _c, v in atoms}
    assert "evil.exe" in values


def test_condition_as_a_list_is_still_parsed() -> None:
    """Condition as a list (Sigma spec allows it)."""
    rule = _rule(
        ["selection and not filter", "selection"],
        selection={"Image": "\\\\evil.exe"},
        filter={"Image": "\\\\teams.exe"},
    )
    atoms = extract_atoms(rule)
    values = {v for _c, v in atoms}
    assert "evil.exe" in values
    assert "teams.exe" not in values


def test_not_one_of_them_excludes_everything() -> None:
    """'not 1 of them' negates every selection in the block."""
    rule = _rule("not 1 of them", selection={"Image": "\\\\evil.exe"})
    assert extract_atoms(rule) == []


def test_non_string_condition_is_ignored_without_raising() -> None:
    """A non-string condition must not raise; nothing is negated."""
    rule = _rule(123, selection={"Image": "\\\\evil.exe"})
    atoms = extract_atoms(rule)
    values = {v for _c, v in atoms}
    assert "evil.exe" in values


def test_negated_name_that_is_not_a_selection_is_ignored() -> None:
    """Negating a name that is not a detection key has no effect."""
    rule = _rule(
        "selection and not nosuchkey",
        selection={"Image": "\\\\evil.exe"},
    )
    atoms = extract_atoms(rule)
    values = {v for _c, v in atoms}
    assert "evil.exe" in values


def test_expand_selector_star_matches_prefix_and_suffix() -> None:
    """_expand_selector handles *, 'them', exact match, and absent keys."""
    keys = frozenset({"filter_a", "filter_b", "selection"})
    assert _expand_selector("filter_*", keys) == {"filter_a", "filter_b"}
    assert _expand_selector("*_a", keys) == {"filter_a"}
    assert _expand_selector("them", keys) == set(keys)
    assert _expand_selector("selection", keys) == {"selection"}
    assert _expand_selector("absent", keys) == set()


def test_negated_selections_returns_lowercased_keys() -> None:
    """Negated selection names are returned lowercased."""
    detection = {
        "condition": "selection and not Filter_Main",
        "selection": {"Image": "\\\\evil.exe"},
        "Filter_Main": {"Image": "\\\\teams.exe"},
    }
    assert _negated_selections(detection) == {"filter_main"}
