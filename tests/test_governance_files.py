"""The governance files: issue forms, the pull request template and the roadmap.

GitHub drops a malformed issue form without a word: the "New issue" page then shows
no template, or the wrong one.  Nothing else in CI reads these files, so a typo in a
key, a duplicate id or a link to a page that moved would reach `main` unseen.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
GITHUB = ROOT / ".github"
TEMPLATES = GITHUB / "ISSUE_TEMPLATE"
PR_TEMPLATE = GITHUB / "PULL_REQUEST_TEMPLATE.md"
ROADMAP = ROOT / "ROADMAP.md"
SECURITY = ROOT / "SECURITY.md"

FORMS = ["bug_report.yml", "feature_request.yml"]
ELEMENT_TYPES = {"markdown", "input", "textarea", "dropdown", "checkboxes"}
#: The fields each form must make mandatory, by id.
REQUIRED = {
    "bug_report.yml": {"version", "image", "install", "host", "llm_provider", "where",
                       "what_happened", "expected", "reproduction", "blocker"},
    "feature_request.yml": {"problem", "proposal"},
}
BLOB_LINK = re.compile(r"https://github\.com/Stixaly/CTIParsor/blob/main/([^)\s#\"']+)(?:#([^)\s\"']*))?")
ADVISORY = re.compile(r"\((https://github\.com/[^)\s]+/security/advisories/new)\)")
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def _load(name: str) -> dict:
    data = yaml.safe_load((TEMPLATES / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{name} is not a YAML mapping"
    return data


def _slugs(md: Path) -> set[str]:
    """The anchors GitHub gives the headings of a Markdown file."""
    seen: Counter[str] = Counter()
    slugs: set[str] = set()
    in_fence = False
    for line in md.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        heading = None if in_fence else re.match(r"#{1,6}\s+(.*?)\s*$", line)
        if not heading:
            continue
        text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading.group(1)).replace("`", "").replace("*", "")
        slug = re.sub(r"[^\w\- ]", "", text.lower()).replace(" ", "-")
        slugs.add(slug if not seen[slug] else f"{slug}-{seen[slug]}")
        seen[slug] += 1
    return slugs


def _check_target(source: Path, path: Path, anchor: str) -> list[str]:
    if not path.exists():
        return [f"{source.name}: {path.relative_to(ROOT).as_posix()} does not exist"]
    if anchor and path.suffix == ".md" and anchor not in _slugs(path):
        return [f"{source.name}: {path.relative_to(ROOT).as_posix()} has no heading #{anchor}"]
    return []


@pytest.mark.parametrize("name", FORMS)
def test_an_issue_form_has_the_keys_github_requires(name):
    form = _load(name)
    assert isinstance(form.get("name"), str) and form["name"].strip()
    assert isinstance(form.get("description"), str) and form["description"].strip()
    body = form.get("body")
    assert isinstance(body, list) and body, "an issue form needs a non-empty body"
    ids = []
    for index, element in enumerate(body):
        where = f"{name} body[{index}]"
        assert isinstance(element, dict), where
        assert element.get("type") in ELEMENT_TYPES, f"{where}: type {element.get('type')!r}"
        attributes = element.get("attributes")
        assert isinstance(attributes, dict), f"{where}: no attributes"
        if element["type"] == "markdown":
            assert isinstance(attributes.get("value"), str) and attributes["value"].strip(), where
            continue
        assert isinstance(attributes.get("label"), str) and attributes["label"].strip(), f"{where}: no label"
        element_id = element.get("id")
        assert isinstance(element_id, str) and re.fullmatch(r"[A-Za-z0-9_-]+", element_id), f"{where}: id"
        ids.append(element_id)
        required = (element.get("validations") or {}).get("required", False)
        assert isinstance(required, bool), f"{where}: validations.required"
        if element["type"] == "dropdown":
            options = attributes.get("options")
            assert isinstance(options, list) and options, where
            assert all(isinstance(o, str) and o.strip() for o in options), f"{where}: an empty option"
            assert len(set(options)) == len(options), f"{where}: a duplicate option"
            assert "None" not in options, f"{where}: GitHub reserves the option 'None'"
        if element["type"] == "checkboxes":
            options = attributes.get("options")
            assert isinstance(options, list) and options, where
            for option in options:
                assert isinstance(option.get("label"), str) and option["label"].strip(), where
                assert isinstance(option.get("required", False), bool), where
    assert len(ids) == len(set(ids)), f"{name}: duplicate ids {[i for i, n in Counter(ids).items() if n > 1]}"


@pytest.mark.parametrize("name", FORMS)
def test_an_issue_form_requires_the_fields_it_cannot_do_without(name):
    by_id = {e["id"]: e for e in _load(name)["body"] if "id" in e}
    missing = {i for i in REQUIRED[name] if i not in by_id}
    assert not missing, f"{name} lost the fields {sorted(missing)}"
    optional = {i for i in REQUIRED[name] if not (by_id[i].get("validations") or {}).get("required")}
    assert not optional, f"{name}: {sorted(optional)} must be required"


def test_the_bug_form_warns_before_it_asks_and_makes_redaction_required():
    body = _load("bug_report.yml")["body"]
    first = body[0]
    assert first["type"] == "markdown"
    assert "SECURITY.md" in first["attributes"]["value"]
    assert ADVISORY.search(first["attributes"]["value"]), "the first block must point to the private channel"
    redaction = next(e for e in body if e.get("id") == "redaction")
    assert any(o.get("required") for o in redaction["attributes"]["options"])


def test_there_is_no_blank_issue_and_the_contact_link_is_the_one_security_md_gives():
    config = yaml.safe_load((TEMPLATES / "config.yml").read_text(encoding="utf-8"))
    assert config["blank_issues_enabled"] is False
    links = config["contact_links"]
    assert isinstance(links, list) and len(links) == 1
    assert all(isinstance(links[0].get(k), str) and links[0][k].strip() for k in ("name", "url", "about"))
    advisory = set(ADVISORY.findall(SECURITY.read_text(encoding="utf-8")))
    assert len(advisory) == 1, f"SECURITY.md should give one advisory URL, it gives {advisory}"
    assert links[0]["url"] == next(iter(advisory))
    bug_form = (TEMPLATES / "bug_report.yml").read_text(encoding="utf-8")
    assert set(ADVISORY.findall(bug_form)) == advisory


def test_the_templates_only_link_to_repository_files_that_exist():
    # Absolute URLs: a relative link in an issue form or a pull request description
    # is resolved against the issue's own address, and leads nowhere.
    problems: list[str] = []
    found = 0
    for source in [*(TEMPLATES / n for n in FORMS), PR_TEMPLATE]:
        for path, anchor in BLOB_LINK.findall(source.read_text(encoding="utf-8")):
            found += 1
            problems += _check_target(source, ROOT / path, anchor)
    assert found >= 8, f"only {found} links to the repository found: the pattern no longer matches the files"
    assert not problems, problems


def test_the_pull_request_template_asks_for_the_records_the_contributing_guide_asks_for():
    text = PR_TEMPLATE.read_text(encoding="utf-8")
    for needle in ("make ci", "make contract", "CHANGELOG", "docs/adr/", "CONTRIBUTING.md", "TESTING.md"):
        assert needle in text, f"the pull request template no longer mentions {needle}"


def test_the_roadmap_has_its_three_groups_and_a_way_to_propose():
    text = ROADMAP.read_text(encoding="utf-8")
    headings = re.findall(r"^## (.+)$", text, flags=re.M)
    assert headings[:3] == ["1.0", "After 1.0", "Not planned"], headings
    assert "issues/new/choose" in text


def test_every_relative_link_of_the_roadmap_resolves():
    problems: list[str] = []
    checked = 0
    for target in LINK.findall(ROADMAP.read_text(encoding="utf-8")):
        if re.match(r"[a-z][a-z0-9+.-]*:", target):   # https:, mailto:
            continue
        checked += 1
        path, _, anchor = target.partition("#")
        problems += _check_target(ROADMAP, ROADMAP.parent / path if path else ROADMAP, anchor)
    assert checked >= 10, f"only {checked} relative links found in the roadmap"
    assert not problems, problems
