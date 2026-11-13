"""scripts/check_doc_links.py: the relative links in the Markdown resolve.

Each test builds a small tree in tmp_path (no .git there, so the checker walks
it) and runs main() on it; the last test runs it on this repository, as
`make check-docs` and the fast-tests CI job do.
"""
from __future__ import annotations

from pathlib import Path

from scripts.check_doc_links import LOCAL_DATA_ALLOWED, ROOT, anchors_of, main, slugify


def _write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run(root: Path, capsys) -> tuple[int, str]:
    code = main([str(root)])
    return code, capsys.readouterr().out


def test_good_links_pass_including_heading_slug_and_html_anchor(tmp_path, capsys):
    _write(tmp_path, "docs/a.md",
           "[b](b.md) [s](b.md#section-one) [t](b.md#check-the-make-target-v2) [h](#own) "
           "[k](b.md#custom) [img](../img/x.png)\n\n## Own\n")
    _write(tmp_path, "docs/b.md",
           "# Section One\n\n## Check the `make` target (v2)\n\n<a id=\"custom\"></a>\n")
    _write(tmp_path, "img/x.png", "not really a picture")
    code, out = _run(tmp_path, capsys)
    assert code == 0, out


def test_missing_file_and_missing_anchor_are_reported(tmp_path, capsys):
    _write(tmp_path, "a.md", "[gone](missing.md) [nope](b.md#no-such-heading)\n")
    _write(tmp_path, "b.md", "# Present\n")
    code, out = _run(tmp_path, capsys)
    assert code == 1
    assert "a.md:1: [missing.md] no such tracked file" in out
    assert "a.md:1: [b.md#no-such-heading]" in out
    assert "2 broken link(s)" in out


def test_repeated_heading_gets_numbered_anchor(tmp_path, capsys):
    _write(tmp_path, "a.md", "[first](b.md#setup) [second](b.md#setup-1)\n")
    _write(tmp_path, "b.md", "## Setup\n\n## Setup\n")
    assert _run(tmp_path, capsys)[0] == 0
    _write(tmp_path, "a.md", "[third](b.md#setup-2)\n")
    code, out = _run(tmp_path, capsys)
    assert code == 1
    assert "[b.md#setup-2]" in out


def test_links_in_code_are_ignored(tmp_path, capsys):
    _write(tmp_path, "a.md",
           "Inline `[x](missing.md)` is code.\n\n"
           "```markdown\n[y](missing.md)\n```\n\n"
           "~~~\n[z](missing.md)\n~~~\n")
    assert _run(tmp_path, capsys)[0] == 0


def test_local_data_link_is_allowed_only_from_the_listed_file(tmp_path, capsys):
    assert "docs/gazetteer-ordinary-words.md" in LOCAL_DATA_ALLOWED
    link = "[row](../data/annoctr-repo/AnnoCTR/all/text/x.txt)\n"
    _write(tmp_path, "docs/gazetteer-ordinary-words.md", link)
    assert _run(tmp_path, capsys)[0] == 0
    _write(tmp_path, "docs/other.md", link)
    code, out = _run(tmp_path, capsys)
    assert code == 1
    assert "docs/other.md:1:" in out and "local data, not in the repository" in out
    assert "gazetteer-ordinary-words.md:1:" not in out


def test_link_leaving_the_repository_is_reported(tmp_path, capsys):
    _write(tmp_path, "docs/a.md", "[up](../../outside.md)\n")
    code, out = _run(tmp_path, capsys)
    assert code == 1
    assert "points outside the repository" in out


def test_absolute_path_link_resolves_from_the_root(tmp_path, capsys):
    _write(tmp_path, "docs/a.md", "[root](/README.md) [bad](/threat-actors/revil)\n")
    _write(tmp_path, "README.md", "# Root\n")
    code, out = _run(tmp_path, capsys)
    assert code == 1
    assert "[/threat-actors/revil]" in out and "[/README.md]" not in out


def test_slug_and_anchor_rules():
    assert slugify("Check the `make` target (v2)") == "check-the-make-target-v2"
    assert slugify("A [link](x.md) and under_score") == "a-link-and-under_score"
    assert anchors_of("```\n# not a heading\n```\n# Real\n<a name='tag'></a>\n") == {"real", "tag"}


def test_this_repository_has_no_broken_relative_link(capsys):
    code = main([str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
