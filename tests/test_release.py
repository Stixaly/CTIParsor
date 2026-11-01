"""The release process: one version, the changelog, the notes (scripts/release.py).

The first block reads the repository's own files, so that a version bumped in
one place only, or a changelog the script can no longer read, fails here and
not in the release workflow.  The second reads ci.yml: the image a release
promotes is the one main's CI built once and tested, pushed unchanged
(ADR-0047 as amended on 2026-11-01).  The rest builds small trees in tmp_path.
"""
from __future__ import annotations

import ast
import datetime
import io
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.release import (
    DEFAULT_MAX_CHARS,
    ReleaseError,
    changelog_sections,
    declared_versions,
    main,
    next_version,
    read_version,
    release_notes,
)

ROOT = Path(__file__).resolve().parent.parent
FILES = ("pipeline/__init__.py", "frontend/package.json", "frontend/package-lock.json", "CHANGELOG.md")
IMAGE = "ghcr.io/stixaly/ctiparsor@sha256:" + "ab12" * 16

CHANGELOG = """\
# Changelog

Intro that is not part of any section.

## [Unreleased]

### Added

#### Entry one, 2026-10-12

Text one.

#### Entry two, 2026-10-13

Text two.

## [0.2.0] - 2026-10-01

### Added

#### Fenced, 2026-09-30

Before the block.

```text
## Not a heading
#### Not an entry
---
```

After the block.

### Fixed

- A fix.

## [0.1.0] - 2026-09-01

### Added

- Old thing.

---

Earlier history predates this changelog; see `git log` and `docs/adr/`.
"""


def put(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def make_tree(root: Path, version: str = "0.2.0", *, package: str | None = None, lock: str | None = None,
              lock_root: str | None = None, changelog: str = CHANGELOG) -> Path:
    """A tree with the four files the script reads; the optional versions default to ``version``."""
    put(root / "pipeline" / "__init__.py", f'"""A pipeline."""\n\n__version__ = "{version}"\n')
    package_json = {"name": "cti-stix-ui", "version": package or version, "private": True,
                    "dependencies": {"zod": "^4.0.0"}}
    put(root / "frontend" / "package.json", json.dumps(package_json, indent=2) + "\n")
    lock_json = {"name": "cti-stix-ui", "version": lock or version, "lockfileVersion": 3,
                 "packages": {"": {"name": "cti-stix-ui", "version": lock_root or version,
                                   "dependencies": {"zod": "^4.0.0"}},
                              "node_modules/zod": {"version": "4.0.0", "license": "MIT"}}}
    put(root / "frontend" / "package-lock.json", json.dumps(lock_json, indent=2) + "\n")
    put(root / "CHANGELOG.md", changelog)
    return root


def snapshot(root: Path) -> dict[str, bytes]:
    return {rel: (root / rel).read_bytes() for rel in FILES}


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    return make_tree(tmp_path)


@pytest.fixture
def cli(capsys: pytest.CaptureFixture[str]):
    def run(root: Path, *argv: object) -> tuple[int, str, str]:
        code = main(["--root", str(root), *map(str, argv)])
        out, err = capsys.readouterr()
        return code, out, err
    return run


# --- The repository's own files ---------------------------------------------

def test_the_repository_states_one_version():
    found = declared_versions(ROOT)
    assert len(found) == 4  # __version__, package.json, and the two of package-lock.json
    assert len(set(found.values())) == 1, found


def test_the_changelog_opens_with_unreleased():
    assert changelog_sections(ROOT)[0].title == "## [Unreleased]"


def test_the_current_version_can_be_released_as_its_tag(capsys):
    version = read_version(ROOT)
    if version == "0.0.0":
        pytest.skip("before the first release there is no section for it")
    assert main(["check", f"v{version}"]) == 0
    assert capsys.readouterr().out == f"{version}\n"


@pytest.mark.parametrize("rel", ["frontend/package.json", "frontend/package-lock.json"])
def test_the_json_files_are_in_the_format_prepare_writes(rel):
    # prepare rewrites them with json.dumps: if npm's format differed, a release would reformat the lock file.
    text = (ROOT / rel).read_text(encoding="utf-8")
    assert json.dumps(json.loads(text), indent=2, ensure_ascii=False) + "\n" == text


def test_the_next_minor_version_can_be_prepared_checked_and_noted_from_the_real_files(tmp_path, cli):
    for rel in FILES:
        put(tmp_path / rel, (ROOT / rel).read_text(encoding="utf-8"))
    unreleased = changelog_sections(tmp_path)[0]
    if not unreleased.body:
        pytest.skip("[Unreleased] is empty: right after a release there is nothing to prepare")
    version = next_version(read_version(tmp_path), "minor")

    assert cli(tmp_path, "prepare", version, "--date", "2026-10-17")[0] == 0
    assert cli(tmp_path, "check", f"v{version}") == (0, f"{version}\n", "")
    code, notes, err = cli(tmp_path, "notes", version)
    assert (code, err) == (0, "")
    assert notes.endswith("\n") and not notes.endswith("\n\n")
    assert "Earlier history predates" not in notes  # the footer after "---" is not a note
    assert len(notes) <= DEFAULT_MAX_CHARS

    body = unreleased.body
    if len(body) < DEFAULT_MAX_CHARS - 1000:
        assert notes == body + "\n"
    else:
        assert notes.startswith(f"The notes for {version} are longer than a GitHub release allows.")
        titles = [line[5:] for line in body.split("\n") if line.startswith("#### ")]
        assert titles and all(f"- {title}\n" in notes for title in titles)
        assert "#### " not in notes
        ordinary = "The ordinary-word policy recognises naming constructions, 2026-10-12"
        if f"#### {ordinary}\n" in body:  # the entry the file holds before the first release
            assert f"- {ordinary}\n" in notes


def test_the_script_imports_nothing_outside_the_standard_library():
    # The release workflow runs it with the runner's own python3, before anything is installed.
    tree = ast.parse((ROOT / "scripts" / "release.py").read_text(encoding="utf-8"))
    modules = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
               for alias in node.names}
    modules |= {node.module.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module}
    assert modules <= set(sys.stdlib_module_names) | {"__future__"}, modules


def test_the_script_runs_as_a_program(tree):
    script = ROOT / "scripts" / "release.py"
    ok = subprocess.run([sys.executable, str(script), "--root", str(tree), "version", "--next", "minor"],
                        capture_output=True, text=True, check=False)
    assert (ok.returncode, ok.stdout, ok.stderr) == (0, "0.3.0\n", "")
    refused = subprocess.run([sys.executable, str(script), "--root", str(tree), "check", "v0.3.0"],
                             capture_output=True, text=True, check=False)
    assert refused.returncode == 1 and refused.stdout == ""
    assert "pipeline/__init__.py __version__ is 0.2.0, the tag says 0.3.0" in refused.stderr


# --- ci.yml: one build, tested, then pushed unchanged ------------------------

CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
ARCHIVE = "${{ runner.temp }}/ctiparsor.oci.tar"
MAIN_PUSH = "github.event_name == 'push' && github.ref == 'refs/heads/main'"
#: A build in a run: step: docker build, docker buildx build/bake, docker image build, podman/buildah.
_BUILD_COMMAND = re.compile(r"\b(?:docker|podman|buildah)\s+(?:buildx\s+|image\s+)?(?:build|bake|bud)\b")
CONTAINERD = "*'\"io.containerd.snapshotter.v1\"'*) ;;"


@pytest.fixture(scope="module")
def ci_jobs() -> dict[str, Any]:
    return yaml.safe_load(CI_YML.read_text(encoding="utf-8"))["jobs"]


def _action(step: dict[str, Any]) -> str:
    return str(step.get("uses", "")).partition("@")[0]


def _only(job: dict[str, Any], action: str) -> dict[str, Any]:
    found = [step for step in job["steps"] if _action(step) == action]
    assert len(found) == 1, f"{len(found)} steps use {action}"
    return found[0]


def _by_id(job: dict[str, Any], step_id: str) -> dict[str, Any]:
    found = [step for step in job["steps"] if step.get("id") == step_id]
    assert len(found) == 1, f"{len(found)} steps have the id {step_id}"
    return found[0]


def _code(run: object) -> list[str]:
    """The lines a run: script executes: stripped, without blank lines and comments."""
    lines = (line.strip() for line in str(run or "").splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def _script(job: dict[str, Any], step_id: str) -> list[str]:
    code = _code(_by_id(job, step_id)["run"])
    assert code[0] == "set -euo pipefail", f"{step_id} does not stop at its first failure"
    return code


def _line(code: list[str], text: str) -> int:
    found = [i for i, line in enumerate(code) if text in line]
    assert found, f"no line of the script holds {text!r}"
    return found[0]


def _fails_unless(code: list[str], condition: str) -> int:
    """``condition`` is an `if` line whose branch reports an error and exits 1."""
    i = code.index(condition)
    assert code[i + 1].startswith('echo "::error::') and code[i + 2] == "exit 1", code[i:i + 3]
    return i


def _requires_containerd(code: list[str]) -> int:
    drivers = code.index("drivers=$(docker info --format '{{json .DriverStatus}}')")
    assert code[drivers + 1:drivers + 4] == ['case "$drivers" in', CONTAINERD, "*)"]
    assert code[drivers + 4].startswith("echo \"::error::Docker's image store is ")
    assert code[drivers + 5:drivers + 7] == ["exit 1 ;;", "esac"]
    return drivers


def test_publish_image_builds_nothing(ci_jobs):
    steps = ci_jobs["publish-image"]["steps"]
    for step in steps:
        assert _action(step) not in {"docker/build-push-action", "docker/bake-action"}, step
        assert not _BUILD_COMMAND.search(str(step.get("run", ""))), step["run"]
    # Nothing to build from: the job never checks the repository out.
    assert not [step for step in steps if _action(step) == "actions/checkout"]


def test_the_image_jobs_run_no_container_of_their_own(ci_jobs):
    # A third-party image (skopeo's is rebuilt daily, its old digests deleted) or the Docker socket in one.
    assert "SKOPEO_IMAGE" not in CI_YML.read_text(encoding="utf-8")
    for name in ("container-image", "publish-image"):
        for step in ci_jobs[name]["steps"]:
            for line in _code(step.get("run")):
                assert "docker run" not in line and "docker.sock" not in line and "skopeo" not in line, line


def test_the_image_jobs_run_on_ubuntu_26_04_and_require_the_containerd_store(ci_jobs):
    assert ci_jobs["container-image"]["runs-on"] == "ubuntu-26.04"
    assert ci_jobs["publish-image"]["runs-on"] == "ubuntu-26.04"
    for job, step_id in (("container-image", "archive"), ("publish-image", "push")):
        code = _script(ci_jobs[job], step_id)
        assert _requires_containerd(code) < code.index('docker load --input "$archive"')


def test_container_image_builds_an_oci_archive_with_stated_provenance(ci_jobs):
    build = _by_id(ci_jobs["container-image"], "build")
    assert _action(build) == "docker/build-push-action"
    assert build["with"]["outputs"] == f"type=oci,dest={ARCHIVE}"
    assert not build["with"].get("push") and not build["with"].get("load")
    # BuildKit's SLSA v1 provenance, as GHCR holds it, written out rather than an action default.
    assert build["with"]["provenance"] == (
        "mode=max,version=v1,builder-id=${{ github.server_url }}/${{ github.repository }}"
        "/actions/runs/${{ github.run_id }}/attempts/${{ github.run_attempt }}")
    # The labels publish-image used to give, from the same inputs.
    assert build["with"]["labels"] == "${{ steps.meta.outputs.labels }}"
    meta = _by_id(ci_jobs["container-image"], "meta")
    assert _action(meta) == "docker/metadata-action"
    assert meta["with"]["tags"].split() == ["type=sha,format=long,prefix=sha-",
                                            "type=raw,value=latest,enable={{is_default_branch}}"]


def test_container_image_scans_and_smokes_the_image_loaded_from_its_archive(ci_jobs):
    steps = ci_jobs["container-image"]["steps"]
    ids = [step.get("id") for step in steps]
    load = ids.index("archive")
    assert load == ids.index("build") + 1
    assert steps[load]["env"]["BUILT"] == "${{ steps.build.outputs.digest }}"
    code = _script(ci_jobs["container-image"], "archive")
    assert code[1] == "archive=$RUNNER_TEMP/ctiparsor.oci.tar"
    order = [_fails_unless(code, 'if [ "$index" != "$BUILT" ]; then'),
             code.index('docker load --input "$archive"'),
             code.index("id=$(docker image inspect ctiparsor:ci --format '{{.Id}}')"),
             _fails_unless(code, 'if [ "$id" != "$index" ]; then'),   # the loaded image is the archive's
             code.index('echo "digest=$index" >> "$GITHUB_OUTPUT"')]
    assert order == sorted(order) and order[-1] == len(code) - 1
    assert ci_jobs["container-image"]["outputs"]["digest"] == "${{ steps.archive.outputs.digest }}"
    scan = steps.index(_only(ci_jobs["container-image"], "anchore/scan-action"))
    assert scan > load and steps[scan]["with"]["image"] == "ctiparsor:ci"
    runs_the_image = [i for i, step in enumerate(steps) if step.get("env", {}).get("CTI_IMAGE")]
    assert len(runs_the_image) == 2 and min(runs_the_image) > load  # the smoke test, the air-gap check
    assert all(steps[i]["env"]["CTI_IMAGE"] == "ctiparsor:ci" for i in runs_the_image)


def test_publish_image_pushes_the_archive_container_image_tested(ci_jobs):
    image, publish = ci_jobs["container-image"], ci_jobs["publish-image"]
    upload = _only(image, "actions/upload-artifact")
    assert image["steps"][-1] is upload  # after every step that tests the image
    assert upload["if"] == MAIN_PUSH and upload["with"]["path"] == ARCHIVE
    assert "container-image" in publish["needs"] and publish["if"] == MAIN_PUSH
    download = _only(publish, "actions/download-artifact")
    assert download["with"] == {"name": upload["with"]["name"], "path": "${{ runner.temp }}"}
    push = _by_id(publish, "push")
    assert publish["steps"].index(download) < publish["steps"].index(push)
    assert push["env"]["TESTED"] == "${{ needs.container-image.outputs.digest }}"
    code = _script(publish, "push")
    assert code[1] == "archive=$RUNNER_TEMP/ctiparsor.oci.tar"
    order = [code.index('docker load --input "$archive"'),
             code.index("id=$(docker image inspect ctiparsor:ci --format '{{.Id}}')"),
             _fails_unless(code, 'if [ "$id" != "$TESTED" ]; then'),   # the archive is the image tested
             code.index('docker tag ctiparsor:ci "$IMAGE:sha-$GITHUB_SHA"'),
             code.index('docker push "$IMAGE:sha-$GITHUB_SHA"')]
    assert order == sorted(order)


def test_publish_image_fails_unless_the_registry_holds_the_tested_digest(ci_jobs):
    publish = ci_jobs["publish-image"]
    code = _script(publish, "push")
    order = [code.index('docker push "$IMAGE:sha-$GITHUB_SHA"'),
             _line(code, 'got=$(docker buildx imagetools inspect "$IMAGE:sha-$GITHUB_SHA"'),
             _fails_unless(code, 'if [ "$got" != "$TESTED" ]; then'),  # what the registry holds, read back
             code.index('echo "digest=$TESTED" >> "$GITHUB_OUTPUT"')]
    assert order == sorted(order) and order[-1] == len(code) - 1
    # The SBOM, both attestations and latest bind to that digest.
    after = publish["steps"][publish["steps"].index(_by_id(publish, "push")) + 1:]
    digests = re.findall(r"\$\{\{\s*([\w.-]+\.digest)\s*\}\}", json.dumps(after))
    assert len(digests) == 4 and set(digests) == {"steps.push.outputs.digest"}


def test_latest_moves_only_to_the_attested_image_of_mains_head(ci_jobs):
    publish = ci_jobs["publish-image"]
    latest = _by_id(publish, "latest")
    assert publish["steps"][-1] is latest  # after the SBOM and both attestations
    assert latest["env"]["TESTED"] == "${{ steps.push.outputs.digest }}"
    assert latest["env"]["GH_TOKEN"] == "${{ github.token }}"
    code = _script(publish, "latest")
    head = code.index('head=$(gh api "repos/$GITHUB_REPOSITORY/commits/main" --jq .sha)')
    guard = code.index('if [ "$head" != "$GITHUB_SHA" ]; then')
    assert code[guard + 1].startswith('echo "::notice::') and code[guard + 2] == "exit 0"
    order = [head, guard,
             code.index('docker tag ctiparsor:ci "$IMAGE:latest"'),
             code.index('docker push "$IMAGE:latest"'),
             _line(code, 'got=$(docker buildx imagetools inspect "$IMAGE:latest"'),
             _fails_unless(code, 'if [ "$got" != "$TESTED" ]; then')]
    assert order == sorted(order)
    # No other step of the workflow names latest.
    for job in ci_jobs.values():
        for step in job["steps"]:
            if step is not latest:
                assert not [line for line in _code(step.get("run")) if ":latest" in line], step


def test_every_action_in_ci_yml_is_pinned_to_a_commit_with_its_version():
    lines = [line.strip() for line in CI_YML.read_text(encoding="utf-8").splitlines()
             if line.strip().startswith(("uses:", "- uses:"))]
    assert lines
    for line in lines:
        assert re.fullmatch(r"(?:- )?uses: [\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+(?:\.\d+){1,2}", line), line


# --- version ----------------------------------------------------------------

def test_version_prints_the_current_version(tree, cli):
    assert cli(tree, "version") == (0, "0.2.0\n", "")


@pytest.mark.parametrize(("level", "expected"), [("major", "2.0.0"), ("minor", "1.3.0"), ("patch", "1.2.4")])
def test_version_next_resets_the_lower_parts(tmp_path, cli, level, expected):
    make_tree(tmp_path, "1.2.3")
    assert cli(tmp_path, "version", "--next", level) == (0, f"{expected}\n", "")


def test_the_first_minor_after_zero_is_0_1_0(tmp_path, cli):
    make_tree(tmp_path, "0.0.0")
    assert cli(tmp_path, "version", "--next", "minor") == (0, "0.1.0\n", "")


def test_version_refuses_a_tree_without_a_version(tmp_path, cli):
    make_tree(tmp_path)
    put(tmp_path / "pipeline" / "__init__.py", "x = 1\n")
    code, out, err = cli(tmp_path, "version")
    assert (code, out) == (1, "")
    assert "pipeline/__init__.py" in err


# --- check ------------------------------------------------------------------

def test_check_accepts_a_consistent_tree_and_prints_the_version(tree, cli):
    assert cli(tree, "check", "v0.2.0") == (0, "0.2.0\n", "")


@pytest.mark.parametrize("tag", ["0.2.0", "v0.2", "v01.2.0", "v0.2.0-rc.1", "V0.2.0", "v0.2.0 ", "v", ""])
def test_check_refuses_a_malformed_tag(tree, cli, tag):
    code, out, err = cli(tree, "check", tag)
    assert (code, out) == (1, "")
    assert "not a release tag" in err


@pytest.mark.parametrize(("odd", "label"), [
    (0, "pipeline/__init__.py __version__ is 0.1.9"),
    (1, "frontend/package.json version is 0.1.9"),
    (2, "frontend/package-lock.json version is 0.1.9"),
    (3, 'frontend/package-lock.json packages."".version is 0.1.9'),
])
def test_check_names_each_place_that_disagrees(tmp_path, cli, odd, label):
    versions = ["0.2.0"] * 4  # __version__, package.json, package-lock.json twice
    versions[odd] = "0.1.9"
    make_tree(tmp_path, versions[0], package=versions[1], lock=versions[2], lock_root=versions[3])
    code, out, err = cli(tmp_path, "check", "v0.2.0")
    assert (code, out) == (1, "")
    assert err == f"{label}, the tag says 0.2.0\n"


def test_check_reports_every_problem_not_only_the_first(tmp_path, cli):
    make_tree(tmp_path, "0.1.0", package="0.1.1", lock="0.1.2", lock_root="0.1.3")
    code, out, err = cli(tmp_path, "check", "v0.3.0")  # and the changelog has no [0.3.0]
    assert (code, out) == (1, "")
    problems = err.splitlines()
    assert len(problems) == 5
    for place in ("pipeline/__init__.py", "frontend/package.json", "package-lock.json version",
                  'package-lock.json packages."".version', "CHANGELOG.md"):
        assert sum(place in line for line in problems) == 1, (place, problems)


def test_check_refuses_a_version_without_a_changelog_section(tree, cli):
    make_tree(tree, "0.3.0")
    code, _, err = cli(tree, "check", "v0.3.0")
    assert code == 1
    assert err == "CHANGELOG.md has no '## [0.3.0] - YYYY-MM-DD' section\n"


def test_check_refuses_an_empty_section(tmp_path, cli):
    make_tree(tmp_path, "0.2.0",
              changelog="## [Unreleased]\n\n## [0.2.0] - 2026-10-01\n\n\n## [0.1.0] - 2026-09-01\n\nOld.\n")
    code, _, err = cli(tmp_path, "check", "v0.2.0")
    assert code == 1
    assert "the section '## [0.2.0] - 2026-10-01' is empty" in err


@pytest.mark.parametrize("heading", ["## [0.2.0] - 2026-13-45", "## [0.2.0] - yesterday", "## [0.2.0] - 20261001",
                                     "## [0.2.0]"])
def test_check_refuses_a_section_without_a_valid_date(tmp_path, cli, heading):
    make_tree(tmp_path, "0.2.0", changelog=f"## [Unreleased]\n\n{heading}\n\nSomething.\n")
    code, _, err = cli(tmp_path, "check", "v0.2.0")
    assert code == 1
    assert f"{heading!r} has no valid date" in err


def test_check_names_a_file_it_cannot_read(tree, cli):
    (tree / "frontend" / "package.json").unlink()
    code, _, err = cli(tree, "check", "v0.2.0")
    assert code == 1
    assert err.startswith("frontend/package.json: cannot read it")


# --- notes ------------------------------------------------------------------

def test_notes_stop_at_the_next_heading(tree):
    notes = release_notes(tree, "0.2.0")
    assert notes.startswith("### Added\n\n#### Fenced, 2026-09-30\n")
    assert notes.endswith("### Fixed\n\n- A fix.\n")
    assert "Old thing" not in notes and "## [0.1.0]" not in notes


def test_notes_stop_at_the_closing_rule_not_at_the_footer(tree):
    assert release_notes(tree, "0.1.0") == "### Added\n\n- Old thing.\n"


def test_a_heading_or_a_rule_inside_a_code_block_does_not_cut_the_notes(tree):
    notes = release_notes(tree, "0.2.0")
    assert "## Not a heading\n#### Not an entry\n---\n```\n\nAfter the block." in notes


RULES_CHANGELOG = """\
## [Unreleased]

Entry A.

---

Entry B.

## [0.2.0] - 2026-10-01

Old A.

---

Old B.

---

Footer text.
"""


def test_only_the_last_rule_after_the_last_heading_is_the_footer(tmp_path):
    make_tree(tmp_path, changelog=RULES_CHANGELOG)
    bodies = {s.title: s.body for s in changelog_sections(tmp_path)}
    assert bodies["## [Unreleased]"] == "Entry A.\n\n---\n\nEntry B."  # a rule in a section that is not the last
    assert bodies["## [0.2.0] - 2026-10-01"] == "Old A.\n\n---\n\nOld B."  # one before the footer, and no footer text


def test_the_last_section_runs_to_the_end_without_a_footer(tmp_path):
    make_tree(tmp_path, changelog="## [Unreleased]\n\nA.\n\n---\n\nB.\n\n## [0.2.0] - 2026-10-01\n\nOld.\n\nMore.\n")
    assert release_notes(tmp_path, "0.2.0") == "Old.\n\nMore.\n"
    assert changelog_sections(tmp_path)[0].body == "A.\n\n---\n\nB."


def test_what_follows_a_rule_inside_a_section_is_still_released(tmp_path, cli):
    make_tree(tmp_path, changelog=RULES_CHANGELOG)
    assert cli(tmp_path, "prepare", "0.3.0", "--date", "2026-10-17")[0] == 0
    assert cli(tmp_path, "check", "v0.3.0") == (0, "0.3.0\n", "")
    assert cli(tmp_path, "notes", "0.3.0") == (0, "Entry A.\n\n---\n\nEntry B.\n", "")
    assert "Footer text" not in cli(tmp_path, "notes", "0.2.0")[1]


def test_a_tilde_fence_hides_headings_like_a_backtick_fence(tmp_path):
    make_tree(tmp_path, changelog=(
        "## [Unreleased]\n\n## [0.2.0] - 2026-10-01\n\n"
        "~~~text\n## Not a heading\n```\n## Still not a heading\n~~~\n\n"  # a backtick fence is text in ~~~
        "```text\n~~~\n## Nor this\n```\n\n"  # and the other way round
        "After.\n\n## [0.1.0] - 2026-09-01\n\nOld.\n"))
    sections = changelog_sections(tmp_path)
    assert [s.title for s in sections] == ["## [Unreleased]", "## [0.2.0] - 2026-10-01", "## [0.1.0] - 2026-09-01"]
    assert "## Not a heading" in sections[1].body and "## Still not a heading" in sections[1].body
    assert "## Nor this" in sections[1].body and sections[1].body.endswith("After.")


def test_notes_without_image_have_no_annex(tree, cli):
    code, out, err = cli(tree, "notes", "0.1.0")
    assert (code, err) == (0, "")
    assert out == "### Added\n\n- Old thing.\n"


def test_notes_with_image_append_the_annex_after_one_blank_line(tree, cli):
    code, out, err = cli(tree, "notes", "0.1.0", "--image", IMAGE)
    assert (code, err) == (0, "")
    assert out.startswith("### Added\n\n- Old thing.\n\n## Container image\n\n")
    assert out.endswith("```\n") and not out.endswith("\n\n")
    assert ("`ghcr.io/stixaly/ctiparsor:0.1.0` is the image main's CI built and tested from this commit, "
            "given the version as a second name; nothing was rebuilt.") in out
    # The commands pin the workflow that signed, so another workflow of the repository does not verify.
    assert (f"```\ndocker pull {IMAGE}\n"
            f"gh attestation verify oci://{IMAGE} -R Stixaly/CTIParsor "
            "--signer-workflow Stixaly/CTIParsor/.github/workflows/ci.yml --source-ref refs/heads/main\n```") in out
    assert ("`SHA256SUMS` lists the source archive and the image's SBOM. "
            "`ctiparsor-0.1.0.intoto.jsonl` is their SLSA build provenance, signed by the workflow run that "
            "published it. `ctiparsor-0.1.0-image.cdx.json` is the image's SBOM, as attested when main's CI "
            "built it.") in out
    assert ("```\nsha256sum -c SHA256SUMS\n"
            "gh attestation verify ctiparsor-0.1.0.tar.gz -R Stixaly/CTIParsor "
            "--signer-workflow Stixaly/CTIParsor/.github/workflows/release.yml --source-ref refs/tags/v0.1.0\n"
            "```") in out
    assert "{" not in out


def test_the_annex_takes_the_repository_from_the_option(tree):
    notes = release_notes(tree, "0.1.0", image=IMAGE, repo="someone/else")
    assert "-R someone/else --signer-workflow someone/else/.github/workflows/ci.yml" in notes
    assert "-R someone/else --signer-workflow someone/else/.github/workflows/release.yml" in notes
    assert "Stixaly" not in notes


@pytest.mark.parametrize("image", ["ghcr.io/stixaly/ctiparsor:latest", "ghcr.io/stixaly/ctiparsor@sha256:",
                                   "sha256:ab"])
def test_notes_refuse_an_image_without_a_digest(tree, cli, image):
    code, out, err = cli(tree, "notes", "0.1.0", "--image", image)
    assert (code, out) == (1, "")
    assert "digest" in err


def test_notes_refuse_a_version_without_a_section(tree, cli):
    code, out, err = cli(tree, "notes", "0.9.0")
    assert (code, out) == (1, "")
    assert "no '## [0.9.0] - YYYY-MM-DD' section" in err


def test_notes_refuse_a_malformed_version(tree, cli):
    assert cli(tree, "notes", "v0.2.0")[0] == 1


SUMMARY_CHANGELOG = """\
## [Unreleased]

## [0.3.0] - 2026-10-17

The opening summary.

#### Before any group, 2026-10-01

Text.

### Added

#### First, 2026-10-02

{filler}

```text
#### Not an entry
### Not a group
```

#### Second, 2026-10-03

### Fixed

- Plain bullet, no entry.

### Security

##### Too deep to be an entry

#### Third, 2026-10-04

### Added

#### Fourth, 2026-10-05

---

Earlier history.
"""


def test_a_body_past_the_limit_becomes_the_list_of_its_entries(tmp_path, cli):
    make_tree(tmp_path, "0.3.0", changelog=SUMMARY_CHANGELOG.format(filler="Words. " * 100))
    code, out, err = cli(tmp_path, "notes", "0.3.0", "--max-chars", 600)
    assert (code, err) == (0, "")
    # The opening paragraph stays; "### Added" is listed once with its later entry; "### Fixed",
    # which has plain bullets and no entry, is left out.
    assert out == (
        "The opening summary.\n"
        "\n"
        "The notes for 0.3.0 are longer than a GitHub release allows. Every change is described in "
        "[CHANGELOG.md](https://github.com/Stixaly/CTIParsor/blob/v0.3.0/CHANGELOG.md); its entries:\n"
        "\n"
        "- Before any group, 2026-10-01\n"
        "\n"
        "### Added\n"
        "\n"
        "- First, 2026-10-02\n"
        "- Second, 2026-10-03\n"
        "- Fourth, 2026-10-05\n"
        "\n"
        "### Security\n"
        "\n"
        "- Third, 2026-10-04\n")


def test_the_body_is_kept_when_it_fits_the_limit(tmp_path):
    make_tree(tmp_path, "0.3.0", changelog=SUMMARY_CHANGELOG.format(filler="Words. " * 100))
    notes = release_notes(tmp_path, "0.3.0", max_chars=10_000)
    assert notes.startswith("The opening summary.\n\n#### Before any group, 2026-10-01\n\nText.")


def test_the_annex_stays_when_the_body_is_summarised(tmp_path):
    make_tree(tmp_path, "0.3.0", changelog=SUMMARY_CHANGELOG.format(filler="Words. " * 100))
    notes = release_notes(tmp_path, "0.3.0", image=IMAGE, repo="x/y", max_chars=1500)
    assert notes.startswith("The opening summary.\n\nThe notes for 0.3.0 are longer than a GitHub release allows.")
    assert "blob/v0.3.0/CHANGELOG.md" in notes and "github.com/x/y/" in notes
    assert "- Third, 2026-10-04\n\n## Container image\n\n" in notes
    assert f"docker pull {IMAGE}" in notes
    assert len(notes) <= 1500


def test_notes_refuse_what_is_too_long_even_as_a_list(tmp_path, cli):
    make_tree(tmp_path, "0.3.0", changelog=SUMMARY_CHANGELOG.format(filler="Words. " * 100))
    code, out, err = cli(tmp_path, "notes", "0.3.0", "--max-chars", 100)
    assert (code, out) == (1, "")
    assert "even as a list of entries" in err


def test_the_output_is_utf8_whatever_the_console_encoding(tmp_path, monkeypatch):
    make_tree(tmp_path, changelog="## [Unreleased]\n\n## [0.2.0] - 2026-10-01\n\nCafé ☕ → done.\n")
    out, err = io.BytesIO(), io.BytesIO()  # a console in cp1252 cannot write "☕" or "→"
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(out, encoding="cp1252", write_through=True))
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(err, encoding="cp1252", write_through=True))
    assert main(["--root", str(tmp_path), "notes", "0.2.0"]) == 0
    assert main(["--root", str(tmp_path), "notes", "☕"]) == 1
    assert out.getvalue().decode("utf-8") == "Café ☕ → done.\n"
    assert "'☕' is not a version" in err.getvalue().decode("utf-8")


# --- unreleased -------------------------------------------------------------

def test_unreleased_prints_what_the_next_release_would_ship(tree, cli):
    assert cli(tree, "unreleased") == (
        0, "### Added\n\n#### Entry one, 2026-10-12\n\nText one.\n\n#### Entry two, 2026-10-13\n\nText two.\n", "")


def test_unreleased_prints_nothing_when_it_is_empty(tmp_path, cli):
    make_tree(tmp_path, changelog=EMPTY_UNRELEASED)
    assert cli(tmp_path, "unreleased") == (0, "", "")


def test_unreleased_refuses_a_changelog_without_the_section(tmp_path, cli):
    make_tree(tmp_path, changelog=NO_UNRELEASED)
    code, out, err = cli(tmp_path, "unreleased")
    assert (code, out) == (1, "")
    assert err == "CHANGELOG.md has no '## [Unreleased]' section\n"


# --- prepare ----------------------------------------------------------------

def test_prepare_moves_the_unreleased_entries_under_the_version(tree, cli):
    before = changelog_sections(tree)[0].body
    code, out, err = cli(tree, "prepare", "0.3.0", "--date", "2026-10-17")
    assert (code, err) == (0, "")
    assert out.splitlines() == ["CHANGELOG.md", "pipeline/__init__.py", "frontend/package.json",
                                "frontend/package-lock.json"]

    text = (tree / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [Unreleased]\n\n## [0.3.0] - 2026-10-17\n\n### Added\n\n#### Entry one, 2026-10-12" in text
    sections = {s.title: s.body for s in changelog_sections(tree)}
    assert list(sections) == ["## [Unreleased]", "## [0.3.0] - 2026-10-17", "## [0.2.0] - 2026-10-01",
                              "## [0.1.0] - 2026-09-01"]
    assert sections["## [Unreleased]"] == ""
    assert sections["## [0.3.0] - 2026-10-17"] == before
    assert text.endswith("Earlier history predates this changelog; see `git log` and `docs/adr/`.\n")


def test_prepare_sets_every_version_and_changes_nothing_else(tree, cli):
    old = snapshot(tree)
    assert cli(tree, "prepare", "0.3.0", "--date", "2026-10-17")[0] == 0
    new = snapshot(tree)

    assert new["pipeline/__init__.py"] == old["pipeline/__init__.py"].replace(b'"0.2.0"', b'"0.3.0"')
    assert read_version(tree) == "0.3.0"
    assert set(declared_versions(tree).values()) == {"0.3.0"}
    for rel in ("frontend/package.json", "frontend/package-lock.json"):
        expected = json.loads(old[rel])
        expected["version"] = "0.3.0"
        if "packages" in expected:
            expected["packages"][""]["version"] = "0.3.0"
        assert new[rel].decode("utf-8") == json.dumps(expected, indent=2, ensure_ascii=False) + "\n"
        assert [line for line in new[rel].decode().splitlines() if "0.2.0" in line] == []


def test_prepare_dates_the_section_today_by_default(tree, cli):
    before = datetime.date.today()
    assert cli(tree, "prepare", "0.3.0")[0] == 0
    after = datetime.date.today()  # a midnight may fall between the two
    heading = changelog_sections(tree)[1].title
    assert re.fullmatch(r"## \[0\.3\.0\] - \d{4}-\d{2}-\d{2}", heading)
    assert before <= datetime.date.fromisoformat(heading[-10:]) <= after


def test_prepare_refuses_a_malformed_date(tree, cli):
    with pytest.raises(SystemExit) as exc:
        cli(tree, "prepare", "0.3.0", "--date", "17/10/2026")
    assert exc.value.code == 2


def test_a_prepared_tree_passes_check(tree, cli):
    assert cli(tree, "prepare", "0.3.0", "--date", "2026-10-17")[0] == 0
    assert cli(tree, "check", "v0.3.0") == (0, "0.3.0\n", "")


NO_UNRELEASED = "# Changelog\n\n## [0.2.0] - 2026-10-01\n\nSomething.\n"
EMPTY_UNRELEASED = "# Changelog\n\n## [Unreleased]\n\n\n## [0.2.0] - 2026-10-01\n\nSomething.\n"
PRESENT = "## [Unreleased]\n\n- New.\n\n## [0.3.0] - 2026-10-01\n\nSomething.\n"


@pytest.mark.parametrize(("version", "changelog", "reason"), [
    ("0.2.0", CHANGELOG, "is not above the current version 0.2.0"),
    ("0.1.9", CHANGELOG, "is not above the current version 0.2.0"),
    ("0.3", CHANGELOG, "is not a version X.Y.Z"),
    ("v0.3.0", CHANGELOG, "is not a version X.Y.Z"),
    ("0.3.0-rc.1", CHANGELOG, "is not a version X.Y.Z"),
    ("03.0.0", CHANGELOG, "is not a version X.Y.Z"),
    ("0.3.0", NO_UNRELEASED, "has no '## [Unreleased]' section"),
    ("0.3.0", EMPTY_UNRELEASED, "[Unreleased] section of CHANGELOG.md is empty"),
    ("0.3.0", PRESENT, "already has a '## [0.3.0]' section"),
])
def test_prepare_refusals_leave_every_file_as_it_was(tmp_path, cli, version, changelog, reason):
    make_tree(tmp_path, "0.2.0", changelog=changelog)
    before = snapshot(tmp_path)
    code, out, err = cli(tmp_path, "prepare", version, "--date", "2026-10-17")
    assert (code, out) == (1, "")
    assert reason in err
    assert snapshot(tmp_path) == before


def test_prepare_writes_nothing_when_a_json_file_lacks_its_version(tmp_path, cli):
    make_tree(tmp_path, "0.2.0")
    put(tmp_path / "frontend" / "package-lock.json", json.dumps({"name": "x", "version": "0.2.0"}) + "\n")
    before = snapshot(tmp_path)
    code, out, err = cli(tmp_path, "prepare", "0.3.0", "--date", "2026-10-17")
    assert (code, out) == (1, "")
    assert 'frontend/package-lock.json: no packages."".version' in err
    assert snapshot(tmp_path) == before


def test_prepare_leaves_non_ascii_text_as_it_is(tmp_path, cli):
    make_tree(tmp_path, "0.2.0", changelog="## [Unreleased]\n\n#### Café, 2026-10-12\n\nÀ l'œil — “quoted”.\n")
    put(tmp_path / "frontend" / "package.json",
        json.dumps({"name": "cti", "description": "Café ☕", "version": "0.2.0"}, indent=2, ensure_ascii=False) + "\n")
    assert cli(tmp_path, "prepare", "0.3.0", "--date", "2026-10-17")[0] == 0
    assert '"description": "Café ☕"' in (tmp_path / "frontend" / "package.json").read_text(encoding="utf-8")
    assert release_notes(tmp_path, "0.3.0") == "#### Café, 2026-10-12\n\nÀ l'œil — “quoted”.\n"


# --- predicate --------------------------------------------------------------

def verify_output(*predicate_types: str) -> str:
    """The shape `gh attestation verify --format json` prints: a list of entries."""
    entries = [{"attestation": {"bundle": {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}},
                "verificationResult": {"statement": {"_type": "https://in-toto.io/Statement/v1",
                                                     "subject": [{"name": "x", "digest": {"sha256": "ab"}}],
                                                     "predicateType": kind,
                                                     "predicate": {"kind": kind, "name": "Café"}},
                                       "signature": {"certificate": {}}}}
               for kind in predicate_types]
    return json.dumps(entries)


def test_predicate_picks_the_entry_of_the_requested_type(tmp_path, cli):
    put(tmp_path / "verify.json", verify_output("https://slsa.dev/provenance/v1", "https://cyclonedx.org/bom"))
    code, out, err = cli(tmp_path, "predicate", tmp_path / "verify.json", "--type", "https://cyclonedx.org/bom")
    assert (code, err) == (0, "")
    assert out == json.dumps({"kind": "https://cyclonedx.org/bom", "name": "Café"}, ensure_ascii=False) + "\n"


def test_predicate_takes_the_first_of_two_entries_of_the_same_type(tmp_path, cli):
    entries = json.loads(verify_output("https://cyclonedx.org/bom", "https://cyclonedx.org/bom"))
    entries[0]["verificationResult"]["statement"]["predicate"] = {"first": True}
    put(tmp_path / "verify.json", json.dumps(entries))
    assert cli(tmp_path, "predicate", tmp_path / "verify.json", "--type", "https://cyclonedx.org/bom") == (
        0, '{"first": true}\n', "")


def test_predicate_refuses_when_no_entry_matches(tmp_path, cli):
    put(tmp_path / "verify.json", verify_output("https://slsa.dev/provenance/v1"))
    code, out, err = cli(tmp_path, "predicate", tmp_path / "verify.json", "--type", "https://cyclonedx.org/bom")
    assert (code, out) == (1, "")
    assert "no attestation with predicate type https://cyclonedx.org/bom" in err


@pytest.mark.parametrize("text", ["not json", "{}", "[]", '[null, 1, {"verificationResult": null}]'])
def test_predicate_refuses_output_it_cannot_read(tmp_path, cli, text):
    put(tmp_path / "verify.json", text)
    code, out, _ = cli(tmp_path, "predicate", tmp_path / "verify.json", "--type", "https://cyclonedx.org/bom")
    assert (code, out) == (1, "")


def test_predicate_refuses_a_missing_file(tmp_path, cli):
    assert cli(tmp_path, "predicate", tmp_path / "absent.json", "--type", "t")[0] == 1


def test_next_version_refuses_an_unknown_level():
    with pytest.raises(ReleaseError):
        next_version("1.2.3", "huge")
