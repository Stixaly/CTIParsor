"""scripts/check_release_dossier.py: the delivery proofs of a candidate commit (docs/releasing.md).

The recorded answers in tests/fixtures/release_dossier/ are GitHub's, read
on 2026-11-13 through gh (read-only) for commit d1389f7, CI run 43318438919,
image sha256:1c6016…: run_view.json, the analyses, the alerts, the rulesets and
the attestation are copied as gh printed them (the logs are excerpts of the
marker lines and of the first 60 lines of the unit-test step).  The SBOM
attestation is 7 MB and is not recorded: the tests derive it from the SLSA one,
changing only its predicate type.  No test calls GitHub or the network: gh is
a fake that answers from these files, and records each call so that a test
can check that none of them writes.

Tests marked with the failure they guard fail if the check stops seeing it.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

from scripts import check_release_dossier as dossier
from scripts.check_release_dossier import (
    FAILED,
    INCOMPLETE,
    INFO,
    MISSING,
    NOT_RUN,
    PASS,
    SKIPPED,
    TOLERATED,
    DossierError,
    GhError,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "release_dossier"
#: .grype.yaml and SECURITY.md as they stood when the GitHub answers were recorded (d1389f7):
#: the tests read these, so accepting or removing an exception in the repository does not
#: change what the recorded run is expected to give.  The repository's own files are
#: checked by test_the_repository_exceptions_are_all_valid.
RECORDED_ROOT = FIXTURES / "repo"
REPO = "Stixaly/CTIParsor"
SHA = "d1389f76b1453789d73512733042d9b858f9d381"
OTHER_SHA = "f475ca8899dc58bd242d71f5876849d80901dfdb"
DIGEST = "sha256:1c60161fb1965133ba7965196e882b114c818ebcf5aa67fd31810836082c922b"
OTHER_DIGEST = "sha256:" + "a" * 64
RUN_ID = 43318438919
MODEL_JOB = 131532458049
CONTAINER_JOB = 131532458065
FAST_JOB = 131532458160
PUBLISH_JOB = 131542717637
BROWSER_JOB = 131532457625
PYTEST_SUMMARY = (
    "2026-11-12T22:36:07.1000000Z Fast tests (lint + type check + unit tests)\tRun unit tests\t"
    "=========== 7135 passed, 12 skipped, 3 warnings in 1034.56s (0:17:14) ===========\n"
)


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _json(name: str) -> Any:
    return json.loads(_read(name))


class FakeGh:
    """Answers each gh call from the first route whose key is in the call's text; records every call."""

    def __init__(self, routes: list[tuple[str, Any]]) -> None:
        self.routes = routes
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> str:
        self.calls.append(list(args))
        line = " ".join(args)
        for key, answer in self.routes:
            if key in line:
                if isinstance(answer, Exception):
                    raise answer
                return answer
        raise GhError(f"no recorded answer for: {line}")


def _sbom_from_slsa(slsa_text: str) -> str:
    values = json.loads(slsa_text)
    for value in values:
        value["verificationResult"]["statement"]["predicateType"] = dossier.SBOM_PREDICATE
    return json.dumps(values)


def recorded(**over: Any) -> list[tuple[str, Any]]:
    """The routes of the recorded run.  `over` replaces one answer by name (see the keys below)."""
    answers: dict[str, Any] = {
        "run_list": _read("runs_list.json"),
        "run_view": _read("run_view.json"),
        "fast_log": _read("log_fast_tests_excerpt.txt"),
        "container_log": _read("log_container_excerpt.txt"),
        "publish_log": _read("log_publish_excerpt.txt"),
        "analyses": _read("analyses.json"),
        "alerts": _read("alerts.json"),
        "ruleset": _read("ruleset.json"),
        "rulesets": _read("rulesets.json"),
        "check_runs": _read("check_runs.json"),
        "statuses": _read("statuses.json"),
        "immutable": _read("immutable_releases.json"),
        "attest_slsa": _read("attestation_slsa.json"),
    }
    answers.update(over)
    slsa = answers["attest_slsa"]
    attest_sbom = over.get("attest_sbom", _sbom_from_slsa(slsa) if isinstance(slsa, str) else slsa)
    return [
        (f"--job {FAST_JOB} --log", answers["fast_log"]),
        (f"--job {CONTAINER_JOB} --log", answers["container_log"]),
        (f"--job {PUBLISH_JOB} --log", answers["publish_log"]),
        ("run list", answers["run_list"]),
        (f"run view {RUN_ID}", answers["run_view"]),
        ("code-scanning/analyses", answers["analyses"]),
        ("code-scanning/alerts", answers["alerts"]),
        ("rulesets/19765507", answers["ruleset"]),
        ("/rulesets", answers["rulesets"]),
        ("check-runs", answers["check_runs"]),
        ("/status", answers["statuses"]),
        ("immutable-releases", answers["immutable"]),
        ("--predicate-type https://slsa.dev/provenance/v1", answers["attest_slsa"]),
        ("--predicate-type https://cyclonedx.org/bom", attest_sbom),
    ]


def green(**over: Any) -> list[tuple[str, Any]]:
    """The recorded run with every proof passing: no open alert, CodeQL succeeded, a pytest summary line."""
    checks = _json("check_runs.json")
    checks["check_runs"].append({"id": 1, "name": "CodeQL", "status": "completed", "conclusion": "success"})
    base: dict[str, Any] = {
        "alerts": "[]",
        "check_runs": json.dumps(checks),
        "fast_log": _read("log_fast_tests_excerpt.txt") + PYTEST_SUMMARY,
    }
    base.update(over)
    return recorded(**base)


def run_view(**changes: Any) -> str:
    """The recorded run view, with top-level fields or jobs changed."""
    view = _json("run_view.json")
    jobs_changes = changes.pop("jobs", {})
    for job in view["jobs"]:
        if job["databaseId"] in jobs_changes:
            job.update(jobs_changes[job["databaseId"]])
    view.update(changes)
    return json.dumps(view)


def collect(gh: FakeGh, digest: str | None = DIGEST, root: Path = RECORDED_ROOT, sha: str = SHA) -> dossier.Report:
    ctx = dossier.Context(sha=sha, digest=digest, repo=REPO, gh=gh, root=root, ruleset="basic rules")
    return dossier.collect(ctx)


def item(report: dossier.Report, item_id: str) -> dossier.Item:
    return next(i for i in report.items if i.id == item_id)


def _alert(**changes: Any) -> dict[str, Any]:
    """The recorded Grype alert 62 (python 3.14.10, CVE-2026-119170, high), changed as given."""
    alert = copy.deepcopy(_json("alerts.json")[0])
    alert.update({k: v for k, v in changes.items() if k in alert})
    return alert


def _alert_for(cve: str, version: str, level: str = "high", text: str | None = None) -> str:
    alert = _alert()
    alert["rule"]["id"] = f"{cve}-python"
    alert["rule"]["security_severity_level"] = level
    alert["most_recent_instance"]["message"]["text"] = text or (
        f"A {level} vulnerability in binary package: python, version {version} was found in image ctiparsor:ci at: "
        "/usr/local/bin/python3.14"
    )
    return json.dumps([alert])


# ── The recorded run ──────────────────────────────────────────────────────────

def test_recorded_run_is_not_qualified_and_names_each_gap() -> None:
    """Real data: the run of d1389f7 is green, but main's Grype alert 62 blocks it, and two proofs are not visible."""
    gh = FakeGh(recorded())
    report = collect(gh)

    assert report.verdict == "failed"
    assert item(report, "ci_run").status == PASS
    for job_id in ("job:fast_tests", "job:frontend", "job:dependency_audit", "job:browser_e2e",
                   "job:container_image", "job:publish_image"):
        assert item(report, job_id).status in (PASS, MISSING), job_id
    assert item(report, "job:container_image").status == PASS
    assert item(report, "job:publish_image").status == PASS
    assert item(report, "digest").status == PASS
    assert item(report, "attestation_slsa").status == PASS
    assert item(report, "attestation_sbom").status == PASS
    assert item(report, "grype_config").status == PASS
    assert item(report, "grype_scan").status == PASS
    alerts = item(report, "grype_alerts")
    assert alerts.status == FAILED
    assert "CVE-2026-119170" in alerts.detail and "not accepted" in alerts.detail
    # The fast-tests log excerpt has no pytest summary: missing, not a pass.
    fast = item(report, "job:fast_tests")
    assert fast.status == MISSING and "no pytest summary" in fast.detail
    # The required context CodeQL is not among the checks of this commit.
    checks = item(report, "required_checks")
    assert checks.status == MISSING and "CodeQL: missing" in checks.detail
    assert item(report, "tag_protection").status == INFO
    assert report.exit_code == 1


def test_green_candidate_is_qualified_and_the_report_says_so() -> None:
    report = collect(FakeGh(green()))

    assert report.verdict == "qualified"
    assert report.exit_code == 0
    required = [i for i in report.items if i.required]
    assert required and all(i.status == PASS for i in required)
    assert "QUALIFIED" in dossier.to_markdown(report).splitlines()[5]


# ── One gap at a time ─────────────────────────────────────────────────────────

def test_a_model_test_failure_is_tolerated_and_never_a_pass() -> None:
    gh = FakeGh(green(run_view=run_view(jobs={MODEL_JOB: {"conclusion": "failure"}})))
    report = collect(gh)

    model = item(report, "job:model_tests")
    assert model.status == TOLERATED
    assert "not a pass" in model.detail
    assert model.required is False
    assert report.verdict == "qualified"


def test_a_timed_out_job_is_incomplete() -> None:
    report = collect(FakeGh(green(run_view=run_view(jobs={BROWSER_JOB: {"conclusion": "timed_out"}}))))

    assert item(report, "job:browser_e2e").status == INCOMPLETE
    assert report.verdict == "incomplete"
    assert report.exit_code == 1


def test_a_run_still_going_is_not_run_not_a_pass() -> None:
    report = collect(FakeGh(green(run_view=run_view(status="in_progress", conclusion=""))))

    assert item(report, "ci_run").status == NOT_RUN
    assert report.verdict == "incomplete"


def test_a_run_for_another_commit_fails() -> None:
    report = collect(FakeGh(green(run_view=run_view(headSha=OTHER_SHA))))

    run = item(report, "ci_run")
    assert run.status == FAILED and OTHER_SHA in run.detail
    assert report.verdict == "failed"


@pytest.mark.parametrize("change", [{"event": "pull_request"}, {"headBranch": "feature"}])
def test_a_run_that_is_not_a_push_on_main_fails(change: dict[str, str]) -> None:
    report = collect(FakeGh(green(run_view=run_view(**change))))

    assert item(report, "ci_run").status == FAILED


def test_no_ci_run_for_the_commit_is_missing() -> None:
    report = collect(FakeGh(green(run_list="[]")))

    assert item(report, "ci_run").status == MISSING
    assert report.verdict == "incomplete"


def test_a_digest_that_differs_from_the_logs_fails() -> None:
    report = collect(FakeGh(green()), digest=OTHER_DIGEST)

    assert item(report, "digest").status == FAILED
    assert report.verdict == "failed"


def test_no_candidate_digest_is_not_run_and_the_attestations_are_not_checked() -> None:
    gh = FakeGh(green())
    report = collect(gh, digest=None)

    assert item(report, "digest").status == NOT_RUN
    assert item(report, "attestation_slsa").status == NOT_RUN
    assert item(report, "attestation_sbom").status == NOT_RUN
    assert not any("attestation" in call for call in gh.calls)
    assert report.verdict == "incomplete"


def test_an_attestation_gh_cannot_verify_is_missing() -> None:
    report = collect(FakeGh(green(attest_slsa=GhError("gh attestation verify exited 1: no attestations"))))

    assert item(report, "attestation_slsa").status == MISSING
    assert report.verdict == "incomplete"


def test_an_attestation_of_another_commit_fails() -> None:
    values = json.loads(_read("attestation_slsa.json"))
    values[0]["verificationResult"]["signature"]["certificate"]["sourceRepositoryDigest"] = OTHER_SHA
    report = collect(FakeGh(green(attest_slsa=json.dumps(values))))

    assert item(report, "attestation_slsa").status == FAILED


def test_a_container_log_with_two_digests_is_missing() -> None:
    log = _read("log_container_excerpt.txt") + "x The archive's image index: sha256:" + "b" * 64 + "\n"
    report = collect(FakeGh(green(container_log=log)))

    assert item(report, "job:container_image").status == MISSING


def test_a_publish_log_without_its_push_line_is_missing() -> None:
    report = collect(FakeGh(green(publish_log="nothing here\n")))

    assert item(report, "job:publish_image").status == MISSING


def test_a_fast_tests_log_with_a_summary_passes() -> None:
    report = collect(FakeGh(green()))

    assert item(report, "job:fast_tests").status == PASS


def test_a_fast_tests_log_without_a_summary_is_missing() -> None:
    report = collect(FakeGh(green(fast_log=_read("log_fast_tests_excerpt.txt"))))

    fast = item(report, "job:fast_tests")
    assert fast.status == MISSING
    assert "partial" in fast.action


def test_no_scan_of_this_commit_is_missing() -> None:
    analyses = json.dumps([{"id": 1, "commit_sha": OTHER_SHA, "category": "container-image"}])
    report = collect(FakeGh(green(analyses=analyses)))

    assert item(report, "grype_scan").status == MISSING


def test_a_required_check_that_failed_fails_the_dossier() -> None:
    checks = _json("check_runs.json")
    checks["check_runs"].append({"id": 1, "name": "CodeQL", "status": "completed", "conclusion": "success"})
    # A later re-run of the check (the largest id) is the one that counts.
    checks["check_runs"].append({"id": 10**13, "name": "Fuzz (dates)", "status": "completed", "conclusion": "failure"})
    report = collect(FakeGh(green(check_runs=json.dumps(checks))))

    checks_item = item(report, "required_checks")
    assert checks_item.status == FAILED and "Fuzz (dates): failed" in checks_item.detail
    assert report.verdict == "failed"


def test_a_skipped_required_check_passes_as_github_counts_it() -> None:
    """Dependency review is skipped on a push; GitHub counts a skipped required check as passing."""
    report = collect(FakeGh(green()))

    assert item(report, "required_checks").status == PASS


# ── Grype: the same alert, accepted or not ────────────────────────────────────

def test_the_same_alert_accepted_by_a_valid_rule_passes() -> None:
    report = collect(FakeGh(green(alerts=_alert_for("CVE-2025-15367", "3.14.10"))))

    alerts = item(report, "grype_alerts")
    assert alerts.status == PASS
    assert any("CVE-2025-15367" in line for line in alerts.evidence["accepted"])


def test_the_accepted_rule_stops_matching_when_the_version_moves() -> None:
    report = collect(FakeGh(green(alerts=_alert_for("CVE-2025-15367", "3.14.11"))))

    alerts = item(report, "grype_alerts")
    assert alerts.status == FAILED
    assert "not accepted" in alerts.detail


def test_a_medium_alert_is_listed_and_does_not_block() -> None:
    report = collect(FakeGh(green(alerts=_alert_for("CVE-2026-99999", "3.14.10", level="medium"))))

    alerts = item(report, "grype_alerts")
    assert alerts.status == PASS
    assert alerts.evidence["below_threshold"]


def test_an_alert_whose_text_cannot_be_read_fails_closed() -> None:
    report = collect(FakeGh(green(alerts=_alert_for("CVE-2026-99999", "3.14.10", text="no package here"))))

    alerts = item(report, "grype_alerts")
    assert alerts.status == FAILED and "cannot be read" in alerts.detail


def test_an_alert_with_no_severity_fails_closed() -> None:
    alert = _alert()
    del alert["rule"]["security_severity_level"]
    report = collect(FakeGh(green(alerts=json.dumps([alert]))))

    assert item(report, "grype_alerts").status == FAILED


# ── .grype.yaml: exceptions are reviewed, with their SECURITY.md row ──────────

def test_the_repository_exceptions_are_all_valid() -> None:
    rules = dossier.parse_grype_ignore((ROOT / ".grype.yaml").read_text(encoding="utf-8"))
    section = dossier.accepted_section((ROOT / "SECURITY.md").read_text(encoding="utf-8"))

    assert rules
    assert [dossier.rule_problems(rule, section) for rule in rules] == [[]] * len(rules)


def test_the_repository_exceptions_pass_the_gate() -> None:
    report = collect(FakeGh(green()))

    assert item(report, "grype_config").status == PASS


RULE = """ignore:
  - vulnerability: CVE-2025-15367
    reason: "Unreachable"
    package:
      name: python
      version: 3.14.10
      type: binary
"""


def _repo_with_grype(tmp_path: Path, grype: str) -> Path:
    (tmp_path / ".grype.yaml").write_text(grype, encoding="utf-8")
    (tmp_path / "SECURITY.md").write_text((RECORDED_ROOT / "SECURITY.md").read_text(encoding="utf-8"),
                                          encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    "grype",
    [
        RULE.replace("CVE-2025-15367", "CVE-2099-0001"),  # no SECURITY.md row
        RULE.replace("3.14.10", "9.9.9"),  # the row does not name this version
        RULE.replace('"Unreachable"', '""'),  # no reason
    ],
    ids=["no-security-row", "wrong-version", "no-reason"],
)
def test_an_invalid_exception_fails_the_gate(tmp_path: Path, grype: str) -> None:
    root = _repo_with_grype(tmp_path, grype)
    report = collect(FakeGh(green()), root=root)

    config = item(report, "grype_config")
    assert config.status == FAILED
    assert report.verdict == "failed"


def test_an_exception_file_of_another_shape_is_missing(tmp_path: Path) -> None:
    root = _repo_with_grype(tmp_path, "ignore:\n  - vulnerability: CVE-2025-15367\n    surprise line\n")
    report = collect(FakeGh(green()), root=root)

    assert item(report, "grype_config").status == MISSING


def test_the_parser_reads_the_rule_fields() -> None:
    rules = dossier.parse_grype_ignore(RULE)

    assert rules == [{"vulnerability": "CVE-2025-15367", "reason": "Unreachable",
                      "package": {"name": "python", "version": "3.14.10", "type": "binary"}}]


def test_the_parser_refuses_a_file_that_does_not_start_with_ignore() -> None:
    with pytest.raises(DossierError):
        dossier.parse_grype_ignore("other:\n  - vulnerability: CVE-2025-15367\n")


# ── Required jobs match ci.yml ────────────────────────────────────────────────

def test_the_job_names_are_the_names_ci_yml_gives_them() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    for spec in dossier.JOBS:
        assert re.search(rf"^    name: {re.escape(spec.name)}$", ci, re.MULTILINE), spec.name


def test_the_model_tests_are_the_only_tolerated_job_in_ci_yml() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    tolerated = [spec for spec in dossier.JOBS if spec.tolerated]
    assert [spec.id for spec in tolerated] == ["model_tests"]
    assert "continue-on-error: true" in ci


# ── Helpers ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("job", "tolerated", "expected"),
    [
        ({"status": "completed", "conclusion": "success"}, False, PASS),
        ({"status": "completed", "conclusion": "skipped"}, False, SKIPPED),
        ({"status": "completed", "conclusion": "failure"}, False, FAILED),
        ({"status": "completed", "conclusion": "failure"}, True, TOLERATED),
        ({"status": "completed", "conclusion": "timed_out"}, True, INCOMPLETE),
        ({"status": "completed", "conclusion": "cancelled"}, False, INCOMPLETE),
        ({"status": "in_progress", "conclusion": None}, False, NOT_RUN),
    ],
)
def test_a_job_status_is_classified(job: dict[str, Any], tolerated: bool, expected: str) -> None:
    assert dossier.classify_job(job, tolerated) == expected


def test_paginated_answers_are_read_page_after_page() -> None:
    assert dossier.pages("[1, 2]\n[3]") == [1, 2, 3]
    assert dossier.pages('{"check_runs": [{"name": "a"}]}\n{"check_runs": []}', key="check_runs") == [{"name": "a"}]


@pytest.mark.parametrize(
    ("line", "matches"),
    [
        ("=== 7135 passed, 12 skipped in 1034.56s (0:17:14) ===", True),
        ("=== 3 failed, 7132 passed in 900.0s ===", True),
        ("tests/test_x.py::test_a PASSED [ 15%]", False),
        ("collected 7135 items", False),
    ],
)
def test_the_pytest_summary_line_is_recognised(line: str, matches: bool) -> None:
    assert bool(dossier._PYTEST_SUMMARY.search(line)) is matches


def test_a_recorded_run_makes_no_write_call() -> None:
    gh = FakeGh(green())
    collect(gh)

    assert gh.calls
    forbidden = {"-X", "--method", "-f", "-F", "--field", "--raw-field", "--input", "POST", "PATCH", "PUT", "DELETE"}
    for call in gh.calls:
        assert forbidden.isdisjoint(call), call
        assert call[0] in {"run", "api", "attestation"}, call


# ── Command line ──────────────────────────────────────────────────────────────

def test_the_command_line_refuses_a_bad_sha_or_digest() -> None:
    assert dossier.main(["not-a-sha"], gh=FakeGh([])) == 2
    assert dossier.main([SHA, "--digest", "md5:abc"], gh=FakeGh([])) == 2


def test_the_command_line_writes_the_report_and_exits_by_verdict(tmp_path: Path) -> None:
    out = tmp_path / "out"
    code = dossier.main([SHA, "--digest", DIGEST, "--out", str(out), "--root", str(RECORDED_ROOT)],
                        gh=FakeGh(recorded()))

    assert code == 1
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["verdict"] == "failed" and report["sha"] == SHA
    assert "NOT QUALIFIED: failed" in (out / "report.md").read_text(encoding="utf-8")

    code = dossier.main([SHA, "--digest", DIGEST, "--out", str(tmp_path / "ok"), "--root", str(RECORDED_ROOT)],
                        gh=FakeGh(green()))
    assert code == 0
    assert json.loads((tmp_path / "ok" / "report.json").read_text(encoding="utf-8"))["verdict"] == "qualified"
