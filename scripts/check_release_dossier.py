#!/usr/bin/env python3
"""Release dossier: are the delivery proofs of one candidate commit all present and passing?

A green CI run on main does not show every delivery proof on its own: the
image scan (Grype) does not fail the build, and the model tests may fail
(`continue-on-error`).  This script reads, for one commit of main, what
docs/releasing.md and docs/releases/1.0-readiness.md say must hold before a
tag, and classifies each item as one of:

    pass             the job or check succeeded, or the proof is verified
    tolerated_failure  a job that may fail (continue-on-error) failed: never a pass
    skipped          the job or check was skipped (only accepted where GitHub accepts it)
    not_run          the job or the proof is still running or was not done
    incomplete       the job was cancelled or timed out
    failed           the proof is there and wrong (failed job, wrong digest, unaccepted alert)
    missing          the proof cannot be read or is absent (no run, no summary line, no analysis)
    info             read for the record; does not decide the verdict

The verdict is "qualified" (exit 0) only when every required item is pass or
info.  "failed" and "incomplete" exit 1.  Every gh call goes through one
function (`run_gh`), so the tests feed recorded JSON to `collect`.  Nothing is
changed in the repository or on GitHub: the calls are read-only.

Usage:
    python scripts/check_release_dossier.py SHA [--digest sha256:HEX]
        [--repo OWNER/NAME] [--ruleset NAME] [--root DIR] [--out DIR]

Exit codes:
    0  qualified: every required item passes
    1  not qualified: the report names each item that does not pass and what to do
    2  usage error
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO = "Stixaly/CTIParsor"
DEFAULT_RULESET = "basic rules"
CI_WORKFLOW = "ci.yml"
MAIN_REF = "refs/heads/main"
GRYPE_TOOL = "Grype"
IMAGE_CATEGORY = "container-image"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"
SBOM_PREDICATE = "https://cyclonedx.org/bom"
#: Alerts at these levels block the release unless accepted; so does a level
#: that cannot be read (the check fails closed).
BLOCKING_LEVELS = frozenset({"critical", "high"})

PASS = "pass"
TOLERATED = "tolerated_failure"
SKIPPED = "skipped"
NOT_RUN = "not_run"
INCOMPLETE = "incomplete"
FAILED = "failed"
MISSING = "missing"
INFO = "info"
#: Statuses that do not stop a required item.
OK_STATUSES = frozenset({PASS, INFO})

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SHA = re.compile(r"[0-9a-f]{40}")
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]+")
#: The digest the container job logs: "The archive's image index: sha256:…".
_INDEX_LOG = re.compile(r"image index: (sha256:[0-9a-f]{64})")
#: The digest publish-image logs per name it pushed: "…:sha-<commit> -> sha256:…".
_PUSHED_LOG = re.compile(r"sha-([0-9a-f]{40}) -> (sha256:[0-9a-f]{64})")
#: pytest's final line: "=== 7135 passed, 12 skipped in 1034.56s (0:17:14) ===".
_PYTEST_SUMMARY = re.compile(r"=+ [^\n]*\b[0-9]+ passed\b[^\n]* in [0-9]+(?:\.[0-9]+)?s")
#: Grype's alert text: "A high vulnerability in binary package: python, version 3.14.10 was found".
_GRYPE_TEXT = re.compile(
    r"vulnerability in (?P<kind>.+?) package: (?P<name>[^,\s]+), version (?P<version>\S+) was found"
)
_TEST_LINE = re.compile(r"\b(PASSED|FAILED|SKIPPED|ERROR)\b")


class DossierError(Exception):
    """Something the dossier cannot read or check; the item that asked for it says so."""


class GhError(DossierError):
    """A gh call that failed (no such resource, not logged in, network)."""


GhCall = Callable[[list[str]], str]


def run_gh(args: list[str]) -> str:
    """Run `gh` with `args` and return its standard output.  The one place gh is run."""
    try:
        proc = subprocess.run(
            ["gh", *args], capture_output=True, text=True, encoding="utf-8",
            errors="replace", check=False, timeout=900,
        )
    except FileNotFoundError as exc:
        raise GhError("the gh CLI is not installed") from exc
    if proc.returncode != 0:
        first = (proc.stderr.strip().splitlines() or ["no message"])[0]
        raise GhError(f"gh {' '.join(args[:2])} exited {proc.returncode}: {first}")
    return proc.stdout


@dataclass
class Item:
    """One checked proof: its status, what was seen, and what to do when it is not a pass."""

    id: str
    title: str
    status: str
    detail: str
    required: bool = True
    action: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Report:
    sha: str
    digest: str | None
    repo: str
    generated_at: str
    items: list[Item]
    informational: dict[str, Any] = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        required = [i for i in self.items if i.required]
        if any(i.status == FAILED for i in required):
            return "failed"
        if any(i.status not in OK_STATUSES for i in required):
            return "incomplete"
        return "qualified"

    @property
    def exit_code(self) -> int:
        return 0 if self.verdict == "qualified" else 1


@dataclass(frozen=True)
class Context:
    """What one collection needs: the commit, the candidate digest, the repository and the gh function."""

    sha: str
    digest: str | None
    repo: str
    gh: GhCall
    root: Path
    ruleset: str

    @property
    def image(self) -> str:
        return f"ghcr.io/{self.repo.lower()}"


@dataclass(frozen=True)
class JobSpec:
    id: str
    name: str
    required: bool = True
    tolerated: bool = False
    #: Job steps the dossier reads from the log: the pytest summary, the digests.
    needs_log: bool = False


#: The jobs of ci.yml a release waits for (publish-image needs them), by the names GitHub shows.
JOBS = (
    JobSpec("fast_tests", "Fast tests (lint + type check + unit tests)", needs_log=True),
    JobSpec("frontend", "Frontend (lint + type check + unit tests)"),
    JobSpec("dependency_audit", "Dependency audit (pip-audit on the lock, npm audit)"),
    JobSpec("browser_e2e", "Browser journey (Playwright, offline)"),
    JobSpec("container_image", "Container image (build + smoke)", needs_log=True),
    JobSpec("publish_image", "Publish image to GHCR", needs_log=True),
    # A reinforcement, not a gate (ci.yml: continue-on-error). Shown, never a pass when it fails.
    JobSpec("model_tests", "Model tests (full pipeline, with model downloads)", required=False, tolerated=True),
)


# ── Pure helpers (no gh) ──────────────────────────────────────────────────────

def json_values(text: str) -> list[Any]:
    """Every JSON value in `text`.  `gh api --paginate` prints one value per page, one after another."""
    decoder = json.JSONDecoder()
    values: list[Any] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        value, pos = decoder.raw_decode(text, pos)
        values.append(value)
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return values


def pages(text: str, key: str | None = None) -> list[Any]:
    """The items of a paginated gh api answer: each page is a list, or an object holding `key`."""
    items: list[Any] = []
    for value in json_values(text):
        if isinstance(value, list):
            items.extend(value)
        elif key is not None:
            items.extend(value.get(key, []))
        else:
            items.append(value)
    return items


def classify_job(job: dict[str, Any], tolerated: bool) -> str:
    """The status of one job of a run, from its GitHub status and conclusion."""
    if job.get("status") != "completed":
        return NOT_RUN
    conclusion = job.get("conclusion") or ""
    if conclusion == "success":
        return PASS
    if conclusion == "skipped":
        return SKIPPED
    if conclusion in ("cancelled", "timed_out"):
        return INCOMPLETE
    if conclusion == "failure" and tolerated:
        return TOLERATED
    return FAILED


def classify_check(check: dict[str, Any]) -> str:
    """The status of one check run (the API's status and conclusion)."""
    if check.get("status") != "completed":
        return NOT_RUN
    conclusion = check.get("conclusion") or ""
    if conclusion == "success":
        return PASS
    if conclusion in ("skipped", "neutral"):
        return SKIPPED
    if conclusion in ("cancelled", "timed_out"):
        return INCOMPLETE
    return FAILED


def classify_status(state: str) -> str:
    """The status of one commit status (the API's `state`, for contexts not run as check runs)."""
    if state == "success":
        return PASS
    if state == "pending":
        return NOT_RUN
    return FAILED


def parse_grype_ignore(text: str) -> list[dict[str, Any]]:
    """The rules under `ignore:` of .grype.yaml, read without PyYAML (the release runner has none).

    Only the shape the file uses is accepted: a rule starts with `  - key: value`,
    its fields are indented four spaces, and `package:` holds fields indented six.
    Anything else raises DossierError, so that an unreadable file fails the check.
    """
    lines = [line.rstrip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not lines or lines[0] != "ignore:":
        raise DossierError("the file does not start with 'ignore:'")
    rules: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_package = False
    for line in lines[1:]:
        if line.startswith("  - "):
            current = {}
            rules.append(current)
            in_package = False
            key, value = _key_value(line[4:])
            current[key] = value
        elif current is None:
            raise DossierError(f"a field before the first rule: {line.strip()!r}")
        elif in_package and line.startswith("      ") and not line.startswith("       "):
            key, value = _key_value(line.strip())
            current["package"][key] = value
        elif line == "    package:":
            current["package"] = {}
            in_package = True
        elif line.startswith("    ") and not line.startswith("     "):
            in_package = False
            key, value = _key_value(line.strip())
            current[key] = value
        else:
            raise DossierError(f"a line of unexpected shape: {line.strip()!r}")
    return rules


def _key_value(text: str) -> tuple[str, Any]:
    match = re.fullmatch(r"([A-Za-z_]+):\s*(.*)", text)
    if not match:
        raise DossierError(f"not a 'key: value' line: {text!r}")
    key, value = match.group(1), match.group(2).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return key, value or None


def accepted_section(security_text: str) -> list[str]:
    """The lines of SECURITY.md's 'Accepted vulnerabilities' section."""
    lines = security_text.splitlines()
    try:
        start = lines.index("### Accepted vulnerabilities")
    except ValueError as exc:
        raise DossierError("SECURITY.md has no 'Accepted vulnerabilities' section") from exc
    section: list[str] = []
    for line in lines[start + 1:]:
        if line.startswith("## ") or line.startswith("### "):
            break
        section.append(line)
    return section


def rule_problems(rule: dict[str, Any], section: list[str]) -> list[str]:
    """Why an ignore rule is not a valid exception: no reason, no exact package, or no SECURITY.md row."""
    problems: list[str] = []
    vulnerability = rule.get("vulnerability") or ""
    package = rule.get("package") or {}
    if not _CVE.fullmatch(vulnerability):
        problems.append(f"the vulnerability {vulnerability!r} is not a CVE id")
    if not rule.get("reason"):
        problems.append("no reason")
    if not package.get("name") or not package.get("version"):
        problems.append("the package name or version is missing")
        return problems
    rows = [line for line in section if vulnerability and vulnerability in line]
    if not rows:
        problems.append(f"{vulnerability} has no row in SECURITY.md's Accepted vulnerabilities")
    elif not any(package["version"] in row for row in rows):
        problems.append(f"the SECURITY.md row of {vulnerability} does not name version {package['version']}")
    return problems


def alert_package(alert: dict[str, Any]) -> tuple[str, str, str, str] | None:
    """(CVE id, package name, package version, package kind) of a Grype alert, or None if unreadable."""
    rule_id = str(alert.get("rule", {}).get("id") or "")
    text = str(alert.get("most_recent_instance", {}).get("message", {}).get("text") or "")
    match = _GRYPE_TEXT.search(text)
    if not match:
        return None
    name, version, kind = match.group("name"), match.group("version"), match.group("kind")
    cve = rule_id[: -len(name) - 1] if rule_id.endswith("-" + name) else rule_id
    if not _CVE.fullmatch(cve):
        return None
    return cve, name, version, kind


def alert_level(alert: dict[str, Any]) -> str:
    """The alert's severity level as code scanning reports it, lower-cased; 'unknown' when absent."""
    rule = alert.get("rule", {})
    level = rule.get("security_severity_level") or ""
    return str(level).lower() or "unknown"


def match_rule(rules: list[dict[str, Any]], cve: str, name: str, version: str, kind: str) -> dict[str, Any] | None:
    """The valid ignore rule for this exact vulnerability, package, version and package type."""
    for rule in rules:
        package = rule.get("package") or {}
        if rule.get("vulnerability") != cve or package.get("name") != name or package.get("version") != version:
            continue
        if package.get("type") and package.get("type") != kind.split()[0]:
            continue
        return rule
    return None


def validate_candidate_digest(digest: str | None) -> None:
    if digest is not None and not _DIGEST.fullmatch(digest):
        raise DossierError(f"not an image digest: {digest!r}")


# ── Collections (each one calls gh through ctx.gh) ───────────────────────────

def _missing(item_id: str, title: str, exc: Exception, required: bool = True, action: str = "") -> Item:
    return Item(item_id, title, MISSING, f"could not read: {exc}", required,
                action or "re-run the dossier once the GitHub call works")


def check_ci_run(ctx: Context) -> tuple[Item, dict[str, Any] | None]:
    title = "CI run of this commit on main"
    try:
        listed = json.loads(ctx.gh([
            "run", "list", "-R", ctx.repo, "-w", CI_WORKFLOW, "-b", "main", "-e", "push",
            "-c", ctx.sha, "--json", "databaseId,headSha,conclusion,status,event,headBranch,attempt,url", "-L", "20",
        ]))
    except (DossierError, json.JSONDecodeError) as exc:
        return _missing("ci_run", title, exc), None
    if not listed:
        return Item("ci_run", title, MISSING, "no push run of ci.yml on main names this commit",
                    action="wait for main's CI, or check that the commit is on main"), None
    run_id = max(int(r["databaseId"]) for r in listed)
    try:
        run = json.loads(ctx.gh(["run", "view", str(run_id), "-R", ctx.repo, "--json",
                                 "status,conclusion,headSha,event,headBranch,attempt,url,jobs"]))
    except (DossierError, json.JSONDecodeError) as exc:
        return _missing("ci_run", title, exc), None
    evidence = {"run_id": run_id, "url": run.get("url"), "attempt": run.get("attempt"),
                "conclusion": run.get("conclusion")}
    if run.get("headSha") != ctx.sha:
        return Item("ci_run", title, FAILED, f"the run is for {run.get('headSha')}, not {ctx.sha}",
                    action="use the run of the commit named", evidence=evidence), run
    if run.get("event") != "push" or run.get("headBranch") != "main":
        return Item("ci_run", title, FAILED, f"the run is a {run.get('event')} run on {run.get('headBranch')}",
                    action="the release needs the push run on main", evidence=evidence), run
    if run.get("status") != "completed":
        return Item("ci_run", title, NOT_RUN, f"the run is {run.get('status')}", action="wait for the run to finish",
                    evidence=evidence), run
    return Item("ci_run", title, PASS, f"run {run_id}, attempt {run.get('attempt')}, {run.get('conclusion')}",
                evidence=evidence), run


def _job_log(ctx: Context, job_id: int) -> str:
    return ctx.gh(["run", "view", "-R", ctx.repo, "--job", str(job_id), "--log"])


def check_jobs(ctx: Context, run: dict[str, Any] | None) -> tuple[list[Item], dict[str, str]]:
    """One item per JOBS entry, and the digests the container and publish jobs logged."""
    items: list[Item] = []
    digests: dict[str, str] = {}
    by_name: dict[str, dict[str, Any]] = {}
    for job in (run or {}).get("jobs", []):
        seen = by_name.get(job["name"])
        if seen is None or int(job["databaseId"]) > int(seen["databaseId"]):
            by_name[job["name"]] = job
    for spec in JOBS:
        title = spec.name
        job = by_name.get(spec.name)
        if job is None:
            if run is None:
                items.append(Item(f"job:{spec.id}", title, MISSING, "no run to read", spec.required,
                                  "see the CI run item"))
            else:
                items.append(Item(f"job:{spec.id}", title, MISSING, "the run has no such job", spec.required,
                                  "the job was renamed or removed in ci.yml: update JOBS"))
            continue
        status = classify_job(job, spec.tolerated)
        detail = f"{job.get('conclusion') or job.get('status')}"
        action = ""
        if status == NOT_RUN:
            action = "wait for the job to finish"
        elif status == FAILED:
            action = "read the job's log, fix the failure, and run the pipeline again"
        elif status == INCOMPLETE:
            action = "the job timed out or was cancelled: it is incomplete, run it again"
        elif status == SKIPPED:
            action = "a required job must run on main"
        elif status == TOLERATED:
            detail += ": tolerated by continue-on-error, not a pass"
            action = "declare the failure in the release notes (docs/releases/1.0-readiness.md, reinforcements)"
        if spec.needs_log and status in (PASS, TOLERATED):
            try:
                log = _job_log(ctx, int(job["databaseId"]))
            except DossierError as exc:
                status, detail, action = MISSING, f"could not read the job log: {exc}", "re-run the dossier"
            else:
                status, detail, action = _check_log(ctx, spec, log, status, detail, digests)
        items.append(Item(f"job:{spec.id}", title, status, detail, spec.required, action,
                          evidence={"job_id": job.get("databaseId")}))
    return items, digests


def _check_log(ctx: Context, spec: JobSpec, log: str, status: str, detail: str,
               digests: dict[str, str]) -> tuple[str, str, str]:
    if spec.id == "fast_tests":
        if _PYTEST_SUMMARY.search(log):
            return status, detail + "; pytest summary line present", ""
        lines = len(_TEST_LINE.findall(log))
        return (MISSING, f"no pytest summary line in the log ({lines} test result lines read)",
                "the log may be partial: read the job in the Actions UI, or run the suite again")
    if spec.id == "container_image":
        found = set(_INDEX_LOG.findall(log))
        if len(found) != 1:
            return MISSING, f"the log names {len(found)} image index digests, expected 1", "read the job's log"
        digests["container_image"] = found.pop()
        return status, f"{detail}; logged {digests['container_image']}", ""
    if spec.id == "publish_image":
        pairs = [(s, d) for s, d in _PUSHED_LOG.findall(log) if s == ctx.sha]
        if not pairs:
            return MISSING, f"the log names no push of sha-{ctx.sha}", "read the job's log"
        if len({d for _, d in pairs}) != 1:
            return FAILED, "the log names two digests for the same commit", "the registry names one digest per version"
        digests["publish_image"] = pairs[0][1]
        return status, f"{detail}; pushed {pairs[0][1]}", ""
    return status, detail, ""


def check_digest(ctx: Context, digests: dict[str, str]) -> Item:
    title = "Image digest: the one tested, the one pushed and the one given agree"
    logged = {k: v for k, v in digests.items()}
    if ctx.digest is None:
        return Item("digest", title, NOT_RUN, "no candidate digest given (--digest): the image is not tied to a digest",
                    action="pass --digest sha256:<the digest of sha-<commit> in GHCR>", evidence={"logged": logged})
    if "container_image" not in digests or "publish_image" not in digests:
        return Item("digest", title, MISSING, "the container or publish job logged no digest",
                    action="read the job logs", evidence={"logged": logged})
    values = set(digests.values()) | {ctx.digest}
    if len(values) != 1:
        return Item("digest", title, FAILED, f"different digests: {sorted(values)}",
                    action="the image pushed is not the image tested: do not release this commit",
                    evidence={"logged": logged, "given": ctx.digest})
    return Item("digest", title, PASS, f"{ctx.digest} in both logs and the one given",
                evidence={"logged": logged, "given": ctx.digest})


def _attest(ctx: Context, predicate: str) -> list[Any]:
    args = ["attestation", "verify", f"oci://{ctx.image}@{ctx.digest}", "-R", ctx.repo,
            "--signer-workflow", f"{ctx.repo}/.github/workflows/{CI_WORKFLOW}",
            "--source-ref", MAIN_REF, "--source-digest", ctx.sha, "--predicate-type", predicate, "--format", "json"]
    return json_values(ctx.gh(args))


def check_attestation(ctx: Context, predicate: str, item_id: str, title: str) -> Item:
    if ctx.digest is None:
        return Item(item_id, title, NOT_RUN, "needs the candidate digest (--digest)",
                    action="pass --digest sha256:<digest>")
    try:
        records = [r for v in _attest(ctx, predicate) for r in (v if isinstance(v, list) else [v])]
    except (DossierError, json.JSONDecodeError) as exc:
        return Item(item_id, title, MISSING, f"gh attestation verify did not verify it: {exc}",
                    action="the image must carry this attestation, signed by ci.yml on main for this commit")
    hex_digest = ctx.digest.split(":", 1)[1]
    for record in records:
        result = record.get("verificationResult", {})
        statement = result.get("statement", {})
        if statement.get("predicateType") != predicate:
            continue
        subjects = {s.get("digest", {}).get("sha256") for s in statement.get("subject", [])}
        certificate = result.get("signature", {}).get("certificate", {})
        if hex_digest not in subjects:
            return Item(item_id, title, FAILED, "the attestation names another digest",
                        action="the attestation does not describe this image: do not release it")
        if certificate.get("sourceRepositoryDigest") != ctx.sha:
            return Item(item_id, title, FAILED, "the attestation was built from another commit",
                        action="do not release this commit with that attestation")
        return Item(item_id, title, PASS, f"verified for {ctx.digest} from {ctx.sha}",
                    evidence={"predicate": predicate})
    return Item(item_id, title, MISSING, f"no verified attestation of predicate {predicate}",
                action="the image has no such attestation")


def check_grype_config(ctx: Context) -> tuple[Item, list[dict[str, Any]]]:
    title = ".grype.yaml exceptions are valid (reviewed, with a SECURITY.md row)"
    try:
        grype = (ctx.root / ".grype.yaml").read_text(encoding="utf-8")
        security = (ctx.root / "SECURITY.md").read_text(encoding="utf-8")
        rules = parse_grype_ignore(grype)
        section = accepted_section(security)
    except (OSError, DossierError) as exc:
        return Item("grype_config", title, MISSING, f"could not read the exceptions: {exc}",
                    action="fix .grype.yaml or SECURITY.md"), []
    valid: list[dict[str, Any]] = []
    invalid: list[str] = []
    for rule in rules:
        problems = rule_problems(rule, section)
        if problems:
            invalid.append(f"{rule.get('vulnerability')}: " + "; ".join(problems))
        else:
            valid.append(rule)
    if invalid:
        return Item("grype_config", title, FAILED, f"{len(invalid)} invalid exception(s): " + " | ".join(invalid),
                    action="add the SECURITY.md row and the rule together, or remove the rule"), valid
    return Item("grype_config", title, PASS, f"{len(valid)} exception(s), each with a SECURITY.md row",
                evidence={"rules": [r["vulnerability"] for r in valid]}), valid


def check_grype_scan(ctx: Context) -> Item:
    title = "Grype scanned this commit's image (code scanning analysis)"
    try:
        analyses = json.loads(ctx.gh(["api", f"repos/{ctx.repo}/code-scanning/analyses?ref={MAIN_REF}"
                                      f"&tool_name={GRYPE_TOOL}&per_page=100"]))
    except (DossierError, json.JSONDecodeError) as exc:
        return _missing("grype_scan", title, exc, action="the code scanning API must answer")
    own = [a for a in analyses if a.get("commit_sha") == ctx.sha and a.get("category") == IMAGE_CATEGORY]
    newest = next((a.get("commit_sha") for a in analyses if a.get("category") == IMAGE_CATEGORY), None)
    if not own:
        return Item("grype_scan", title, MISSING, "no container-image analysis of this commit in the last 100",
                    action="the scan job must upload its SARIF for this commit (container-image job)")
    detail = f"analysis {own[0].get('id')} of this commit"
    if newest and newest != ctx.sha:
        detail += f"; main's newest scan is {newest} (informational)"
    return Item("grype_scan", title, PASS, detail, evidence={"analysis_id": own[0].get("id")})


def check_grype_alerts(ctx: Context, rules: list[dict[str, Any]]) -> Item:
    title = "No unaccepted high or critical Grype alert is open on main"
    try:
        alerts = pages(ctx.gh(["api", "--paginate", f"repos/{ctx.repo}/code-scanning/alerts?ref={MAIN_REF}"
                               f"&state=open&tool_name={GRYPE_TOOL}&per_page=100"]))
    except (DossierError, json.JSONDecodeError) as exc:
        return _missing("grype_alerts", title, exc, action="the code scanning API must answer")
    blocking: list[str] = []
    accepted: list[str] = []
    below: list[str] = []
    for alert in alerts:
        if alert.get("state") != "open":
            continue
        if alert.get("most_recent_instance", {}).get("category") != IMAGE_CATEGORY:
            continue
        number = alert.get("number")
        parsed = alert_package(alert)
        level = alert_level(alert)
        if parsed is None:
            if level in BLOCKING_LEVELS or level == "unknown":
                blocking.append(f"#{number}: the alert text cannot be read")
            continue
        cve, name, version, kind = parsed
        if level not in BLOCKING_LEVELS and level != "unknown":
            below.append(f"#{number} {cve} {name} {version} ({level})")
            continue
        rule = match_rule(rules, cve, name, version, kind)
        if rule is None:
            blocking.append(f"#{number} {cve} {name} {version} ({level}, not accepted)")
        else:
            accepted.append(f"#{number} {cve} {name} {version} accepted by .grype.yaml")
    evidence = {"blocking": blocking, "accepted": accepted, "below_threshold": below}
    summary = (f"{len(blocking)} blocking, {len(accepted)} accepted, {len(below)} below high "
               "(medium and low are listed, not blocking)")
    if blocking:
        return Item("grype_alerts", title, FAILED, summary + ": " + "; ".join(blocking),
                    action="fix the package in the image, or accept it: a SECURITY.md row and a .grype.yaml rule",
                    evidence=evidence)
    return Item("grype_alerts", title, PASS, summary, evidence=evidence)


def check_required_checks(ctx: Context) -> Item:
    title = "Required checks of the ruleset all succeeded on this commit"
    try:
        rulesets = json.loads(ctx.gh(["api", f"repos/{ctx.repo}/rulesets"]))
        target = next((r for r in rulesets if r.get("name") == ctx.ruleset and r.get("target") == "branch"), None)
        if target is None:
            return Item("required_checks", title, MISSING, f"no branch ruleset named {ctx.ruleset!r}",
                        action="check the ruleset's name")
        detail_json = json.loads(ctx.gh(["api", f"repos/{ctx.repo}/rulesets/{target['id']}"]))
        contexts = [c["context"] for rule in detail_json.get("rules", [])
                    if rule.get("type") == "required_status_checks"
                    for c in rule.get("parameters", {}).get("required_status_checks", [])]
        checks = pages(ctx.gh(["api", "--paginate", f"repos/{ctx.repo}/commits/{ctx.sha}/check-runs?per_page=100"]),
                       key="check_runs")
        statuses = json.loads(ctx.gh(["api", f"repos/{ctx.repo}/commits/{ctx.sha}/status"])).get("statuses", [])
    except (DossierError, json.JSONDecodeError, KeyError) as exc:
        return _missing("required_checks", title, exc, action="the GitHub API must answer")
    if not contexts:
        return Item("required_checks", title, MISSING, "the ruleset names no required check",
                    action="check the ruleset")
    latest_check: dict[str, dict[str, Any]] = {}
    for check in checks:
        name = check.get("name")
        if name not in latest_check or int(check.get("id", 0)) > int(latest_check[name].get("id", 0)):
            latest_check[name] = check
    latest_status: dict[str, str] = {}
    for status in statuses:  # the API lists the newest first
        latest_status.setdefault(status.get("context"), status.get("state"))
    problems: list[str] = []
    per_context: dict[str, str] = {}
    for context in contexts:
        if context in latest_check:
            state = classify_check(latest_check[context])
        elif context in latest_status:
            state = classify_status(str(latest_status[context]))
        else:
            state = MISSING
        per_context[context] = state
        if state not in (PASS, SKIPPED):
            problems.append(f"{context}: {state}")
    if problems:
        status = FAILED if any(p.endswith(f": {FAILED}") for p in problems) else MISSING
        return Item("required_checks", title, status, "; ".join(problems),
                    action="a required check must succeed on this commit; read the run of that check",
                    evidence={"contexts": per_context})
    return Item("required_checks", title, PASS, f"{len(contexts)} required contexts, each succeeded or skipped",
                evidence={"contexts": per_context})


def read_protections(ctx: Context) -> tuple[Item | None, dict[str, Any]]:
    """Informational: the rulesets that cover tags, and immutable releases (maintainer's settings, not gated)."""
    info: dict[str, Any] = {}
    try:
        rulesets = json.loads(ctx.gh(["api", f"repos/{ctx.repo}/rulesets"]))
        info["rulesets"] = [[r.get("id"), r.get("name"), r.get("target"), r.get("enforcement")] for r in rulesets]
        tag_rules = [r for r in rulesets if r.get("target") == "tag" and r.get("enforcement") == "active"]
        info["tag_ruleset_active"] = bool(tag_rules)
        immutable = json.loads(ctx.gh(["api", f"repos/{ctx.repo}/immutable-releases"]))
        info["immutable_releases"] = bool(immutable.get("enabled"))
    except (DossierError, json.JSONDecodeError) as exc:
        info["error"] = str(exc)
        return None, info
    if info["tag_ruleset_active"]:
        return None, info
    item = Item("tag_protection", "A ruleset covers release tags (v*)", INFO,
                "no active tag ruleset: anyone with write access can move a release tag",
                required=False,
                action="the maintainer's setting: docs/releasing.md, One-time repository settings, item 1")
    return item, info


def collect(ctx: Context) -> Report:
    """Run every check of the dossier for `ctx` and return the report (no file is written here)."""
    items: list[Item] = []
    run_item, run = check_ci_run(ctx)
    items.append(run_item)
    job_items, digests = check_jobs(ctx, run)
    items.extend(job_items)
    items.append(check_digest(ctx, digests))
    items.append(check_attestation(ctx, SLSA_PREDICATE, "attestation_slsa", "SLSA build provenance of the image"))
    items.append(check_attestation(ctx, SBOM_PREDICATE, "attestation_sbom", "SBOM attestation of the image"))
    config_item, rules = check_grype_config(ctx)
    items.append(config_item)
    items.append(check_grype_scan(ctx))
    items.append(check_grype_alerts(ctx, rules))
    items.append(check_required_checks(ctx))
    protection_item, protections = read_protections(ctx)
    if protection_item is not None:
        items.append(protection_item)
    return Report(
        sha=ctx.sha,
        digest=ctx.digest,
        repo=ctx.repo,
        generated_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        items=items,
        informational={"protections": protections},
    )


# ── Output ────────────────────────────────────────────────────────────────────

def to_json(report: Report) -> dict[str, Any]:
    return {
        "schema": 1,
        "sha": report.sha,
        "digest": report.digest,
        "repo": report.repo,
        "generated_at": report.generated_at,
        "verdict": report.verdict,
        "items": [
            {"id": i.id, "title": i.title, "status": i.status, "required": i.required,
             "detail": i.detail, "action": i.action, "evidence": i.evidence}
            for i in report.items
        ],
        "informational": report.informational,
    }


def to_markdown(report: Report) -> str:
    verdict = {"qualified": "QUALIFIED", "incomplete": "NOT QUALIFIED: incomplete",
               "failed": "NOT QUALIFIED: failed"}[report.verdict]
    lines = [
        f"# Release dossier of {report.sha}",
        "",
        f"- Repository: {report.repo}",
        f"- Image digest: {report.digest or 'not given'}",
        f"- Generated: {report.generated_at}",
        f"- Verdict: **{verdict}**",
        "",
        "| Item | Required | Status | Detail |",
        "|---|---|---|---|",
    ]
    for item in report.items:
        detail = item.detail.replace("|", "\\|")
        lines.append(f"| {item.title} | {'yes' if item.required else 'no'} | {item.status} | {detail} |")
    todo = [i for i in report.items if i.status not in OK_STATUSES and i.action]
    if todo:
        lines += ["", "## What to do", ""]
        lines += [f"- **{i.title}** ({i.status}): {i.action}" for i in todo]
    lines += ["", "A tolerated failure is shown as such: it is not a pass. Read-only checks only; "
              "nothing was changed on GitHub.", ""]
    return "\n".join(lines)


def write_report(report: Report, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(to_json(report), indent=2) + "\n", encoding="utf-8")
    (out / "report.md").write_text(to_markdown(report), encoding="utf-8")


def main(argv: list[str] | None = None, gh: GhCall = run_gh) -> int:
    parser = argparse.ArgumentParser(description="Check the delivery proofs of a candidate commit (docs/releasing.md).")
    parser.add_argument("sha", help="the full commit SHA of main that is the candidate")
    parser.add_argument("--digest", help="the image digest the candidate is released as (sha256:<64 hex>)")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="OWNER/NAME (default: %(default)s)")
    parser.add_argument("--ruleset", default=DEFAULT_RULESET, help="the branch ruleset whose required checks apply")
    parser.add_argument("--root", type=Path, default=ROOT,
                        help="the repository whose .grype.yaml and SECURITY.md are read")
    parser.add_argument("--out", type=Path,
                        help="where report.json and report.md go (default: output/release-dossier/<UTC time>)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # --help exits 0, a usage error 2
        return exc.code if isinstance(exc.code, int) else 2
    if not _SHA.fullmatch(args.sha):
        print("the commit must be a full 40-character lowercase SHA", file=sys.stderr)
        return 2
    try:
        validate_candidate_digest(args.digest)
    except DossierError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    ctx = Context(sha=args.sha, digest=args.digest, repo=args.repo, gh=gh, root=args.root, ruleset=args.ruleset)
    report = collect(ctx)
    out = args.out or (args.root / "output" / "release-dossier"
                       / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    write_report(report, out)
    print(f"{report.verdict}: {report.sha} ({len([i for i in report.items if i.status not in OK_STATUSES])} item(s) "
          f"not passing). Report: {out}")
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
