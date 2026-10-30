#!/usr/bin/env python3
"""Judge the stage report of a job for `docker_smoke.sh --job` (step 14).

A job that finishes with its LLM or its models missing degrades without an
error, so the smoke test asks whether the stages it names ran. The job's
stage report (ADR-0059) has one entry per stage, `{"stage", "status", "reason",
...}`, the dict form of `StageOutcome` (pipeline/orchestrator.py). This script
reads that report and nothing else, so it runs with the host's bare python3:
no venv, no import from the project.

Usage (from the repository root, as docker_smoke.sh runs it):
    python3 scripts/smoke_stage_report.py "2c 2d 2e 3" < stage_report.json

argv[1]: the stages that must have run (SMOKE_REQUIRED_STAGES).
stdin: the report as JSON, a list of stage entries, or null when the job recorded none.
Prints one `stage <id>: <status>` line per stage and one `problem: ...` line per
problem; exit status 1 when there is any problem, 0 otherwise.
"""
from __future__ import annotations

import json
import sys


def judge(report: object, required: list[str]) -> tuple[list[str], list[str]]:
    """The lines to print for `report`, and its problems, given the stages that must have run."""
    if not isinstance(report, list) or not report or not all(isinstance(e, dict) for e in report):
        return [], ["no stage report for this job (missing, empty or unreadable)"]

    # One row per stage, with its reason on one line.
    rows = [(str(e.get("stage")), str(e.get("status")), " ".join(str(e.get("reason") or "").split()))
            for e in report]
    lines = []
    for stage, status, reason in rows:
        detail = " (" + reason + ")" if reason else ""
        lines.append(f"stage {stage}: {status}{detail}")

    problems = []
    # A failed stage is a problem wherever it is; a required one is reported below.
    for stage, status, reason in rows:
        if status == "failed" and stage not in required:
            problems.append(f"stage {stage} failed: {reason}")
    for name in required:
        found = [row for row in rows if row[0] == name]
        if not found:
            problems.append(f"required stage {name} is missing from the report")
        for _, status, reason in found:
            # It ran, or the configuration turned it off; a skip for any other reason is a problem.
            if status == "ran" or (status == "skipped" and reason.startswith("disabled")):
                continue
            problems.append(f"required stage {name} did not run: {status} ({reason})")
    return lines, problems


def main() -> int:
    required = sys.argv[1].split()
    try:
        report = json.load(sys.stdin)
    except ValueError:
        report = None
    lines, problems = judge(report, required)
    for line in lines:
        print(line)
    for problem in problems:
        print("problem: " + problem)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
