"""scripts/smoke_stage_report.py: the stage report of a job, judged for docker_smoke.sh --job.

judge() is given reports shaped as the pipeline writes them (pipeline/orchestrator.py,
StageOutcome, ADR-0059). main() runs as a subprocess, as docker_smoke.sh runs it.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import smoke_stage_report as ssr

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "smoke_stage_report.py"
REQUIRED = "2c 2d 2e 3"


def row(stage, status, reason=""):
    return {"stage": stage, "status": status, "reason": reason, "seconds": 0.0, "counts": {}}


def run_main(stdin):
    return subprocess.run([sys.executable, str(SCRIPT), REQUIRED], input=stdin,
                          capture_output=True, text=True, check=False)


def test_every_stage_ran_has_no_problem():
    report = [row("1", "ran"), row("2c", "ran"), row("2d", "ran"), row("2e", "ran"), row("3", "ran")]

    lines, problems = ssr.judge(report, REQUIRED.split())

    assert problems == []
    assert lines == ["stage 1: ran", "stage 2c: ran", "stage 2d: ran", "stage 2e: ran", "stage 3: ran"]


def test_required_stage_skipped_for_the_llm_is_a_problem_that_names_it():
    report = [row("2c", "ran"), row("2d", "ran"), row("2e", "ran"),
              row("3", "skipped", "LLM provider not ready (Anthropic/x)")]

    _, problems = ssr.judge(report, REQUIRED.split())

    assert problems == ["required stage 3 did not run: skipped (LLM provider not ready (Anthropic/x))"]


def test_required_stage_turned_off_by_the_configuration_is_accepted():
    _, problems = ssr.judge([row("2d", "skipped", "disabled")], ["2d"])

    assert problems == []


def test_disabled_3d_with_its_reason_is_accepted_when_required():
    report = [row("3d", "skipped", "disabled: the LLM's techniques ship unchecked")]

    _, problems = ssr.judge(report, ["3d"])

    assert problems == []


def test_failed_stage_outside_the_required_list_is_a_problem_with_its_reason_on_one_line():
    report = [row("2c", "ran"), row("4b", "failed", "graph\ncompletion   crashed")]

    lines, problems = ssr.judge(report, ["2c"])

    assert problems == ["stage 4b failed: graph completion crashed"]
    assert lines[1] == "stage 4b: failed (graph completion crashed)"


def test_failed_required_stage_is_reported_once():
    _, problems = ssr.judge([row("3", "failed", "every extraction call failed")], ["3"])

    assert problems == ["required stage 3 did not run: failed (every extraction call failed)"]


def test_required_stage_absent_from_the_report_is_a_problem():
    _, problems = ssr.judge([row("2c", "ran")], ["2c", "3"])

    assert problems == ["required stage 3 is missing from the report"]


@pytest.mark.parametrize("report", [None, [], {"stage": "3", "status": "ran"}, "ran",
                                    [{"stage": "3", "status": "ran"}, "3"]])
def test_no_usable_report_is_one_problem(report):
    lines, problems = ssr.judge(report, ["3"])

    assert lines == []
    assert problems == ["no stage report for this job (missing, empty or unreadable)"]


def test_a_null_reason_prints_no_detail():
    lines, problems = ssr.judge([{"stage": "3", "status": "ran", "reason": None}], ["3"])

    assert lines == ["stage 3: ran"] and problems == []


def test_main_exits_0_and_prints_a_stage_line_when_nothing_is_wrong():
    report = [row("2c", "ran"), row("2d", "ran"), row("2e", "ran"), row("3", "ran")]

    proc = run_main(json.dumps(report))

    assert proc.returncode == 0
    assert "stage 3: ran" in proc.stdout.splitlines()
    assert "problem:" not in proc.stdout


def test_main_reads_invalid_json_as_no_report_and_exits_1():
    proc = run_main("{not json")

    assert proc.returncode == 1
    assert proc.stdout.splitlines() == ["problem: no stage report for this job (missing, empty or unreadable)"]
