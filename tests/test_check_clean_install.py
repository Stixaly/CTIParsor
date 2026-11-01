"""scripts/check_clean_install.sh: the clean install from the published image,
bound to the documentation it runs (ADR-0094 item 9).

The check itself needs Docker, two images and the network: it is a release
step (docs/releasing.md, TESTING.md), never run here.  These tests hold what
can drift without it: the blocks of the documentation the check reads, their
values lines and download URLs, what no block may do, the options and the
guards (a fake `docker`, as tests/test_smoke_project_guard.py uses), the
`docker` wrapper the documented commands go through, the report, and that no
maintainer's path is left in a public document.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from scripts import clean_install_journey as journey

ROOT = Path(__file__).resolve().parent.parent
CHECK = ROOT / "scripts" / "check_clean_install.sh"
RELEASES = "https://github.com/Stixaly/CTIParsor/releases/download/"
DIGEST_0_2_0 = "sha256:f7ea0d3f9d44692b8b08ed31dae5b1738ab19a88bc1cce856d7a297320c95526"
CANDIDATE = "ghcr.io/stixaly/ctiparsor@sha256:" + "0" * 64
TOOLS = ("bash", "curl", "git", "tar", "sha256sum", "free", "df", "python3")

needs_tools = pytest.mark.skipif(not all(shutil.which(t) for t in TOOLS),
                                 reason="needs " + ", ".join(TOOLS) + ", as the check does")


# ── The documentation's blocks ────────────────────────────────────────────────

def _printed() -> dict[str, tuple[str, list[str]]]:
    """--print-blocks, parsed: name -> (file, lines)."""
    done = subprocess.run(["bash", str(CHECK), "--print-blocks"], capture_output=True, text=True, timeout=60,
                          env={**os.environ, "PYTHON": shutil.which("python3") or "python3"})
    assert done.returncode == 0, done.stderr
    out: dict[str, tuple[str, list[str]]] = {}
    name = ""
    for line in done.stdout.splitlines():
        head = re.match(r"^== (\w+) \((.+)\)$", line)
        if head:
            name = head.group(1)
            out[name] = (head.group(2), [])
        else:
            out[name][1].append(line)
    return out


@needs_tools
def test_the_check_runs_every_block_where_the_docs_write_it():
    printed = _printed()
    blocks = journey.read_blocks()
    assert sorted(printed) == sorted(journey.BLOCKS) == sorted(blocks)
    assert {name: lines for name, (_, lines) in printed.items()} == blocks
    assert {name: rel for name, (rel, _) in printed.items()} == {
        "INSTALL_FILES": "README.md", "INSTALL_START": "README.md",
        "RESTART_COMMANDS": "docs/docker.md", "STOP_START_COMMANDS": "docs/docker.md",
        "BACKUP_COMMANDS": "docs/docker.md", "CHECK_COMMANDS": "docs/docker.md",
        "RESTORE_COMMANDS": "docs/docker.md", "UPGRADE_COMMANDS": "docs/upgrading.md"}


def test_a_missing_or_doubled_block_stops_the_check(tmp_path):
    for rel in set(journey.BLOCKS.values()):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, tmp_path / rel)
    readme = tmp_path / "README.md"
    text = readme.read_text(encoding="utf-8")
    readme.write_text(text.replace("<!-- scripts/check_clean_install.sh: INSTALL_START -->\n", ""), encoding="utf-8")
    with pytest.raises(journey.Refused, match="0 block"):
        journey.read_blocks(tmp_path)
    readme.write_text(text + "\n<!-- scripts/check_clean_install.sh: INSTALL_START -->\n```bash\ntrue\n```\n",
                      encoding="utf-8")
    with pytest.raises(journey.Refused, match="2 block"):
        journey.read_blocks(tmp_path)
    readme.write_text(text.replace("version=0.2.0 digest=", "version=0.2.0 hash="), encoding="utf-8")
    with pytest.raises(journey.Refused, match="values line"):
        journey.read_blocks(tmp_path)


def test_the_values_lines_name_the_latest_release_and_its_digest():
    blocks = journey.read_blocks()
    install = dict(w.split("=", 1) for w in blocks["INSTALL_FILES"][0].split())
    upgrade = dict(w.split("=", 1) for w in blocks["UPGRADE_COMMANDS"][0].split())
    # The README installs the latest release; the upgrade's example moves to it.
    assert install == {"version": "0.2.0", "digest": DIGEST_0_2_0}
    assert upgrade == {"old": "0.1.0", "new": install["version"], "digest": install["digest"]}
    # docker.md names the same digest for that release.
    docker = (ROOT / "docs" / "docker.md").read_text(encoding="utf-8")
    assert f"0.2.0, the latest release, is the image of commit ce59cfb, digest\n`{DIGEST_0_2_0}`" in docker


#: What no block may do: delete data, name a project (`-p X`, `-pX`, `-p=X`), run as root, or bypass the
#: `docker` the check puts first on the PATH (an absolute path to it).
FORBIDDEN = re.compile(r"down\s+(-v|--volumes)|volume\s+(rm|remove)|prune|(^|\s)-p|--project-name|COMPOSE_PROJECT_NAME"
                       r"|--rmi|\bsudo\b|(^|[\s(;&|])/\S*docker\b")


def test_no_block_deletes_data_or_names_a_project():
    for name, lines in journey.read_blocks().items():
        for line in lines:
            assert not FORBIDDEN.search(line), f"{name}: {line}"


@pytest.mark.parametrize(("line", "forbidden"), [
    ("docker compose -p ctiparsor up -d", True),
    ("docker compose -pctiparsor up -d", True),
    ("docker compose -p=ctiparsor up -d", True),
    ("docker compose --project-name ctiparsor up -d", True),
    ("sudo docker compose up -d", True),
    ("/usr/bin/docker compose up -d", True),
    ("(umask 077; /usr/bin/docker compose ps)", True),
    ("docker volume rm x", True),
    ("docker volume remove x", True),
    ("docker compose down -v", True),
    ("docker compose --profile bootstrap run --rm bootstrap", False),
    ("docker compose up -d --wait postgres", False),
    ("curl -fsSLO https://github.com/Stixaly/CTIParsor/releases/download/v$new/SHA256SUMS", False),
])
def test_the_forbidden_pattern_sees_what_it_is_there_for(line, forbidden):
    assert bool(FORBIDDEN.search(line)) is forbidden


def test_the_downloads_come_from_the_releases_page_the_check_stands_in_for():
    blocks = journey.read_blocks()
    for name, var in (("INSTALL_FILES", "version"), ("UPGRADE_COMMANDS", "new")):
        curls = [line for line in blocks[name] if line.startswith("curl ")]
        assert curls == [f"curl -fsSLO {RELEASES}v${var}/ctiparsor-${var}.tar.gz",
                         f"curl -fsSLO {RELEASES}v${var}/SHA256SUMS"], name
        assert "sha256sum -c --ignore-missing SHA256SUMS" in blocks[name]
        assert blocks[name][-1 if name == "INSTALL_FILES" else -4] == \
            'echo "CTI_IMAGE=ghcr.io/stixaly/ctiparsor@$digest" >> .env'
    script = CHECK.read_text(encoding="utf-8")
    assert f"RELEASES={RELEASES}\n" in script
    assert r"s#https://github\.com/Stixaly/CTIParsor/releases/download/#file://$STANDIN/#g" in script
    # Every block that starts the stack pulls by digest first; none builds.
    for name in ("INSTALL_START", "UPGRADE_COMMANDS"):
        lines = blocks[name]
        assert lines.index("docker compose pull") < lines.index("docker compose up -d"), name
        assert not any("build" in line.split() for line in lines), name


@needs_tools
def test_the_backup_leaves_the_shell_s_umask_and_its_files_private(tmp_path):
    """The block runs as a shell runs it; `docker` answers every call with a line."""
    fake = tmp_path / "bin" / "docker"
    fake.parent.mkdir()
    fake.write_text("#!/usr/bin/env bash\necho fake-output\n")
    fake.chmod(0o755)
    lines = journey.read_blocks()["BACKUP_COMMANDS"]
    script = "umask 022\n" + "\n".join(lines) + '\necho "umask after: $(umask)"\n'
    done = subprocess.run(["bash", "-c", script], cwd=tmp_path, capture_output=True, text=True, timeout=30,
                          env={"PATH": f"{fake.parent}:{os.environ['PATH']}", "HOME": str(tmp_path)})
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip().endswith("umask after: 0022")
    written = sorted(p for p in tmp_path.iterdir() if p.is_file())
    assert [p.name.split("-")[0] for p in written] == ["cti", "ctiparsor"]
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in written)


# ── Options and guards ───────────────────────────────────────────────────────

FAKE_DOCKER = """#!/usr/bin/env bash
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$*" in
    "compose version") echo "Docker Compose version v2.40.0"; exit 0 ;;
    "context show") echo "${FAKE_DOCKER_CONTEXT:-default}"; exit 0 ;;
    "info --format "*) echo "$FAKE_DOCKER_ROOT"; exit 0 ;;
    "ps -aq --filter label=com.docker.compose.project=$FAKE_DOCKER_BUSY") echo 0123abcd; exit 0 ;;
    "volume ls -q --filter label=com.docker.compose.project=$FAKE_DOCKER_BUSY_VOLUME") echo vol; exit 0 ;;
    "ps -aq "*|"volume ls "*|"network ls "*) exit 0 ;;
esac
exit 1
"""


def _run(tmp_path: Path, *args: str, busy: str = "", busy_volume: str = "", port: int | None = None,
         extra: dict[str, str] | None = None) -> tuple[int, str, list[str]]:
    fake = tmp_path / "fake-docker"
    fake.write_text(FAKE_DOCKER)
    fake.chmod(0o755)
    log = tmp_path / "docker.log"
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "TMPDIR": str(tmp_path), "DOCKER_BIN": str(fake),
           "FAKE_DOCKER_LOG": str(log), "FAKE_DOCKER_ROOT": str(tmp_path), "FAKE_DOCKER_BUSY": busy or "-",
           "FAKE_DOCKER_BUSY_VOLUME": busy_volume or "-", "CLEAN_INSTALL_MIN_AVAILABLE_MB": "0",
           "CLEAN_INSTALL_MIN_DISK_GB": "0", "CLEAN_INSTALL_PORT": str(port or _free_port()), **(extra or {})}
    done = subprocess.run(["bash", str(CHECK), *args], cwd=tmp_path, env=env, capture_output=True, text=True,
                          timeout=120)
    calls = log.read_text().splitlines() if log.exists() else []
    return done.returncode, done.stdout + done.stderr, calls


def _free_port() -> int:
    """A port with nothing on it, and nothing on the next one (the restored project's)."""
    for _ in range(50):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port + 1)) != 0:
                return port
    raise AssertionError("no free pair of ports")


@needs_tools
def test_help_and_bad_options(tmp_path):
    code, out, _ = _run(tmp_path, "--help")
    assert code == 0 and out.startswith("The clean install from the published image (ADR-0094 item 9)")
    code, out, _ = _run(tmp_path, "--frobnicate")
    assert code == 2 and "unknown option --frobnicate" in out
    code, out, calls = _run(tmp_path)
    assert code == 2 and "give --candidate REF" in out and calls == []
    code, out, _ = _run(tmp_path, "--candidate", CANDIDATE, "--previous", "0.2.0")
    assert code == 2 and "--previous is VERSION@sha256:" in out


@needs_tools
def test_another_docker_context_or_a_docker_host_stops_the_check(tmp_path):
    """The blocks run with a new HOME, so under the default context: the check's own calls must too."""
    code, out, calls = _run(tmp_path, "--candidate", CANDIDATE, extra={"FAKE_DOCKER_CONTEXT": "desktop-linux"})
    assert code == 2 and "Docker's context is desktop-linux" in out
    code, out, calls = _run(tmp_path, "--candidate", CANDIDATE, extra={"DOCKER_HOST": "tcp://203.0.113.1:2375"})
    assert code == 2 and "DOCKER_HOST is set (tcp://203.0.113.1:2375)" in out
    assert "context show" in calls
    assert not any(c.startswith(("pull", "image inspect", "ps ", "volume ")) for c in calls)   # it went no further


@needs_tools
@pytest.mark.parametrize("project", ["ctiparsor-clean-install", "ctiparsor-clean-install-restored"])
def test_a_project_left_by_another_run_stops_the_check(tmp_path, project):
    code, out, calls = _run(tmp_path, "--candidate", CANDIDATE, busy=project)
    assert code == 2 and f"the Compose project {project} exists" in out
    code, out, calls = _run(tmp_path, "--candidate", CANDIDATE, busy_volume=project)
    assert code == 2 and f"the Compose project {project} exists" in out
    assert not any(c.startswith(("compose ", "pull", "rm", "volume rm")) and "version" not in c for c in calls)


@needs_tools
def test_a_directory_left_by_a_killed_run_stops_the_check(tmp_path):
    (tmp_path / "ctiparsor-clean-install.Ab12Cd").mkdir()
    code, out, _ = _run(tmp_path, "--candidate", CANDIDATE)
    assert code == 2 and "ctiparsor-clean-install.Ab12Cd is left from an earlier run" in out


@needs_tools
def test_a_busy_port_stops_the_check(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        code, out, _ = _run(tmp_path, "--candidate", CANDIDATE, port=s.getsockname()[1])
    assert code == 2 and "is in use: set CLEAN_INSTALL_PORT" in out


@needs_tools
def test_a_candidate_that_cannot_be_pulled_leaves_nothing_behind(tmp_path):
    out_dir = tmp_path / "report"
    code, out, calls = _run(tmp_path, "--candidate", CANDIDATE, "--out", str(out_dir))
    assert code == 2 and f"cannot pull {CANDIDATE}" in out
    assert [c for c in calls if c.startswith(("image inspect", "pull"))] == [
        f"image inspect {CANDIDATE}", f"pull {CANDIDATE}"]
    assert not any(c.startswith("compose ") and c != "compose version" for c in calls)     # nothing was created
    assert not list(tmp_path.glob("ctiparsor-clean-install.*"))                          # its directory removed
    assert (out_dir / "logs" / "candidate-pull.log").exists()


# ── The wrapper the documented commands go through ───────────────────────────

@needs_tools
@pytest.mark.parametrize(("project", "args", "allowed"), [
    ("ctiparsor-clean-install", "compose up -d", True),
    ("ctiparsor-clean-install", "compose --profile bootstrap run --rm bootstrap", True),
    ("ctiparsor-clean-install-restored", "compose up -d --wait postgres", True),
    ("ctiparsor-clean-install", "compose down", True),
    ("ctiparsor-clean-install", "compose version --short", True),
    # What setup.sh calls beside compose, and nothing else
    ("ctiparsor-clean-install", "info", True),
    ("ctiparsor-clean-install", "--version", True),
    ("ctiparsor-clean-install", "info --format {{.Name}}", False),
    ("ctiparsor", "compose up -d", False),
    (None, "compose ps", False),
    ("ctiparsor-clean-install", "compose -p ctiparsor down", False),
    ("ctiparsor-clean-install", "compose -pctiparsor down", False),
    ("ctiparsor-clean-install", "compose -p=ctiparsor down", False),
    ("ctiparsor-clean-install", "compose --project-name=ctiparsor ps", False),
    ("ctiparsor-clean-install", "compose --project-name ctiparsor ps", False),
    ("ctiparsor-clean-install", "compose up -d -p ctiparsor", False),         # a global option after the subcommand
    ("ctiparsor-clean-install", "compose down -v", False),
    ("ctiparsor-clean-install", "compose --profile x down --volumes", False),
    ("ctiparsor-clean-install", "compose down --rmi all", False),
    # Anything that is not `docker compose`, the allowlist's first word
    ("ctiparsor-clean-install", "-D compose up -d", False),
    ("ctiparsor-clean-install", "--context other compose up -d", False),
    ("ctiparsor-clean-install", "volume rm ctiparsor_pg-data-18", False),
    ("ctiparsor-clean-install", "volume remove ctiparsor_pg-data-18", False),
    ("ctiparsor-clean-install", "rm -f ctiparsor-postgres-1", False),
    ("ctiparsor-clean-install", "run -v ctiparsor_pg-data-18:/v alpine rm -rf /v", False),
    ("ctiparsor-clean-install", "system prune -af", False),
])
def test_the_wrapper_lets_through_the_run_s_projects_only(tmp_path, project, args, allowed):
    real = tmp_path / "real-docker"
    real.write_text('#!/usr/bin/env bash\necho "$*" >> "$REAL_LOG"\n')
    real.chmod(0o755)
    done = subprocess.run(["bash", str(CHECK), "--print-wrapper"], capture_output=True, text=True, timeout=60,
                          env={"PATH": os.environ["PATH"], "DOCKER_BIN": str(real)})
    assert done.returncode == 0, done.stderr
    wrapper = tmp_path / "docker"
    wrapper.write_text(done.stdout)
    wrapper.chmod(0o755)
    env = {"PATH": os.environ["PATH"], "REAL_LOG": str(tmp_path / "real.log")}
    if project:
        env["COMPOSE_PROJECT_NAME"] = project
    ran = subprocess.run([str(wrapper), *args.split()], env=env, capture_output=True, text=True, timeout=30)
    logged = (tmp_path / "real.log").read_text().splitlines() if (tmp_path / "real.log").exists() else []
    if allowed:
        assert ran.returncode == 0 and logged == [args]
    else:
        assert ran.returncode == 97 and logged == [] and "refused" in ran.stderr


def test_every_documented_command_runs_without_the_caller_s_environment():
    script = CHECK.read_text(encoding="utf-8")
    assert re.search(r'^CLEAN_ENV=\(env -i "PATH=\$TMP/bin:[^"]*" "HOME=\$TMP/home"', script, re.M)
    runs = [line for line in script.splitlines() if "runner.sh" in line and not line.lstrip().startswith("#")
            and "cat >" not in line]
    assert runs and all(line.lstrip().startswith('"${CLEAN_ENV[@]}"') for line in runs)
    own = re.search(r"^in_project\(\) \{.*?\n(.*?)\n\}", script, re.M | re.S)
    assert own and own.group(1).strip().startswith('"${CLEAN_ENV[@]}" "$DOCKER_PATH" compose -p "$1"')


# ── The steps that judge a run ───────────────────────────────────────────────

def _verdict_of_report_b(tmp_path: Path, *, quick: bool, before: str, statuses: list[str], final: str,
                         log: str = "") -> str:
    """The script's own lines that judge report B, run with `step` printing PASS|FAIL|INFO and the detail."""
    lines = CHECK.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("# Was B put back in the queue?"))
    end = next(i for i, line in enumerate(lines) if line.startswith("run_block STOP_START_COMMANDS"))
    (tmp_path / "logs").mkdir(exist_ok=True)
    (tmp_path / "logs" / "restart-app-worker.log").write_text(log, encoding="utf-8")
    (tmp_path / "B.meta.json").write_text(json.dumps(
        {"timeline": [{"status": s, "at_s": float(n)} for n, s in enumerate(statuses)]}), encoding="utf-8")
    script = ("set -u\nstep() { echo \"$2|$4\"; }\n" + "\n".join(lines[start:end]) + "\n")
    done = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30, env={
        "PATH": os.environ["PATH"], "PYTHON": shutil.which("python3") or "python3", "OUT": str(tmp_path),
        "QUICK": "1" if quick else "0", "B_BEFORE": before, "B_FINAL": final})
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


DRAINED = "worker-1  | 2026-11-01T10:00:09Z Drain timeout: 1 job(s) still running, requeued"


@needs_tools
@pytest.mark.parametrize(("quick", "before", "statuses", "final", "log", "result", "detail"), [
    # Put back in the queue, seen in the timeline or in the worker's log: the step passes
    (False, "processing", ["processing", "queued", "processing", "for_review"], "for_review", "", "PASS",
     "queued after processing in its timeline"),
    (False, "processing", ["processing", "(API not answering)", "processing", "for_review"], "for_review", DRAINED,
     "PASS", "the worker's drain timed out and requeued it"),
    (True, "processing", ["processing", "queued", "processing", "for_review"], "for_review", "", "PASS", "requeued"),
    # Readable at the end but never put back (it finished before or during the drain): the gate fails
    (False, "processing", ["processing", "for_review"], "for_review", "", "FAIL", "NOT requeued"),
    (False, "processing", ["queued", "processing", "for_review"], "for_review", "", "FAIL", "NOT requeued"),
    (False, "reviewing", ["reviewing"], "reviewing", "", "FAIL", "status reviewing at the restart"),
    (False, "processing", ["processing", "failed"], "failed", DRAINED, "FAIL", "requeued"),
    # --quick is not the gate: the same facts, as INFO, unless B did not end readable
    (True, "processing", ["processing", "for_review"], "for_review", "", "INFO", "NOT requeued"),
    (True, "queued", ["queued", "processing", "for_review"], "for_review", DRAINED, "INFO", "status queued"),
    (True, "processing", ["processing", "failed"], "failed", DRAINED, "FAIL", "requeued"),
])
def test_report_b_passes_only_when_it_was_requeued_and_ended_readable(
        tmp_path, quick, before, statuses, final, log, result, detail):
    verdict = _verdict_of_report_b(tmp_path, quick=quick, before=before, statuses=statuses,
                                   final=f"{final} after 30 s: x", log=log)
    assert verdict.startswith(f"{result}|") and detail in verdict, verdict


def test_report_a_is_compared_by_status_and_by_sha256_every_time():
    script = CHECK.read_text(encoding="utf-8")
    compared = [line for line in script.splitlines() if " bundle --api" in line]
    assert len(compared) == 3 and all(
        '--expect-sha256 "$A_SHA" --expect-status "$A_STATUS"' in line for line in compared), compared


def test_bundle_fails_on_a_different_status_as_well_as_on_a_different_sha256(tmp_path, monkeypatch):
    monkeypatch.setattr(journey, "bundle_of", lambda api, job_id: {"job_id": job_id, "status": "completed",
                                                                     "sha256": "ab" * 32})
    out = tmp_path / "A.meta.json"

    def bundle(*expect: str) -> int:
        return journey.main(["bundle", "--api", "http://127.0.0.1:1", "--job", "j", "--out", str(out), *expect])

    assert bundle("--expect-sha256", "ab" * 32, "--expect-status", "completed") == 0
    assert bundle("--expect-sha256", "ab" * 32, "--expect-status", "for_review") == 1
    assert bundle("--expect-sha256", "cd" * 32, "--expect-status", "completed") == 1
    assert bundle("--expect-sha256", "ab" * 32) == 0
    assert bundle() == 0


# ── The report ───────────────────────────────────────────────────────────────

def test_the_report_says_what_failed_and_that_quick_is_not_the_gate(tmp_path):
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "01-INSTALL_START.times").write_text(
        "0\t12.5\tdocker compose pull\n0\t3.0\tdocker compose up -d\n", encoding="utf-8")
    (tmp_path / "steps.tsv").write_text("INSTALL_START\tPASS\t16\t3 line(s)\nreport A\tFAIL\t40\tunknown\n",
                                        encoding="utf-8")
    (tmp_path / "run.json").write_text(json.dumps({"mode": "quick", "previous": {"release": "0.2.0@sha256:x"}}),
                                       encoding="utf-8")
    report = journey.summary(tmp_path)
    assert report["result"] == "FAIL"
    assert report["commands"][0] == {"block": "INSTALL_START", "exit": 0, "seconds": 12.5,
                                     "command": "docker compose pull"}
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert md.startswith("# Clean install: FAIL") and "This run is not the release gate." in md


# ── No maintainer's path in a public document ────────────────────────────────

def test_no_public_document_names_a_maintainer_s_machine():
    listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--", "*.md", ".env.example"],
                            capture_output=True, text=True)
    if listed.returncode != 0:
        pytest.skip("not a git checkout")
    # A checkout in someone's Windows profile, seen from WSL or from Windows; the
    # `C:\Users\Public` of a report's example, or a redacted profile, is not one.
    private = re.compile(r"/mnt/c/Users/|[Cc]:\\[Uu]sers\\(?!Public\b|\[redacted\])")
    found = [f"{rel}:{n}" for rel in listed.stdout.splitlines()
             for n, line in enumerate((ROOT / rel).read_text(encoding="utf-8").splitlines(), 1)
             if private.search(line)]
    assert found == []
