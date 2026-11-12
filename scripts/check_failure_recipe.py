"""The load and failure recipe on a running Compose stack (ADR-0097 item 23).

    python scripts/check_failure_recipe.py --base-url http://127.0.0.1:8000 \\
        --i-know-this-stops-services [--compose-file compose.yaml] [--case NAME ...] \\
        [--report-dir output/failure-recipe/<UTC time>] [--wait-s 1200]

Five cases make one failure each and check what the service did about it:

- worker-killed: a worker is killed in the middle of a report. The job must
  end in a terminal status (never stuck in `processing`), be claimed again
  after the lease expires, exist once, and the queue must recover in /metrics.
- llm-down: the worker runs with an LLM endpoint that refuses connections
  (127.0.0.1:9). The job must end, Stage 3 must be recorded as failed or
  skipped with a reason, and the API must stay healthy.
- database-down: `postgres` is stopped. /api/health must answer 503, and
  `ctiparsor_database_up` must be 0 for the rule's `for:` duration. After the
  start, the jobs table must hold the same job ids as before.
- disk-nearly-full: `app` runs with UPLOAD_MIN_FREE_MB above the free space.
  An upload must get 507 and write nothing. The disk alert's condition must be
  true on /metrics for the rule's `for:` duration.
- restore-drill: the backup commands of docs/docker.md run as written, then the
  restore commands run into an empty database, and the job rows and a few
  files of the archive are compared with the source. The duration of the
  restore is recorded.

The alert conditions are read from docs/monitoring/ctiparsor.rules.yml, not
copied here. A form that the small evaluator below cannot read (`delta()`
over a range, for one) is reported as "not checked", never as passed.

Every case restores the stack afterwards: `app`, `worker` and `postgres` run
again with the configuration of `.env`. The run stops services, so it takes an
explicit flag, and it refuses a base URL that is not on loopback. Standard
library only. Run it from WSL, where the Docker CLI is. The report holds no
secret: the database password is read inside the container and is never
printed, and METRICS_TOKEN (read from the environment) is never written.

Exit 0 when every selected case passed, 1 when one did not, 2 on a usage or
environment error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shlex
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = ROOT / "docs" / "monitoring" / "ctiparsor.rules.yml"
DEFAULT_COMPOSE = ROOT / "compose.yaml"
FIXTURE = ROOT / "tests" / "fixtures" / "sample_report.txt"
MIB = 1024 * 1024
GIB = 1024 * MIB
TERMINAL = ("completed", "for_review", "failed")
CASE_ORDER = ("worker-killed", "llm-down", "database-down", "disk-nearly-full", "restore-drill")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
LLM_REFUSING_URL = "http://127.0.0.1:9"
TOKEN_ENV = "METRICS_TOKEN"  # noqa: S105 - the name of the variable, not a secret

# The commands of docs/docker.md ("Data and backups"), character for character:
# tests/test_failure_recipe.py fails when these and the documented blocks differ.
# YYYY-MM-DD-HHMMSS stands for the stamp of the backup's file names.
BACKUP_COMMANDS = [
    "stamp=$(date +%F-%H%M%S)",
    "docker compose stop app worker",
    "(umask 077; docker compose exec -T postgres sh -c 'PGPASSWORD=\"$(cat /run/secrets/db_password)\" exec \"$@\"' "
    "sh pg_dump -U ctiparsor -d ctiparsor -Fc > ctiparsor-$stamp.dump)",
    "(umask 077; docker compose run --rm --no-deps -T --entrypoint tar app czf - -C /app/state . > "
    "cti-state-$stamp.tgz)",
    "docker compose start app worker",
]
CHECK_COMMANDS = [
    "(set -o pipefail; docker compose exec -T postgres pg_restore -l < ctiparsor-YYYY-MM-DD-HHMMSS.dump "
    "| grep -c 'TABLE DATA')",
    "(set -o pipefail; tar tzf cti-state-YYYY-MM-DD-HHMMSS.tgz | grep -c '^./uploads/.')",
]
# The documented restore line, with its target database named by the drill.
RESTORE_PG_LINE = (
    "docker compose exec -T postgres sh -c 'PGPASSWORD=\"$(cat /run/secrets/db_password)\" exec \"$@\"' sh "
    "pg_restore -U {user} -d {database} --single-transaction < ctiparsor-YYYY-MM-DD-HHMMSS.dump"
)


class StepError(Exception):
    """A command or request that failed or timed out. The case that raised it stops."""


class NotEvaluable(Exception):
    """An expression form this evaluator does not read. It is reported as not checked."""


# ── The alert rules ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Rule:
    name: str
    expr: str
    for_seconds: int | None
    severity: str
    runbook: str

    @property
    def for_label(self) -> str:
        if self.for_seconds is None:
            return "none"
        return f"{self.for_seconds} s"


_DURATION = re.compile(r"^(\d+)([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _seconds(number: str, unit: str) -> int:
    return int(number) * _UNIT_SECONDS[unit]


def load_rules(path: Path = RULES_FILE) -> list[Rule]:
    """The alert rules of the Prometheus rules file.

    A reader for the shape this file uses (one `- alert:` per rule, plain
    `expr:`, `for:`, `severity:` and `runbook:` lines), so the check needs no
    YAML library. A rule without an `expr:` is an error.
    """
    rules: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        start = re.match(r"^\s*-\s+alert:\s*(\S+)\s*$", raw)
        if start:
            current = {"name": start.group(1), "for_seconds": None, "severity": "", "runbook": ""}
            rules.append(current)
            continue
        if current is None:
            continue
        key = re.match(r"^\s+(expr|for|severity|runbook):\s*(.*?)\s*$", raw)
        if not key:
            continue
        field_name, value = key.group(1), key.group(2)
        if field_name == "expr":
            if value[:1] in ("|", ">") or not value:
                # A block scalar spans several lines this reader does not join:
                # refuse rather than evaluate half an expression.
                raise ValueError(f"{path}: rule {current['name']} has a multi-line expr; "
                                 "write it on one line")
            current["expr"] = value
        elif field_name == "for":
            found = _DURATION.match(value)
            if not found:
                raise ValueError(f"{path}: rule {current['name']} has an unreadable for: {value!r}")
            current["for_seconds"] = _seconds(found.group(1), found.group(2))
        else:
            current[field_name] = value.strip('"')
    out = []
    for item in rules:
        if not item.get("expr"):
            raise ValueError(f"{path}: rule {item['name']} has no expr")
        out.append(Rule(item["name"], item["expr"], item["for_seconds"], item["severity"], item["runbook"]))
    return out


# ── A small evaluator for the expressions of the rules file ──────────────────

Labels = tuple[tuple[str, str], ...]
Series = dict[str, list[tuple[dict[str, str], float]]]

_TOKEN = re.compile(
    r"\s*(?:(?P<num>\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)"
    r"|(?P<str>\"(?:[^\"\\]|\\.)*\")"
    r"|(?P<id>[A-Za-z_:][A-Za-z0-9_:]*)"
    r"|(?P<op>==|!=|<=|>=|=~|!~|[<>=+\-*/(){}\[\],]))"
)
_CMP = ("==", "!=", "<", ">", "<=", ">=")


@dataclass(frozen=True)
class _Num:
    value: float


@dataclass(frozen=True)
class _Sel:
    name: str
    matchers: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class _Range:
    sel: _Sel
    seconds: int


@dataclass(frozen=True)
class _Call:
    name: str
    args: tuple[Any, ...]


@dataclass(frozen=True)
class _Bin:
    op: str
    left: Any
    right: Any


@dataclass(frozen=True)
class _Neg:
    value: Any


def _tokens(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos, text = 0, text.strip()
    while pos < len(text):
        found = _TOKEN.match(text, pos)
        if not found or found.end() == pos:
            raise NotEvaluable(f"cannot read {text[pos:pos + 12]!r}")
        kind = found.lastgroup or ""
        out.append((kind, found.group(kind)))
        pos = found.end()
    return out


class _Parser:
    def __init__(self, text: str) -> None:
        self.tokens = _tokens(text)
        self.at = 0

    def _peek(self, value: str, kind: str | None = None) -> bool:
        if self.at >= len(self.tokens):
            return False
        tok_kind, tok_value = self.tokens[self.at]
        return tok_value == value and (kind is None or tok_kind == kind)

    def _take(self) -> tuple[str, str]:
        if self.at >= len(self.tokens):
            raise NotEvaluable("the expression ends early")
        tok = self.tokens[self.at]
        self.at += 1
        return tok

    def _expect(self, value: str) -> None:
        if not self._peek(value):
            raise NotEvaluable(f"expected {value!r}")
        self.at += 1

    def parse(self) -> Any:
        node = self._or()
        if self.at != len(self.tokens):
            raise NotEvaluable(f"unexpected {self.tokens[self.at][1]!r}")
        return node

    def _or(self) -> Any:
        node = self._and()
        while self._peek("or", "id"):
            self.at += 1
            node = _Bin("or", node, self._and())
        return node

    def _and(self) -> Any:
        node = self._cmp()
        while self._peek("and", "id"):
            self.at += 1
            node = _Bin("and", node, self._cmp())
        return node

    def _cmp(self) -> Any:
        node = self._add()
        for op in _CMP:
            if self._peek(op, "op"):
                self.at += 1
                return _Bin(op, node, self._add())
        return node

    def _add(self) -> Any:
        node = self._mul()
        while self._peek("+", "op") or self._peek("-", "op"):
            op = self._take()[1]
            node = _Bin(op, node, self._mul())
        return node

    def _mul(self) -> Any:
        node = self._unary()
        while self._peek("*", "op") or self._peek("/", "op"):
            op = self._take()[1]
            node = _Bin(op, node, self._unary())
        return node

    def _unary(self) -> Any:
        if self._peek("-", "op"):
            self.at += 1
            return _Neg(self._unary())
        return self._primary()

    def _primary(self) -> Any:
        kind, value = self._take()
        if kind == "num":
            return _Num(float(value))
        if kind == "op" and value == "(":
            node = self._or()
            self._expect(")")
            return node
        if kind != "id":
            raise NotEvaluable(f"unexpected {value!r}")
        if self._peek("(", "op"):
            self.at += 1
            args = []
            if not self._peek(")"):
                args.append(self._or())
                while self._peek(","):
                    self.at += 1
                    args.append(self._or())
            self._expect(")")
            return _Call(value, tuple(args))
        matchers = self._matchers() if self._peek("{", "op") else ()
        sel = _Sel(value, matchers)
        if self._peek("[", "op"):
            self.at += 1
            number = self._take()
            unit = self._take()
            if number[0] != "num" or unit[0] != "id" or unit[1] not in _UNIT_SECONDS:
                raise NotEvaluable("a range must read like [1h]")
            self._expect("]")
            return _Range(sel, _seconds(number[1].split(".")[0], unit[1]))
        return sel

    def _matchers(self) -> tuple[tuple[str, str, str], ...]:
        self._expect("{")
        found = []
        while not self._peek("}"):
            label_kind, label = self._take()
            op_kind, op = self._take()
            value_kind, value = self._take()
            if label_kind != "id" or op_kind != "op" or op not in ("=", "!=", "=~", "!~") or value_kind != "str":
                raise NotEvaluable("a label matcher must read like state=~\"busy|idle\"")
            found.append((label, op, value[1:-1]))
            if self._peek(","):
                self.at += 1
        self._expect("}")
        return tuple(found)


def parse_expr(text: str) -> Any:
    """Parse an alert expression with the recipe's small parser and return the parse tree."""
    return _Parser(text).parse()


def parse_metrics(text: str) -> Series:
    """The series of a Prometheus text exposition, by metric name."""
    sample = re.compile(r"^([A-Za-z_:][A-Za-z0-9_:]*)(\{.*\})?\s+(\S+)(?:\s+\S+)?$")
    label = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"')
    series: Series = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        found = sample.match(line)
        if not found:
            continue
        labels = {
            key: re.sub(r"\\(.)", lambda m: "\n" if m.group(1) == "n" else m.group(1), value)
            for key, value in label.findall(found.group(2) or "")
        }
        series.setdefault(found.group(1), []).append((labels, float(found.group(3))))
    return series


def _labels_key(labels: dict[str, str]) -> Labels:
    return tuple(sorted(labels.items()))


def _select(sel: _Sel, series: Series) -> list[tuple[Labels, float]]:
    out = []
    for labels, value in series.get(sel.name, []):
        keep = True
        for name, op, expected in sel.matchers:
            actual = labels.get(name, "")
            if op == "=":
                keep = actual == expected
            elif op == "!=":
                keep = actual != expected
            elif op == "=~":
                keep = re.fullmatch(expected, actual) is not None
            else:
                keep = re.fullmatch(expected, actual) is None
            if not keep:
                break
        if keep:
            out.append((_labels_key(labels), value))
    return out


def _divide(a: float, b: float) -> float:
    if b == 0:
        if a == 0 or math.isnan(a):
            return math.nan
        return math.copysign(math.inf, a) * math.copysign(1.0, b)
    return a / b


_ARITH: dict[str, Callable[[float, float], float]] = {
    "+": lambda a, b: a + b,
    "-": lambda a, b: a - b,
    "*": lambda a, b: a * b,
    "/": _divide,
}
_COMPARE: dict[str, Callable[[float, float], bool]] = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "<": lambda a, b: a < b,
    ">": lambda a, b: a > b,
    "<=": lambda a, b: a <= b,
    ">=": lambda a, b: a >= b,
}


def _eval(node: Any, series: Series, now: float) -> float | list[tuple[Labels, float]]:
    if isinstance(node, _Num):
        return node.value
    if isinstance(node, _Sel):
        return _select(node, series)
    if isinstance(node, _Range):
        raise NotEvaluable("a range needs samples over time; one scrape holds one value per series")
    if isinstance(node, _Neg):
        value = _eval(node.value, series, now)
        return -value if isinstance(value, float) else [(lab, -v) for lab, v in value]
    if isinstance(node, _Call):
        return _call(node, series, now)
    return _binary(node, series, now)


def _call(node: _Call, series: Series, now: float) -> float | list[tuple[Labels, float]]:
    if node.name == "time":
        if node.args:
            raise NotEvaluable("time() takes no argument")
        return now
    if node.name == "delta":
        raise NotEvaluable("delta() needs samples over a range; one scrape holds one value per series")
    if len(node.args) != 1:
        raise NotEvaluable(f"{node.name}() takes one argument")
    arg = _eval(node.args[0], series, now)
    if node.name == "sum":
        if isinstance(arg, float):
            raise NotEvaluable("sum() needs a series")
        return [((), sum(v for _, v in arg))] if arg else []
    if node.name == "absent":
        if not isinstance(node.args[0], _Sel):
            raise NotEvaluable("absent() takes one metric selector")
        return [((), 1.0)] if not arg else []
    raise NotEvaluable(f"{node.name}() is not a function this check reads")


def _binary(node: _Bin, series: Series, now: float) -> float | list[tuple[Labels, float]]:
    left = _eval(node.left, series, now)
    right = _eval(node.right, series, now)
    op = node.op
    if op in ("or", "and"):
        if not isinstance(left, list) or not isinstance(right, list):
            raise NotEvaluable(f"{op} needs two series")
        right_keys = {lab for lab, _ in right}
        if op == "and":
            return [(lab, v) for lab, v in left if lab in right_keys]
        left_keys = {lab for lab, _ in left}
        return left + [(lab, v) for lab, v in right if lab not in left_keys]
    if op in _ARITH:
        apply = _ARITH[op]
        if isinstance(left, float) and isinstance(right, float):
            return apply(left, right)
        if isinstance(left, list) and isinstance(right, float):
            return [(lab, apply(v, right)) for lab, v in left]
        if isinstance(left, float) and isinstance(right, list):
            return [(lab, apply(left, v)) for lab, v in right]
        if isinstance(left, list) and isinstance(right, list):
            index = dict(right)
            return [(lab, apply(v, index[lab])) for lab, v in left if lab in index]
        raise NotEvaluable(f"{op} cannot combine these values")
    compare = _COMPARE[op]
    if isinstance(left, float) and isinstance(right, float):
        return 1.0 if compare(left, right) else 0.0
    if isinstance(left, list) and isinstance(right, float):
        return [(lab, v) for lab, v in left if compare(v, right)]
    if isinstance(left, float) and isinstance(right, list):
        return [(lab, v) for lab, v in right if compare(left, v)]
    if isinstance(left, list) and isinstance(right, list):
        index = dict(right)
        return [(lab, v) for lab, v in left if lab in index and compare(v, index[lab])]
    raise NotEvaluable(f"{op} cannot compare these values")


@dataclass(frozen=True)
class Reading:
    state: str  # "true", "false" or "not_checked"
    detail: str


def evaluate_rule(rule: Rule, series: Series, now: float) -> Reading:
    """Whether the rule's condition holds on this scrape, as a reading."""
    try:
        result = _eval(parse_expr(rule.expr), series, now)
    except NotEvaluable as exc:
        return Reading("not_checked", f"{rule.name}: {exc}")
    if isinstance(result, float):
        fired = result != 0 and not math.isnan(result)
        return Reading("true" if fired else "false", f"{result:g}")
    fired = bool(result)
    shown = "; ".join(f"{dict(lab) or '{}'} = {v:g}" for lab, v in result[:5])
    return Reading("true" if fired else "false", shown or "no series")


def gauge(series: Series, name: str, **labels: str) -> float | None:
    """The sum of the samples of a metric whose labels match, None when absent."""
    values = [v for lab, v in series.get(name, []) if all(lab.get(k) == v2 for k, v2 in labels.items())]
    return sum(values) if values else None


# ── Reports ───────────────────────────────────────────────────────────────────


@dataclass
class Check:
    name: str
    status: str  # "pass", "fail" or "not_checked"
    detail: str = ""


@dataclass
class CaseReport:
    name: str
    status: str = "pending"  # passed, failed, not_checked or error
    checks: list[Check] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    seconds: float = 0.0
    error: str = ""

    def settle(self) -> None:
        if self.error:
            self.status = "error"
        elif any(c.status == "fail" for c in self.checks):
            self.status = "failed"
        elif any(c.status == "not_checked" for c in self.checks):
            self.status = "not_checked"
        elif self.checks:
            self.status = "passed"
        else:
            self.status = "error"
            self.error = "no check ran"


def tail(text: str, lines: int = 12) -> str:
    """Return the last lines of a text, blank lines skipped (12 by default), for an error message."""
    kept = [line for line in text.strip().splitlines() if line.strip()]
    return "\n".join(kept[-lines:])


def _safe_id(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f-]{36}", value):
        raise StepError(f"not a job id: {value!r}")
    return value


def _safe_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*", value):
        raise StepError(f"not a safe name: {value!r}")
    return value


def _multipart(filename: str, data: bytes) -> tuple[bytes, str]:
    boundary = uuid4().hex
    head = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: text/plain\r\n\r\n"
    ).encode()
    return head + data + f"\r\n--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


def write_override(path: Path, service: str, env: dict[str, str]) -> Path:
    """A Compose file that sets environment variables on one service. No secret goes in it."""
    lines = ["services:", f"  {service}:", "    environment:"]
    for key, value in env.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"not an environment name: {key!r}")
        lines.append(f"      {key}: {json.dumps(value)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# ── The stack ────────────────────────────────────────────────────────────────


class Stack:
    """The Compose stack under test: commands, its API and its /metrics.

    Every command goes through `_run` and every HTTP call through `_request`,
    so the tests replace those two and nothing else."""

    def __init__(self, base_url: str, compose_file: Path, token: str | None, *,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        self.base_url = base_url.rstrip("/")
        self.compose_file = compose_file
        self.token = token
        self.clock = clock
        self.sleep = sleep
        self.current: CaseReport | None = None

    # primitives

    def _run(self, argv: list[str], *, timeout: float, stdin_text: str | None = None,
             env: dict[str, str] | None = None, cwd: Path | None = None) -> tuple[int, str, str]:
        shown = shlex.join(argv)
        print(f"    $ {shown}", flush=True)
        if self.current is not None:
            self.current.commands.append(shown)
        try:
            done = subprocess.run(argv, input=stdin_text, capture_output=True, text=True, timeout=timeout,
                                  env=env, cwd=cwd, check=False)
        except subprocess.TimeoutExpired as exc:
            raise StepError(f"timed out after {timeout:.0f} s: {shown}") from exc
        except OSError as exc:
            raise StepError(f"cannot run {argv[0]}: {exc}") from exc
        return done.returncode, done.stdout, done.stderr

    def _request(self, method: str, path: str, *, body: bytes | None = None,
                 headers: dict[str, str] | None = None, timeout: float = 20.0) -> tuple[int, bytes]:
        request = urllib.request.Request(self.base_url + path, data=body, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - loopback only
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except (urllib.error.URLError, OSError) as exc:
            raise StepError(f"{method} {path}: {exc}") from exc

    def compose(self, *args: str, override: Path | None = None, timeout: float = 600.0) -> str:
        argv = ["docker", "compose", "-f", str(self.compose_file)]
        if override is not None:
            argv += ["-f", str(override)]
        rc, out, err = self._run([*argv, *args], timeout=timeout)
        if rc:
            raise StepError(f"docker compose {' '.join(args)} exited {rc}: {tail(err)}")
        return out

    def psql(self, sql: str, *, database: str | None = None) -> str:
        """One SQL script on the database, rows back, unaligned. The password stays in the container."""
        target = shlex.quote(_safe_name(database)) if database else '"$POSTGRES_DB"'
        inner = ('PGPASSWORD="$(cat /run/secrets/db_password)" exec psql -X -q -At -v ON_ERROR_STOP=1 '
                 f'-U "$POSTGRES_USER" -d {target}')
        rc, out, err = self._run(
            ["docker", "compose", "-f", str(self.compose_file), "exec", "-T", "postgres", "sh", "-c", inner],
            timeout=120.0, stdin_text=sql,
        )
        if rc:
            raise StepError(f"psql exited {rc}: {tail(err)}")
        return out.strip()

    def app_exec(self, *argv: str) -> str:
        rc, out, err = self._run(
            ["docker", "compose", "-f", str(self.compose_file), "exec", "-T", "app", *argv], timeout=120.0)
        if rc:
            raise StepError(f"app {' '.join(argv[:1])} exited {rc}: {tail(err)}")
        return out

    # the API and /metrics

    def health(self) -> int:
        try:
            status, _ = self._request("GET", "/api/health", timeout=10.0)
        except StepError:
            return 0
        return status

    def scrape(self) -> Series:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        status, body = self._request("GET", "/metrics", headers=headers)
        if status == 403:
            raise StepError("/metrics answered 403: this client is not on loopback; export METRICS_TOKEN "
                            "(the value in .env) to scrape through the published port")
        if status != 200:
            raise StepError(f"/metrics answered {status}")
        return parse_metrics(body.decode("utf-8", "replace"))

    def job_count(self) -> int:
        status, body = self._request("GET", "/api/queue/status")
        if status != 200:
            raise StepError(f"/api/queue/status answered {status}")
        return int(sum(json.loads(body)["counts"].values()))

    def job_status(self, job_id: str) -> str | None:
        status, body = self._request("GET", f"/api/jobs/{_safe_id(job_id)}")
        if status == 404:
            return None
        if status != 200:
            raise StepError(f"/api/jobs/{job_id} answered {status}")
        return str(json.loads(body)["status"])

    def upload_attempt(self, filename: str, data: bytes) -> tuple[int, str]:
        body, content_type = _multipart(_safe_name(filename), data)
        status, raw = self._request("POST", "/api/upload", body=body, headers={"Content-Type": content_type})
        return status, raw.decode("utf-8", "replace")

    def upload(self, filename: str, data: bytes) -> str:
        status, text = self.upload_attempt(filename, data)
        if status not in (200, 201, 202):
            raise StepError(f"POST /api/upload answered {status}: {text[:200]}")
        return str(json.loads(text)["job_id"])

    def wait_for(self, read: Callable[[], Any], done: Callable[[Any], bool], *,
                 timeout: float, interval: float) -> tuple[bool, Any]:
        """Read until `done` holds or the timeout passes; (reached, last value)."""
        start = self.clock()
        last: Any = None
        while True:
            try:
                last = read()
            except StepError:
                last = None
            if done(last):
                return True, last
            if self.clock() - start >= timeout:
                return False, last
            self.sleep(interval)

    def live_workers(self) -> int:
        series = self.scrape()
        return int((gauge(series, "ctiparsor_workers", state="busy") or 0)
                   + (gauge(series, "ctiparsor_workers", state="idle") or 0))

    def wait_healthy(self, timeout: float) -> bool:
        return self.wait_for(self.health, lambda code: code == 200, timeout=timeout, interval=3.0)[0]

    def restore_services(self) -> None:
        """app, worker and postgres again, with the configuration of .env and no override."""
        self.compose("up", "-d", "--no-deps", "postgres", "app", "worker")
        if not self.wait_healthy(timeout=300.0):
            raise StepError("/api/health did not answer 200 after the stack was restored")


# ── The cases ────────────────────────────────────────────────────────────────


@dataclass
class Options:
    wait_s: float = 1200.0
    poll_s: float = 5.0


class Run:
    """One case: its steps and checks, written into its report."""

    def __init__(self, stack: Stack, report: CaseReport, opts: Options, out_dir: Path, rules: list[Rule]) -> None:
        self.stack = stack
        self.report = report
        self.opts = opts
        self.out_dir = out_dir
        self.rules = rules
        self.started = stack.clock()

    def step(self, name: str) -> None:
        at = round(self.stack.clock() - self.started, 1)
        print(f"  - {name} (at {at} s)", flush=True)
        self.report.steps.append({"name": name, "at_s": at})

    def check(self, name: str, status: str, detail: str = "") -> None:
        print(f"    {status.upper()}: {name}" + (f" ({detail})" if detail else ""), flush=True)
        self.report.checks.append(Check(name, status, detail))

    def expect(self, name: str, ok: bool, detail: str = "") -> bool:
        self.check(name, "pass" if ok else "fail", detail)
        return ok

    def rule(self, name: str) -> Rule:
        for rule in self.rules:
            if rule.name == name:
                return rule
        raise StepError(f"the rules file has no alert {name}")

    def hold_alert(self, name: str, poll_s: float = 5.0) -> None:
        """The alert's condition must hold on every scrape for its `for:` duration.

        A condition that is false on a scrape fails the check at once: the rule
        would not fire. A rule the evaluator cannot read is not checked."""
        rule = self.rule(name)
        self.report.alerts.append(name)
        need = rule.for_seconds or 0
        first_true: float | None = None
        while True:
            reading = evaluate_rule(rule, self.stack.scrape(), time.time())
            now = self.stack.clock()
            label = f"alert {name} (severity {rule.severity}, for {rule.for_label})"
            if reading.state == "not_checked":
                self.check(label, "not_checked", reading.detail)
                return
            if reading.state == "false":
                self.check(label, "fail", f"the condition is false: {reading.detail}")
                return
            if first_true is None:
                first_true = now
            if now - first_true >= need:
                self.check(label, "pass", f"held {now - first_true:.0f} s; {reading.detail}")
                return
            self.stack.sleep(poll_s)


def _job_row(stack: Stack, job_id: str) -> tuple[str, int, str] | None:
    out = stack.psql(f"SELECT status, attempts, COALESCE(worker_id, '') FROM jobs WHERE id='{_safe_id(job_id)}';")
    if not out:
        return None
    status, attempts, worker = out.split("|", 2)
    return status, int(attempts), worker


def _last_error(stack: Stack, job_id: str) -> str:
    out = stack.psql(
        "SELECT COALESCE(data, '{}') FROM progress_events "
        f"WHERE job_id='{_safe_id(job_id)}' AND event_type='done' ORDER BY id DESC LIMIT 1;"
    )
    return str(json.loads(out or "{}").get("error", "")).strip()


def _stage_report(stack: Stack, job_id: str) -> list[dict[str, Any]]:
    out = stack.psql(f"SELECT COALESCE(run_config_json, '{{}}') FROM jobs WHERE id='{_safe_id(job_id)}';")
    return list(json.loads(out or "{}").get("stage_report", []))


def _wait_terminal(run: Run, job_id: str) -> str | None:
    reached, status = run.stack.wait_for(lambda: run.stack.job_status(job_id), lambda s: s in TERMINAL,
                                         timeout=run.opts.wait_s, interval=run.opts.poll_s)
    return status if reached else None


def case_worker_killed(run: Run) -> None:
    """Kill the worker container while a job runs, then check that a worker runs the job again after its lease expires
    and the job ends."""
    st = run.stack
    run.step("count the jobs, then upload the fixture report")
    before = st.job_count()
    name = f"failure-recipe-worker-{uuid4().hex[:8]}.txt"
    job_id = st.upload(name, FIXTURE.read_bytes())
    run.step(f"wait for a worker to take job {job_id}")
    reached, status = st.wait_for(lambda: st.job_status(job_id), lambda s: s == "processing",
                                  timeout=run.opts.wait_s, interval=run.opts.poll_s)
    if not run.expect("the job reaches processing", reached, f"last status {status}"):
        return
    _, _, worker = _job_row(st, job_id) or ("", 0, "")
    run.step(f"kill the worker service while the job runs (loop {worker or 'unknown'})")
    st.compose("kill", "worker")
    still_running = st.compose("ps", "--status", "running", "-q", "worker").strip()
    run.step("Docker restarted the worker by its restart policy" if still_running
             else "the worker container stayed down after the kill")
    st.compose("start", "worker")
    run.step("wait for the lease to expire and a worker to run the job again")
    status = _wait_terminal(run, job_id)
    if not run.expect("the job ends in a terminal status, never processing", status is not None,
                      f"last status {status}"):
        return
    row = _job_row(st, job_id)
    attempts = row[1] if row else 0
    run.expect("a failed job says why", status != "failed" or _last_error(st, job_id) != "",
               f"status {status}")
    run.expect("the job was claimed again after the kill", attempts >= (1 if status == "failed" else 2),
               f"attempts {attempts}")
    run.expect("no duplicate job", st.psql(
        f"SELECT count(*) FROM jobs WHERE original_filename='{_safe_name(name)}';") == "1"
        and st.job_count() == before + 1,
        f"{st.job_count() - before} job(s) added")
    reached, series = st.wait_for(st.scrape, lambda s: s is not None and gauge(
        s, "ctiparsor_jobs", status="processing") == 0, timeout=120.0, interval=5.0)
    run.expect("/metrics shows no processing job after the recovery", reached,
               f"processing {gauge(series, 'ctiparsor_jobs', status='processing') if series else 'unknown'}")
    reached, live = st.wait_for(st.live_workers, lambda n: n >= 1, timeout=120.0, interval=5.0)
    run.expect("/metrics shows a live worker again", reached, f"busy+idle {live}")


def case_llm_down(run: Run) -> None:
    """Restart the worker with an LLM endpoint that refuses connections, run a job, and check how Stage 3 reports the
    refusal."""
    st = run.stack
    override = write_override(run.out_dir / "override-llm-down.yaml", "worker",
                              {"LLM_PROVIDER": "vllm", "VLLM_BASE_URL": LLM_REFUSING_URL})
    run.step(f"recreate the worker with VLLM_BASE_URL={LLM_REFUSING_URL} (refuses connections)")
    st.compose("up", "-d", "--no-deps", "worker", override=override)
    reached, live = st.wait_for(st.live_workers, lambda n: n >= 1, timeout=180.0, interval=5.0)
    if not run.expect("a worker is live with that endpoint", reached, f"busy+idle {live}"):
        return
    name = f"failure-recipe-llm-{uuid4().hex[:8]}.txt"
    run.step("upload the fixture report")
    job_id = st.upload(name, FIXTURE.read_bytes())
    run.expect("the API answers while the job is queued or running", st.health() == 200)
    run.step("wait for the job to end")
    status = _wait_terminal(run, job_id)
    if not run.expect("the job ends in a terminal status", status is not None, f"last status {status}"):
        return
    stages = [s for s in _stage_report(st, job_id) if str(s.get("stage")) == "3"]
    stage = stages[0] if stages else {}
    reason = str(stage.get("reason", "")).strip()
    run.expect("Stage 3 is recorded as failed or skipped, with a reason",
               stage.get("status") in ("failed", "skipped") and bool(reason),
               f"status {stage.get('status')!r}; reason {reason[:160]!r}" if stage else "no Stage 3 entry")
    run.expect("the job is kept", st.job_status(job_id) is not None, f"status {status}")
    run.expect("the API answers after the run", st.health() == 200)


def case_database_down(run: Run) -> None:
    """Stop the postgres service and check the 503 of /api/health, the database-up gauge and its alert; then start it
    and check that the jobs table holds the same ids."""
    st = run.stack
    run.step("fingerprint the job ids before the stop")
    before = st.psql("SELECT count(*) || '|' || COALESCE(md5(string_agg(id, ',' ORDER BY id)), '') FROM jobs;")
    run.step("stop the postgres service")
    st.compose("stop", "postgres", timeout=300.0)
    reached, code = st.wait_for(st.health, lambda c: c == 503, timeout=120.0, interval=5.0)
    run.expect("/api/health answers 503 while the database is down", reached, f"last status {code}")
    reached, series = st.wait_for(st.scrape, lambda s: s is not None and gauge(s, "ctiparsor_database_up") == 0,
                                  timeout=120.0, interval=5.0)
    run.expect("ctiparsor_database_up is 0", reached,
               f"value {gauge(series, 'ctiparsor_database_up') if series else 'unknown'}")
    run.step("hold the database-down condition for the rule's for: duration")
    run.hold_alert("CtiparsorDatabaseDown")
    run.step("start the postgres service")
    st.compose("start", "postgres")
    run.expect("/api/health answers 200 again", st.wait_healthy(timeout=300.0))
    after = st.psql("SELECT count(*) || '|' || COALESCE(md5(string_agg(id, ',' ORDER BY id)), '') FROM jobs;")
    run.expect("the jobs table holds the same job ids as before", after == before,
               f"{before.split('|')[0]} before, {after.split('|')[0]} after")
    reached, series = st.wait_for(st.scrape, lambda s: s is not None and gauge(s, "ctiparsor_database_up") == 1,
                                  timeout=120.0, interval=5.0)
    run.expect("ctiparsor_database_up is 1 again", reached)


def _inventory(stack: Stack) -> tuple[str, str]:
    files = stack.app_exec("sh", "-c", "find /app/state/uploads -type f 2>/dev/null | wc -l").strip()
    jobs = stack.psql("SELECT count(*) || '|' || COALESCE(md5(string_agg(id, ',' ORDER BY id)), '') FROM jobs;")
    return files, jobs


#: The thresholds of CtiparsorDiskNearlyFull in docs/monitoring/ctiparsor.rules.yml.
DISK_ALERT_MIN_FREE = 2 * 1024 ** 3
DISK_ALERT_RATIO = 0.10


def case_disk_nearly_full(run: Run) -> None:
    """Restart the app with the minimum free space for uploads set above the free disk space, then check that an upload
    is refused with 507 and writes nothing, and check the disk alert's condition."""
    st = run.stack
    free = gauge(st.scrape(), "ctiparsor_state_dir_free_bytes")
    if free is None:
        raise StepError("/metrics has no ctiparsor_state_dir_free_bytes")
    threshold = int(free // MIB) + 1
    override = write_override(run.out_dir / "override-disk.yaml", "app", {"UPLOAD_MIN_FREE_MB": str(threshold)})
    run.step(f"restart app with UPLOAD_MIN_FREE_MB={threshold}, above the free space")
    st.compose("up", "-d", "--no-deps", "app", override=override)
    run.expect("/api/health answers 200 with the override", st.wait_healthy(timeout=240.0))
    before = _inventory(st)
    run.step("upload the fixture report")
    status, text = st.upload_attempt(f"failure-recipe-disk-{uuid4().hex[:8]}.txt", FIXTURE.read_bytes())
    run.expect("the upload is refused with 507", status == 507, f"status {status}")
    run.expect("the refusal says why", "Insufficient Storage" in text)
    run.expect("nothing was written: no file and no job", _inventory(st) == before)
    run.step("check the disk alert's condition on /metrics")
    total = gauge(st.scrape(), "ctiparsor_state_dir_total_bytes")
    if free >= DISK_ALERT_MIN_FREE and (total is None or free / total >= DISK_ALERT_RATIO):
        # The 507 gate is a setting; the alert reads the real filesystem. With room
        # on the disk the alert cannot fire, which proves nothing either way.
        run.check("alert CtiparsorDiskNearlyFull", "not_checked",
                  f"{free / GIB:.1f} GiB free"
                  + (f" of {total / GIB:.1f} GiB" if total else "")
                  + ": the alert fires below 10 % or 2 GiB; run this case on a state "
                    "filesystem that is nearly full to check it")
        return
    run.hold_alert("CtiparsorDiskNearlyFull")


def _checksum_of_live_file(stack: Stack, member: str) -> str:
    text = stack.app_exec("sha256sum", f"/app/state/{member}")
    return text.split()[0]


def case_restore_drill(run: Run) -> None:
    """Run the backup commands of the documented procedure in a scratch folder and check the dump and archive they
    write. The restore checks follow them."""
    st = run.stack
    work = run.out_dir / "restore-drill"
    work.mkdir(parents=True, exist_ok=True)
    os.chmod(work, 0o700)
    env = dict(os.environ, COMPOSE_FILE=str(st.compose_file))
    run.step("take the backup with the documented commands")
    block = "\n".join(["set -e", *BACKUP_COMMANDS])
    for line in BACKUP_COMMANDS:
        print(f"    $ {line}", flush=True)
        run.report.commands.append(line)
    rc, _, err = st._run(["bash", "-c", block], timeout=1800.0, env=env, cwd=work)
    if rc:
        raise StepError(f"the backup commands exited {rc}: {tail(err)}")
    dumps = sorted(work.glob("ctiparsor-*.dump"))
    archives = sorted(work.glob("cti-state-*.tgz"))
    if not (dumps and archives):
        raise StepError("the backup commands wrote no dump or no archive")
    stamp = dumps[-1].name[len("ctiparsor-"):-len(".dump")]
    sizes = (dumps[-1].stat().st_size, archives[-1].stat().st_size)
    run.expect("the dump and the archive were written", min(sizes) > 0,
               f"{sizes[0]} and {sizes[1]} bytes")
    run.step("check the backup with the documented commands")
    for line in CHECK_COMMANDS:
        shown = line.replace("YYYY-MM-DD-HHMMSS", stamp)
        print(f"    $ {shown}", flush=True)
        run.report.commands.append(shown)
        rc, out, err = st._run(["bash", "-c", "set -e\n" + shown], timeout=600.0, env=env, cwd=work)
        if rc or int(out.strip() or 0) < 1:
            raise StepError(f"{shown} exited {rc} with {out.strip()!r}: {tail(err)}")
        run.report.extra.setdefault("check_counts", []).append(int(out.strip()))
    drill = f"ctiparsor_drill_{re.sub(r'[^0-9]', '_', stamp)}"
    run.step(f"create the empty database {drill}")
    st.psql(f'CREATE DATABASE "{_safe_name(drill)}";')
    run.step("restore the dump into it, with the documented restore line")
    line = RESTORE_PG_LINE.format(user="ctiparsor", database=drill).replace("YYYY-MM-DD-HHMMSS", stamp)
    print(f"    $ {line}", flush=True)
    run.report.commands.append(line)
    started = st.clock()
    rc, out, err = st._run(["bash", "-c", "set -e\n" + line], timeout=3600.0, env=env, cwd=work)
    restore_seconds = round(st.clock() - started, 1)
    run.report.extra["restore_seconds"] = restore_seconds
    run.expect("pg_restore exited 0 and printed nothing", rc == 0 and not err.strip(),
               f"exit {rc}; {tail(err, 3)}")
    try:
        probe = (
            "SELECT count(*) || '|' || COALESCE(md5(string_agg("
            "id || '|' || status || '|' || original_filename, ',' ORDER BY id)), '') FROM jobs;"
        )
        source = st.psql(probe)
        restored = st.psql(probe, database=drill)
        run.expect("the restored jobs equal the source's, row by row", source == restored,
                   f"{source.split('|')[0]} job(s) in the source, {restored.split('|')[0]} restored")
        tables = st.psql("SELECT count(*) FROM pg_tables WHERE schemaname='public';", database=drill)
        run.report.extra["restored_tables"] = int(tables)
        run.step("compare a few files of the archive with the live state")
        wanted, mismatches = _compare_archive_files(st, archives[-1])
        run.expect("the archive holds bundles or uploads to compare", wanted > 0, f"{wanted} file(s)")
        run.expect("the archive's bundles and uploads match the live files", not mismatches,
                   f"{wanted - len(mismatches)} of {wanted} match" + (f"; differ: {', '.join(mismatches)}"
                                                                     if mismatches else ""))
    finally:
        st.psql(f'DROP DATABASE IF EXISTS "{_safe_name(drill)}" WITH (FORCE);')
        for path in [*dumps, *archives]:
            path.unlink(missing_ok=True)


def _compare_archive_files(stack: Stack, archive: Path, limit: int = 3) -> tuple[int, list[str]]:
    """Up to `limit` bundles or uploads of the archive, by sha256 against the live files.

    Returns the number compared and the names whose live bytes differ. The
    archive is read, never extracted to disk."""
    compared: list[tuple[str, str]] = []
    with tarfile.open(archive, "r:gz") as tar:
        members = [m for m in tar.getmembers() if m.isfile() and re.match(r"^\./?(output|uploads)/", m.name)]
        members.sort(key=lambda m: (not m.name.lstrip("./").startswith("output/"), m.name))
        for member in members[:limit]:
            rel = member.name.lstrip("./")
            handle = tar.extractfile(member)
            if ".." in Path(rel).parts or handle is None:
                continue
            compared.append((rel, hashlib.sha256(handle.read()).hexdigest()))
    mismatches = [rel for rel, digest in compared if _checksum_of_live_file(stack, rel) != digest]
    return len(compared), mismatches


CASES: dict[str, Callable[[Run], None]] = {
    "worker-killed": case_worker_killed,
    "llm-down": case_llm_down,
    "database-down": case_database_down,
    "disk-nearly-full": case_disk_nearly_full,
    "restore-drill": case_restore_drill,
}


def run_cases(names: list[str], stack: Stack, opts: Options, out_dir: Path, rules: list[Rule]) -> list[CaseReport]:
    """Run the named cases in order against the stack. A case that raises or stops with a StepError is recorded as an
    error and the next case still runs; the services are restored after each case."""
    reports = []
    for name in names:
        report = CaseReport(name)
        run = Run(stack, report, opts, out_dir, rules)
        stack.current = report
        print(f"== case {name}", flush=True)
        begun = stack.clock()
        try:
            CASES[name](run)
        except StepError as exc:
            report.error = str(exc)
        except Exception as exc:  # a step that broke: the case is an error, the others still run
            report.error = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                stack.restore_services()
            except StepError as exc:
                report.error = (report.error + "; " if report.error else "") + f"restore: {exc}"
            report.seconds = round(stack.clock() - begun, 1)
            stack.current = None
            report.settle()
        print(f"== {name}: {report.status} in {report.seconds} s", flush=True)
        reports.append(report)
    return reports


# ── Output ───────────────────────────────────────────────────────────────────


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def render_markdown(meta: dict[str, Any], reports: list[CaseReport], rules: list[Rule]) -> str:
    """Render the case reports as Markdown: the run header, a summary table of the cases, then the steps and checks of
    each case."""
    lines = [
        f"# Failure recipe, run {meta['started_at']}",
        "",
        f"Base URL: `{meta['base_url']}`. Compose file: `{meta['compose_file']}`. "
        f"Result: **{'passed' if meta['exit_code'] == 0 else 'not passed'}** (exit {meta['exit_code']}).",
        "",
        "| Case | Status | Seconds | Checks passed | Not passed |",
        "|---|---|---|---|---|",
    ]
    for report in reports:
        passed = sum(1 for c in report.checks if c.status == "pass")
        lines.append(f"| {report.name} | {report.status} | {report.seconds} | {passed} | "
                     f"{len(report.checks) - passed} |")
    for report in reports:
        lines += ["", f"## {report.name}: {report.status}", ""]
        if report.error:
            lines += [f"Error: {_cell(report.error)}", ""]
        if report.extra:
            lines += ["Measured: " + ", ".join(f"{k} {v}" for k, v in report.extra.items()
                                                 if not k.endswith("_note")), ""]
        lines += ["Steps:", ""]
        lines += [f"- {_cell(step['name'])} (at {step['at_s']} s)" for step in report.steps]
        lines += ["", "| Check | Result | Detail |", "|---|---|---|"]
        lines += [f"| {_cell(c.name)} | {c.status} | {_cell(c.detail)} |" for c in report.checks]
        lines += ["", "Commands run:", "", "```"]
        lines += report.commands or ["(none)"]
        lines += ["```"]
    exercised: dict[str, list[str]] = {}
    for report in reports:
        for alert in report.alerts:
            exercised.setdefault(alert, []).append(report.name)
    lines += ["", "## Alerts", "", "| Alert | Severity | for | Exercised by |", "|---|---|---|---|"]
    for rule in rules:
        names = ", ".join(exercised.get(rule.name, [])) or "not exercised by these cases"
        lines.append(f"| {rule.name} | {rule.severity} | {rule.for_label} | {names} |")
    lines.append("")
    return "\n".join(lines)


def write_reports(out_dir: Path, meta: dict[str, Any], reports: list[CaseReport],
                  rules: list[Rule]) -> tuple[Path, Path]:
    """Write report.json and report.md to out_dir, including the alerts each case exercised. Returns the paths of the
    Markdown and the JSON file."""
    out_dir.mkdir(parents=True, exist_ok=True)
    exercised: dict[str, list[str]] = {}
    for report in reports:
        for alert in report.alerts:
            exercised.setdefault(alert, []).append(report.name)
    payload = {
        **meta,
        "cases": [
            {
                "name": r.name, "status": r.status, "seconds": r.seconds, "error": r.error,
                "steps": r.steps, "checks": [c.__dict__ for c in r.checks], "commands": r.commands,
                "extra": r.extra,
            }
            for r in reports
        ],
        "alerts": [
            {"name": rule.name, "severity": rule.severity, "for": rule.for_label, "expr": rule.expr,
             "runbook": rule.runbook, "exercised_by": exercised.get(rule.name, [])}
            for rule in rules
        ],
    }
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(meta, reports, rules), encoding="utf-8")
    return md_path, json_path


# ── Command line ─────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser of the command."""
    parser = argparse.ArgumentParser(prog="python scripts/check_failure_recipe.py",
                                     description="The load and failure recipe (ADR-0097 item 23).")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000",
                        help="the API of the running stack, on loopback (default: %(default)s)")
    parser.add_argument("--compose-file", type=Path, default=DEFAULT_COMPOSE)
    parser.add_argument("--case", action="append", choices=CASE_ORDER, dest="cases",
                        help="a case to run; repeat for several (default: all, in order)")
    parser.add_argument("--report-dir", type=Path, default=None,
                        help="where report.md and report.json go (default: output/failure-recipe/<UTC time>)")
    parser.add_argument("--wait-s", type=float, default=1200.0,
                        help="how long a job may take to end (default: %(default)s)")
    parser.add_argument("--i-know-this-stops-services", action="store_true",
                        help="required: the cases stop and restart app, worker and postgres")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the selected cases against a stack on loopback and return the exit code: 0 when every case passed, 1
    otherwise, 2 when the compose file or the rules cannot be read. Refuses to run without --i-know-this-stops-
    services."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.i_know_this_stops_services:
        parser.error("this recipe stops and restarts services; pass --i-know-this-stops-services to run it")
    host = urlsplit(args.base_url).hostname or ""
    if host not in LOOPBACK_HOSTS:
        parser.error(f"--base-url must be on loopback, not {host!r}")
    if not args.compose_file.is_file():
        print(f"check_failure_recipe: no compose file at {args.compose_file}", file=sys.stderr)
        return 2
    try:
        rules = load_rules()
    except (OSError, ValueError) as exc:
        print(f"check_failure_recipe: {exc}", file=sys.stderr)
        return 2
    stamp = datetime.now(timezone.utc)
    out_dir = args.report_dir or ROOT / "output" / "failure-recipe" / stamp.strftime("%Y%m%dT%H%M%SZ")
    token = os.environ.get(TOKEN_ENV) or None  # never printed, never written
    stack = Stack(args.base_url, args.compose_file, token)
    try:
        if stack.health() != 200:
            print(f"check_failure_recipe: {args.base_url}/api/health does not answer 200; start the stack first",
                  file=sys.stderr)
            return 2
    except StepError as exc:
        print(f"check_failure_recipe: {exc}", file=sys.stderr)
        return 2
    names = args.cases or list(CASE_ORDER)
    out_dir.mkdir(parents=True, exist_ok=True)
    started_at = stamp.isoformat()
    reports = run_cases(names, stack, Options(wait_s=args.wait_s), out_dir, rules)
    failed = [r for r in reports if r.status != "passed"]
    exit_code = 1 if failed else 0
    meta = {
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "base_url": args.base_url,
        "compose_file": str(args.compose_file),
        "cases_run": names,
        "exit_code": exit_code,
    }
    md_path, json_path = write_reports(out_dir, meta, reports, rules)
    print(f"report: {md_path}\n        {json_path}")
    print("PASSED" if exit_code == 0 else f"NOT PASSED: {', '.join(r.name for r in failed)}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
