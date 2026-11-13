"""Measure the qualified LLM configuration (ADR-0100, amending ADR-0094 item 11
and decision 13).

By default (`--provider vllm`): two runs of the qualified configuration on the
AnnoCTR test split, and two on the in-house set, with figure reading on
(`VISION_PROVIDER=vllm`), at `LLM_TEMPERATURE=0` and `LLM_SEED=13`, with a local
vLLM serving `Inferact/Qwen3.8-27B-NVFP4`, thinking off. vLLM is not billed.

`--provider anthropic` runs the same steps with the default `LLM_PROVIDER` of
the code. Every run of it is billed per call, and Anthropic takes no seed.

In both cases the scores and the spread between the two runs of each set are
written, and the spread is what gets published.

    python scripts/measure_default_provider.py --dry-run
    python scripts/measure_default_provider.py
    python scripts/measure_default_provider.py --provider anthropic --dry-run
    python scripts/measure_default_provider.py --estimate qualified-vllm-inhouse-1 \
        --provider anthropic --price-in <USD per million input tokens> --price-out <USD per million output tokens>

Refuses to start unless the environment (or `.env`) names the chosen provider
as LLM_PROVIDER, LLM_TEMPERATURE is 0, and VISION_PROVIDER does not turn figure
reading off (none) nor send figures to another provider. For vllm it also
requires VLLM_BASE_URL, VLLM_MODEL=Inferact/Qwen3.8-27B-NVFP4,
VLLM_ENABLE_THINKING=false, LLM_TIMEOUT=600 and LLM_SEED=13. For anthropic it
requires ANTHROPIC_API_KEY and ANTHROPIC_MODEL to be the code's default. In both
cases none of the four run names exists yet.

The environment is read as `python -m evaluation` reads it: the process
environment first, then `.env` (python-dotenv does not override a variable
already set). The child processes get the checked values explicitly.

Standard library only. Each step is `python -m evaluation ...` in a subprocess,
the commands of docs/eval/README.md. The summary goes to
data/eval/default-provider-<timestamp>.json. Exit 0 when every step ran; the
first failing step stops the script, writes no summary, and exits with its code.

--estimate NAME reads a run already made (data/eval/runs/NAME or
data/eval/inhouse-runs/NAME) and counts its LLM requests and the characters of
each report. The records do not store tokens: input tokens are estimated from
the characters of the report text at CHARS_PER_TOKEN characters a token, which
is an approximation. Output tokens are not recorded anywhere; they are counted
only when --out-tokens-per-call is given. Prices are arguments, never constants.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EVAL = REPO / "data" / "eval"

# pipeline/stage3_llm.py holds the defaults (LLM_PROVIDER, ANTHROPIC_MODEL). The
# model is read from that source, not copied here, so a change of the default
# is measured without editing this script; tests/test_measure_default_provider.py
# checks both against it.
DEFAULT_PROVIDER = "anthropic"


def _code_default_model() -> str:
    source = (REPO / "pipeline" / "stage3_llm.py").read_text(encoding="utf-8")
    found = re.search(r'^_DEFAULT_ANTHROPIC_MODEL = "([^"]+)"', source, re.MULTILINE)
    if found is None:
        raise SystemExit("pipeline/stage3_llm.py: _DEFAULT_ANTHROPIC_MODEL not found")
    return found.group(1)


DEFAULT_MODEL = _code_default_model()

#: The qualified configuration of ADR-0100 (the maintainer's decision of 2026-11-13).
QUALIFIED_VLLM_MODEL = "Inferact/Qwen3.8-27B-NVFP4"
QUALIFIED_VLLM_SEED = "13"
QUALIFIED_VLLM_TIMEOUT = "600"

PROVIDERS = ("vllm", "anthropic")
#: Run names per provider: the qualified runs and the anthropic option keep
#: apart, so a run of one never blocks the other.
RUN_PREFIX = {"vllm": "qualified-vllm", "anthropic": "default-provider"}


def run_names(provider: str) -> dict[str, tuple[str, str]]:
    """The two AnnoCTR test runs and the two in-house runs of a provider."""
    prefix = RUN_PREFIX[provider]
    return {"annoctr": (f"{prefix}-annoctr-1", f"{prefix}-annoctr-2"),
            "inhouse": (f"{prefix}-inhouse-1", f"{prefix}-inhouse-2")}

# Rule of thumb for prose, approximate: no tokenizer is run here.
CHARS_PER_TOKEN = 4

# Figure reading follows LLM_PROVIDER when VISION_PROVIDER is unset, empty or
# auto (ADR-0094 item 12). These values keep figures with the text's provider.
VISION_ALLOWED = ("", "auto", "anthropic")

METRICS = ("precision", "recall", "f1")


# ── configuration ────────────────────────────────────────────────────────────

def read_dotenv(path: Path) -> dict[str, str]:
    """KEY=VALUE lines of a .env file: comments, `export`, quotes and inline
    comments on unquoted values are handled. A missing file is empty."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].strip()
        values[key.strip()] = value
    return values


def effective(key: str, environ: dict, dotenv: dict, default: str | None = None) -> str | None:
    """The value python -m evaluation sees: the environment, then .env, then the default."""
    if key in environ:
        return environ[key]
    if key in dotenv:
        return dotenv[key]
    return default


def run_exists(name: str) -> bool:
    return (EVAL / "runs" / name).exists() or (EVAL / "inhouse-runs" / name).exists()


def check(environ: dict, dotenv: dict, provider: str = "vllm") -> tuple[dict, list[str]]:
    """The settings the measurement runs with, and why it must not start."""
    def get(key: str, default: str | None = None) -> str | None:
        return effective(key, environ, dotenv, default)

    problems: list[str] = []
    chosen = (get("LLM_PROVIDER", DEFAULT_PROVIDER) or "").strip().lower()
    if chosen != provider:
        problems.append(f"LLM_PROVIDER is {chosen!r}: the measurement is of {provider!r}")

    if provider == "anthropic":
        if not (get("ANTHROPIC_API_KEY") or "").strip():
            problems.append("ANTHROPIC_API_KEY is not set (in the environment or .env)")
        model = (get("ANTHROPIC_MODEL", DEFAULT_MODEL) or "").strip()
        if model != DEFAULT_MODEL:
            problems.append(f"ANTHROPIC_MODEL is {model!r}: the decision is about the default, {DEFAULT_MODEL!r}")
        model_or_default = model or DEFAULT_MODEL
        vision_allowed = VISION_ALLOWED
    else:
        if not (get("VLLM_BASE_URL") or "").strip():
            problems.append("VLLM_BASE_URL is not set (in the environment or .env)")
        model = (get("VLLM_MODEL") or "").strip()
        if model != QUALIFIED_VLLM_MODEL:
            problems.append(f"VLLM_MODEL is {model!r}: the qualified model is {QUALIFIED_VLLM_MODEL!r}")
        thinking = (get("VLLM_ENABLE_THINKING") or "").strip().lower()
        if thinking not in ("false", "0", "no", "off"):
            problems.append(f"VLLM_ENABLE_THINKING is {thinking!r}: the qualified configuration has it off")
        timeout = (get("LLM_TIMEOUT") or "").strip()
        if timeout != QUALIFIED_VLLM_TIMEOUT:
            problems.append(f"LLM_TIMEOUT is {timeout!r}: the qualified configuration uses {QUALIFIED_VLLM_TIMEOUT}")
        seed = (get("LLM_SEED") or "").strip()
        if seed != QUALIFIED_VLLM_SEED:
            problems.append(f"LLM_SEED is {seed!r}: the qualified configuration uses {QUALIFIED_VLLM_SEED}")
        model_or_default = QUALIFIED_VLLM_MODEL
        vision_allowed = ("", "auto", "vllm")

    temperature = get("LLM_TEMPERATURE")
    try:
        zero = temperature is not None and float(temperature) == 0.0
    except ValueError:
        zero = False
    if not zero:
        problems.append(f"LLM_TEMPERATURE is {temperature!r}: the two runs must be at 0 "
                        "(unset, the provider's own sampling applies)")

    vision = (get("VISION_PROVIDER", "") or "").strip().lower()
    if vision == "none":
        problems.append("VISION_PROVIDER=none turns figure reading off: the default journey reads figures (item 12)")
    elif vision not in vision_allowed:
        problems.append(f"VISION_PROVIDER is {vision!r}: figures would go to another provider than the text's")

    for name in (n for pair in run_names(provider).values() for n in pair):
        if run_exists(name):
            problems.append(f"run {name!r} already exists: a measurement uses fresh run names")

    if provider == "anthropic":
        settings = {"provider": provider, "temperature": "0",
                    "vision_provider": vision or "auto", "model": model_or_default}
    else:
        settings = {"provider": provider, "temperature": "0", "seed": QUALIFIED_VLLM_SEED,
                    "timeout": QUALIFIED_VLLM_TIMEOUT, "vision_provider": "vllm",
                    "model": model_or_default}
    return settings, problems


def child_environment(settings: dict, environ: dict) -> dict:
    """The environment of the child processes: the checked values, set explicitly."""
    env = dict(environ)
    env["LLM_PROVIDER"] = settings["provider"]
    env["LLM_TEMPERATURE"] = settings["temperature"]
    env["VISION_PROVIDER"] = settings["vision_provider"]
    if settings["provider"] == "anthropic":
        env["ANTHROPIC_MODEL"] = settings["model"]
    else:
        env["VLLM_MODEL"] = settings["model"]
        env["VLLM_ENABLE_THINKING"] = "false"
        env["LLM_TIMEOUT"] = settings["timeout"]
        env["LLM_SEED"] = settings["seed"]
    return env


# ── the steps ────────────────────────────────────────────────────────────────

def plan(python: str, provider: str = "vllm") -> list[tuple[str, list[str], bool]]:
    """(label, argv, capture stdout). Only inhouse-compare prints its result."""
    ev = [python, "-m", "evaluation"]
    annoctr, inhouse = run_names(provider)["annoctr"], run_names(provider)["inhouse"]
    a1, a2 = annoctr
    i1, i2 = inhouse
    steps: list[tuple[str, list[str], bool]] = []
    for name in annoctr:
        steps.append((f"run {name}", [*ev, "run", "--split", "test", "--name", name], False))
        steps.append((f"score {name}", [*ev, "score", "--name", name], False))
    for name in inhouse:
        steps.append((f"inhouse-run {name}", [*ev, "inhouse-run", "--name", name], False))
        steps.append((f"inhouse-score {name}", [*ev, "inhouse-score", "--name", name, "--from", "bundle"], False))
    steps.append(("compare AnnoCTR", [*ev, "compare", "--a", a1, "--b", a2, "--task", "ttp"], False))
    steps.append(("inhouse-compare", [*ev, "inhouse-compare",
                                      str(EVAL / "inhouse-runs" / i1 / "score-bundle.json"),
                                      str(EVAL / "inhouse-runs" / i2 / "score-bundle.json")], True))
    return steps


def spread(first: dict, second: dict) -> dict:
    """Per metric: the two values and the second minus the first (None when one is missing)."""
    out = {}
    for m in METRICS:
        a, b = first.get(m), second.get(m)
        out[m] = {"run_1": a, "run_2": b,
                  "difference": None if a is None or b is None else round(b - a, 4)}
    return out


def inhouse_spread(micro_1: dict, micro_2: dict) -> dict:
    """The spread for each in-house layer that both runs scored."""
    return {layer: spread(micro_1[layer], micro_2[layer])
            for layer in sorted(set(micro_1) & set(micro_2))
            if isinstance(micro_1[layer], dict) and isinstance(micro_2[layer], dict)}


def git_head() -> str | None:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else None


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _llm_manifest(run_json: Path) -> dict | None:
    return ((_load(run_json).get("manifest") or {}).get("llm")) if run_json.exists() else None


def summarise(settings: dict) -> dict:
    """The summary of the four runs, read from the files the steps wrote."""
    names = run_names(settings["provider"])
    annoctr = {}
    for name in names["annoctr"]:
        score = _load(EVAL / "runs" / name / "score.json")
        annoctr[name] = {"documents_scored": score.get("documents_scored"),
                         "documents_failed": score.get("documents_failed"),
                         "technique_micro": score["ttp"]["technique_micro"],
                         "seconds_per_document": score.get("seconds_per_document"),
                         "llm": score.get("llm")}
    inhouse = {}
    for name in names["inhouse"]:
        score = _load(EVAL / "inhouse-runs" / name / "score-bundle.json")
        inhouse[name] = {"documents": score.get("documents"),
                         "documents_failed": score.get("documents_failed"),
                         "documents_unscored": score.get("documents_unscored"),
                         "micro": score.get("micro"),
                         "llm": _llm_manifest(EVAL / "inhouse-runs" / name / "run.json")}
    a1, a2 = names["annoctr"]
    i1, i2 = names["inhouse"]
    compare_file = EVAL / "compare" / f"{a1}__vs__{a2}__ttp.json"
    qualified = settings["provider"] == "vllm"
    return {
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "decision": ("ADR-0100 (the qualified configuration; amends ADR-0094 item 11)" if qualified
                     else "ADR-0094 item 11 (decision 13), the anthropic option"),
        "commit": git_head(),
        "provider": settings["provider"],
        "model": settings["model"],
        "llm_temperature": 0,
        "llm_seed": int(settings["seed"]) if qualified else None,
        "vision_provider": settings["vision_provider"],
        "billed": not qualified,
        "annoctr_test": {
            "runs": annoctr,
            "spread_technique_micro": spread(annoctr[a1]["technique_micro"], annoctr[a2]["technique_micro"]),
            "compare": _load(compare_file).get("results") if compare_file.exists() else None,
        },
        "inhouse": {
            "runs": inhouse,
            "spread_micro": inhouse_spread(inhouse[i1]["micro"] or {}, inhouse[i2]["micro"] or {}),
        },
    }


def measure(steps: list[tuple[str, list[str], bool]], settings: dict, environ: dict,
            runner=subprocess.run) -> int:
    env = child_environment(settings, environ)
    captured = ""
    for label, argv, capture in steps:
        print(f"== {label}", flush=True)
        proc = runner(argv, cwd=REPO, env=env, check=False,
                      capture_output=capture, text=True)
        if proc.returncode != 0:
            print(f"step failed: {label} (exit {proc.returncode}); no summary written", file=sys.stderr)
            return proc.returncode or 1
        if capture:
            captured = proc.stdout
    summary = summarise(settings)
    # The result of the existing comparison command, as it printed it.
    summary["inhouse"]["compare"] = json.loads(captured) if captured.strip() else None
    EVAL.mkdir(parents=True, exist_ok=True)
    path = EVAL / f"default-provider-{time.strftime('%Y-%m-%d-%H%M%S')}.json"
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"summary written to {path}")
    return 0


# ── estimate ─────────────────────────────────────────────────────────────────

def estimate_run(run_dir: Path, out_tokens_per_call: int | None) -> dict:
    """Counts for one run directory. Each docs/*.json record is one document.
    LLM requests: Stage 3 counts its provider requests; 3d and 3f count their
    answers (one per call, batches included)."""
    docs = []
    for path in sorted((run_dir / "docs").glob("*.json")):
        record = _load(path)
        stages = {s["stage"]: s.get("counts") or {} for s in record.get("stages") or []}
        chars = int(stages.get("1", {}).get("chars", 0))
        s3 = stages.get("3", {})
        s3d = stages.get("3d", {})
        s3f = stages.get("3f", {})
        calls = {
            "3": int(s3.get("provider_calls", s3.get("llm_calls", 0))),
            "3d": sum(int(s3d.get(k, 0)) for k in ("ok", "unparsed", "failed")),
            "3f": sum(int(s3f.get(k, 0)) for k in ("ok", "unparsed", "failed", "truncated")),
        }
        tokens_in = round(chars / CHARS_PER_TOKEN)
        docs.append({"doc_id": record.get("doc_id", path.stem), "error": record.get("error"),
                     "chars": chars, "llm_calls": calls, "llm_requests": sum(calls.values()),
                     "input_tokens_estimated": tokens_in,
                     "output_tokens_estimated": (sum(calls.values()) * out_tokens_per_call
                                                 if out_tokens_per_call is not None else None)})
    return {"run_dir": str(run_dir), "documents": docs}


def estimate(name: str, out_tokens_per_call: int | None) -> dict | None:
    dirs = [d for d in (EVAL / "runs" / name, EVAL / "inhouse-runs" / name) if (d / "docs").is_dir()]
    if not dirs:
        return None
    return {"name": name, "runs": [estimate_run(d, out_tokens_per_call) for d in dirs]}


def price_total(runs: list[dict], price_in: float | None, price_out: float | None) -> dict:
    docs = [d for r in runs for d in r["documents"]]
    tokens_in = sum(d["input_tokens_estimated"] for d in docs)
    requests = sum(d["llm_requests"] for d in docs)
    out_known = bool(docs) and all(d["output_tokens_estimated"] is not None for d in docs)
    tokens_out = sum(d["output_tokens_estimated"] or 0 for d in docs) if out_known else None
    total = {"documents": len(docs), "documents_in_error": sum(1 for d in docs if d["error"]),
             "llm_requests": requests, "input_tokens_estimated": tokens_in,
             "output_tokens_estimated": tokens_out, "cost_usd": None}
    if price_in is not None:
        cost = tokens_in * price_in / 1e6
        if tokens_out is not None and price_out is not None:
            cost += tokens_out * price_out / 1e6
        total["cost_usd"] = round(cost, 4)
    return total


def print_estimate(result: dict, price_in: float | None, price_out: float | None, billed: bool = True) -> None:
    print(f"{result['name']}: estimate from the recorded run(s)")
    print(f"  rule: input tokens = report characters / {CHARS_PER_TOKEN} (approximate; the prompt "
          "template and entity list added per call are not counted)")
    for run in result["runs"]:
        print(f"  {run['run_dir']}")
        for d in run["documents"]:
            flag = f"  ERROR {d['error']}" if d["error"] else ""
            print(f"    {d['doc_id']:<40} {d['chars']:>9} chars  {d['llm_requests']:>4} requests  "
                  f"{d['input_tokens_estimated']:>8} input tokens{flag}")
    total = price_total(result["runs"], price_in, price_out)
    print("total:")
    for key, value in total.items():
        print(f"  {key}: {value}")
    if not billed:
        print("  vLLM is not billed: the local server has no per-token price, so no cost is estimated")
    elif total["output_tokens_estimated"] is None:
        print("  output tokens are not recorded: pass --out-tokens-per-call to estimate them")


# ── command line ─────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None, environ: dict | None = None,
         dotenv: dict | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--provider", choices=PROVIDERS, default="vllm",
                        help="the configuration measured: vllm (the qualified one, ADR-0100) or anthropic (billed)")
    parser.add_argument("--dry-run", action="store_true", help="check, then print the commands; run nothing")
    parser.add_argument("--estimate", metavar="NAME", help="estimate the cost of a run already made")
    parser.add_argument("--price-in", type=float, help="USD per million input tokens (estimate, anthropic only)")
    parser.add_argument("--price-out", type=float, help="USD per million output tokens (estimate, anthropic only)")
    parser.add_argument("--out-tokens-per-call", type=int,
                        help="assumed output tokens per LLM request (estimate; not recorded)")
    args = parser.parse_args(argv)

    if args.estimate:
        result = estimate(args.estimate, args.out_tokens_per_call)
        if result is None:
            print(f"no run named {args.estimate!r} with docs/ under data/eval/runs or data/eval/inhouse-runs",
                  file=sys.stderr)
            return 1
        billed = args.provider == "anthropic"
        print_estimate(result, args.price_in if billed else None,
                       args.price_out if billed else None, billed=billed)
        return 0

    environ = dict(os.environ) if environ is None else environ
    dotenv = read_dotenv(REPO / ".env") if dotenv is None else dotenv
    settings, problems = check(environ, dotenv, args.provider)
    if problems:
        for p in problems:
            print(f"refused: {p}", file=sys.stderr)
        return 1
    steps = plan(sys.executable, args.provider)
    if args.dry_run:
        print(f"settings: {settings}")
        for label, cmd, _ in steps:
            print(f"{label}: {' '.join(cmd)}")
        return 0
    return measure(steps, settings, environ)


if __name__ == "__main__":
    sys.exit(main())
