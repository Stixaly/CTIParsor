"""Capture the execution configuration of a job so its bundle is reproducible
and auditable.

This module records the policy, environment flags, and model settings that
influenced a specific run. It NEVER captures secrets (API keys, tokens, etc.).
"""

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from pipeline.env_flags import env_bool

# Allow-list, never a scan of os.environ: the process environment holds API
# keys (ANTHROPIC_API_KEY, MISTRAL_API_KEY) and this dict is persisted to the
# database and served over the API.  Adding a name here is a deliberate act.
_CAPTURED_ENV = (
    "TTP_EMBEDDING_MODEL", "TTP_TOP2_MARGIN", "TTP_MAX_CANDIDATES",
    "TTP_KEYWORD_GATE", "TTP_UNWRAP_LINES", "TTP_SEMANTIC_DOMAINS",
    "TTP_HIGH_THRESHOLD", "TTP_MEDIUM_THRESHOLD",
    "ENABLE_STIX_VERIFICATION", "ENABLE_TTP_VERIFICATION", "ENABLE_CONSENSUS",
    "CONSENSUS_PROVIDER", "LLM_PROVIDER", "LLM_PARALLELISM",
    "CYNER_ENABLED", "GLINER_MODEL", "SKIP_HEAVY_MODELS",
)


def _resolve_git_rev() -> str | None:
    """Resolve the git revision for the run config.

    Prefers the local git repository; falls back to the CTIPARSOR_GIT_REV
    environment variable (set by the container build); returns None if neither
    is available.
    """
    try:
        project_root = Path(__file__).parent.parent
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=project_root,
        )
        if result.returncode == 0:
            rev = result.stdout.strip()
            if rev:
                return rev
    except Exception:
        pass

    # A container image carries no .git directory, so the build stamps the
    # revision into the environment instead (docker build --build-arg GIT_REV).
    # git wins when it is available: a developer checkout must never be
    # mislabelled by a stale variable.
    env_rev = os.getenv("CTIPARSOR_GIT_REV")
    if env_rev is not None:
        env_rev = env_rev.strip()
        if env_rev:
            return env_rev

    return None


def build_run_config(policy: dict | None = None) -> dict:
    """Build a JSON-serializable dict capturing the run configuration.

    Args:
        policy: The relationship policy dict used for the run.

    Returns:
        A dict with keys: recorded_at, git_rev, policy, embedding_model,
        ttp_thresholds, stages, env.
    """
    # recorded_at
    recorded_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # git_rev
    git_rev = _resolve_git_rev()

    # embedding_model
    embedding_model = os.getenv("TTP_EMBEDDING_MODEL", "all-MiniLM-L6-v2")

    # ttp_thresholds
    try:
        from pipeline.stage2c_ttp_semantic import _thresholds
        high, medium = _thresholds()
        ttp_thresholds: dict[str, float | None] = {"high": high, "medium": medium}
    except Exception:
        ttp_thresholds = {"high": None, "medium": None}

    # ner_thresholds (ADR-0051) — the per-type cutoffs Stage 2d/2e applied, so
    # a bundle built under a calibrated cutoff stays explainable after the next
    # recalibration moves it.  The stage default plus whatever rows overrode it.
    ner_thresholds: dict | None
    try:
        from pipeline.calibration import stage_default
        from pipeline.thresholds import calibration_enabled, overrides_for
        ner_thresholds = {
            "calibration_enabled": calibration_enabled(),
            **{
                source: {"default": stage_default(source), "overrides": overrides_for(source)}
                for source in ("cyner", "gliner")
            },
        }
    except Exception:
        ner_thresholds = None

    # stages
    #
    # Ask each stage its OWN availability predicate — the same call the worker
    # makes — instead of guessing from environment variables.  The env-var guess
    # was wrong in both directions on the stored jobs: it recorded
    # `semantic: True` when Stage 2c never ran (SKIP_HEAVY_MODELS aside,
    # semantic_available() also requires the embedding cache and a matching
    # manifest), and `llm: False` when the LLM did run, because LLM_PROVIDER
    # defaults to "anthropic" when unset.  A run config that misattributes the
    # bundle defeats the point of recording one at all (ADR-0024 Phase B).
    _skip_heavy = env_bool("SKIP_HEAVY_MODELS")

    def _ask(module: str, predicate: str) -> bool | None:
        """Call a stage's availability predicate; None if it cannot be asked."""
        try:
            mod = __import__(module, fromlist=[predicate])
            return bool(getattr(mod, predicate)())
        except Exception:
            return None

    stages = {
        "gazetteer": True,
        "semantic": _ask("pipeline.stage2c_ttp_semantic", "semantic_available"),
        "cyner": _ask("pipeline.stage2d_cyner", "cyner_available"),
        "gliner": _ask("pipeline.stage2e_gliner", "gliner_available"),
        "llm": _ask("pipeline.stage3_llm", "_provider_ready"),
        # Same reasoning as the four predicates above: `_flag` answered from the
        # environment with a *third* vocabulary, so `ENABLE_CONSENSUS=1` was
        # recorded as consensus-on while stage 3e (which demanded the literal
        # "true") had it off, and `_flag` could not see that consensus also
        # needs CONSENSUS_PROVIDER != LLM_PROVIDER.
        "stix_verification": _ask("pipeline.stage3d_verify", "verify_enabled"),
        "ttp_verification": _ask("pipeline.stage3f_ttp_verify", "verify_enabled"),
        "consensus": _ask("pipeline.stage3e_consensus", "consensus_enabled"),
        # Kept alongside so a run can still be read as "heavy models were off"
        # rather than "the cache was missing" — the predicates conflate them.
        "skip_heavy_models": _skip_heavy,
    }

    # env
    env = {}
    for var_name in _CAPTURED_ENV:
        val = os.getenv(var_name)
        if val is not None:
            env[var_name] = val

    return {
        "recorded_at": recorded_at,
        "git_rev": git_rev,
        "policy": policy,
        "embedding_model": embedding_model,
        "ttp_thresholds": ttp_thresholds,
        "ner_thresholds": ner_thresholds,
        "stages": stages,
        "env": env,
    }
