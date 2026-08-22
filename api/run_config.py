"""Capture the execution configuration of a job so its bundle is reproducible
and auditable.

This module records the policy, environment flags, and model settings that
influenced a specific run. It NEVER captures secrets (API keys, tokens, etc.).
"""

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

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


def _flag(name: str) -> bool:
    """Check if an environment variable is set to a truthy flag value."""
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


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
    git_rev = None
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
            git_rev = result.stdout.strip()
    except Exception:
        pass

    # embedding_model
    embedding_model = os.getenv("TTP_EMBEDDING_MODEL", "all-MiniLM-L6-v2")

    # ttp_thresholds
    try:
        from pipeline.stage2c_ttp_semantic import _thresholds
        high, medium = _thresholds()
        ttp_thresholds = {"high": high, "medium": medium}
    except Exception:
        ttp_thresholds = {"high": None, "medium": None}

    # stages
    _skip_heavy = os.getenv("SKIP_HEAVY_MODELS") == "1"
    stages = {
        "gazetteer": True,
        "semantic": not _skip_heavy,
        "cyner": (not _skip_heavy) and _flag("CYNER_ENABLED"),
        "gliner": not _skip_heavy,
        "llm": bool(os.getenv("LLM_PROVIDER", "").strip()),
        "stix_verification": _flag("ENABLE_STIX_VERIFICATION"),
        "ttp_verification": _flag("ENABLE_TTP_VERIFICATION"),
        "consensus": _flag("ENABLE_CONSENSUS"),
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
        "stages": stages,
        "env": env,
    }
