"""Capture the execution configuration of a job so its bundle is reproducible
and auditable.

This module records the policy, environment flags, and model settings that
influenced a specific run. It NEVER captures secrets (API keys, tokens, etc.).
"""

import functools
import hashlib
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
    "VLLM_ENABLE_THINKING", "REVIEW_CONTROL_SAMPLE_RATE", "PIPELINE_DISABLED_STAGES",
    "ENABLE_DOCUMENT_LEVEL_RELATIONS", "CVE_ENRICHMENT", "OCR_LANG",
    "LLM_TEMPERATURE", "LLM_SEED",
    "TTP_MODE", "TTP_RETRIEVAL_CORPUS", "TTP_RETRIEVAL_METHOD", "TTP_CANDIDATES_PER_PASSAGE",
    "TTP_CANDIDATES_PER_CHUNK", "TTP_SELECT_MIN_QUOTE_WORDS", "TTP_RETRIEVAL_EXCLUDE_CITED",
    "TTP_RETRIEVAL_KEYWORD_GATE", "TTP_SELECT_SKIPPED_CHUNKS",
    "TTP_ADVISORY_GATE",
)

# The data files whose content decides what Stages 2b, 2c and 3c emit.
_DATA_DIR = Path(__file__).parent.parent / "pipeline" / "data"
_DATA_FILES = (
    "mitre_index.json", "attack_relationships.json", "gazetteer.json",
    "mitre_embeddings.npy", "mitre_embeddings_meta.json",
    "attack_retrieval_corpus.json", "attack_retrieval_embeddings.npy",
)

# Distributions whose version can change an extraction or a bundle.
_PACKAGES = (
    "stix2", "pydantic", "pdfplumber", "markitdown", "python-docx", "iocextract",
    "sentence-transformers", "transformers", "torch", "gliner",
    "anthropic", "openai", "google-re2",
)


@functools.lru_cache(maxsize=32)
def _sha256_of(path: str, mtime_ns: int, size: int) -> str:
    """Content hash, cached on (path, mtime, size): the embeddings file is
    megabytes and a worker records a manifest for every job."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _file_fingerprint(path: Path) -> str | None:
    try:
        st = path.stat()
        return _sha256_of(str(path), st.st_mtime_ns, st.st_size)[:16]
    except OSError:
        return None


def build_manifest() -> dict:
    """What a rerun needs to be the same run (ADR-0059): the exact LLM and NER
    models, a hash of the Stage 3 prompts, the content of the ATT&CK and
    gazetteer data, and the package versions.  git_rev pins the code; this
    pins what the code loaded."""
    from importlib import metadata

    def _version(dist: str) -> str | None:
        try:
            return metadata.version(dist)
        except metadata.PackageNotFoundError:
            return None

    llm: dict = {"model": None, "prompt_fingerprint": None, "sampling": None}
    try:
        from pipeline.stage3_llm import prompt_fingerprint, provider_label, sampling_options
        llm = {"model": provider_label(), "prompt_fingerprint": prompt_fingerprint(),
               "sampling": sampling_options() or "provider default"}
    except Exception:
        pass

    models: dict[str, str | None] = {
        "embedding": os.getenv("TTP_EMBEDDING_MODEL", "all-MiniLM-L6-v2"),
        "cyner": None, "gliner": None,
    }
    try:
        from pipeline.stage2d_cyner import _MODEL_ID as _cyner_model
        models["cyner"] = _cyner_model
    except Exception:
        pass
    try:
        from pipeline.stage2e_gliner import _GLINER_MODEL_ID as _gliner_model
        models["gliner"] = _gliner_model
    except Exception:
        pass

    return {
        "llm": llm,
        "models": models,
        "data": {name: _file_fingerprint(_DATA_DIR / name) for name in _DATA_FILES},
        "packages": {dist: _version(dist) for dist in _PACKAGES},
    }


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
        ttp_thresholds, ner_thresholds, entity_overrides, stages, env,
        manifest.  The worker adds stage_report once the run is over.
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

    # entity_overrides (ADR-0052) — how many analyst-grown deny / promote rows
    # were active for this run.  The rows themselves are in the store; the
    # counts say whether any applied at all.
    entity_overrides: dict | None
    try:
        from pipeline.overrides import denied_keys, overrides_enabled, promoted_entries
        entity_overrides = {
            "enabled": overrides_enabled(),
            "deny": len(denied_keys()),
            "promote": len(promoted_entries()),
        }
    except Exception:
        entity_overrides = None

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
        "entity_overrides": entity_overrides,
        "stages": stages,
        "env": env,
        "manifest": build_manifest(),
    }
