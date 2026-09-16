"""Pre-download the NLP models into HF_HOME so the first report does not pay
for ~2.6 GB of network transfer.

Mirrors the model-loading calls in the pipeline (setup.sh equivalent) but
only verifies that the weights are present in the local cache.  Heavy imports
are deferred inside each function so that a missing optional dependency does
not abort the whole warm-up.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from pipeline.env_flags import env_bool  # noqa: E402


def warm_embeddings() -> bool:
    """Download / verify the sentence-transformer embedding model."""
    label = "embeddings"
    model_id = os.getenv("TTP_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    try:
        from sentence_transformers import SentenceTransformer
        SentenceTransformer(model_id)
        print(f"  OK   {label}: {model_id}")
        return True
    except Exception as exc:
        print(f"  FAIL {label}: {model_id} - {type(exc).__name__}: {exc}")
        return False


def warm_cyner() -> bool:
    """Download / verify the CyNER named-entity model."""
    label = "cyner"
    model_id = os.getenv("CYNER_MODEL", "PranavaKailash/CyNER-2.0-DeBERTa-v3-base")
    if not env_bool("CYNER_ENABLED", default=True):
        print(f"  SKIP {label}: disabled by CYNER_ENABLED=false")
        return True
    try:
        from transformers import pipeline
        pipeline(
            "ner",
            model=model_id,
            aggregation_strategy="simple",
            device=-1,
        )
        print(f"  OK   {label}: {model_id}")
        return True
    except Exception as exc:
        print(f"  FAIL {label}: {model_id} - {type(exc).__name__}: {exc}")
        return False


def warm_gliner() -> bool:
    """Download / verify the GLiNER entity model."""
    label = "gliner"
    model_id = os.getenv("GLINER_MODEL", "urchade/gliner_large-v2.1")
    if not env_bool("GLINER_ENABLED", default=True):
        print(f"  SKIP {label}: disabled by GLINER_ENABLED=false")
        return True
    try:
        from gliner import GLiNER
        GLiNER.from_pretrained(model_id)
        print(f"  OK   {label}: {model_id}")
        return True
    except Exception as exc:
        print(f"  FAIL {label}: {model_id} - {type(exc).__name__}: {exc}")
        return False


def main() -> int:
    # Reduce noise before any heavy import
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")

    hf_home = os.getenv("HF_HOME")
    print(f"Model cache: {hf_home or '(default)'}")

    if env_bool("HF_HUB_OFFLINE"):
        print("HF_HUB_OFFLINE is set - verifying the cache, nothing will be downloaded")

    results = [
        warm_embeddings(),
        warm_cyner(),
        warm_gliner(),
    ]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
