"""Where the API keeps uploaded sources and exported bundles.

Both default to the repository's own ``uploads/`` and ``output/`` (in the
image, symlinks into the state volume).  ``CTIPARSOR_UPLOADS_DIR`` and
``CTIPARSOR_OUTPUT_DIR`` move them: the test suite points them at a per-test
temp directory, so no test writes into the working tree.

Read on every call rather than once at import, so a change applies at once,
and a pipeline subprocess that inherits the environment agrees with its parent.
"""
import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def uploads_dir() -> Path:
    """Uploaded sources (``<job_id>.<ext>``) and URL-capture metadata (``meta/``)."""
    return Path(os.environ.get("CTIPARSOR_UPLOADS_DIR") or _ROOT / "uploads")


def output_dir() -> Path:
    """Exported STIX bundles and Stage 3 crash-resume checkpoints."""
    return Path(os.environ.get("CTIPARSOR_OUTPUT_DIR") or _ROOT / "output")


def state_dir() -> Path:
    """What the app remembers between starts (`db-identity.json`, ADR-0077).
    In the image, the `cti-state` volume; ``CTIPARSOR_STATE_DIR`` moves it."""
    return Path(os.environ.get("CTIPARSOR_STATE_DIR") or _ROOT / "state")
