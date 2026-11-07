"""scripts/build_indexes.py (issue #536): `--only embeddings` writes
mitre_embeddings_manifest.json only for an embedding model other than the default
(ADR-0087: the default track has no manifest), as scripts/build_attack_release.py does.

build_embeddings is replaced by a recorder: only the flag main() passes is under test."""
from __future__ import annotations

import sys

from scripts import build_indexes as bi

DEFAULT_MODEL = "all-MiniLM-L6-v2"


def _run_embeddings_only(monkeypatch, tmp_path, model):
    """Run main() for the embeddings step alone; return the write_manifest it passed."""
    passed = []
    monkeypatch.setattr(bi, "build_embeddings",
                        lambda bundles, out_dir=None, write_manifest=True: passed.append(write_manifest))
    # The .env file of the checkout must not change the model these tests set.
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: False)
    monkeypatch.setenv("TTP_EMBEDDING_MODEL", model)
    monkeypatch.setattr(sys, "argv", ["build_indexes.py", "--only", "embeddings",
                                      "--enterprise", str(tmp_path / "enterprise-attack.json"),
                                      "--out-dir", str(tmp_path / "out")])
    bi.main()
    assert len(passed) == 1
    return passed[0]


def test_the_default_model_writes_no_embeddings_manifest(monkeypatch, tmp_path):  # (#536)
    """ADR-0087: the default track is the one without a manifest."""
    assert _run_embeddings_only(monkeypatch, tmp_path, DEFAULT_MODEL) is False


def test_another_model_writes_the_embeddings_manifest(monkeypatch, tmp_path):  # (#536)
    """Stage 2c reads the model and its thresholds from the manifest, so another model gets one."""
    assert _run_embeddings_only(monkeypatch, tmp_path, "ehsanaghaei/SecureBERT-Plus") is True
