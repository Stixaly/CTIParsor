"""detection_corpora.yaml: a corpus without a licence is opt-in.

`bootstrap` clones every enabled corpus onto the operator's machine, and the
detection export can hand its rules on.  The maintainer decided on 2026-11-01
that a corpus whose licence is `none` (no LICENSE upstream: all rights
reserved) or unknown is disabled by default and enabled only by the
operator's own choice.  This reads the committed file alone, never the
gitignored local overlay of whoever runs the test.  No network.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from pipeline.detection.registry import load_corpora

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "detection_corpora.yaml"

#: What `license:` holds when upstream gives no licence (`none`), the operator
#: could not say (`unknown`, the default the settings API and the adapters
#: write) or nothing was written.
NO_LICENCE = {"", "none", "unknown"}


def committed() -> list[dict]:
    return yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))["corpora"]


def has_no_licence(corpus: dict) -> bool:
    return str(corpus.get("license") or "").strip().lower() in NO_LICENCE


def test_a_corpus_without_a_licence_is_not_enabled_by_default():
    # An entry with no `enabled` key is enabled: load_corpora() reads it with
    # `c.get("enabled", True)`.
    enabled = [c["name"] for c in committed() if has_no_licence(c) and c.get("enabled", True)]
    assert not enabled, (
        f"{enabled}: licence none/unknown/missing, so `enabled: false` "
        "(opt-in, THIRD_PARTY_NOTICES.md)"
    )


def test_the_guard_sees_a_corpus_that_would_regress():
    for licence in ("none", "None", "unknown", "", None):
        assert has_no_licence({"name": "x", "license": licence})
    assert has_no_licence({"name": "x"})
    assert not has_no_licence({"name": "x", "license": "DRL-1.1"})


def test_an_opt_in_corpus_stays_listed_and_the_overlay_turns_it_on(tmp_path):
    optional = [c["name"] for c in committed() if has_no_licence(c)]
    assert optional, "no corpus without a licence is listed any more: update docs/detection-coverage.md"

    shutil.copy(REGISTRY, tmp_path / REGISTRY.name)
    assert not set(optional) & {c["name"] for c in load_corpora(tmp_path / REGISTRY.name)}

    overlay = [{"name": name, "enabled": True} for name in optional]
    (tmp_path / "detection_corpora.local.yaml").write_text(
        yaml.safe_dump({"corpora": overlay}), encoding="utf-8")
    assert set(optional) <= {c["name"] for c in load_corpora(tmp_path / REGISTRY.name)}
