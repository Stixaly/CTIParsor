"""Issue #368: changing a corpus's source type kept both URLs in the merged registry.

The committed entry names a Git remote; the overlay names a tarball for the same
`name`. `_merged` used to `update()` the entry, so the Git remote survived next to
the tarball. Settings then showed the old Git URL with the tarball badge, while
the sync (which prefers `tarball`) downloaded the archive. The merged entry must
carry one source only: the one the overlay chose. Real YAML files in tmp_path.
"""
import yaml

from pipeline.detection import registry

GIT_URL = "https://github.com/example/rules.git"
TARBALL_URL = "https://rules.example.org/rules.tar.gz"


def _registry(tmp_path, base_entry: dict, overlay_entry: dict | None = None):
    config = tmp_path / "detection_corpora.yaml"
    config.write_text(yaml.safe_dump({"corpora": [base_entry]}, sort_keys=False), encoding="utf-8")
    if overlay_entry is not None:
        overlay = tmp_path / "detection_corpora.local.yaml"
        overlay.write_text(yaml.safe_dump({"corpora": [overlay_entry]}, sort_keys=False), encoding="utf-8")
    return config


def _git_base() -> dict:
    return {"name": "demo", "adapter": "sigma", "path": "./corpora/demo", "git": GIT_URL,
            "license": "MIT", "priority": 10, "enabled": True}


def _tarball_base() -> dict:
    return {"name": "demo", "adapter": "suricata", "path": "./corpora/demo", "tarball": TARBALL_URL,
            "license": "MIT", "priority": 10, "enabled": True}


def test_git_base_with_tarball_overlay_keeps_only_the_tarball_issue_368(tmp_path):
    config = _registry(tmp_path, _git_base(),
                       {"name": "demo", "tarball": TARBALL_URL})
    [merged] = registry.merged_corpora(config)
    assert merged["tarball"] == TARBALL_URL
    assert "git" not in merged
    # The fields the overlay did not touch still come from the committed entry.
    assert merged["path"] == "./corpora/demo"
    assert merged["license"] == "MIT"


def test_tarball_base_with_git_overlay_keeps_only_the_git_remote_issue_368(tmp_path):
    config = _registry(tmp_path, _tarball_base(),
                       {"name": "demo", "git": GIT_URL})
    [merged] = registry.merged_corpora(config)
    assert merged["git"] == GIT_URL
    assert "tarball" not in merged
    assert registry.load_corpora(config)[0]["git"] == GIT_URL


def test_overlay_without_a_source_keeps_the_base_source_issue_368(tmp_path):
    # Control: a disable override names no source, so the committed source stays.
    config = _registry(tmp_path, _git_base(), {"name": "demo", "enabled": False})
    [merged] = registry.merged_corpora(config)
    assert merged["git"] == GIT_URL
    assert "tarball" not in merged
    assert merged["enabled"] is False


def test_add_corpus_then_merged_corpora_switches_the_source_issue_368(tmp_path):
    config = _registry(tmp_path, _git_base())
    registry.add_corpus(config, {"name": "demo", "adapter": "sigma",
                                 "path": "./corpora/demo", "tarball": TARBALL_URL})
    [merged] = registry.merged_corpora(config)
    assert {k: merged[k] for k in ("git", "tarball") if k in merged} == {"tarball": TARBALL_URL}
    [enabled] = registry.load_corpora(config)
    assert enabled.get("tarball") == TARBALL_URL and "git" not in enabled
