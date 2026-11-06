"""Issue #371: two overlapping `add_corpus` calls lost one entry.

Both calls read the overlay before either wrote it, so the second write erased
the first entry. The test uses real YAML files and forces only the order: A reads
the empty overlay and is held before its write until B tries to read. With the
lock, B waits for A's write, A's wait runs out after one second, and nothing
deadlocks.
"""
import threading

import pytest
import yaml

from pipeline.detection import registry


def _entry(name: str) -> dict:
    return {"name": name, "adapter": "sigma", "path": f"./corpora/{name}"}


def test_overlapping_add_corpus_keeps_both_entries_issue_371(tmp_path, monkeypatch):
    config = tmp_path / "detection_corpora.yaml"
    config.write_text("corpora: []\n", encoding="utf-8")
    overlay = tmp_path / "detection_corpora.local.yaml"
    order: list[str] = []
    a_has_read = threading.Event()
    b_has_read = threading.Event()
    real_read = registry._read_corpora
    real_write = registry._write_overlay_file

    def read(path):
        corpora = real_read(path)
        name = threading.current_thread().name
        if name == "A":
            a_has_read.set()
        elif name == "B":
            order.append("B:read")
            b_has_read.set()
        return corpora

    def write(config_path, corpora):
        if threading.current_thread().name == "A":
            # A has read the empty overlay. Hold its write until B reads, or give up
            # after one second: under the lock B cannot read before A has written.
            b_has_read.wait(timeout=1.0)
            order.append("A:write")
        real_write(config_path, corpora)

    monkeypatch.setattr(registry, "_read_corpora", read)
    monkeypatch.setattr(registry, "_write_overlay_file", write)

    results: dict[str, list[dict]] = {}
    errors: list[BaseException] = []

    def add(name: str) -> None:
        try:
            results[name] = registry.add_corpus(config, _entry(name))
        except BaseException as exc:   # surfaced by the assertions below
            errors.append(exc)

    thread_a = threading.Thread(target=add, args=("A",), name="A")
    thread_b = threading.Thread(target=add, args=("B",), name="B")
    thread_a.start()
    assert a_has_read.wait(timeout=10)   # A reads first, so B is the one that must wait
    thread_b.start()
    thread_a.join(timeout=10)
    thread_b.join(timeout=10)

    assert not thread_a.is_alive() and not thread_b.is_alive(), "deadlock"
    assert not errors
    assert [c["name"] for c in results["A"]] == ["A"]
    assert [c["name"] for c in results["B"]] == ["A", "B"]
    assert order == ["A:write", "B:read"]   # B read only after A had written
    final = yaml.safe_load(overlay.read_text(encoding="utf-8"))["corpora"]
    assert [c["name"] for c in final] == ["A", "B"]


def test_failed_overlay_write_keeps_the_previous_overlay_issue_371(tmp_path, monkeypatch):
    config = tmp_path / "detection_corpora.yaml"
    config.write_text("corpora: []\n", encoding="utf-8")
    overlay = tmp_path / "detection_corpora.local.yaml"
    registry.add_corpus(config, _entry("kept"))
    before = overlay.read_text(encoding="utf-8")

    def replace_fails(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(registry.os, "replace", replace_fails)
    with pytest.raises(OSError):
        registry.add_corpus(config, _entry("lost"))
    assert overlay.read_text(encoding="utf-8") == before
