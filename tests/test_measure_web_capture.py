"""scripts/measure_web_capture.py: the harness compares like with like."""
from __future__ import annotations


def test_the_dom_reference_uses_the_capture_s_javascript_setting(tmp_path, monkeypatch):
    # #316: a capture with JS was measured against a DOM read without it.
    from scripts import measure_web_capture as mwc
    seen: dict[str, bool] = {}
    monkeypatch.setattr(mwc, "capture_url_to_pdf", lambda url, dest, enable_js, timeout_ms:
                        seen.setdefault("capture", enable_js) and None)
    monkeypatch.setattr(mwc, "ingest", lambda path: "text")
    monkeypatch.setattr(mwc, "_read_dom_text", lambda url, timeout_ms, enable_js=False:
                        seen.setdefault("dom", enable_js) and "")
    for js in (True, False):
        seen.clear()
        try:
            mwc.measure_one("https://example.test/", tmp_path, enable_js=js, timeout_ms=1000)
        except Exception:      # noqa: BLE001 — only the flags passed are under test
            pass
        assert seen == {"capture": js, "dom": js}
