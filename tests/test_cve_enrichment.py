# tests/test_cve_enrichment.py
from unittest.mock import patch

import pipeline.stage2f_cve_enrichment as module


def test_is_valid_cve_valid():
    assert module.is_valid_cve("CVE-2024-1234") is True
    assert module.is_valid_cve("cve-2024-1234") is True


def test_is_valid_cve_invalid():
    assert module.is_valid_cve("CVE-24-1") is False
    assert module.is_valid_cve("") is False
    assert module.is_valid_cve("../../etc/passwd") is False
    assert module.is_valid_cve("CVE-2024-1234/../x") is False
    assert module.is_valid_cve("CVE-2024-12") is False


def test_enrich_cves_rejects_invalid_without_network():
    """A path-traversal id must never reach the URL.

    `enrichment_enabled` is forced True on purpose: without it the network is off
    by default, so this passed with the validation deleted — it was proving the
    feature flag worked, not the guard.
    """
    def fake_fetch(cve_id):
        raise AssertionError("Network call should not be triggered for invalid CVE")

    with patch.object(module, "enrichment_enabled", return_value=True):
        with patch.object(module, "_fetch_from_circl", side_effect=fake_fetch):
            with patch.object(module, "get_cached", return_value=({}, set())):
                result = module.enrich_cves({"../../../etc/passwd"})
                assert result == {}


def test_enrichment_disabled_by_default():
    def fake_fetch(cve_id):
        raise AssertionError("Network call should not be triggered when disabled")

    with patch.object(module, "enrichment_enabled", return_value=False):
        with patch.object(module, "_fetch_from_circl", side_effect=fake_fetch):
            with patch.object(module, "get_cached", return_value=({}, set())):
                result = module.enrich_cves({"CVE-2024-1234"})
                assert result == {}


def test_enrichment_enabled_fetches_missing():
    fetch_calls = []

    def fake_fetch(cve_id):
        fetch_calls.append(cve_id)
        return {"description": "Test", "cvss_score": 5.0, "cvss_vector": "CVSS:3.1/AV:N"}

    with patch.object(module, "enrichment_enabled", return_value=True):
        with patch.object(module, "_fetch_from_circl", side_effect=fake_fetch):
            with patch.object(module, "get_cached", return_value=({}, set())):
                with patch.object(module, "save_to_cache"):
                    result = module.enrich_cves({"CVE-2024-1234"})
                    assert len(fetch_calls) == 1
                    assert result["CVE-2024-1234"]["description"] == "Test"


def test_max_fetch_limit():
    fetch_calls = []

    def fake_fetch(cve_id):
        fetch_calls.append(cve_id)
        return {"description": "Test", "cvss_score": 5.0, "cvss_vector": "CVSS:3.1/AV:N"}

    cve_ids = {f"CVE-2024-{i:04d}" for i in range(40)}

    with patch.object(module, "enrichment_enabled", return_value=True):
        with patch.object(module, "_fetch_from_circl", side_effect=fake_fetch):
            with patch.object(module, "get_cached", return_value=({}, set())):
                with patch.object(module, "save_to_cache"):
                    module.enrich_cves(cve_ids)
                    assert len(fetch_calls) == module._MAX_FETCH


def test_negative_cache_prevents_refetch():
    fetch_calls = []

    def fake_fetch(cve_id):
        fetch_calls.append(cve_id)
        return None

    with patch.object(module, "enrichment_enabled", return_value=True):
        with patch.object(module, "_fetch_from_circl", side_effect=fake_fetch):
            with patch.object(module, "get_cached", return_value=({}, set())):
                with patch.object(module, "save_to_cache"):
                    module.enrich_cves({"CVE-2024-1234"})
                    assert len(fetch_calls) == 1

            with patch.object(module, "get_cached", return_value=({}, {"CVE-2024-1234"})):
                with patch.object(module, "save_to_cache"):
                    module.enrich_cves({"CVE-2024-1234"})
                    assert len(fetch_calls) == 1
