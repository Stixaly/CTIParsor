# tests/test_cve_enrichment.py
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

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


def test_the_time_budget_stops_fetching(monkeypatch):
    """Past _MAX_TOTAL_SECONDS nothing more is fetched, whatever _MAX_FETCH allows."""
    clock = iter([0.0, 0.0, module._MAX_TOTAL_SECONDS + 1])
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    fetched = []

    with patch.object(module, "enrichment_enabled", return_value=True), \
         patch.object(module, "_fetch_from_circl", side_effect=lambda c: fetched.append(c) or None), \
         patch.object(module, "get_cached", return_value=({}, set())), \
         patch.object(module, "save_to_cache"):
        module.enrich_cves({"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"})

    assert fetched == ["CVE-2024-0001"]


def test_nothing_is_fetched_when_everything_is_cached():
    cached = {"CVE-2024-1234": {"description": "d", "cvss_score": 9.8, "cvss_vector": "v"}}
    with patch.object(module, "enrichment_enabled", return_value=True), \
         patch.object(module, "_fetch_from_circl", side_effect=AssertionError("network")), \
         patch.object(module, "get_cached", return_value=(cached, {"CVE-2024-1234"})):
        assert module.enrich_cves({" cve-2024-1234 "}) == cached


def test_enrichment_follows_the_environment(monkeypatch):
    monkeypatch.delenv("CVE_ENRICHMENT", raising=False)
    assert module.enrichment_enabled() is False
    monkeypatch.setenv("CVE_ENRICHMENT", "true")
    assert module.enrichment_enabled() is True


def test_a_non_string_id_is_not_a_cve():
    assert module.is_valid_cve(None) is False       # type: ignore[arg-type]
    assert module.is_valid_cve(20241234) is False   # type: ignore[arg-type]


# ── The CIRCL response (CVE JSON 5.x) ────────────────────────────────────────

class _Response:
    def __init__(self, body, status: int = 200):
        self.status = status
        self._raw = body if isinstance(body, bytes) else json.dumps(body).encode()

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _circl(monkeypatch, body, status: int = 200) -> list:
    requests = []

    def urlopen(req, timeout):
        requests.append((req.full_url, timeout))
        if isinstance(body, BaseException):
            raise body
        return _Response(body, status)

    monkeypatch.setattr(module.urllib.request, "urlopen", urlopen)
    return requests


def _metric(version: str, score: float) -> dict:
    return {version: {"baseScore": score, "vectorString": f"CVSS:{version[-3:]}/AV:N"}}


def test_circl_description_and_adp_score_are_read(monkeypatch):
    requests = _circl(monkeypatch, {"containers": {
        "cna": {
            "descriptions": [{"lang": "fr", "value": "non"}, {"lang": "en", "value": "Orion RCE"}],
            "metrics": [_metric("cvssV3_1", 1.0)],
        },
        "adp": ["junk", {"metrics": "junk"}, {"metrics": ["junk", {"other": {}}, _metric("cvssV3_1", 9.8)]}],
    }})

    result = module._fetch_from_circl(" cve-2020-10148 ")

    assert result == {"description": "Orion RCE", "cvss_score": 9.8, "cvss_vector": "CVSS:3_1/AV:N"}
    assert requests == [("https://cve.circl.lu/api/cve/CVE-2020-10148", 5)]


def test_circl_cvss_3_0_is_used_when_3_1_is_absent(monkeypatch):
    _circl(monkeypatch, {"containers": {"adp": [{"metrics": [_metric("cvssV3_0", 7.5)]}]}})
    result = module._fetch_from_circl("CVE-2019-0001")
    assert result == {"description": None, "cvss_score": 7.5, "cvss_vector": "CVSS:3_0/AV:N"}


@pytest.mark.parametrize("version,score", [("cvssV3_1", 8.1), ("cvssV3_0", 6.5)])
def test_circl_falls_back_to_the_cna_score(monkeypatch, version, score):
    _circl(monkeypatch, {"containers": {
        "adp": [{"metrics": []}],
        "cna": {"descriptions": "junk", "metrics": ["junk", {"cvssV2_0": {}}, _metric(version, score)]},
    }})
    assert module._fetch_from_circl("CVE-2019-0001")["cvss_score"] == score


def test_circl_answer_without_containers_is_an_empty_record(monkeypatch):
    _circl(monkeypatch, {"dataType": "CVE_RECORD"})
    assert module._fetch_from_circl("CVE-2019-0001") == {
        "description": None, "cvss_score": None, "cvss_vector": None}


@pytest.mark.parametrize("body,status", [
    ({"containers": {}}, 404),
    (b"<html>not json</html>", 200),
    ([1, 2, 3], 200),
    (module.urllib.error.URLError("unreachable"), 200),
    (TimeoutError("timed out"), 200),
])
def test_circl_failures_are_none(monkeypatch, body, status):
    _circl(monkeypatch, body, status)
    assert module._fetch_from_circl("CVE-2019-0001") is None


def test_an_invalid_id_never_reaches_circl(monkeypatch):
    requests = _circl(monkeypatch, {})
    assert module._fetch_from_circl("CVE-2019-0001/../../admin") is None
    assert requests == []


# ── The cache (PostgreSQL) ───────────────────────────────────────────────────

def test_the_cache_keeps_hits_and_remembers_misses(temp_db):
    module.save_to_cache("CVE-2024-0001", {"description": "d", "cvss_score": 9.8, "cvss_vector": "v"})
    module.save_to_cache("CVE-2024-0002", None)

    data, known = module.get_cached({"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"})

    assert data == {"CVE-2024-0001": {"description": "d", "cvss_score": 9.8, "cvss_vector": "v"}}
    assert known == {"CVE-2024-0001", "CVE-2024-0002"}
    assert module.get_cached(set()) == ({}, set())


def test_a_new_lookup_replaces_the_cached_one(temp_db):
    module.save_to_cache("CVE-2024-0001", None)
    module.save_to_cache("CVE-2024-0001", {"description": "now known", "cvss_score": 5.0})
    data, _ = module.get_cached({"CVE-2024-0001"})
    assert data["CVE-2024-0001"] == {"description": "now known", "cvss_score": 5.0, "cvss_vector": None}

    module.save_to_cache("CVE-2024-0001", None)
    data, known = module.get_cached({"CVE-2024-0001"})
    assert data == {} and known == {"CVE-2024-0001"}


def test_enrich_cves_reads_and_fills_the_real_cache(temp_db, monkeypatch):
    monkeypatch.setenv("CVE_ENRICHMENT", "1")
    _circl(monkeypatch, {"containers": {"cna": {"descriptions": [{"lang": "en", "value": "x"}]}}})

    first = module.enrich_cves({"CVE-2024-0001"})
    _circl(monkeypatch, AssertionError("must come from the cache"))
    second = module.enrich_cves({"CVE-2024-0001"})

    assert first == second == {"CVE-2024-0001": {"description": "x", "cvss_score": None, "cvss_vector": None}}
