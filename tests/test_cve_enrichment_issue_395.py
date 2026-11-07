# tests/test_cve_enrichment_issue_395.py
"""Issue 395: a CIRCL answer with no usable data is a miss on every call, and a
CVSS metric whose baseScore is None does not end the search for a score.

The network is never reached: urlopen is replaced by a canned answer.
"""
import json

import pytest

import pipeline.stage2f_cve_enrichment as module


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
        requests.append(req.full_url)
        if isinstance(body, BaseException):
            raise body
        return _Response(body, status)

    monkeypatch.setattr(module.urllib.request, "urlopen", urlopen)
    return requests


def _metric(version: str, score: float) -> dict:
    return {version: {"baseScore": score, "vectorString": f"CVSS:{version[-3:]}/AV:N"}}


# ── An answer with nothing in it ─────────────────────────────────────────────

def test_an_answer_with_no_description_and_no_score_is_a_miss(monkeypatch):
    _circl(monkeypatch, {"containers": {"cna": {"descriptions": [{"lang": "fr", "value": "non"}]}}})
    assert module._fetch_from_circl("CVE-2019-0001") is None


def test_the_first_and_second_lookup_agree_on_an_empty_answer(temp_db, monkeypatch):
    """Before the fix the first call returned a record of Nones, and the second, read from the
    cache, returned nothing for the same CVE."""
    monkeypatch.setenv("CVE_ENRICHMENT", "1")
    _circl(monkeypatch, {"containers": {}})

    first = module.enrich_cves({"CVE-2019-0001"})
    _circl(monkeypatch, AssertionError("must come from the cache"))
    second = module.enrich_cves({"CVE-2019-0001"})

    assert first == second == {}


# ── A metric with no baseScore ───────────────────────────────────────────────

def test_a_none_score_in_cvss_3_1_does_not_hide_cvss_3_0_of_the_same_metric(monkeypatch):
    _circl(monkeypatch, {"containers": {"adp": [{"metrics": [
        {"cvssV3_1": {"baseScore": None, "vectorString": "CVSS:3.1/AV:N"}, **_metric("cvssV3_0", 7.5)},
    ]}]}})
    assert module._fetch_from_circl("CVE-2019-0001") == {
        "description": None, "cvss_score": 7.5, "cvss_vector": "CVSS:3_0/AV:N"}


def test_a_none_score_does_not_hide_the_metrics_after_it(monkeypatch):
    _circl(monkeypatch, {"containers": {"adp": [{"metrics": [
        {"cvssV3_1": {"baseScore": None, "vectorString": "CVSS:3.1/AV:N"}},
        _metric("cvssV3_1", 9.8),
    ]}]}})
    assert module._fetch_from_circl("CVE-2019-0001") == {
        "description": None, "cvss_score": 9.8, "cvss_vector": "CVSS:3_1/AV:N"}


def test_a_none_score_in_the_adp_does_not_hide_the_cna_score(monkeypatch):
    _circl(monkeypatch, {"containers": {
        "adp": [{"metrics": [{"cvssV3_1": {"baseScore": None}}]}],
        "cna": {"metrics": [_metric("cvssV3_1", 8.1)]},
    }})
    assert module._fetch_from_circl("CVE-2019-0001")["cvss_score"] == 8.1


def test_a_description_with_no_score_is_still_a_record(monkeypatch):
    """Control: a description alone is data, so the answer is kept (and cached by enrich_cves)."""
    _circl(monkeypatch, {"containers": {"cna": {
        "descriptions": [{"lang": "en", "value": "Orion RCE"}],
        "metrics": [{"cvssV3_1": {"baseScore": None}}],
    }}})
    assert module._fetch_from_circl("CVE-2019-0001") == {
        "description": "Orion RCE", "cvss_score": None, "cvss_vector": None}


@pytest.mark.parametrize("version,score", [("cvssV3_1", 5.4), ("cvssV3_0", 6.1)])
def test_a_valid_score_still_wins_over_an_earlier_none(monkeypatch, version, score):
    """Control: the first metric with a score is still the one used."""
    _circl(monkeypatch, {"containers": {"adp": [{"metrics": [
        {"cvssV3_1": {"baseScore": None}},
        _metric(version, score),
        _metric("cvssV3_0", 1.0),
    ]}]}})
    assert module._fetch_from_circl("CVE-2019-0001")["cvss_score"] == score
