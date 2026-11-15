"""Issue 919: the CIRCL reader takes a CVSS score only when it is a real number from
0 to 10, and an English description only when it is a non-blank string.

The network is never reached: urlopen is replaced by a canned answer.
"""
import json

import pytest

import pipeline.stage2f_cve_enrichment as module


class _Response:
    def __init__(self, body, status: int = 200):
        self.status = status
        self._raw = json.dumps(body).encode()

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _circl(monkeypatch, body) -> None:
    def urlopen(req, timeout):
        return _Response(body)

    monkeypatch.setattr(module.urllib.request, "urlopen", urlopen)


# ── A CVSS score ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("score", [True, False, "9.8", float("nan"), float("inf"), 11, -1, None])
def test_a_score_that_is_not_a_cvss_number_is_passed_over_issue_919(score):
    metrics = [{"cvssV3_1": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N"}}]
    assert module._cvss_v3(metrics) == (None, None)


def test_an_integer_score_is_returned_as_a_float_issue_919():
    score, vector = module._cvss_v3([{"cvssV3_1": {"baseScore": 10, "vectorString": "CVSS:3.1/AV:N"}}])
    assert score == 10.0 and isinstance(score, float)
    assert vector == "CVSS:3.1/AV:N"


def test_a_bad_cvss_3_1_score_falls_through_to_cvss_3_0_issue_919():
    metrics = [{"cvssV3_1": {"baseScore": "9.8", "vectorString": "CVSS:3.1/AV:N"},
                "cvssV3_0": {"baseScore": 7.5, "vectorString": "CVSS:3.0/AV:N"}}]
    assert module._cvss_v3(metrics) == (7.5, "CVSS:3.0/AV:N")


# ── An English description ───────────────────────────────────────────────────

@pytest.mark.parametrize("value", [None, 42, "   ", ["text"]])
def test_a_blank_or_non_string_english_description_is_passed_over_issue_919(monkeypatch, value):
    _circl(monkeypatch, {"containers": {"cna": {"descriptions": [
        {"lang": "en", "value": value},
        {"lang": "en", "value": "Real text."},
    ]}}})
    assert module._fetch_from_circl("CVE-2019-0001")["description"] == "Real text."
