"""Defanging and URL hosts in Stage 2 (#915, #916, #917).

No network and no LLM: the extraction functions are called on the text itself.
"""
from __future__ import annotations

import pytest

from models.schemas import EntityType
from pipeline.stage2_extraction import _extract_network_iocs, _url_host, refang


def _values(text: str, entity_type: EntityType) -> list[str]:
    return [e.value for e in _extract_network_iocs(text) if e.entity_type == entity_type]


@pytest.mark.parametrize("defanged, live", [
    ("h[tt]ps[://]evil[.]com", "https://evil.com"),
    ("fxp[:]//x[.]com", "ftp://x.com"),
    ("me{at}evil{dot}com", "me@evil.com"),
])
def test_more_defang_spellings_are_refanged_issue_915(defanged, live):
    assert refang(defanged) == live


def test_a_trailing_dot_on_a_url_host_is_the_url_host_issue_916():
    assert _url_host("http://evil.com./x") == "evil.com"
    assert _url_host("http://[evil.com.]/x") == "evil.com"


def test_a_trailing_dot_on_a_url_host_is_not_a_second_domain_issue_916():
    assert _values("fetch http://evil.com./x now", EntityType.DOMAIN) == []


def test_the_userinfo_of_a_url_is_not_an_email_issue_917():
    assert _values("beacon http://user:pass@evil.com/x", EntityType.URL) == ["http://user:pass@evil.com/x"]
    assert _values("beacon http://user:pass@evil.com/x", EntityType.EMAIL) == []
    assert _values("beacon http://user@evil.com/x", EntityType.EMAIL) == []


def test_an_address_in_a_url_query_is_still_an_email_issue_917():
    assert _values("beacon http://evil.com/x?email=a@b.com", EntityType.EMAIL) == ["a@b.com"]
    assert _values("beacon http://evil.com?email=a@b.com", EntityType.EMAIL) == ["a@b.com"]
