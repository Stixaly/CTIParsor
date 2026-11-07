"""Hosts anyone publishes on are payloads, not references; `www.` is one site (#411).

The MISP blogpost list carries gist.github.com, raw.github.com and
sites.google.com: a malicious payload hosted there got no Indicator.  The
list also carries `www.alienvault.com` but not `alienvault.com`, so the bare
domain was an Indicator and the `www.` one was not.
"""
from __future__ import annotations

import pytest

from models.schemas import EntityType as T
from pipeline import benign

REFERENCE = "reference_site:security-provider-blogpost"


@pytest.mark.parametrize("etype, value", [
    (T.URL, "https://gist.github.com/evil/payload.exe"),
    (T.URL, "https://raw.github.com/evil/payload.exe"),
    (T.URL, "https://sites.google.com/view/evil/payload"),
    (T.DOMAIN, "evil.sites.google.com"),
    (T.URL, "https://evil.sites.google.com/payload.exe"),
])
def test_a_host_anyone_publishes_on_is_not_a_reference_issue_411(etype, value):
    assert benign.benign_reason(etype, value) is None


@pytest.mark.parametrize("etype, value", [
    (T.DOMAIN, "alienvault.com"),
    (T.DOMAIN, "www.alienvault.com"),
    (T.URL, "https://alienvault.com/reports/x"),
])
def test_www_prefix_is_ignored_on_both_sides_issue_411(etype, value):
    assert benign.benign_reason(etype, value) == REFERENCE


@pytest.mark.parametrize("etype, value, reason", [
    # A vendor's blog is still a reference: only the platforms above are not.
    (T.URL, "https://blog.talosintelligence.com/some-post", REFERENCE),
    (T.URL, "https://download.microsoft.com/evil.exe", REFERENCE),
    # The blogpost list names authors' pages on blogspot, not the platform.
    (T.URL, "https://evilx.blogspot.com/payload.exe", None),
    (T.URL, "https://evil.wordpress.com/payload.exe", None),
    # Unchanged controls.
    (T.URL, "https://raw.githubusercontent.com/evil/payload.exe", None),
    (T.DOMAIN, "google.com", "popular_domain:tranco10k"),
    (T.DOMAIN, "www.google.com", "popular_domain:tranco10k"),
])
def test_the_other_references_and_popular_domains_are_unchanged_issue_411(etype, value, reason):
    assert benign.benign_reason(etype, value) == reason
