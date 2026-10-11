"""Values a report names without accusing them (audit B 8.1.7).

A report says "the malware checks connectivity with www.google.com", "the
victim host 10.0.0.5", "see https://www.mandiant.com/resources/blog/apt29":
Stage 2 extracts every one, and Stage 4 used to give each an Indicator typed
`malicious-activity`.  An Indicator is a detection: a consumer that loads the
bundle would alert on Google.

`benign_reason` names why a value is not one:

- a non-routable address (private, loopback, link-local, documentation,
  shared, reserved, multicast): Python's `ipaddress`, not a list;
- the four big public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS),
  which malware queries to test its connectivity: named here, since MISP's
  public-dns-v4 lists 62,780 open resolvers, a compromised C2 among them
  possibly;
- a vendor's, researcher's or sandbox's site, the host of a reference link
  (MISP warninglists security-provider-blogpost, automated-malware-analysis;
  the host or any subdomain of it), except the platforms anyone publishes on
  that the blogpost list also carries (GitHub, Medium, Twitter, S3…): a
  payload on `raw.githubusercontent.com` is a payload;
- one of the 10,000 most popular domains (MISP warninglist tranco10k), for
  that exact domain only: `x.duckdns.org` or `evil.blogspot.com` are not
  popular because their parent is, and a URL on a popular domain keeps its
  Indicator (a payload on GitHub is still a payload).

The observable still ships, without an Indicator; Stage 4's ledger says why.
`BENIGN_IOC_FILTER=false` turns this off.  The lists are vendored by
`scripts/build_warninglists.py` (CC0 1.0).
"""
from __future__ import annotations

import functools
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit

from api.logging_config import get_logger
from models.schemas import EntityType
from pipeline.env_flags import env_bool

logger = get_logger(__name__)

_PATH = Path(__file__).parent / "data" / "warninglists.json"
_REFERENCE_LISTS = ("security-provider-blogpost", "automated-malware-analysis")
_POPULAR_LIST = "tranco10k"

# Entries of the reference lists where anyone can publish: a link there is a
# reference only as often as it is a payload.  A named author's page on such a
# platform (gchq.github.io, a blog on blogspot) stays a reference.
_USER_CONTENT = frozenset({
    "github.com", "raw.githubusercontent.com", "gist.githubusercontent.com", "medium.com",
    "twitter.com", "t.co", "facebook.com", "www.facebook.com", "stackoverflow.com",
    "dropbox.com", "www.dropbox.com", "pastebin.lu",
    "s3-eu-west-1.amazonaws.com", "s3-us-west-2.amazonaws.com",
})


_PUBLIC_RESOLVERS = frozenset({
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
    "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2620:fe::fe", "2620:fe::9",
})


def enabled() -> bool:
    return env_bool("BENIGN_IOC_FILTER", default=True)


@functools.lru_cache(maxsize=1)
def _lists() -> dict[str, frozenset[str]]:
    try:
        data = json.loads(_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(f"[benign] {_PATH.name} unreadable, no warninglist applies: "
                       f"{type(exc).__name__}: {exc}")
        return {}
    lists = {name: frozenset(entry.get("values", [])) for name, entry in data.get("lists", {}).items()}
    for name in _REFERENCE_LISTS:
        if name in lists:
            lists[name] = lists[name] - _USER_CONTENT
    return lists


def _host_in(host: str, values: frozenset[str]) -> bool:
    """`host` or one of its parent domains is listed."""
    parts = host.split(".")
    return any(".".join(parts[i:]) in values for i in range(len(parts) - 1))


def _reference_site(host: str) -> str | None:
    lists = _lists()
    for name in _REFERENCE_LISTS:
        if _host_in(host, lists.get(name, frozenset())):
            return f"reference_site:{name}"
    return None


def benign_reason(entity_type: EntityType, value: str) -> str | None:
    """Why `value` is not an indicator of compromise, or None."""
    if not enabled() or not isinstance(value, str) or not value.strip():
        return None
    v = value.strip().lower()
    if entity_type in (EntityType.IPV4, EntityType.IPV6):
        try:
            address = ipaddress.ip_address(v)
        except ValueError:
            return None
        if not address.is_global:
            return "non_routable_address"
        return "public_dns_resolver" if str(address) in _PUBLIC_RESOLVERS else None
    if entity_type == EntityType.DOMAIN:
        host = v.rstrip(".")
        reference = _reference_site(host)
        if reference:
            return reference
        bare = host[4:] if host.startswith("www.") else host
        if bare in _lists().get(_POPULAR_LIST, frozenset()):
            return f"popular_domain:{_POPULAR_LIST}"
        return None
    if entity_type == EntityType.URL:
        try:
            host = (urlsplit(v).hostname or "").rstrip(".")
        except ValueError:
            return None
        return _reference_site(host) if host else None
    return None
