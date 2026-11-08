"""TLP egress policy (ADR-0097): which providers may receive a report's content.

CLEAR and GREEN reports go to any configured provider.  AMBER, AMBER+STRICT and
RED reports go to a local provider only: `vllm`, `ollama` or `lmstudio` whose
base URL points at a loopback or private address, or at a name the operator
lists in LLM_LOCAL_HOSTS.  A report without a marking is AMBER, or whatever
STIX_TLP says, because that is the marking its bundle carries.

Pure: the environment is read, nothing is resolved and nothing is sent.  A
hostname that is not in the list is external, whatever it resolves to.
"""
from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

#: The Compose service name and the Docker host alias, plus localhost.
DEFAULT_LOCAL_HOSTS = "localhost,ollama,host.docker.internal"

#: Providers that can be local, with the variable and default Stage 3 reads
#: their base URL from (pipeline/stage3_llm.py, pipeline/vlm.py).
_BASE_URLS = {
    "vllm": ("VLLM_BASE_URL", "http://localhost:8000"),
    "ollama": ("OLLAMA_BASE_URL", "http://localhost:11434"),
    "lmstudio": ("LMSTUDIO_BASE_URL", "http://localhost:1234"),
}

#: Hosted providers, always external.
_HOSTED = {
    "anthropic": "api.anthropic.com",    # unless ANTHROPIC_BASE_URL, which the SDK reads
    "gemini": "generativelanguage.googleapis.com",
    "mistral": "api.mistral.ai",
}

logger = logging.getLogger(__name__)

#: Variables an HTTP client reads to route its requests through a proxy.
_PROXY_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")

#: LLM_LOCAL_HOSTS entries already reported as ignored: one warning each.
_WARNED: set[str] = set()

#: Levels that may go to any provider; every other level needs a local one.
_OPEN_LEVELS = frozenset({"CLEAR", "GREEN"})


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    local: bool
    tlp: str
    provider: str
    host: str | None
    reason: str = ""    # why it is refused; empty when allowed

    def record(self) -> dict:
        """What a stage record carries: the host only, never a URL or a key."""
        return {"tlp": self.tlp, "provider": self.provider, "host": self.host,
                "local": self.local, "allowed": self.allowed}


def effective_tlp(doc_tlp: str | None) -> str:
    """The report's own marking, else the default its bundle gets (STIX_TLP,
    AMBER when unset).  Raises ValueError, saying which setting is wrong, on an
    unknown level."""
    from pipeline.stage4_stix_mapping import normalise_tlp, tlp_default

    if doc_tlp is not None and doc_tlp.strip():
        try:
            return normalise_tlp(doc_tlp)
        except ValueError as exc:
            raise ValueError(f"the report's TLP marking is refused: {exc}") from exc
    try:
        return tlp_default()
    except ValueError as exc:
        raise ValueError(f"STIX_TLP is refused: {exc}") from exc


def _host_of(base: str) -> str | None:
    """The host of a base URL: lower-case, no credentials, port, brackets or
    trailing dot.  None for a URL with a backslash, a space or a control
    character (clients and this parser may read it differently) or no host."""
    base = base.strip()
    if not base or any(c == "\\" or c.isspace() or ord(c) < 32 or ord(c) == 127 for c in base):
        return None
    if "://" not in base:
        base = f"//{base}"
    try:
        host = urlsplit(base).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def provider_host(provider: str) -> str | None:
    """The host `provider` is reached at (see `_host_of`); None for a provider this
    module does not know or a base URL it will not read."""
    prov = provider.strip().lower()
    if prov == "anthropic":
        base = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
        return _host_of(base) if base else _HOSTED[prov]
    if prov in _HOSTED:
        return _HOSTED[prov]
    if prov not in _BASE_URLS:
        return None
    var, default = _BASE_URLS[prov]
    return _host_of(os.environ.get(var, default).strip() or default)


def local_hosts() -> frozenset[str]:
    """The names LLM_LOCAL_HOSTS declares local (case-insensitive, a trailing dot
    dropped).  An entry with a colon (a port, a URL) is ignored, with a warning."""
    raw = os.environ.get("LLM_LOCAL_HOSTS")
    if raw is None:
        raw = DEFAULT_LOCAL_HOSTS
    names = set()
    for entry in raw.split(","):
        name = entry.strip().lower().rstrip(".")
        if not name:
            continue
        if ":" in name:
            if name not in _WARNED:
                _WARNED.add(name)
                logger.warning("LLM_LOCAL_HOSTS: %r ignored: an entry is a hostname, without a port "
                               "or a scheme", entry.strip())
            continue
        names.add(name)
    return frozenset(names)


def _no_proxy_covers(host: str) -> bool:
    """NO_PROXY as httpx reads it: `*`, an exact host, a domain suffix, an address
    or a network."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    for entry in (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "").split(","):
        entry = entry.strip().lower().rstrip(".")
        if not entry:
            continue
        if entry == "*":
            return True
        if addr is not None:
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
        entry = entry.lstrip(".")
        if host == entry or host.endswith("." + entry):
            return True
    return False


def proxied(host: str | None) -> bool:
    """True when a proxy is configured and NO_PROXY does not cover `host`: the
    request then leaves for the proxy, which may be anywhere."""
    if not host:
        return False
    if not any((os.environ.get(v) or os.environ.get(v.lower()) or "").strip() for v in _PROXY_VARS):
        return False
    return not _no_proxy_covers(host)


def _host_is_local(host: str) -> bool:
    name = host.strip().strip("[]").lower().rstrip(".")
    try:
        # A scoped IPv6 address (fe80::1%eth0) carries a zone.
        addr = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        return name in local_hosts()
    # Link-local (169.254.169.254, the cloud metadata address) and unspecified
    # addresses are private to ipaddress, and are not a model server.
    if addr.is_link_local or addr.is_unspecified:
        return False
    return addr.is_loopback or addr.is_private


def is_local(provider: str, host: str | None) -> bool:
    """True when `provider` is a local kind, `host` is a loopback or private address
    or a declared name, and no proxy sits in between.  No DNS lookup."""
    if provider.strip().lower() not in _BASE_URLS or not host:
        return False
    return _host_is_local(host) and not proxied(host)


def decide(tlp: str, provider: str) -> EgressDecision:
    """May a report marked `tlp` (already normalised) go to `provider`?"""
    prov = provider.strip().lower()
    host = provider_host(prov)
    local = is_local(prov, host)
    if tlp in _OPEN_LEVELS or local:
        return EgressDecision(True, local, tlp, prov, host)
    where = f" ({host})" if host else ""
    why = (f"a proxy is configured for {host}; "
           if prov in _BASE_URLS and host and _host_is_local(host) and proxied(host) else "")
    return EgressDecision(False, local, tlp, prov, host,
                          f"TLP:{tlp} forbids sending the report to {prov}{where}: "
                          f"{why}only a local provider may process it (ADR-0097)")
