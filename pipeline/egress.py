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
    "anthropic": "api.anthropic.com",
    "gemini": "generativelanguage.googleapis.com",
    "mistral": "api.mistral.ai",
}

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
    AMBER when unset).  Raises ValueError on an unknown level."""
    from pipeline.stage4_stix_mapping import normalise_tlp, tlp_default

    if doc_tlp is not None and doc_tlp.strip():
        return normalise_tlp(doc_tlp)
    return tlp_default()


def provider_host(provider: str) -> str | None:
    """The host `provider` is reached at, lower-case and without credentials, port
    or brackets; None for a provider this module does not know."""
    prov = provider.strip().lower()
    if prov in _HOSTED:
        return _HOSTED[prov]
    if prov not in _BASE_URLS:
        return None
    var, default = _BASE_URLS[prov]
    base = os.environ.get(var, default).strip() or default
    if "://" not in base:
        base = f"//{base}"
    try:
        host = urlsplit(base).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def local_hosts() -> frozenset[str]:
    """The names LLM_LOCAL_HOSTS declares local (case-insensitive)."""
    raw = os.environ.get("LLM_LOCAL_HOSTS")
    if raw is None:
        raw = DEFAULT_LOCAL_HOSTS
    return frozenset(h.strip().strip("[]").lower() for h in raw.split(",") if h.strip())


def is_local(provider: str, host: str | None) -> bool:
    """True when `provider` is a local kind and `host` is a loopback or private
    address or a declared name.  No DNS lookup."""
    if provider.strip().lower() not in _BASE_URLS or not host:
        return False
    name = host.strip().strip("[]").lower()
    try:
        # A scoped IPv6 address (fe80::1%eth0) carries a zone ipaddress rejects before 3.9.
        addr = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        return name in local_hosts()
    return addr.is_loopback or addr.is_private


def decide(tlp: str, provider: str) -> EgressDecision:
    """May a report marked `tlp` (already normalised) go to `provider`?"""
    prov = provider.strip().lower()
    host = provider_host(prov)
    local = is_local(prov, host)
    if tlp in _OPEN_LEVELS or local:
        return EgressDecision(True, local, tlp, prov, host)
    where = f" ({host})" if host else ""
    return EgressDecision(False, local, tlp, prov, host,
                          f"TLP:{tlp} forbids sending the report to {prov}{where}: "
                          f"only a local provider may process it (ADR-0097)")
