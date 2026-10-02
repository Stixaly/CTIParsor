"""
Read a network-traffic observable an analyst typed ("beacon to 10.0.0.1:443",
"tcp/8443 to evil.example.com") into what a STIX 2.1 `network-traffic` needs
(ADR-0069).

Stage 4 used to ship it as `Software(name=...)`, which kept the words and lost
the type, the destination and the port.  A `network-traffic` needs at least one
of `src_ref`/`dst_ref` and a non-empty `protocols` list, so a descriptor that
names no destination, or names a domain but no protocol, is not built: nothing
here is guessed.  An IP destination gives its network layer (`ipv4`/`ipv6`) by
construction; the other protocols come only from words in the text.

Pure and stdlib-only.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from pipeline.detection.tlds import looks_like_domain
from pipeline.regex_safety import compile_pattern

# Low to high, as STIX lists protocols (§6.12): transport, then application.
_TRANSPORT = ("tcp", "udp", "icmp")
_APPLICATION = ("http", "https", "dns", "tls", "smtp", "ftp", "ssh")
_WORD = compile_pattern(r"[a-z0-9]+", re.IGNORECASE)
_PORT = compile_pattern(r"\b(?:port|tcp/|udp/)\s*(\d{1,5})\b", re.IGNORECASE)
_HOST_PORT = compile_pattern(r"^\[?([0-9A-Za-z.:-]+?)\]?(?::(\d{1,5}))?$")


@dataclass(frozen=True)
class TrafficDescriptor:
    host: str                  # the destination's value, lowercased
    host_type: str             # "ipv4-addr" | "ipv6-addr" | "domain-name"
    port: int | None
    protocols: tuple[str, ...]


def _host(token: str) -> tuple[str, str, int | None] | None:
    token = re.sub(r"^[a-z][a-z0-9+.-]*://", "", token.strip(".,;()'\""), flags=re.IGNORECASE)
    token = token.split("/", 1)[0]
    candidates: list[tuple[str, int | None]] = [(token, None)]
    m = _HOST_PORT.match(token)
    if m:
        candidates.insert(0, (m.group(1), int(m.group(2)) if m.group(2) else None))
    for host, port in candidates:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if looks_like_domain(host):
                return host.lower(), "domain-name", port
            continue
        return str(ip), ("ipv4-addr" if ip.version == 4 else "ipv6-addr"), port
    return None


def parse_network_traffic(text: str) -> TrafficDescriptor | None:
    """The destination, port and protocols `text` states, or None."""
    if not isinstance(text, str):
        return None
    found = None
    for token in text.split():
        found = _host(token)
        if found:
            break
    if found is None:
        return None
    host, host_type, port = found
    if port is None:
        m = _PORT.search(text)
        port = int(m.group(1)) if m else None
    if port is not None and not 0 < port < 65536:
        port = None
    words = {w.lower() for w in _WORD.findall(text)}
    network = {"ipv4-addr": ("ipv4",), "ipv6-addr": ("ipv6",)}.get(host_type, ())
    protocols = network + tuple(p for p in (*_TRANSPORT, *_APPLICATION) if p in words)
    if not protocols:
        return None
    return TrafficDescriptor(host, host_type, port, protocols)
