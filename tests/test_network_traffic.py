"""ADR-0069: a network-traffic observable is read into a destination, a port
and protocols, and nothing is guessed."""
import pytest

from pipeline.network_traffic import TrafficDescriptor, parse_network_traffic


@pytest.mark.parametrize("text,expected", [
    ("beacon to 10.0.0.1:443", TrafficDescriptor("10.0.0.1", "ipv4-addr", 443, ("ipv4",))),
    ("TCP 8443 to 203.0.113.9, port 8443",
     TrafficDescriptor("203.0.113.9", "ipv4-addr", 8443, ("ipv4", "tcp"))),
    ("tcp/4444 to 203.0.113.9", TrafficDescriptor("203.0.113.9", "ipv4-addr", 4444, ("ipv4", "tcp"))),
    ("[2001:db8::1]:53 udp dns", TrafficDescriptor("2001:db8::1", "ipv6-addr", 53, ("ipv6", "udp", "dns"))),
    ("https://Update.Example.com/check", TrafficDescriptor("update.example.com", "domain-name", None, ("https",))),
    ("evil.example.com:8080 over http", TrafficDescriptor("evil.example.com", "domain-name", 8080, ("http",))),
])
def test_what_the_text_states_is_read(text, expected):
    assert parse_network_traffic(text) == expected


@pytest.mark.parametrize("text", [
    "tcp/445",                       # no destination: STIX needs src_ref or dst_ref
    "beacon to evil.example.com",    # a domain and no protocol: protocols cannot be empty
    "drops update.exe",              # a file name, not a host (pipeline/detection/tlds.py)
    "",
])
def test_nothing_is_guessed(text):
    assert parse_network_traffic(text) is None


def test_an_out_of_range_port_is_not_kept():
    assert parse_network_traffic("10.0.0.1:99999").port is None
