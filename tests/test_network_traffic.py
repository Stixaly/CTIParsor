"""ADR-0069: a network-traffic observable is read into a destination, a port
and protocols, and nothing is guessed."""
import pytest

from models.schemas import EntityType, RawEntity
from pipeline.network_traffic import TrafficDescriptor, parse_network_traffic
from pipeline.stage3_llm import LLMEnrichmentResult
from pipeline.stage4_stix_mapping import build_stix_bundle


@pytest.mark.parametrize("text,expected", [
    ("beacon to 10.0.0.1:443", TrafficDescriptor("10.0.0.1", "ipv4-addr", 443, ("ipv4",))),
    ("TCP 8443 to 203.0.113.9, port 8443",
     TrafficDescriptor("203.0.113.9", "ipv4-addr", 8443, ("ipv4", "tcp"))),
    ("tcp/4444 to 203.0.113.9", TrafficDescriptor("203.0.113.9", "ipv4-addr", 4444, ("ipv4", "tcp"))),
    ("[2001:db8::1]:53 udp dns", TrafficDescriptor("2001:db8::1", "ipv6-addr", 53, ("ipv6", "udp", "dns"))),
    ("https://Update.Example.com/check", TrafficDescriptor("update.example.com", "domain-name", None, ("https",))),
    ("evil.example.com:8080 over http", TrafficDescriptor("evil.example.com", "domain-name", 8080, ("http",))),
    # a bare IPv6 keeps its last group: it is not a port
    ("beacon to 2001:db8::1:443", TrafficDescriptor("2001:db8::1:443", "ipv6-addr", None, ("ipv6",))),
    # a domain label that names a protocol is not a protocol mention
    ("The domain ftp.example.com was registered", None),
    # ... however many times, and whatever punctuation follows it
    ("the ftp.example.com, ftp.example.com", None),
    ("ftp.example.com over ftp", TrafficDescriptor("ftp.example.com", "domain-name", None, ("ftp",))),
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


# #364: the host a network-traffic names is an observable like any other.  An
# entity naming the same host, before or after the flow, is the same object,
# not a second ipv4-addr with the same deterministic id.
@pytest.mark.parametrize("order", ["flow", "flow_then_ip", "ip_then_flow"])
def test_a_flow_and_its_host_are_one_observable_issue_364(order):
    # a public address: the benign filter keeps its Indicator
    flow = RawEntity(value="tcp/443 to 45.61.136.9", entity_type=EntityType.NETWORK_TRAFFIC)
    ip = RawEntity(value="45.61.136.9", entity_type=EntityType.IPV4)
    entities = {"flow": [flow], "flow_then_ip": [flow, ip], "ip_then_flow": [ip, flow]}[order]
    bundle = build_stix_bundle(entities, LLMEnrichmentResult(), "audit-network")
    objects = list(bundle.objects)

    ids = [o.id for o in objects]
    assert len(ids) == len(set(ids))
    (ipv4,) = [o for o in objects if o.type == "ipv4-addr"]
    (traffic,) = [o for o in objects if o.type == "network-traffic"]
    assert traffic.dst_ref == ipv4.id
    assert ipv4.value == "45.61.136.9"
    # the host's own Indicator, once, and its relationship to the one ipv4-addr
    ip_indicators = [o for o in objects if o.type == "indicator" and o.pattern == "[ipv4-addr:value = '45.61.136.9']"]
    assert len(ip_indicators) == (0 if order == "flow" else 1)
    ip_rels = [o for o in objects if o.type == "relationship" and o.source_ref in {i.id for i in ip_indicators}]
    assert [r.target_ref for r in ip_rels] == [ipv4.id] * len(ip_indicators)
