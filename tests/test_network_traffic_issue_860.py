"""#860: a destination written against an arrow, with no blank around it
("tcp/443->evil.com"), is read as the flow it is.  The arrow splits the words;
the port still comes from the `tcp/` prefix."""
import pytest

from pipeline.network_traffic import TrafficDescriptor, parse_network_traffic


@pytest.mark.parametrize("text,expected", [
    ("tcp/443->evil.com", TrafficDescriptor("evil.com", "domain-name", 443, ("tcp",))),
    ("udp/53=>1.2.3.4", TrafficDescriptor("1.2.3.4", "ipv4-addr", 53, ("ipv4", "udp"))),
    ("tcp/443 → evil.com", TrafficDescriptor("evil.com", "domain-name", 443, ("tcp",))),
    # the control: the same flows with blanks, and the forms that must not change
    ("tcp/443 to evil.com", TrafficDescriptor("evil.com", "domain-name", 443, ("tcp",))),
    ("https://evil.com/path", TrafficDescriptor("evil.com", "domain-name", None, ("https",))),
    ("beacon to 2001:db8::1:443", TrafficDescriptor("2001:db8::1:443", "ipv6-addr", None, ("ipv6",))),
])
def test_an_arrow_separates_the_destination_issue_860(text, expected):
    assert parse_network_traffic(text) == expected


def test_a_text_without_a_host_is_still_none_issue_860():
    assert parse_network_traffic("tcp/443 -> nothing here") is None
