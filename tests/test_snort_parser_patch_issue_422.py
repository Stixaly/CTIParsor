"""#422: the copied Snort parser accepted a bare Suricata sticky buffer (`http.uri;`)
after an option it knew, and raised UnboundLocalError when it came first.  The
local patch in snort_parser.py (ADR-0070, "Local patch") resets `opt` for every
option."""
import pytest

from pipeline.detection.opencti_snort import Parser
from pipeline.detection.pattern_check import ACCEPTED, REFUSED, check_pattern, net_rule_dialect

# A Suricata sticky buffer after a content match: Snort does not know `http.uri`.
_AFTER_CONTENT = 'alert tcp any any -> any any (msg:"x"; content:"abc"; http.uri; sid:1; rev:1;)'
# The same bare option as the first option of the rule.
_FIRST = 'alert tcp any any -> any any (http.uri; content:"abc"; sid:1; rev:1;)'
# A keyword neither dialect knows, after a content match.
_UNKNOWN_BARE = 'alert tcp any any -> any any (msg:"x"; content:"abc"; bogus.keyword; sid:1; rev:1;)'
# Control: a Snort rule with a bare option Dicts knows.  It must stay accepted.
_NOCASE = 'alert tcp any any -> any any (msg:"x"; content:"abc"; nocase; sid:1; rev:1;)'
# Suricata rule: `http.uri` is valid Suricata, so a rule typed snort must move to suricata.
_SURICATA_HTTP_URI = ('alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"x"; content:"abc"; '
                      'http.uri; sid:1; rev:1;)')


def test_a_sticky_buffer_after_content_is_refused_as_unrecognized_issue_422():
    with pytest.raises(ValueError, match="unrecognized option: http.uri"):
        Parser(_AFTER_CONTENT)
    status, error = check_pattern("snort", _AFTER_CONTENT)
    assert status == REFUSED and "unrecognized option: http.uri" in error


def test_a_sticky_buffer_first_is_refused_without_an_unbound_local_error_issue_422():
    with pytest.raises(ValueError, match="unrecognized option: http.uri"):
        Parser(_FIRST)
    status, error = check_pattern("snort", _FIRST)
    assert status == REFUSED and "UnboundLocalError" not in error


def test_an_unknown_bare_keyword_after_content_is_refused_issue_422():
    status, error = check_pattern("snort", _UNKNOWN_BARE)
    assert status == REFUSED and "unrecognized option: bogus.keyword" in error


def test_a_known_bare_option_after_content_is_still_accepted_issue_422():
    assert check_pattern("snort", _NOCASE) == (ACCEPTED, None)
    assert net_rule_dialect("snort", _NOCASE) == ("snort", ACCEPTED, None, None)


def test_a_suricata_sticky_buffer_typed_snort_is_retyped_suricata_issue_422():
    pytest.importorskip("parsuricata")
    assert check_pattern("snort", _SURICATA_HTTP_URI)[0] == REFUSED
    assert net_rule_dialect("snort", _SURICATA_HTTP_URI) == (
        "suricata", ACCEPTED, None, "snort")
