"""`rel_is_listed` against `rel_is_allowed` (ADR-0062).

Stage 4 keeps an observable opposite an SDO only for a listed verb; the two
checks differ exactly where that decision would go wrong with the looser one.
"""
from pipeline.stix_rel_spec import rel_is_allowed, rel_is_listed


def test_common_relationships_are_allowed_but_not_listed():
    # §3.7: valid between any two objects, so they say nothing about the pair.
    assert rel_is_allowed("malware", "related-to", "domain-name")
    assert not rel_is_listed("malware", "related-to", "domain-name")
    assert rel_is_allowed("file", "derived-from", "file")
    assert not rel_is_listed("file", "derived-from", "file")


def test_unknown_or_empty_types_are_not_listed():
    # rel_is_suggested fails open on what it cannot classify; this must not.
    assert rel_is_allowed("", "communicates-with", "domain-name")
    assert not rel_is_listed("", "communicates-with", "domain-name")
    assert not rel_is_listed("x-custom", "communicates-with", "domain-name")


def test_listed_pairs_including_the_sco_wildcard_and_the_extension():
    assert rel_is_listed("malware", "communicates-with", "ipv6-addr")
    assert rel_is_listed("malware", "Drops", "file")                 # verb case-insensitive
    assert rel_is_listed("infrastructure", "consists-of", "x509-certificate")
    assert rel_is_listed("indicator", "based-on", "url")               # ADR-0061 extension
    assert not rel_is_listed("indicator", "based-on", "malware")


def test_direction_and_pair_matter():
    assert not rel_is_listed("domain-name", "communicates-with", "malware")
    assert not rel_is_listed("malware", "communicates-with", "file")
    assert not rel_is_listed("tool", "drops", "file")                # tool drops malware only
