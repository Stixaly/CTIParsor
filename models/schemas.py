from enum import Enum

from pydantic import BaseModel


class EntityType(str, Enum):
    # ── STIX SCOs — cyber-observables ────────────────────────────────────────
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    MAC_ADDR = "mac_addr"          # mac-addr SCO
    ASN = "asn"                    # autonomous-system SCO
    FILE = "file"                  # file SCO (path / filename)
    REGISTRY_KEY = "registry_key"  # windows-registry-key SCO
    MUTEX = "mutex"                # mutex SCO
    NETWORK_TRAFFIC = "network_traffic"  # network-traffic SCO
    USER_ACCOUNT = "user_account"  # user-account SCO
    # ── CVE / Vulnerability ───────────────────────────────────────────────────
    CVE = "cve"                    # vulnerability SDO (CVE id)
    # ── ATT&CK TTPs ───────────────────────────────────────────────────────────
    TTP = "ttp"
    TECHNIQUE = "technique"        # attack-pattern SDO
    TACTIC = "tactic"
    PROCEDURE = "procedure"
    # ── Named SDOs ────────────────────────────────────────────────────────────
    MALWARE = "malware"
    THREAT_ACTOR = "threat_actor"  # threat-actor SDO
    INTRUSION_SET = "intrusion_set"  # intrusion-set SDO
    TOOL = "tool"
    CAMPAIGN = "campaign"
    INFRASTRUCTURE = "infrastructure"  # infrastructure SDO
    IDENTITY = "identity"          # identity SDO (org / individual)
    LOCATION = "location"          # location SDO
    INCIDENT = "incident"          # incident SDO (STIX 2.1)


# Canonical set of valid STIX 2.1 relationship (SRO) types.
#
# Single source of truth shared by the STIX builder (pipeline/stage4) and the
# manual relationship-editing API (api/routes/relationships).  Keeping these in
# one place prevents the two from drifting: a reviewer must be able to add any
# verb the pipeline itself can emit, otherwise valid edges like
# "communicates-with" or "beacons-to" get rejected with a 400.
STIX_RELATIONSHIP_TYPES: frozenset[str] = frozenset({
    # Delivery & execution
    "delivers", "drops", "downloads", "exploits",
    # Targeting & attribution
    "targets", "attributed-to", "originates-from", "authored-by", "impersonates",
    # Usages
    "uses", "controls", "has", "hosts", "owns",
    # Infrastructure / C2
    "compromises", "beacons-to", "communicates-with", "exfiltrates-to",
    # Detection & analysis
    "indicates", "based-on", "consists-of",
    "analysis-of", "static-analysis-of", "dynamic-analysis-of",
    "characterizes", "investigates",
    # Mitigation
    "mitigates", "remediates",
    # Location
    "located-at",
    # SCO-specific
    "resolves-to", "belongs-to",
    # Malware variants
    "variant-of",
    # Generic
    "duplicate-of", "derived-from", "related-to",
})


class EvidenceLabel(str, Enum):
    """How well a source supports a claim (NATO/Admiralty-style evidence grading).

    Applied to relationships (and, later, entities) so an analyst can tell a
    directly-observed fact from an LLM inference at the same confidence number.
    """
    OBSERVED = "observed"   # directly shown in telemetry/sample/log/screenshot — strongest
    REPORTED = "reported"   # the source states it (assertion-level)
    ASSESSED = "assessed"   # the source's analytical judgment
    INFERRED = "inferred"   # analyst/LLM conclusion combining multiple facts — weakest
    GAP      = "gap"        # unknown / not proven in the text


class RawEntity(BaseModel):
    value: str
    entity_type: EntityType
    context: str = ""
    confidence: float = 1.0
    mitre_id: str | None = None
    # Origin of this entity — used as the 'source' column in the DB
    # "ioc"       = regex/spaCy pattern match (Stage 2)
    # "gazetteer" = MITRE name dictionary match (Stage 2b)
    # "llm"       = LLM extraction (Stage 3)
    source: str = "ioc"
