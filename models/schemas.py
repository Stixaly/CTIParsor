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
