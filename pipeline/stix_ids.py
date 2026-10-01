"""STIX ids computed the way OpenCTI computes its standard ids (ADR-0066).

OpenCTI derives the id of a STIX object from a few of its properties: the
lower-cased name, an ATT&CK id, an indicator's pattern, a marking's definition.
They are serialised as RFC 8785 canonical JSON and hashed as a UUIDv5 under
00abedb4-aa42-466c-9c01-fed23315a9b7.  The platform does it in
`opencti-graphql/src/schema/identifier.js` (`generateStixId`).  Its Python
client does it in the `generate_id` functions of `pycti/entities/`, which
connectors call so that their ids match the platform's.  Each function below
reproduces one of them, with the same canonicaliser pycti imports
(`stix2.canonicalization`).

A bundle carrying these ids lands in OpenCTI on the objects already there: the
ATT&CK technique another connector imported, the built-in PAP marking, the
sector, the country.  Before, every CTIParsor id was OpenCTI's own lookup key
for nothing; its dedup merged the objects back by properties, and kept the
foreign id as an alias.

What this inherits from OpenCTI, knowingly:

* STIX 2.1 §2.9 says domain objects SHOULD use UUIDv4.  The validator's {103}
  warning stays, as it does on OpenCTI's own exports.
* §2.9 also says a producer generating UUIDv5 ids for anything but SCOs MUST
  NOT use the namespace above, and MUST NOT reuse a UUID across object types.
  OpenCTI does both: a malware and a tool of the same name share the UUID
  part.  The full ids still differ, because the type prefix does.

The scheme it replaces (`_make_deterministic_id`, removed) also used that namespace, and
also yielded UUIDv5.  It only matched nothing outside CTIParsor.
"""
from __future__ import annotations

import uuid

from stix2.canonicalization.Canonicalize import canonicalize

OASIS_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _gen(stix_type: str, data: dict) -> str:
    return f"{stix_type}--{uuid.uuid5(OASIS_NAMESPACE, canonicalize(data, utf8=False))}"


def _norm(value: str) -> str:
    # identifier.js `normalizeName`; pycti `.lower().strip()`
    return value.lower().strip()


# pycti Malware / Tool / Campaign / IntrusionSet / Infrastructure /
# Vulnerability `generate_id(name)`: {"name": <normalised>}.
_BY_NAME = frozenset({"malware", "tool", "campaign", "intrusion-set", "infrastructure",
                      "vulnerability"})


def named_object_id(stix_type: str, name: str) -> str:
    """Id of an object OpenCTI identifies by its name alone, or a threat actor."""
    if stix_type == "threat-actor":
        # pycti ThreatActorGroup: OpenCTI imports a STIX threat-actor as a
        # Threat-Actor-Group, and that type is part of its id.
        return _gen(stix_type, {"name": _norm(name), "opencti_type": "Threat-Actor-Group"})
    if stix_type in _BY_NAME:
        return _gen(stix_type, {"name": _norm(name)})
    raise ValueError(f"no name-based id rule for {stix_type!r}")


def attack_pattern_id(name: str, mitre_id: str | None = None) -> str:
    """pycti AttackPattern: the ATT&CK id when there is one, else the name.

    Only an ATT&CK id counts.  On import, pycti reads `x_mitre_id` from an
    external reference whose source starts with "mitre-", and a CAPEC
    reference does not.  A CAPEC pattern is therefore identified by its name,
    in OpenCTI and here alike.
    """
    if mitre_id and not mitre_id.strip().upper().startswith("CAPEC-"):
        return _gen("attack-pattern", {"x_mitre_id": _norm(mitre_id)})
    return _gen("attack-pattern", {"name": _norm(name)})


def course_of_action_id(name: str, mitre_id: str | None = None) -> str:
    """pycti CourseOfAction: the ATT&CK id when there is one, else the name."""
    if mitre_id:
        return _gen("course-of-action", {"x_mitre_id": _norm(mitre_id)})
    return _gen("course-of-action", {"name": _norm(name)})


def identity_id(name: str, identity_class: str) -> str:
    """pycti Identity: name and identity_class ("class" for a sector)."""
    return _gen("identity", {"name": _norm(name), "identity_class": identity_class.lower()})


def location_id(name: str, location_type: str = "Country") -> str:
    """pycti Location for a named place.  The type is OpenCTI's, not STIX's:
    a STIX location carrying `country` is imported as a Country."""
    return _gen("location", {"name": _norm(name), "x_opencti_location_type": location_type})


def indicator_id(pattern: str) -> str:
    """pycti Indicator: the pattern, stripped — the same IoC or rule always
    lands on the same Indicator, whichever report produced it."""
    return _gen("indicator", {"pattern": pattern.strip()})


def marking_id(definition_type: str, definition: str) -> str:
    """pycti MarkingDefinition, for a marking OpenCTI has no static id for.

    OpenCTI's built-in PAP markings are `definition_type: 'PAP'` with
    `definition: 'PAP:CLEAR' | 'PAP:GREEN' | 'PAP:AMBER' | 'PAP:RED'`
    (`domain/markingDefinition.js`).  The same pair gives the same id.
    """
    return _gen("marking-definition", {"definition_type": definition_type, "definition": definition})


def incident_id(name: str) -> str:
    """Deterministic incident id — the one place this does NOT match OpenCTI.

    pycti's Incident id also hashes `created`, which a bundle build stamps with
    the build time.  Following it would give the same incident a new id at
    every rebuild.  OpenCTI recomputes its own id on import either way.
    """
    return _gen("incident", {"name": _norm(name)})
