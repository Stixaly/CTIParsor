import json
import os
import uuid
from datetime import datetime, timezone

import stix2

# Initialize logging
from api.logging_config import get_logger
from models.schemas import EntityType, RawEntity
from pipeline.stage3_llm import LLMEnrichmentResult
from pipeline.stix_rel_spec import rel_is_suggested

logger = get_logger(__name__)

# STIX 2.1 deterministic ID namespace (SCO/SDO identity namespace per the spec)
_STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _make_deterministic_id(value: str, entity_type: str, prefix: str = "") -> str:
    """
    Generate a deterministic STIX 2.1-compliant ID for an entity.

    Uses UUID v5 (namespace + name) so the same entity always gets the same
    STIX ID across runs and reports, preventing duplicate objects in bundles.
    STIX 2.1 requires IDs to be in <type>--<UUIDv4-or-v5> format.
    """
    normalized = f"{prefix}:{entity_type.lower().strip()}:{value.lower().strip()}"
    det_uuid = uuid.uuid5(_STIX_NAMESPACE, normalized)
    return f"{entity_type}--{det_uuid}"


# ---------------------------------------------------------------------------
# Provenance & sharing metadata (TLP marking + authoring Identity)
#
# Every object in the bundle is stamped with:
#   • object_marking_refs → a TLP marking (configurable via STIX_TLP)
#   • created_by_ref      → an Identity SDO representing CTIParsor as the
#                           intelligence AUTHOR (not the threat actor).  SCOs
#                           are marked but carry no created_by_ref (STIX 2.1
#                           cyber-observables have no such property).
# This is what makes a bundle "ingestion-grade" for OpenCTI / MISP, which apply
# sharing policy from the TLP marking and group intel by author identity.
# ---------------------------------------------------------------------------

_TLP_MARKINGS = {
    "clear": stix2.TLP_WHITE, "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red":   stix2.TLP_RED,
}


def _tlp_marking() -> stix2.MarkingDefinition:
    """Return the TLP MarkingDefinition selected by STIX_TLP (default: clear).

    Uses the stix2 predefined TLP markings, which have the standard interoperable
    IDs that OpenCTI / MISP recognise out of the box.
    """
    level = os.environ.get("STIX_TLP", "clear").strip().lower()
    return _TLP_MARKINGS.get(level, stix2.TLP_WHITE)


def _authoring_identity() -> stix2.Identity:
    """Stable Identity SDO naming CTIParsor as the author of all bundle objects.

    created_by_ref on every object points here — to the pipeline that produced
    the intelligence, NOT to the threat actor.  Actor attribution is expressed
    only via the `attributed-to` relationship.
    """
    name = os.environ.get("STIX_AUTHOR_NAME", "CTIParsor").strip() or "CTIParsor"
    ident_id = _make_deterministic_id(name, "identity", prefix="author")
    return stix2.Identity(
        id=ident_id,
        name=name,
        identity_class="system",
        description=(
            "Automated CTI extraction pipeline. Authored the objects in this "
            "bundle. created_by_ref refers to this pipeline as the intelligence "
            "author, not to the threat actor."
        ),
        allow_custom=True,
    )


def _stamp_provenance(obj, author_id: str, marking_id: str):
    """Return a copy of *obj* carrying the TLP marking (and, for SDO/SRO, the
    authoring created_by_ref).  Serialises to plain JSON first so nested
    properties reconstruct cleanly via stix2.parse.
    """
    if obj.get("type") == "marking-definition":
        return obj  # don't mark the marking itself
    try:
        d = json.loads(obj.serialize())
    except Exception:
        return obj
    marks = list(d.get("object_marking_refs", []))
    if marking_id not in marks:
        marks.append(marking_id)
    d["object_marking_refs"] = marks
    # SDOs and SROs have a 'created' timestamp and may carry created_by_ref;
    # SCOs (cyber-observables) do not.  Never self-reference the author.
    if "created" in d and d.get("id") != author_id:
        d.setdefault("created_by_ref", author_id)
    try:
        return stix2.parse(d, allow_custom=True)
    except Exception:
        return obj

# ---------------------------------------------------------------------------
# All valid STIX 2.1 relationship types (Section 4 + Appendix B of the spec).
# Used to validate / filter LLM-suggested relationship_type values before
# creating stix2.Relationship objects.
# ---------------------------------------------------------------------------

VALID_REL_TYPES: frozenset[str] = frozenset({
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

# Common country name → ISO 3166-1 alpha-2 codes appearing in CTI reports
_COUNTRY_ISO: dict[str, str] = {
    "afghanistan": "AF", "albania": "AL", "algeria": "DZ", "angola": "AO",
    "argentina": "AR", "armenia": "AM", "australia": "AU", "austria": "AT",
    "azerbaijan": "AZ", "bahrain": "BH", "bangladesh": "BD", "belarus": "BY",
    "belgium": "BE", "bolivia": "BO", "brazil": "BR", "bulgaria": "BG",
    "cambodia": "KH", "canada": "CA", "chile": "CL", "china": "CN",
    "colombia": "CO", "croatia": "HR", "cuba": "CU", "czechia": "CZ",
    "czech republic": "CZ", "denmark": "DK", "ecuador": "EC", "egypt": "EG",
    "ethiopia": "ET", "finland": "FI", "france": "FR", "georgia": "GE",
    "germany": "DE", "ghana": "GH", "greece": "GR", "hungary": "HU",
    "india": "IN", "indonesia": "ID", "iran": "IR", "iraq": "IQ",
    "ireland": "IE", "israel": "IL", "italy": "IT", "japan": "JP",
    "jordan": "JO", "kazakhstan": "KZ", "kenya": "KE", "kuwait": "KW",
    "latvia": "LV", "lebanon": "LB", "libya": "LY", "lithuania": "LT",
    "malaysia": "MY", "mexico": "MX", "moldova": "MD", "morocco": "MA",
    "mozambique": "MZ", "myanmar": "MM", "namibia": "NA", "netherlands": "NL",
    "new zealand": "NZ", "nigeria": "NG", "north korea": "KP", "norway": "NO",
    "oman": "OM", "pakistan": "PK", "palestine": "PS", "panama": "PA",
    "peru": "PE", "philippines": "PH", "poland": "PL", "portugal": "PT",
    "qatar": "QA", "romania": "RO", "russia": "RU", "russian federation": "RU",
    "saudi arabia": "SA", "serbia": "RS", "singapore": "SG", "slovakia": "SK",
    "somalia": "SO", "south africa": "ZA", "south korea": "KR", "spain": "ES",
    "sri lanka": "LK", "sudan": "SD", "sweden": "SE", "switzerland": "CH",
    "syria": "SY", "taiwan": "TW", "tajikistan": "TJ", "thailand": "TH",
    "tunisia": "TN", "turkey": "TR", "turkmenistan": "TM", "uganda": "UG",
    "ukraine": "UA", "united arab emirates": "AE", "uae": "AE",
    "united kingdom": "GB", "uk": "GB", "great britain": "GB",
    "united states": "US", "usa": "US", "u.s.": "US", "u.s.a.": "US",
    "uzbekistan": "UZ", "venezuela": "VE", "vietnam": "VN", "yemen": "YE",
    "zimbabwe": "ZW",
}


_MIME_TYPES: dict[str, str] = {
    ".pdf":  "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".html": "text/html",
    ".htm":  "text/html",
    ".txt":  "text/plain",
    ".md":   "text/markdown",
}

# Entity types that are technical observables (the regex/defang IoC outputs of
# Stage 2).  Each should map to a STIX SCO and — via _build_stix_pattern — an
# Indicator.  CVE/TTP/named-entity types are intentionally excluded: they become
# Vulnerability/AttackPattern/Malware SDOs, not cyber-observable Indicators.
_OBSERVABLE_IOC_TYPES: frozenset[EntityType] = frozenset({
    EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN, EntityType.URL,
    EntityType.EMAIL, EntityType.MD5, EntityType.SHA1, EntityType.SHA256,
    EntityType.MAC_ADDR, EntityType.ASN, EntityType.FILE,
    EntityType.REGISTRY_KEY, EntityType.MUTEX, EntityType.NETWORK_TRAFFIC,
    EntityType.USER_ACCOUNT,
})


def build_stix_bundle(
    raw_entities: list[RawEntity],
    llm_result: LLMEnrichmentResult,
    report_name: str,
    *,
    report_text: str = "",
    original_filename: str = "",
    source_hash: str | None = None,
    relationship_policy: dict | None = None,
) -> stix2.Bundle:
    """
    Converts all extracted entities to STIX 2.1 objects and returns a Bundle.

    New optional keyword arguments:
      report_text       — full extracted text of the ingested document.
                          Stored in report.description so STIX consumers can
                          read the original narrative alongside the objects.
      original_filename — original filename (e.g. "apt29_report.pdf").
                          Used to determine the artifact MIME type and to
                          add a human-readable external reference.
      source_hash       — SHA-256 hex digest of the original uploaded file.
                          Creates an artifact SCO (STIX 2.1 §4.4) that
                          represents the source document with its hash —
                          allowing consumers to verify or retrieve the file.

    Mapping:
    - IP, domain, URL, hash  → SCO  (Cyber-observable Object)
    - Malware, ThreatActor   → SDO  (Domain Object)
    - AttackPattern, Tool    → SDO
    - CVE                    → Vulnerability SDO
    - IoC + malware link     → Indicator SDO  + indicates → Malware
    - Semantic relations     → Relationship SRO (deduplicated)
    - Source document        → artifact SCO + report.description
    - Relationship policy    → pinned rules override inferred verbs

    relationship_policy — optional dict loaded from the database.
      Shape: { "version": 1, "global": "enforce"|"auto",
               "rules": [{ "src": stix_type, "verb", "tgt": stix_type,
                           "mode": "pin"|"auto", "enabled": bool }] }
      Resolution (mirrors the frontend preview logic):
        • global == "auto"              → keep pipeline verb (always)
        • rule exists + enabled + pin   → replace verb with rule.verb
        • otherwise                     → keep pipeline verb
    """
    stix_objects: list = []

    # ── Pre-compute policy rule index ────────────────────────────────────────
    # Keyed by "src_stix_type>tgt_stix_type" → rule dict.
    # Only built when the policy is in "enforce" mode; ignored when "auto".
    _pol_index: dict[str, dict] = {}
    if relationship_policy and relationship_policy.get("global") != "auto":
        for _rule in relationship_policy.get("rules", []):
            _src = _rule.get("src", "")
            _tgt = _rule.get("tgt", "")
            if _src and _tgt:
                _pol_index[f"{_src}>{_tgt}"] = _rule

    # Maps name/value (lowercase) → STIX object, used to resolve relationships
    name_to_stix: dict[str, object] = {}

    # --- SCOs from technical IoCs ---
    scos, value_to_sco = _map_iocs_to_scos(raw_entities)
    stix_objects.extend(scos)
    name_to_stix.update(value_to_sco)

    # --- SDOs from pipeline-detected entity types (infrastructure, intrusion_set, etc.) ---
    _sdo_entity_types = {
        EntityType.INFRASTRUCTURE,
        EntityType.INTRUSION_SET,
        EntityType.LOCATION,
        EntityType.IDENTITY,
        EntityType.CAMPAIGN,
        EntityType.INCIDENT,
    }
    for entity in raw_entities:
        if entity.entity_type not in _sdo_entity_types:
            continue
        key = entity.value.lower()
        if key in name_to_stix:
            continue
        sdo = _entity_to_sdo(entity)
        if sdo is not None:
            stix_objects.append(sdo)
            name_to_stix[key] = sdo

    # --- SDOs from LLM results ---
    # Deduplicate names case-insensitively before creating SDOs so that
    # "APT29" and "apt29" don't produce two separate ThreatActor objects.

    _seen_actors: set[str] = set()
    for actor_name in llm_result.threat_actors:
        if actor_name.lower() in _seen_actors:
            continue
        _seen_actors.add(actor_name.lower())
        # Use deterministic ID to prevent collisions across reports
        actor_id = _make_deterministic_id(actor_name, "threat-actor", "cti")
        obj = stix2.ThreatActor(name=actor_name, id=actor_id)
        stix_objects.append(obj)
        name_to_stix[actor_name.lower()] = obj

    _seen_malware: set[str] = set()
    for malware_name in llm_result.malware_families:
        if malware_name.lower() in _seen_malware:
            continue
        _seen_malware.add(malware_name.lower())
        # Use deterministic ID to prevent collisions across reports
        malware_id = _make_deterministic_id(malware_name, "malware", "cti")
        obj = stix2.Malware(name=malware_name, is_family=True, id=malware_id)
        stix_objects.append(obj)
        name_to_stix[malware_name.lower()] = obj

    _seen_tools: set[str] = set()
    for tool_name in llm_result.tools:
        if tool_name.lower() in _seen_tools:
            continue
        _seen_tools.add(tool_name.lower())
        # Use deterministic ID to prevent collisions across reports
        tool_id = _make_deterministic_id(tool_name, "tool", "cti")
        obj = stix2.Tool(name=tool_name, id=tool_id)
        stix_objects.append(obj)
        name_to_stix[tool_name.lower()] = obj

    for ttp in llm_result.ttps:
        external_refs = []
        if ttp.mitre_id:
            mid = ttp.mitre_id
            # Route by ID family:
            #   CAPEC-NNN  → Common Attack Pattern Enumeration and Classification
            #   TA0NNN     → MITRE ATT&CK tactic
            #   T1NNN[.NNN] → MITRE ATT&CK technique / sub-technique
            #
            # The stix2validator enforces that external references whose external_id
            # matches CAPEC-N+ format MUST have source_name="capec" (not "mitre-attack").
            # Routing CAPEC IDs to source_name="mitre-attack" is the STIX 2.1 spec
            # violation that marks the bundle Invalid with error {104}.
            if mid.upper().startswith("CAPEC-"):
                capec_num = mid.split("-", 1)[1]
                ref_source = "capec"
                ref_url = f"https://capec.mitre.org/data/definitions/{capec_num}.html"
            elif mid.upper().startswith("TA"):
                ref_source = "mitre-attack"
                ref_url = f"https://attack.mitre.org/tactics/{mid}/"
            else:
                ref_source = "mitre-attack"
                ref_url = f"https://attack.mitre.org/techniques/{mid.replace('.', '/')}/"
            external_refs.append(
                stix2.ExternalReference(
                    source_name=ref_source,
                    external_id=mid,
                    url=ref_url,
                )
            )
        # Use MITRE ID for deterministic ID if available, otherwise use name
        ttp_id_value = ttp.mitre_id if ttp.mitre_id else ttp.technique_name
        ttp_id = _make_deterministic_id(ttp_id_value, "attack-pattern", "cti")
        obj = stix2.AttackPattern(
            name=ttp.technique_name,
            description=ttp.description or "",
            external_references=external_refs,
            id=ttp_id,
        )
        stix_objects.append(obj)
        name_to_stix[ttp.technique_name.lower()] = obj
        if ttp.mitre_id:
            name_to_stix[ttp.mitre_id.lower()] = obj

    # Manually annotated technique / tactic / procedure / ttp entities → AttackPattern SDOs.
    # Guard: skip if an AttackPattern with the same name or MITRE ID was already created
    # by the llm_result.ttps loop above — avoids duplicate SDOs in the bundle.
    for entity in raw_entities:
        if entity.entity_type in (EntityType.TECHNIQUE, EntityType.TACTIC,
                                   EntityType.PROCEDURE, EntityType.TTP):
            key = entity.value.lower()
            id_key = entity.mitre_id.lower() if entity.mitre_id else None
            if key in name_to_stix or (id_key and id_key in name_to_stix):
                continue   # already created from llm_result.ttps
            ext_refs = []
            if entity.mitre_id:
                mid = entity.mitre_id
                # Same CAPEC / tactic / technique routing as the LLM TTP loop above.
                # CAPEC IDs require source_name="capec"; mixing them with "mitre-attack"
                # triggers stix2validator error {104} and marks the bundle Invalid.
                if mid.upper().startswith("CAPEC-"):
                    capec_num = mid.split("-", 1)[1]
                    ref_source = "capec"
                    ref_url = f"https://capec.mitre.org/data/definitions/{capec_num}.html"
                elif mid.upper().startswith("TA"):
                    ref_source = "mitre-attack"
                    ref_url = f"https://attack.mitre.org/tactics/{mid}/"
                else:
                    ref_source = "mitre-attack"
                    ref_url = f"https://attack.mitre.org/techniques/{mid.replace('.', '/')}/"
                ext_refs.append(stix2.ExternalReference(
                    source_name=ref_source,
                    external_id=mid,
                    url=ref_url,
                ))
            obj = stix2.AttackPattern(name=entity.value, external_references=ext_refs)
            stix_objects.append(obj)
            name_to_stix[key] = obj
            if id_key:
                name_to_stix[id_key] = obj

    for entity in raw_entities:
        if entity.entity_type == EntityType.CVE:
            key = entity.value.lower()
            if key in name_to_stix:
                continue  # same CVE from a second source — don't create duplicate SDO
            vuln_id = _make_deterministic_id(entity.value, "vulnerability", "cti")
            obj = stix2.Vulnerability(
                name=entity.value,
                external_references=[
                    stix2.ExternalReference(
                        source_name="cve",
                        external_id=entity.value,
                        url=f"https://nvd.nist.gov/vuln/detail/{entity.value}",
                    )
                ],
                id=vuln_id,
            )
            stix_objects.append(obj)
            name_to_stix[key] = obj

    if llm_result.campaign_name:
        _camp_key = llm_result.campaign_name.lower()
        if _camp_key not in name_to_stix:  # may already exist from raw_entities Campaign entity
            campaign_id = _make_deterministic_id(llm_result.campaign_name, "campaign", "cti")
            obj = stix2.Campaign(name=llm_result.campaign_name, id=campaign_id)
            stix_objects.append(obj)
            name_to_stix[_camp_key] = obj

    # --- Location SDOs (targeted countries) ---
    # One stix2.Location per country; linked via targets SRO from threat actors later
    for country in llm_result.targeted_countries:
        try:
            iso2 = _COUNTRY_ISO.get(country.strip().lower())
            if not iso2:
                # Skip countries we can't map to a valid ISO code; using
                # region="unknown" is not in the STIX 2.1 vocabulary and would
                # fail strict validation.
                continue
            location_id = _make_deterministic_id(f"{country}_{iso2}", "location", "cti")
            obj = stix2.Location(name=country, country=iso2, id=location_id)
            stix_objects.append(obj)
            name_to_stix[f"location:{country.lower()}"] = obj
        except Exception:
            pass

    # --- Identity SDOs (targeted sectors) ---
    # Represents a class of organisations in that sector
    for sector in llm_result.targeted_sectors:
        try:
            identity_id = _make_deterministic_id(sector, "identity", "cti")
            obj = stix2.Identity(name=sector, identity_class="class", id=identity_id)
            stix_objects.append(obj)
            name_to_stix[f"identity:{sector.lower()}"] = obj
        except Exception:
            pass

    # --- CourseOfAction SDOs (recommended mitigations) ---
    for coa in llm_result.course_of_action:
        try:
            coa_id = _make_deterministic_id(coa, "course-of-action", "cti")
            obj = stix2.CourseOfAction(name=coa, id=coa_id)
            stix_objects.append(obj)
            name_to_stix[f"coa:{coa.lower()}"] = obj
        except Exception:
            pass

    # Shared dedup set for ALL Relationship SROs created below (indicates,
    # based-on, targets, and the semantic relationships loop).  Keyed by
    # (source_id, rel_type, target_id) so a repeated logical edge is emitted once.
    seen_rel_keys: set[tuple] = set()

    # ObservedData wrapping for IoC indicators.  STIX 2.1 best-practice chain is
    #   SCO  ◄─(object_refs)─  observed-data  ◄─(based-on)─  indicator
    # Linking an indicator --based-on--> directly to a SCO is permitted but raises
    # a {202} best-practice warning; observed-data is the suggested target.
    # Cached per SCO id so indicators sharing an observable share one ObservedData.
    _observed_data_by_sco: dict[str, object] = {}

    def _observed_data_for(sco):
        """Create (once) an ObservedData SDO referencing one SCO; return it or None."""
        if sco is None or not hasattr(sco, "id"):
            return None
        if sco.id in _observed_data_by_sco:
            return _observed_data_by_sco[sco.id]
        try:
            _now = datetime.now(timezone.utc)
            od = stix2.ObservedData(
                id=_make_deterministic_id(sco.id, "observed-data", "cti"),
                first_observed=_now,
                last_observed=_now,
                number_observed=1,
                object_refs=[sco.id],
            )
            stix_objects.append(od)
            _observed_data_by_sco[sco.id] = od
            return od
        except Exception:
            return None

    # --- Indicator SDOs for IoCs linked to malware ---
    # Each ioc_association becomes: Indicator (pattern) --indicates--> Malware
    seen_indicators: set[str] = set()

    for assoc in llm_result.ioc_associations:
        if not assoc.ioc_value or not assoc.malware_name:
            continue
        sco = name_to_stix.get(assoc.ioc_value.lower())
        malware = name_to_stix.get(assoc.malware_name.lower())

        if not sco or not malware:
            continue

        ioc_key = assoc.ioc_value.lower()
        if ioc_key in seen_indicators:
            # Indicator already created for this IoC — just add another indicates rel if needed
            existing_indicator = name_to_stix.get(f"indicator:{ioc_key}")
            if existing_indicator:
                _add_relationship(
                    stix_objects, existing_indicator, "indicates", malware,
                    confidence=0.8, pol_index=_pol_index, seen=seen_rel_keys,
                )
            continue

        pattern = _build_stix_pattern(assoc.ioc_value, sco)
        if not pattern:
            continue

        try:
            indicator_id = _make_deterministic_id(f"ioc_{assoc.ioc_value}", "indicator", "cti")
            indicator = stix2.Indicator(
                name=f"Malicious IoC: {assoc.ioc_value}",
                pattern=pattern,
                pattern_type="stix",
                valid_from=datetime.now(timezone.utc),
                indicator_types=["malicious-activity"],
                id=indicator_id,
            )
            stix_objects.append(indicator)
            name_to_stix[f"indicator:{ioc_key}"] = indicator
            seen_indicators.add(ioc_key)

            _add_relationship(stix_objects, indicator, "indicates", malware, confidence=0.8,
                              pol_index=_pol_index, seen=seen_rel_keys)
            # Indicator --based-on--> ObservedData --(object_refs)--> SCO
            obs = _observed_data_for(sco)
            if obs is not None:
                _add_relationship(stix_objects, indicator, "based-on", obs, confidence=0.9,
                                  pol_index=_pol_index, seen=seen_rel_keys)
        except Exception:
            pass

    # --- Indicator SDOs for remaining IoCs (not already covered by ioc_associations) ---
    # Research best-practice: every accepted IoC should have a machine-readable pattern
    for entity in raw_entities:
        ioc_key = entity.value.lower()
        if ioc_key in seen_indicators:
            continue  # already has an indicator
        sco = value_to_sco.get(ioc_key)
        if sco is None:
            continue
        pattern = _build_stix_pattern(entity.value, sco)
        if not pattern:
            continue
        try:
            indicator_id = _make_deterministic_id(f"ioc_{entity.value}", "indicator", "cti")
            indicator = stix2.Indicator(
                name=f"Indicator: {entity.value}",
                pattern=pattern,
                pattern_type="stix",
                valid_from=datetime.now(timezone.utc),
                indicator_types=["malicious-activity"],
                id=indicator_id,
            )
            stix_objects.append(indicator)
            name_to_stix[f"indicator:{ioc_key}"] = indicator
            seen_indicators.add(ioc_key)
            # Indicator --based-on--> ObservedData --(object_refs)--> SCO
            obs = _observed_data_for(sco)
            if obs is not None:
                _add_relationship(stix_objects, indicator, "based-on", obs, confidence=0.9,
                                  pol_index=_pol_index, seen=seen_rel_keys)
        except Exception:
            pass

    # --- Targets SROs: threat actors → targets → locations and sectors ---
    for actor_name in llm_result.threat_actors:
        actor = name_to_stix.get(actor_name.lower())
        if not actor:
            continue
        for country in llm_result.targeted_countries:
            location = name_to_stix.get(f"location:{country.lower()}")
            if location:
                _add_relationship(stix_objects, actor, "targets", location,
                                  pol_index=_pol_index, seen=seen_rel_keys)
        for sector in llm_result.targeted_sectors:
            identity = name_to_stix.get(f"identity:{sector.lower()}")
            if identity:
                _add_relationship(stix_objects, actor, "targets", identity,
                                  pol_index=_pol_index, seen=seen_rel_keys)

    # --- SROs — semantic relationships (deduplicated, spec-validated) ---
    # Reuses the shared seen_rel_keys set so a semantic edge that duplicates a
    # targets/indicates edge created above is also collapsed.
    for rel in llm_result.relationships:
        source = name_to_stix.get(rel.source_value.lower())
        target = name_to_stix.get(rel.target_value.lower())

        if not source or not target:
            continue
        if not hasattr(source, "id") or not hasattr(target, "id"):
            continue

        # Normalise and validate relationship type against the STIX 2.1 spec
        rel_type = rel.relationship_type.strip().lower()
        if rel_type not in VALID_REL_TYPES:
            rel_type = "related-to"   # safe fallback for any LLM hallucination

        # Apply relationship policy (may override the inferred verb)
        if _pol_index:
            rel_type = _apply_policy(rel_type, source, target, _pol_index)

        # STIX 2.1 best-practice: if the verb is not a *suggested* relationship
        # for this (source-type → target-type) pair, fall back to the universal
        # 'related-to' so the bundle stays within the spec's relationship model.
        if not rel_is_suggested(getattr(source, "type", ""), rel_type, getattr(target, "type", "")):
            rel_type = "related-to"

        rel_key = (source.id, rel_type, target.id)
        if rel_key in seen_rel_keys:
            continue
        seen_rel_keys.add(rel_key)

        try:
            # Evidence label has no native STIX 2.1 field — carry it as a custom
            # property (x_ prefix is spec-legal; requires allow_custom=True).
            _label = getattr(rel, "evidence_label", "reported")
            _label = getattr(_label, "value", _label)  # EvidenceLabel enum → str
            relationship = stix2.Relationship(
                relationship_type=rel_type,
                source_ref=source.id,
                target_ref=target.id,
                confidence=max(0, min(100, int(rel.confidence * 100))),
                allow_custom=True,
                x_evidence_label=str(_label),
            )
            stix_objects.append(relationship)
        except Exception:
            pass

    # --- Policy-forced relationships (enforce mode, "pin" rules) ---
    # In "enforce" mode a pinned rule does more than relabel edges the pipeline
    # already inferred (handled by _apply_policy above): it MATERIALISES the
    # analyst's link model.  For every enabled "pin" rule, an edge is created
    # between each object of the rule's source type and each object of its target
    # type — so e.g. "threat-actor uses malware" links the report's actors to its
    # malware even when no extraction stage proposed that connection.
    #
    # Notes:
    #   • Existing edges are not duplicated (shared seen_rel_keys set).
    #   • Self-loops are skipped.
    #   • This is an all-pairs (Cartesian) materialisation, so high-cardinality
    #     pairs (e.g. indicator>malware over a large IoC list) can create many
    #     edges — set such pairs to "Auto" in the policy if that's not wanted.
    if relationship_policy and relationship_policy.get("global") != "auto":
        # Snapshot the created SDOs/SCOs grouped by STIX type (taken before we
        # start appending the forced relationships below).
        _type_to_objs: dict[str, list] = {}
        for _obj in stix_objects:
            _otype = _obj.get("type") if hasattr(_obj, "get") else getattr(_obj, "type", None)
            if _otype in ("relationship", "report") or _otype is None:
                continue
            _type_to_objs.setdefault(_otype, []).append(_obj)

        for _rule in relationship_policy.get("rules", []):
            if _rule.get("mode") != "pin" or not _rule.get("enabled", True):
                continue
            _verb = (_rule.get("verb") or "").strip().lower()
            if _verb not in VALID_REL_TYPES:
                continue   # non-spec verb — don't force-create (matches _apply_policy)
            for _s_obj in _type_to_objs.get(_rule.get("src", ""), []):
                for _t_obj in _type_to_objs.get(_rule.get("tgt", ""), []):
                    if _s_obj.id == _t_obj.id:
                        continue
                    # pol_index=None: the verb is already the pinned verb, so we
                    # don't want _apply_policy to re-resolve it.
                    _add_relationship(
                        stix_objects, _s_obj, _verb, _t_obj,
                        pol_index=None, seen=seen_rel_keys,
                    )

    # --- Artifact SCO for the source document ---
    # Represents the original ingested file (PDF, DOCX, …) as a STIX 2.1
    # artifact object (§4.4).  We include the SHA-256 hash and MIME type
    # so consumers can verify or retrieve the source document; we do NOT
    # embed the binary content (payload_bin) to keep the bundle compact.
    artifact_obj = None
    if source_hash:
        suffix = ("." + original_filename.rsplit(".", 1)[-1].lower()) if "." in original_filename else ""
        mime   = _MIME_TYPES.get(suffix, "application/octet-stream")
        try:
            artifact_obj = stix2.Artifact(
                mime_type=mime,
                hashes={"SHA-256": source_hash},
            )
            stix_objects.append(artifact_obj)
        except Exception:
            artifact_obj = None

    # --- Report SDO wrapping all objects ---
    # description : full extracted text so STIX consumers see the narrative
    # external_references : filename + hash for tracing back to the source file
    if stix_objects:
        report_kwargs: dict = {
            "name":        report_name,
            "published":   datetime.now(timezone.utc),
            "object_refs": [obj.id for obj in stix_objects if hasattr(obj, "id")],
        }

        if report_text:
            report_kwargs["description"] = report_text

        ext_refs = []
        if original_filename:
            ref_kwargs: dict = {
                "source_name": "original_document",
                "description": f"Original CTI report: {original_filename}",
            }
            if source_hash:
                ref_kwargs["hashes"] = {"SHA-256": source_hash}
            ext_refs.append(stix2.ExternalReference(**ref_kwargs))
        if ext_refs:
            report_kwargs["external_references"] = ext_refs

        try:
            report = stix2.Report(**report_kwargs)
            stix_objects.append(report)
        except Exception:
            # Fallback without optional fields if stix2 rejects them
            report = stix2.Report(
                name=report_name,
                published=datetime.now(timezone.utc),
                object_refs=[obj.id for obj in stix_objects if hasattr(obj, "id")],
            )
            stix_objects.append(report)

    # --- Stamp provenance: TLP marking + authoring Identity on every object ---
    # The author Identity and TLP marking are added to the bundle but kept OUT
    # of the Report's object_refs (they are bundle-level provenance, referenced
    # via created_by_ref / object_marking_refs rather than report contents).
    _author = _authoring_identity()
    _tlp    = _tlp_marking()
    stamped = [_stamp_provenance(o, _author.id, _tlp.id) for o in stix_objects]

    # allow_custom so Relationship x_evidence_label (and any other x_ props)
    # pass through Bundle construction + serialization without rejection.
    return stix2.Bundle(objects=[_author, _tlp, *stamped], allow_custom=True)


def verify_ioc_coverage(raw_entities: list[RawEntity], bundle: stix2.Bundle) -> dict:
    """
    Verify that every observable IoC extracted by Stage 2 (regex / defang) is
    represented in *bundle* as a STIX SCO **and** has an Indicator built from it.

    This is a completeness audit: it catches IoCs that were extracted but then
    silently dropped from the bundle (e.g. an observable type with no STIX
    pattern mapping, so no Indicator is generated).

    Detection is exact, not heuristic: SCO ids are the deterministic UUIDv5 the
    stix2 library derives from the observable value, and Indicator ids are the
    deterministic ids build_stix_bundle assigns ("ioc_{value}").  We recompute
    both and check membership in the bundle.

    Returns a report dict:
        {
          "total_iocs":        int,   # distinct observable IoCs from regex/defang
          "with_sco":          int,
          "with_indicator":    int,
          "missing_sco":       [{"value", "type"}, ...],
          "missing_indicator": [{"value", "type"}, ...],
          "ok":                bool,  # True iff every IoC has both SCO + Indicator
        }
    """
    bundle_ids = {obj.id for obj in bundle.objects if hasattr(obj, "id")}

    total = with_sco = with_indicator = 0
    missing_sco: list[dict] = []
    missing_indicator: list[dict] = []
    seen: set[tuple[str, EntityType]] = set()

    for entity in raw_entities:
        if entity.entity_type not in _OBSERVABLE_IOC_TYPES:
            continue
        key = (entity.value.lower(), entity.entity_type)
        if key in seen:
            continue
        seen.add(key)
        total += 1

        sco = _entity_to_sco(entity)
        has_sco = sco is not None and getattr(sco, "id", None) in bundle_ids

        indicator_id = _make_deterministic_id(f"ioc_{entity.value}", "indicator", "cti")
        has_indicator = indicator_id in bundle_ids

        record = {"value": entity.value, "type": entity.entity_type.value}
        if has_sco:
            with_sco += 1
        else:
            missing_sco.append(record)
        if has_indicator:
            with_indicator += 1
        else:
            missing_indicator.append(record)

    return {
        "total_iocs":        total,
        "with_sco":          with_sco,
        "with_indicator":    with_indicator,
        "missing_sco":       missing_sco,
        "missing_indicator": missing_indicator,
        "ok":                not missing_sco and not missing_indicator,
    }


def _map_iocs_to_scos(entities: list[RawEntity]) -> tuple[list, dict[str, object]]:
    """
    Creates SCO objects and returns both the list and a value→SCO index.
    Each entity is mapped to its SCO exactly once.
    """
    scos = []
    value_to_sco: dict[str, object] = {}

    for entity in entities:
        sco = _entity_to_sco(entity)
        if sco is not None:
            scos.append(sco)
            value_to_sco[entity.value.lower()] = sco

    return scos, value_to_sco


def _entity_to_sco(entity: RawEntity):
    """Converts a single RawEntity to a STIX 2.1 SCO, or returns None."""
    try:
        t = entity.entity_type
        v = entity.value

        # ── Network observables ──────────────────────────────────────────────
        if t == EntityType.IPV4:
            return stix2.IPv4Address(value=v)
        if t == EntityType.IPV6:
            return stix2.IPv6Address(value=v)
        if t == EntityType.DOMAIN:
            return stix2.DomainName(value=v)
        if t == EntityType.URL:
            return stix2.URL(value=v)
        if t == EntityType.EMAIL:
            return stix2.EmailAddress(value=v)
        if t == EntityType.MAC_ADDR:
            return stix2.MACAddress(value=v)
        if t == EntityType.ASN:
            # Accept "AS12345", "as12345", or bare "12345"
            num_str = v.upper().lstrip("AS").strip()
            if num_str.isdigit():
                return stix2.AutonomousSystem(number=int(num_str), name=v)
        if t == EntityType.NETWORK_TRAFFIC:
            # Store raw network-traffic descriptor as a Software object when
            # full src/dst resolution isn't available (placeholder SCO).
            return stix2.Software(name=v)

        # ── File / hash observables ──────────────────────────────────────────
        if t == EntityType.MD5:
            return stix2.File(hashes={"MD5": v})
        if t == EntityType.SHA1:
            return stix2.File(hashes={"SHA-1": v})
        if t == EntityType.SHA256:
            return stix2.File(hashes={"SHA-256": v})
        if t == EntityType.FILE:
            return stix2.File(name=v)

        # ── System observables ───────────────────────────────────────────────
        if t == EntityType.REGISTRY_KEY:
            return stix2.WindowsRegistryKey(key=v)
        if t == EntityType.MUTEX:
            return stix2.Mutex(name=v)
        if t == EntityType.USER_ACCOUNT:
            return stix2.UserAccount(user_id=v)

    except Exception:
        pass
    return None


def _entity_to_sdo(entity: RawEntity):
    """
    Converts pipeline-detected entities whose entity_type maps to an SDO
    (Infrastructure, IntrusionSet, Location, Identity, Campaign, Incident).
    Returns None for types handled elsewhere (Malware, ThreatActor, etc.).
    """
    try:
        t = entity.entity_type
        v = entity.value

        if t == EntityType.INFRASTRUCTURE:
            infra_id = _make_deterministic_id(v, "infrastructure", "cti")
            return stix2.Infrastructure(
                name=v,
                infrastructure_types=["unknown"],
                id=infra_id,
            )
        if t == EntityType.INTRUSION_SET:
            intrusion_id = _make_deterministic_id(v, "intrusion-set", "cti")
            return stix2.IntrusionSet(name=v, id=intrusion_id)
        if t == EntityType.LOCATION:
            iso2 = _COUNTRY_ISO.get(v.strip().lower())
            location_id = _make_deterministic_id(f"{v}_{iso2}" if iso2 else v, "location", "cti")
            if iso2:
                return stix2.Location(name=v, country=iso2, id=location_id)
            # Fall back to name-only Location — region is optional in STIX 2.1
            # and "unknown" is not a valid vocabulary value (raises InvalidValueError)
            return stix2.Location(name=v, id=location_id)
        if t == EntityType.IDENTITY:
            identity_id = _make_deterministic_id(v, "identity", "cti")
            return stix2.Identity(name=v, identity_class="class", id=identity_id)
        if t == EntityType.CAMPAIGN:
            campaign_id = _make_deterministic_id(v, "campaign", "cti")
            return stix2.Campaign(name=v, id=campaign_id)
        if t == EntityType.INCIDENT:
            incident_id = _make_deterministic_id(v, "incident", "cti")
            return stix2.Incident(name=v, id=incident_id)

    except Exception:
        pass
    return None


def _escape_stix_value(v: str) -> str:
    """Escape single quotes and backslashes in a STIX pattern string value."""
    return v.replace("\\", "\\\\").replace("'", "\\'")


def _build_stix_pattern(ioc_value: str, sco) -> str | None:
    """Builds a STIX 2.1 pattern string from a SCO object."""
    sco_type = sco.get("type", "") if hasattr(sco, "get") else ""
    esc = _escape_stix_value(ioc_value)

    if sco_type == "ipv4-addr":
        return f"[ipv4-addr:value = '{esc}']"
    elif sco_type == "ipv6-addr":
        return f"[ipv6-addr:value = '{esc}']"
    elif sco_type == "domain-name":
        return f"[domain-name:value = '{esc}']"
    elif sco_type == "url":
        return f"[url:value = '{esc}']"
    elif sco_type == "email-addr":
        return f"[email-addr:value = '{esc}']"
    elif sco_type == "mac-addr":
        return f"[mac-addr:value = '{esc}']"
    elif sco_type == "autonomous-system":
        # Pattern uses the integer number, not the string
        num_str = ioc_value.upper().lstrip("AS").strip()
        if num_str.isdigit():
            return f"[autonomous-system:number = {num_str}]"
    elif sco_type == "windows-registry-key":
        return f"[windows-registry-key:key = '{esc}']"
    elif sco_type == "mutex":
        return f"[mutex:name = '{esc}']"
    elif sco_type == "user-account":
        return f"[user-account:user_id = '{esc}']"
    elif sco_type == "file":
        hashes = sco.get("hashes", {})
        if hashes:
            if "SHA-256" in hashes:
                return f"[file:hashes.'SHA-256' = '{_escape_stix_value(hashes['SHA-256'])}']"
            elif "SHA-1" in hashes:
                return f"[file:hashes.'SHA-1' = '{_escape_stix_value(hashes['SHA-1'])}']"
            elif "MD5" in hashes:
                return f"[file:hashes.MD5 = '{_escape_stix_value(hashes['MD5'])}']"
        # Named file without hashes
        name = (sco.get("name") or "").strip()
        if name:
            return f"[file:name = '{_escape_stix_value(name)}']"
    return None


def _apply_policy(
    rel_type: str,
    source,
    target,
    pol_index: dict,
) -> str:
    """
    Apply the relationship policy rule index to potentially override rel_type.

    pol_index is keyed by "src_stix_type>tgt_stix_type".  If a pinned, enabled
    rule is found for the (source.type, target.type) pair, its verb replaces the
    pipeline-inferred verb.  The final verb is always validated against
    VALID_REL_TYPES; invalid verbs fall back to "related-to".
    """
    if pol_index:
        src_type = getattr(source, "type", "")
        tgt_type = getattr(target, "type", "")
        rule = pol_index.get(f"{src_type}>{tgt_type}")
        if rule and rule.get("enabled", True) and rule.get("mode") == "pin":
            pinned_verb = rule.get("verb", rel_type)
            if pinned_verb in VALID_REL_TYPES:
                rel_type = pinned_verb
    return rel_type if rel_type in VALID_REL_TYPES else "related-to"


def _add_relationship(
    stix_objects: list,
    source,
    rel_type: str,
    target,
    confidence: float | None = None,
    pol_index: dict | None = None,
    seen: set | None = None,
) -> None:
    """Appends a Relationship SRO if source and target have ids.

    pol_index: optional policy rule index (pre-computed in build_stix_bundle).
    When provided, a pinned rule for the (source.type, target.type) pair
    overrides the inferred rel_type.

    seen: optional shared set of (source_id, rel_type, target_id) keys used to
    deduplicate.  stix2.Relationship assigns a fresh random UUID on every call,
    so without this guard the same logical edge (e.g. actor --targets--> country)
    would appear multiple times in the bundle when its endpoints repeat.
    """
    if not hasattr(source, "id") or not hasattr(target, "id"):
        return

    # Apply policy override if available
    if pol_index:
        rel_type = _apply_policy(rel_type, source, target, pol_index)
    elif rel_type not in VALID_REL_TYPES:
        rel_type = "related-to"

    # STIX 2.1 best-practice: downgrade a verb that is not *suggested* for this
    # (source-type → target-type) pair to the universal 'related-to'.  Applies to
    # the targets/indicates/based-on helpers and to policy-forced edges alike.
    if not rel_is_suggested(getattr(source, "type", ""), rel_type, getattr(target, "type", "")):
        rel_type = "related-to"

    if seen is not None:
        key = (source.id, rel_type, target.id)
        if key in seen:
            return
        seen.add(key)

    try:
        kwargs: dict = {
            "relationship_type": rel_type,
            "source_ref": source.id,
            "target_ref": target.id,
        }
        if confidence is not None:
            kwargs["confidence"] = max(0, min(100, int(confidence * 100)))
        stix_objects.append(stix2.Relationship(**kwargs))
    except Exception:
        pass
