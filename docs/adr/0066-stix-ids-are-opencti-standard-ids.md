# ADR-0066: STIX ids are OpenCTI's standard ids

**Status:** Accepted
**Date:** 2026-10-01
**Deciders:** maintainer
**Relates to:** ADR-0009 (STIX trust and provenance), ADR-0012 (canonical names
and alias merge), ADR-0042 (embedded rules as Indicators)

## Context

The STIX 2.1 validator gives two warnings on every CTIParsor bundle, which the
maintainer asked to fix:

- `{103}` "not a valid UUIDv4 ID", on every domain object, indicator and
  marking: 791 on the 7 real reports of `ctiparsor_measure`;
- `{302}` "External reference 'mitre-attack' has a URL but no hash": 130.

Reading the spec (§2.9) found more than the warning. Domain objects SHOULD use
UUIDv4. A producer that uses UUIDv5 for them instead MUST NOT use the namespace
`00abedb4-aa42-466c-9c01-fed23315a9b7`, which is reserved for observables
(SCOs).

`_make_deterministic_id` did exactly that. It hashed
`"cti:<type>:<lower name>"` under the SCO namespace, a key nothing outside
CTIParsor computes.

The maintainer's answer was to do what OpenCTI does. Read in OpenCTI master
(2026-10-01, the copy the maintainer provided):

- The platform's `generateStixId` (`opencti-graphql/src/schema/identifier.js`)
  builds the standard id of every STIX object as a UUIDv5 under that same SCO
  namespace. The input is RFC 8785 canonical JSON of a few properties per type,
  normalised (`normalizeName`: lower case, trimmed):

  | Type | Properties |
  |---|---|
  | attack-pattern, course-of-action | the ATT&CK id, else the name |
  | identity | name and `identity_class` |
  | threat-actor | name and `opencti_type: Threat-Actor-Group` |
  | location | name and the OpenCTI location type |
  | indicator | pattern |
  | marking | definition type and definition |
  | malware, tool, campaign, intrusion-set, infrastructure, vulnerability | name |

  `OPENCTI_NAMESPACE` is used only for internal objects.
- Its Python client does the same in the `generate_id` functions of
  `client-python/pycti/entities/`. It uses `stix2`'s canonicaliser, and
  connectors are expected to call it so their ids match the platform's.

So OpenCTI breaks both §2.9 rules, the SHOULD and the MUST NOT. It also reuses
one UUID across types: a malware and a tool with the same name share it, and
only the type prefix tells them apart.

On the URL warning: MITRE's own `enterprise-attack.json` carries 37,478 URLs in
its external references and not one hash. A hash of a live web page means
nothing.

## Decision

1. **`pipeline/stix_ids.py` computes ids exactly as pycti's `generate_id`
   does**, and Stage 4 uses it at every place that minted a deterministic id
   (20 call sites). `_make_deterministic_id` is removed.
   - Techniques use their ATT&CK id. CAPEC ones use their name, because pycti
     reads `x_mitre_id` only from a `mitre-*` reference.
   - Sectors are `identity_class: class`. The author is `system`.
   - Countries are located as `Country`.
   - Indicators use their pattern: an IoC's, or an embedded rule's text.
   - A PAP marking uses the pair (`PAP`, `PAP:<level>`) that OpenCTI's built-in
     PAP markings are created with, PAP:WHITE as PAP:CLEAR. It therefore lands
     on OpenCTI's own marking.
2. **Incident is the one exception.** pycti also hashes `created`, which a
   build stamps with the build time, so the same incident would get a new id at
   every rebuild. CTIParsor keeps the name alone; OpenCTI recomputes its own id
   on import either way.
3. **Relationships and the Report keep their random UUIDv4**, as STIX prefers.
4. **ATT&CK and CAPEC URLs stay** (the maintainer's choice), as in MITRE's data.

## Verification

- **IDs match OpenCTI.** pycti's `generate_id` functions were run from the
  OpenCTI zip (extracted with `ast`, no install) on 15 inputs covering every
  type above. 15/15 ids are identical. `tests/test_stix_ids.py` pins those 15
  values.
- **The 7 real bundles, rebuilt:**
  - same 2,534 objects as before, no duplicate id;
  - every attack-pattern, malware, tool, campaign, threat-actor and indicator
    id follows the OpenCTI rule;
  - IoC coverage unchanged.
- **Tests:** full suite 2052 passed; ruff clean; mypy clean as CI runs it.

## Consequences

- **A bundle lands in OpenCTI on the objects already there:** the technique
  the MITRE connector imported, OpenCTI's built-in PAP marking, the sector, the
  country. OpenCTI already merged such objects by their properties, but kept
  CTIParsor's foreign id as an alias. That alias is gone.
- **The validator warnings do not change, by design.**
  - `{103}` stays: the ids are UUIDv5, like OpenCTI's own exports.
  - `{302}` stays: the URLs are kept.
  - Removing `{103}` would need random UUIDv4, which gives a new id at every
    rebuild and duplicates on re-import into id-keyed consumers such as MISP.
    The other way is a name-derived UUID labelled v4, which only hides the
    warning from the validator. Both were rejected.
- **Every domain object, indicator and marking id changes once**, at the next
  finalize. A bundle already imported elsewhere does not share its ids with the
  next one. OpenCTI is unaffected, since it dedups by standard id; an id-keyed
  consumer will see new objects.
- **The SCO namespace is still used for domain objects**, as OpenCTI does.
  §2.9's MUST NOT is knowingly traded for OpenCTI's ids. A strict-spec reading
  would need a CTIParsor namespace, which matches nothing outside CTIParsor.
