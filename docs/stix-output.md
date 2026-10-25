# STIX 2.1 output

What ends up in the exported bundle: which STIX object each extracted value
becomes, which custom properties carry evidence and provenance, and how a
detection rule quoted in the report itself is represented.

## STIX objects produced

| Source | STIX object |
|---|---|
| IPv4 / IPv6 | `ipv4-addr` / `ipv6-addr` SCO |
| Domain | `domain-name` SCO |
| URL | `url` SCO |
| Email | `email-addr` SCO |
| A value the report names without accusing it: a non-routable address, a big public DNS resolver, a security vendor's or sandbox's site, one of the 10,000 most popular domains | its SCO, **without** an Indicator; the ledger says why (`no_indicator: benign`, `benign: <reason>`) |
| File hash (MD5 / SHA-1 / SHA-256) | `file` SCO |
| MAC address | `mac-addr` SCO |
| ASN | `autonomous-system` SCO |
| File path (Windows/Unix) + bare filename | `file` SCO, the value as written in `name`, path included: no `directory` / `parent_directory_ref`, because OpenCTI identifies a hashless file by its name alone and would merge two directories' `svchost.exe` (ADR-0083) |
| Registry key | `windows-registry-key` SCO |
| Mutex † | `mutex` SCO |
| User account † | `user-account` SCO |
| Network traffic † | `network-traffic` SCO |
| CVE | `vulnerability` SDO |
| MITRE ATT&CK TTP (internal type `ttp`) | `attack-pattern` SDO + external reference (tactic vs technique preserved in the `mitre_id` / ATT&CK URL) |
| Malware family | `malware` SDO (`is_family: true`) |
| Threat actor | `threat-actor` SDO |
| Offensive tool | `tool` SDO |
| Campaign | `campaign` SDO |
| Intrusion set | `intrusion-set` SDO |
| Targeted country | `location` SDO (ISO 3166-1, 80+ countries) |
| Targeted sector | `identity` SDO (`identity_class: class`) |
| Infrastructure | `infrastructure` SDO |
| Remediation step | `course-of-action` SDO |
| Any accepted IoC | `indicator` SDO (STIX pattern) + `based-on` SRO; `valid_from` is the report's publication date when the document gives one (else the build time), no `valid_until`: OpenCTI derives it from its decay rule, so an IoC of an old report arrives revoked |
| IoC linked to malware | extra `indicates` SRO Indicator → Malware |
| Relationship between an SDO and an observable (LLM-extracted or policy-pinned) | kept on the observable when STIX 2.1 defines that verb for the pair (`malware communicates-with domain-name`, `malware drops`/`downloads file`, `infrastructure consists-of <any observable>`); every other claim — `related-to` included — goes through the observable's `indicator` (ADR-0041, ADR-0062) |
| Detection rule quoted verbatim in the report (YARA, Suricata, Snort, or Sigma) | `indicator` SDO with `pattern_type` set to the format and `pattern` holding the rule text as-is; auto-linked with `indicates` to a malware/tool whose name appears in the rule's own title (ADR-0042) |
| Source document (PDF, DOCX, …) | `artifact` SCO — `payload_bin` (base64) + SHA-256 hash + MIME type, so the bundle carries the original file, not just a pointer to it (ADR-0043) |
| Threat actor → country / sector | `targets` SRO |
| Semantic relationship | `relationship` SRO (confidence score) |
| Relationship evidence grade | `x_evidence_label` custom property on each `relationship` (`observed` / `reported` / `assessed` / `inferred` / `gap`) |
| TTP evidence (ADR-0028) | each extracted technique carries `evidence_text` — a **verbatim quote** from the report — plus `evidence_label` and `evidence_start`, the resolved character offset. Kept apart from `description`, which is a summary the extractor writes: measured across four reports, quotes locate to a sentence **85.6%** of the time and descriptions **38.9%**. A quote that cannot be located stores a NULL offset and demotes the grade one step; the technique is never dropped |
| Completed edge (Stage 4b/4c) | `relationship` SRO + `x_inference_rule` (`transitive:uses+uses`, `attack-reference:G0016>S0002`, `long-distance`) and `x_inferred_from` (premise edge ids); long-distance edges also carry `x_evidence_text` (the quoted sentence). MITRE's edges are graded `x_evidence_label: "external-reference"`; they and the transitive ones are in the bundle but not in the Report's `object_refs`, since the report does not state them (ADR-0013 amendment) |
| Policy-materialised edge | `relationship` SRO + `x_evidence_label="assessed"` and `x_policy_rule` (`"malware uses attack-pattern"`) — the analyst's link model, not a claim the document made, so it fails the review auto-accept gate |
| Synthesis accounting | `x_synthesis_stats` on the `report` SDO — per-rule `candidates / emitted / truncated` for the pin pass, plus Stage 4b's completion counters |
| Sharing markings | exactly one TLP `marking-definition` (+ optional PAP statement marking) referenced by `object_marking_refs` on every object. CLEAR, GREEN, AMBER and RED are the spec's objects; AMBER+STRICT is OpenCTI's own (`definition_type: "TLP"`, OpenCTI's extension and static id, two SHOULD warnings accepted by choice). An unknown level is refused, never defaulted (ADR-0073) |
| Pipeline authorship | one authoring `identity` SDO; `created_by_ref` on every SDO/SRO (the pipeline, **not** the threat actor) |
| Report wrapper | `report` SDO |

† **Mappable, but never auto-extracted.** No Stage 2 pattern produces a mutex,
user account or network-traffic entity — Stage 4 maps them so an analyst who adds
one by hand in the Review page gets a correct SCO. Everything else in this table
is produced by the pipeline itself.

## Detection rules embedded in the report itself

CTI reports — especially from Mandiant / Google Threat Intelligence Group —
often publish a literal YARA, Suricata, Snort, or Sigma rule alongside their
write-up, not just a description of the malware. These have nothing to do
with your local rule corpora or the Detections tab's ranking (that's a
separate feature, see [Rule proposals](detection-coverage.md#6-read-the-proposals))
— a rule quoted in the report text is extracted and represented
directly in the exported bundle as its own `indicator` SDO (`pattern_type`
set to the matching format, `pattern` holding the rule text verbatim — STIX
2.1's native mechanism for this, no workaround needed), auto-linked to any
malware or tool already named elsewhere in the report whose name appears in
the rule's own title.

Verified on a real Google TIG report that embeds four YARA rules: all four
came through as indicators, each linking correctly to a malware family the
same report named elsewhere. YARA and Suricata/Snort extraction reuse this
project's own corpus parsers unchanged (`pipeline/detection/yara_atoms.py`,
`suricata_atoms.py`); Sigma needed new logic — a grow-then-shrink YAML
boundary search, since YAML has no delimiter that survives being embedded in
prose the way YARA's braces do — and is fail-closed: a candidate that doesn't
parse as a valid rule yields nothing rather than a guess. Design:
[ADR-0042](adr/0042-embedded-yara-rules-as-indicators.md).

A YARA rule ships only if it compiles: OpenCTI refuses a YARA Indicator that
`yara.compile()` rejects, and then every edge to it. Before compiling, Stage 4
repairs two kinds of damage the report's layout causes. It joins back a `meta`
string that a wrapped line cut, and it adds an `import` the report declares
outside the rule. A rule that still does not compile is left out, and the
Graph page lists it with the compiler's message
([ADR-0067](adr/0067-quoted-yara-rules-ship-only-if-they-compile.md)).
Sigma, Suricata and Snort rules go through the parsers OpenCTI uses for them.
A rule typed `snort` by its context but accepted only by Suricata's parser
ships as `suricata`
([ADR-0070](adr/0070-quoted-sigma-suricata-snort-rules-ship-only-if-opencti-parses-them.md)).

## Enriched bundle (ADR-0090)

A job in `enrich` mode is given the analyst's STIX 2.1 bundle with its report
(behind `STIX_ENRICHMENT_ENABLED`, off by default). Its exported bundle is the
analyst's bundle merged with what CTIParsor extracted, and Stage 4 builds it
after graph completion (Stage 4b). A `full` job's bundle is built as before.
Design: [ADR-0090](adr/0090-enriching-an-existing-stix-bundle.md).

### What ships

- **Baseline objects, as received.** Every baseline object the bundle keeps is
  written as it was received, with its own `created_by_ref` and
  `object_marking_refs`. CTIParsor adds neither its TLP/PAP marking nor its
  author to them. They are written from their parsed JSON, not through a stix2
  round trip, which alters foreign objects (invariant I2).
- **CTIParsor objects that match a baseline object are not shipped.** The
  baseline object stands in for them, and every reference to them is rewritten.
  A CTIParsor object with the same id as a baseline object is that baseline
  object.
- **Relationships.** A CTIParsor relationship that becomes a self-loop, or that
  repeats a baseline relationship's source, verb and target, is dropped. The
  mapping ledger records the reason.
- **Rejected objects.** A baseline object is left out when every row the analyst
  linked to it is rejected; a pending row keeps it. Whatever references it leaves
  too. Each one is recorded in the mapping ledger as `removed`, kind `baseline`.
- **Report.** With a chosen Report in the baseline, CTIParsor builds no Report of
  its own and re-issues that one (below). When none of its references ships
  and the document adds none, it is not re-issued (a STIX Report needs one):
  the ledger records `baseline_report_empty`. Without a chosen Report, CTIParsor
  builds its own Report, with `x_ctiparsor_enrichment` recording the baseline's
  `baseline_sha256`, its bundle id, the build time, the counts and the synthesis
  statistics.
- **Scope.** A relationship between two objects in scope is in scope even when
  the Report does not list it. A CTIParsor bundle given back as its own baseline
  therefore round-trips with the same ids.

### The re-issued Report (upsert)

The chosen Report keeps its `id`, so OpenCTI's import updates the Report it
already holds instead of adding a second one. Only four properties change:

- **`object_refs`**: the references to baseline objects that ship, in their
  order, then what CTIParsor adds and the document states: its new objects and
  relationships, and the baseline relationships the Report does not list that
  CTIParsor built too. An ATT&CK or composed edge is not stated, and is not
  added. A reference to an
  object that does not ship is not carried into this list; the mapping ledger's
  entry for the Report lists it under `removed_refs`.
- **`modified`**: the build time, to the millisecond. When the Report's own
  `modified` is not earlier than the build time, it is that value + 1 ms, since
  OpenCTI discards an update that is not newer than the stored object.
- **`external_references`**: the Report's own, plus CTIParsor's
  `original_document` reference (file name and SHA-256 of the uploaded file),
  added once.
- **`x_ctiparsor_enrichment`**: as described above.

`id`, `created`, `created_by_ref`, `confidence`, `name`, `published` and the
markings are the Report as received.

### Confidence and the OpenCTI importer

CTIParsor does not change the Report's `confidence`. OpenCTI adds the upsert's
missing references only when the applied confidence, the import's confidence
capped by the importing user's maximum, is at least the stored object's
confidence (ADR-0090 §6, from OpenCTI's source). The importing user's ceiling
must therefore be at least the Report's confidence. Below it, the additions are
ignored and no error is raised.

Not checked yet on a running OpenCTI: ADR-0090's check A4 imports an enriched
bundle into a throwaway instance (lot 7).

### A rejection in OpenCTI

Rejecting a baseline object removes it from CTIParsor's bundle and from the
Report's `object_refs` in that bundle. OpenCTI never removes a reference on an
upsert outside a full synchronisation, so a Report OpenCTI already holds keeps
the reference to the rejected object. Removing it takes an explicit call to
OpenCTI's API, which CTIParsor does not make.
