# STIX 2.1 output

What ends up in the exported bundle: which STIX object each extracted value
becomes, which custom properties carry evidence and provenance, and how a
detection rule quoted in the report itself is represented.

## STIX objects produced

| Source | STIX object |
|---|---|
| IPv4 / IPv6 | `ipv4-addr` / `ipv6-addr` SCO |
| Domain | `domain-name` SCO |
| URL | `url` SCO, only when the value is a valid URI (RFC 3986); otherwise no observable and no Indicator, and the value is not repaired (ledger reason `not_a_uri`) |
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
| IoC linked to malware | extra `indicates` SRO Indicator → Malware; an association that cannot be built is recorded in the ledger, not skipped (see below) |
| Relationship between an SDO and an observable (LLM-extracted or policy-pinned) | kept on the observable when STIX 2.1 defines that verb for the pair (`malware communicates-with domain-name`, `malware drops`/`downloads file`, `infrastructure consists-of <any observable>`); every other claim — `related-to` included — goes through the observable's `indicator` (ADR-0041, ADR-0062) |
| Detection rule quoted verbatim in the report (YARA, Suricata, Snort, or Sigma) | `indicator` SDO with `pattern_type` set to the format and `pattern` holding the rule text as-is; auto-linked with `indicates` to a malware/tool whose name appears in the rule's own title (ADR-0042) |
| Source document (PDF, DOCX, …) | `artifact` SCO — `payload_bin` (base64) + SHA-256 hash + MIME type, so the bundle carries the original file, not just a pointer to it (ADR-0043) |
| Threat actor → country / sector | `targets` SRO |
| Semantic relationship | `relationship` SRO (confidence score) |
| Relationship evidence grade | `x_evidence_label` custom property on each `relationship` (`observed` / `reported` / `assessed` / `inferred` / `gap`) |
| TTP evidence (ADR-0028) | each extracted technique carries `evidence_text` — a **verbatim quote** from the report — plus `evidence_label` and `evidence_start`, the resolved character offset. Kept apart from `description`, which is a summary the extractor writes: measured across four reports, quotes locate to a sentence **85.6%** of the time and descriptions **38.9%**. A quote that cannot be located stores a NULL offset and demotes the grade one step; the technique is never dropped |
| Completed edge (Stage 4b/4c) | `relationship` SRO + `x_inference_rule` (`transitive:uses+uses`, `attack-reference:G0016>S0002`, `long-distance`) and `x_inferred_from` (premise edge ids); long-distance edges also carry `x_evidence_text` (the quoted sentence), and are built only when the model answers `related: true` and that sentence is found in the report text. MITRE's edges are graded `x_evidence_label: "external-reference"`; they and the transitive ones are in the bundle but not in the Report's `object_refs`, since the report does not state them (ADR-0013 amendment) |
| Policy-materialised edge | `relationship` SRO + `x_evidence_label="assessed"` and `x_policy_rule` (`"malware uses attack-pattern"`) — the analyst's link model, not a claim the document made, so it fails the review auto-accept gate |
| Synthesis accounting | `x_synthesis_stats` on the `report` SDO that CTIParsor builds (in a re-issued baseline Report, the same figures sit under `x_ctiparsor_enrichment.synthesis`) — per-rule `candidates / emitted / truncated` for the pin pass, plus Stage 4b's completion counters |
| Sharing markings | the job's TLP `marking-definition` (+ optional PAP statement marking), referenced by `object_marking_refs` on every object CTIParsor builds (not the markings, the author identity, or the baseline objects it keeps); a `full` bundle holds exactly one TLP. An enriched bundle (ADR-0090) also ships the baseline's own marking-definitions, which the objects it keeps and the re-issued Report still reference, so it can hold several TLPs: a TLP:GREEN baseline in a TLP:AMBER job ships GREEN on the baseline's objects and AMBER on CTIParsor's. A baseline marking with the job's id and level ships once. The job's TLP is at least as restrictive as every TLP a baseline object carries, since a lower one is refused (D2). CLEAR, GREEN, AMBER and RED are the spec's objects; AMBER+STRICT is OpenCTI's own (`definition_type: "TLP"`, OpenCTI's extension and static id, two SHOULD warnings accepted by choice). An unknown level is refused, never defaulted (ADR-0073) |
| Pipeline authorship | one authoring `identity` SDO; `created_by_ref` on every SDO/SRO CTIParsor builds (the pipeline, **not** the threat actor) |
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

A YARA rule ships only if it compiles, and only when `yara-python` is installed.
OpenCTI refuses a YARA Indicator that `yara.compile()` rejects, and then every
edge to it. Without `yara-python` the rule ships unchecked: the ledger records
`pattern_check: "unverified"`, and OpenCTI may refuse it. Before compiling, Stage 4
repairs two kinds of damage the report's layout causes. It joins back a `meta`
string that a wrapped line cut, and it adds an `import` the report declares
outside the rule. The compile runs with `include` disabled, so the server never
opens a file the report names. A rule that includes a file cannot be checked on
its own, and it is refused. A rule that still does not compile is left out
(`rule_does_not_compile`), and the Graph page lists it with the compiler's
message ([ADR-0067](adr/0067-quoted-yara-rules-ship-only-if-they-compile.md)).
Sigma, Suricata and Snort rules go through the parsers OpenCTI uses for them,
when those parsers are installed. Without one, the rule ships unchecked, as a
YARA rule does.
A rule typed `snort` by its context but accepted only by Suricata's parser
ships as `suricata`
([ADR-0070](adr/0070-quoted-sigma-suricata-snort-rules-ship-only-if-opencti-parses-them.md)).

## Enriched bundle (ADR-0090)

A job in `enrich` mode is given the analyst's STIX 2.1 bundle with its report
(on by default; `STIX_ENRICHMENT_ENABLED=false` turns it off). Its exported bundle is the
analyst's bundle merged with what CTIParsor extracted, and Stage 4 builds it
after graph completion (Stage 4b). A `full` job's bundle is built as before.
Design: [ADR-0090](adr/0090-enriching-an-existing-stix-bundle.md).

### What ships

- **Baseline objects, as received.** Every baseline object the bundle keeps is
  written as it was received, with its own `created_by_ref` and
  `object_marking_refs`. CTIParsor adds neither its TLP/PAP marking nor its
  author to them. They are written from their parsed JSON, not through a stix2
  round trip, which alters foreign objects (invariant I2). The ledger gives each
  one the origin `baseline`, with status `matched` when the document states it
  and `only` when it does not.
- **CTIParsor objects that match a baseline object are not shipped.** The
  baseline object stands in for them, and every reference to them is rewritten.
  A CTIParsor object with the same id as a baseline object is that baseline
  object. The mapping ledger records the replacement with reason `baseline_match`.
- **Files known by their name only.** A CTIParsor `file` with no hash of its own
  is merged into the baseline's file when exactly one baseline file carries
  that name, and is then not shipped. When two baseline files carry the name,
  nothing merges and the CTIParsor file ships as its own object beside them. A
  name that only a name-only Indicator carries (no file object) merges nothing.
  A file with a hash of its own is never merged on its name. Before this rule
  (ADR-0090 lot 7) a name-only file never merged.
- **Indicators and objects matched by content.** A CTIParsor name-only Indicator
  `[file:name = …]` is not shipped when the baseline's file of that name has a
  kept Indicator stating the same name and no hash; that one stands in for it.
  A CTIParsor course of action with the same name (case and spacing folded), or a
  detection-rule Indicator (a `pattern_type` other than `stix`) with the same
  pattern text (whitespace folded), is not shipped when exactly one kept baseline
  object has that content. With two such baseline objects, nothing merges and the CTIParsor object ships beside them.
- **Relationships.** A CTIParsor relationship that becomes a self-loop, or that
  repeats a baseline relationship's source, verb and target, is dropped. The
  mapping ledger records it under `removed`, kind `relationship`, as
  `self_loop_after_baseline_merge` or `duplicate_after_baseline_merge`; the
  `replaced_by` of a duplicate names the edge kept.
- **Rejected objects.** A baseline object is left out when every row the analyst
  linked to it is rejected; a pending row keeps it. Whatever references it leaves
  too. Each one is recorded in the mapping ledger as `removed`, kind `baseline`: the
  object with reason `baseline_rejected`, and what references it with
  `baseline_refs_closure:<id>`, where `<id>` is the excluded or already dropped
  object it references.
- **Report.** With a chosen Report in the baseline, CTIParsor re-issues that one
  (below) and builds no Report of its own, with two exceptions. If the analyst
  rejected the chosen Report, it is not re-issued, and CTIParsor builds its own
  Report instead. If the re-issue would list no reference (none of its references
  ships and the document adds none), it is not re-issued, and the ledger records
  `baseline_report_empty`. In either case CTIParsor builds its own Report only when
  the document states at least one object of the enriched bundle, since a STIX
  Report needs one reference. Without a chosen Report, CTIParsor
  builds its own Report, with `x_ctiparsor_enrichment` recording the baseline's
  `baseline_sha256`, its bundle id, the build time, the counts and the synthesis
  statistics.
- **Scope.** A relationship between two objects in scope is in scope even when
  the Report does not list it. A CTIParsor bundle given back as its own baseline
  therefore round-trips with the same ids.

### What the intake leaves out

Before the merge, the intake excludes baseline objects
([ADR-0090](adr/0090-enriching-an-existing-stix-bundle.md), D3). Each exclusion
has one reason:

- `baseline_invalid`: the `id` or `type` is missing or malformed, or the object
  fails the STIX 2.1 parser or schema checks. An Indicator whose pattern is too
  complex to read is refused too.
- `baseline_older_version`: the id has a copy with a later `modified` in the
  bundle, and the older copy is excluded.
- `baseline_rule_refused`: a YARA, Sigma, Suricata or Snort Indicator that its
  checker refuses. A rule whose checker is not installed is kept, with a warning.
- `baseline_id_collision`: an object takes the id of CTIParsor's author identity
  (with another name or identity class) or of its TLP or PAP marking (with
  another level).
- `baseline_refs_closure`: an object references an excluded object, directly or
  through another object excluded this way.

When the bundle has a chosen Report, only that Report, the objects it references
and the relationships between them are imported. The other objects are counted,
not listed. A bundle with no Report keeps every object in scope.

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

The ledger records the re-issue with origin `baseline_report_upsert`, with
`added_refs` (a count) and `removed_refs`.

### Confidence and the OpenCTI importer

CTIParsor does not change the Report's `confidence`. OpenCTI adds the upsert's
missing references only when the applied confidence, the import's confidence
capped by the importing user's maximum, is at least the stored object's
confidence (ADR-0090 §6, from OpenCTI's source). The importing user's ceiling
must therefore be at least the Report's confidence. Below it, the additions are
ignored and no error is raised.

Checked on a running OpenCTI (ADR-0090, check A4, lot 7): OpenCTI
**7.260930.0**, in a throwaway instance (`docker/opencti-test/`), **12 of 12
expectations hold** (the final run, with the final code, on a fresh instance).

- The analyst's bundle, then the enriched one, import as admin with nothing
  refused. The Report keeps the baseline's id: one Report, holding its 16
  references, each baseline object
  present once, and all 23 objects of the bundle present.
- The enriched bundle imports as a user whose maximum confidence is 50, below
  the Report's 85, with no error. The additions are not made: the Report keeps
  its 9 original references.
- The rejected bundle (WellMess removed) imports as admin with nothing refused,
  and the Report still references WellMess: OpenCTI never removes a reference
  on an upsert.

A non-admin importer needs, besides knowledge create and update:

- `SETTINGS_SETMARKINGS`: without it, every object carrying a marking is refused
  (FORBIDDEN_ACCESS, then MISSING_REFERENCE_ERROR);
- `KNOWLEDGE_KNUPLOAD`: the source document artifact;
- `SETTINGS_SETKILLCHAINPHASES`: attack patterns with kill chain phases;
- a maximum confidence at least the Report's confidence.

OpenCTI gives some objects its own `standard_id` (an intrusion set's, from its
name) and keeps the bundle's id in `x_opencti_stix_ids`, so an id in the bundle
and the same object's id in OpenCTI can differ. The relationship ids, and the
attack-pattern ids of techniques the analyst annotated by hand (those no LLM TTP
already built), are drawn at random and change between two builds of one job. OpenCTI attached the new ids to the
existing objects as aliases, with no duplicate. Every other attack-pattern id is
computed: the ATT&CK id when there is one (a CAPEC id does not count), else the
name.

### A rejection in OpenCTI

Rejecting a baseline object removes it from CTIParsor's bundle and from the
Report's `object_refs` in that bundle. OpenCTI never removes a reference on an
upsert outside a full synchronisation, so a Report OpenCTI already holds keeps
the reference to the rejected object. Removing it takes an explicit call to
OpenCTI's API, which CTIParsor does not make.

## What the mapping ledger records

The mapping ledger ([ADR-0061](adr/0061-bundle-view-and-mapping-ledger.md))
records what Stage 4 did with each input, and why. The reasons below are the
ones it gives for what is left out or refused. The enrich-mode reasons are
listed under [What ships](#what-ships).

- **`not_a_uri`** (entity, dropped). A URL that is not a valid URI yields no
  observable and no Indicator. The check is the `uri` format of RFC 3986, which
  needs `rfc3986-validator` installed: without it, every value passes.
- **`outranked_type`** (entity, dropped). When several sources type one name as
  malware, threat actor, tool or campaign, the name keeps the type of its
  best-ranked source. The other types are dropped before Stage 4, with
  `sources`, `kept_types` and `kept_sources`
  ([ADR-0092](adr/0092-one-type-per-name-before-stage-4-by-source-rank.md)).
  Best rank first: `analyst`, `manual` and `baseline_stix`; then `ioc` and
  `gazetteer`; then `semantic` and `llm`; then `cyner` and `gliner`; then
  `spacy` and `alias_list`. Any other source ranks last. A campaign ranks after
  every source except the analyst's. Equal ranks all stay.
- **`ambiguous_name`** (relationship, dropped). When an end names objects of
  several types, the row's verb picks the pair
  ([ADR-0091](adr/0091-a-name-that-denotes-several-objects-resolves-by-the-verb.md)).
  If no pair, or more than one pair, fits the verb, the row does not ship. The
  ledger row carries `source_candidates` and `target_candidates`, the candidate
  ids.
- **IoC association** (a dropped `indicator` entry, `input` `ioc_association`).
  An association that cannot become an `indicates` edge is recorded, with one of
  these reasons:
  - `ioc_not_in_bundle`: the value is no observable, and it names no object in
    the bundle;
  - `malware_not_in_bundle`: no object of the malware's name is in the bundle;
  - `no_pattern`: the value names an object that is not an observable, or no
    pattern can be built on it;
  - `ambiguous_name`: the malware's name denotes several objects, and not
    exactly one of them can be indicated by an Indicator.

  An IoC with an observable and a pattern keeps its Indicator, unless it is
  benign. Only the `indicates` edge is missing.
- **`refused`** (top-level key). A relationship that an analyst rejected
  (`rejected_by_analyst`), or that is held for review (`held_for_review`,
  [ADR-0082](adr/0082-what-the-model-could-not-decide-waits-for-an-analyst.md)),
  is not built back by any builder: not the IoC association's `indicates` edge
  (origin `ioc_association`), not the targets product (`targeted_location`), not
  a pinned rule (`policy_pin`), and not graph completion (`completion_transitive`,
  `completion_reference`, `completion_long_distance`). Each refused triple is
  listed once, with its `origin` and `reason`. The reverse of a `related-to` or
  `duplicate-of` triple is refused too. The key is absent when nothing is
  refused ([ADR-0013](adr/0013-graph-completion.md), amendment of 2026-10-26).
