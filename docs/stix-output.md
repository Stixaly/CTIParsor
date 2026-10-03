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
| File hash (MD5 / SHA-1 / SHA-256) | `file` SCO |
| MAC address | `mac-addr` SCO |
| ASN | `autonomous-system` SCO |
| File path (Windows/Unix) + bare filename | `file` SCO |
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
| Any accepted IoC | `indicator` SDO (STIX pattern) + `based-on` SRO |
| IoC linked to malware | extra `indicates` SRO Indicator → Malware |
| Relationship between an SDO and an observable (LLM-extracted or policy-pinned) | kept on the observable when STIX 2.1 defines that verb for the pair (`malware communicates-with domain-name`, `malware drops`/`downloads file`, `infrastructure consists-of <any observable>`); every other claim — `related-to` included — goes through the observable's `indicator` (ADR-0041, ADR-0062) |
| Detection rule quoted verbatim in the report (YARA, Suricata, Snort, or Sigma) | `indicator` SDO with `pattern_type` set to the format and `pattern` holding the rule text as-is; auto-linked with `indicates` to a malware/tool whose name appears in the rule's own title (ADR-0042) |
| Source document (PDF, DOCX, …) | `artifact` SCO — `payload_bin` (base64) + SHA-256 hash + MIME type, so the bundle carries the original file, not just a pointer to it (ADR-0043) |
| Threat actor → country / sector | `targets` SRO |
| Semantic relationship | `relationship` SRO (confidence score) |
| Relationship evidence grade | `x_evidence_label` custom property on each `relationship` (`observed` / `reported` / `assessed` / `inferred` / `gap`) |
| TTP evidence (ADR-0028) | each extracted technique carries `evidence_text` — a **verbatim quote** from the report — plus `evidence_label` and `evidence_start`, the resolved character offset. Kept apart from `description`, which is a summary the extractor writes: measured across four reports, quotes locate to a sentence **85.6%** of the time and descriptions **38.9%**. A quote that cannot be located stores a NULL offset and demotes the grade one step; the technique is never dropped |
| Completed edge (Stage 4b/4c) | `relationship` SRO + `x_inference_rule` (`transitive:uses+uses`, `attack-reference:G0016>S0002`, `long-distance`) and `x_inferred_from` (premise edge ids); long-distance edges also carry `x_evidence_text` (the quoted sentence) |
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
