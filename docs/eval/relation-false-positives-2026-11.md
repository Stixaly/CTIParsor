# Relation false positives of the in-house bundle run (2026-11)

This page splits the 2,041 relation false positives of the in-house bundle
run into the producing method, the inference rule, the relationship type, the
endpoint types, the gold link and the document. It reads 30 of them against the
report text. It states facts only; it does not propose a fix.

The run is the one in [inhouse-bundle-2026-11.md](inhouse-bundle-2026-11.md):
`data/eval/inhouse-runs/inhouse-bundle-candidate`, the 1.0 candidate at
`fe0b0f3`, as that page records it (`run.json` does not record a commit).

## What was measured

- **Scorer.** `evaluation/inhouse.py` (`score_bundle`) on the bundle the run
  exported, through `evaluation/bundle.py` (`project`). A found relation is a
  `(source, type, target)` triple after the names are resolved to the gold
  names; the match is exact on the normalised triple.
- **Command.** From the worktree root, under WSL with the repository `.venv`
  and `SKIP_HEAVY_MODELS=1`:

  ```
  python scripts/relation_fp_breakdown.py \
    --run-dir data/eval/inhouse-runs/inhouse-bundle-candidate \
    --gold-dir data/eval/inhouse \
    --out <scratch>/breakdown.json
  ```

  The script exits 0 only when the true positives, false positives and false
  negatives per document and in total equal `score-bundle.json`. It printed
  `"ok": true` with no problems.
- **Unit.** The bundle has 2,308 relationships that are not `based-on`. Of
  those, 130 repeat a triple already found, so 2,178 distinct triples are
  scored. Each distinct triple takes its attributes from its first bundle
  relationship, in bundle order.
- **Producing method.** The bundle has no producer field. The script reads the
  `**Why:**` line that the bundle writes in each relationship's description and
  groups the relationships by it. The `x_inference_rule` values are a separate
  attribute.
- **Stage 3 row.** A found relation has a Stage 3 row when its name triple, or
  its `x_evidence_text`, matches a `relations` or `rel_review` row of
  `docs/<doc>.json`. The name triple is read from `bundle_relations`, which the
  script checks is aligned one-to-one with the bundle's relationship objects.
- **Sample.** `random.Random(13).sample` over the 2,041 false positives sorted by
  document and triple. The report text is `pipeline.stage1_ingestion.ingest`
  on each gold `source.*` file. For apt44 it returns 105,912 characters, the
  figure the run recorded for Stage 1.

## Totals

| Found | True positive | False positive | Gold | False negative | Precision | Recall |
|---:|---:|---:|---:|---:|---:|---:|
| 2178 | 137 | 2041 | 320 | 183 | 0.063 | 0.428 |

These equal the `micro.relations` of `score-bundle.json`. By document, 1,533 of
the 2,041 false positives are in apt44-mandiant-2024 (1,030) and
greyvibe-withsecure-2026 (503).

## Where the false positives are

The top three producing methods hold 93.2 % of the false positives: the
co-mention `targets` links (1,354), the ATT&CK-reference edges (316), and the
relations the report states (232).

### By producing method (the bundle's `Why:` line)

| Producing method | Found | True positive | False positive | Precision | Share of false positives |
|---|---:|---:|---:|---:|---:|
| every threat actor x every target | 1354 | 0 | 1354 | 0.000 | 66.3 % |
| MITRE ATT&CK reference | 318 | 2 | 316 | 0.006 | 15.5 % |
| stated in the quoted sentence | 335 | 103 | 232 | 0.307 | 11.4 % |
| indicator association | 136 | 31 | 105 | 0.228 | 5.1 % |
| transitive composition | 32 | 1 | 31 | 0.031 | 1.5 % |
| detection rule title | 3 | 0 | 3 | 0.000 | 0.1 % |

### By inference rule (`x_inference_rule`, kind before the colon)

| Rule | Found | True positive | False positive | Precision | Share of false positives |
|---|---:|---:|---:|---:|---:|
| none | 1828 | 134 | 1694 | 0.073 | 83.0 % |
| attack-reference | 318 | 2 | 316 | 0.006 | 15.5 % |
| transitive | 32 | 1 | 31 | 0.031 | 1.5 % |

The `attack-reference` and `transitive` values are written by Stage 4b
(`pipeline/stage4b_graph_completion.py`). Their counts equal the
producing-method rows above.

### By relationship type

| relationship_type | Found | True positive | False positive | Precision | Share of false positives |
|---|---:|---:|---:|---:|---:|
| targets | 1379 | 0 | 1379 | 0.000 | 67.6 % |
| uses | 463 | 92 | 371 | 0.199 | 18.2 % |
| related-to | 148 | 6 | 142 | 0.041 | 7.0 % |
| indicates | 162 | 31 | 131 | 0.191 | 6.4 % |
| variant-of | 12 | 2 | 10 | 0.167 | 0.5 % |
| communicates-with | 7 | 4 | 3 | 0.571 | 0.1 % |
| drops | 4 | 1 | 3 | 0.250 | 0.1 % |
| authored-by | 1 | 0 | 1 | 0.000 | 0.1 % |
| derived-from | 1 | 0 | 1 | 0.000 | 0.1 % |
| exploits | 1 | 1 | 0 | 1.000 | 0.0 % |

### By source -> target type (top 12 by false positives)

| Pair | Found | True positive | False positive | Precision | Share of false positives |
|---|---:|---:|---:|---:|---:|
| threat-actor->identity | 1075 | 0 | 1075 | 0.000 | 52.7 % |
| threat-actor->location | 298 | 0 | 298 | 0.000 | 14.6 % |
| malware->attack-pattern | 226 | 1 | 225 | 0.004 | 11.0 % |
| indicator->malware | 167 | 31 | 136 | 0.186 | 6.7 % |
| threat-actor->attack-pattern | 105 | 0 | 105 | 0.000 | 5.1 % |
| malware->malware | 61 | 12 | 49 | 0.197 | 2.4 % |
| threat-actor->malware | 94 | 70 | 24 | 0.745 | 1.2 % |
| malware->threat-actor | 21 | 2 | 19 | 0.095 | 0.9 % |
| threat-actor->indicator | 19 | 0 | 19 | 0.000 | 0.9 % |
| threat-actor->tool | 31 | 12 | 19 | 0.387 | 0.9 % |
| malware->indicator | 16 | 0 | 16 | 0.000 | 0.8 % |
| malware->tool | 16 | 4 | 12 | 0.250 | 0.6 % |

### By evidence label (`x_evidence_label`)

| Label | Found | True positive | False positive | Precision | Share of false positives |
|---|---:|---:|---:|---:|---:|
| reported | 1689 | 106 | 1583 | 0.063 | 77.6 % |
| external-reference | 318 | 2 | 316 | 0.006 | 15.5 % |
| observed | 109 | 23 | 86 | 0.211 | 4.2 % |
| inferred | 44 | 2 | 42 | 0.045 | 2.1 % |
| assessed | 18 | 4 | 14 | 0.222 | 0.7 % |

### By Stage 3 row

| Stage 3 row | Found | True positive | False positive | Precision | Share of false positives |
|---|---:|---:|---:|---:|---:|
| no stage3 row | 1838 | 34 | 1804 | 0.018 | 88.4 % |
| stage3 row | 339 | 103 | 236 | 0.304 | 11.6 % |
| rel_review row (quote not found) | 1 | 0 | 1 | 0.000 | 0.1 % |

### By gold link of the two endpoints

| Gold link | Found | True positive | False positive | Precision | Share of false positives |
|---|---:|---:|---:|---:|---:|
| no gold link between these names | 1959 | 0 | 1959 | 0.000 | 96.0 % |
| same pair, other type | 47 | 0 | 47 | 0.000 | 2.3 % |
| reversed pair in gold | 35 | 0 | 35 | 0.000 | 1.7 % |
| exact | 137 | 137 | 0 | 1.000 | 0.0 % |

### By endpoint name

| Source resolved to a gold name | Found | True positive | False positive | Precision | Share of false positives |
|---|---:|---:|---:|---:|---:|
| not a gold name | 1052 | 0 | 1052 | 0.000 | 51.5 % |
| gold name | 1126 | 137 | 989 | 0.122 | 48.5 % |

| Target resolved to a gold name | Found | True positive | False positive | Precision | Share of false positives |
|---|---:|---:|---:|---:|---:|
| not a gold name | 1777 | 0 | 1777 | 0.000 | 87.1 % |
| gold name | 401 | 137 | 264 | 0.342 | 12.9 % |

### By confidence bucket

| Confidence | Found | True positive | False positive | Precision | Share of false positives |
|---|---:|---:|---:|---:|---:|
| none | 1354 | 0 | 1354 | 0.000 | 66.3 % |
| 70-89 | 555 | 44 | 511 | 0.079 | 25.0 % |
| 90-100 | 268 | 93 | 175 | 0.347 | 8.6 % |
| below 70 | 1 | 0 | 1 | 0.000 | 0.1 % |

### By document

| Document | Found | True positive | False positive | Precision | Share of false positives | Gold | False negative |
|---|---:|---:|---:|---:|---:|---:|---:|
| apt44-mandiant-2024 | 1099 | 69 | 1030 | 0.063 | 50.5 % | 121 | 52 |
| cert-polska-energy-2025 | 136 | 9 | 127 | 0.066 | 6.2 % | 27 | 18 |
| cert-ua | 36 | 12 | 24 | 0.333 | 1.2 % | 35 | 23 |
| greyvibe-withsecure-2026 | 516 | 13 | 503 | 0.025 | 24.6 % | 71 | 58 |
| greyvibe-withsecure-web | 140 | 19 | 121 | 0.136 | 5.9 % | 36 | 17 |
| industroyer2-eset-2022 | 145 | 9 | 136 | 0.062 | 6.7 % | 15 | 6 |
| intelsq1-day0-html | 10 | 0 | 10 | 0.000 | 0.5 % | 2 | 2 |
| shinyhunters-gcb-2026 | 96 | 6 | 90 | 0.062 | 4.4 % | 13 | 7 |

### False negatives (gold relations not found)

| Gold relationship type | Count |
|---|---:|
| uses | 82 |
| indicates | 30 |
| related-to | 26 |
| attributed-to | 13 |
| downloads | 11 |
| drops | 7 |
| communicates-with | 7 |
| variant-of | 5 |
| targets | 1 |
| exploits | 1 |

The top gold pairs among the 183 are threat_actor->malware (29),
threat_actor->tool (27), malware->malware (20), malware->tool (15) and
sha256->malware (14).

## The 30-sample reading

Class key: **(a)** the text states it and the gold does not have it; **(b)** a
right link with a wrong endpoint or name (alias, descriptor, persona,
coreference); **(c)** a right pair with a wrong relationship type or direction;
**(d)** produced by inference (`x_inference_rule`) and not stated; **(e)** not
supported by the text.

The class column is the agent's reading. The orchestrator checks part of it.

Counts: (a) 0, (b) 9, (c) 1, (d) 6, (e) 14.

| # | Document | Link (source --type--> target) | Class | Reason |
|---:|---|---|---|---|
| 1 | apt44-mandiant-2024 | Guccifer 2.0 --targets--> Telecom | (b) | The report ties telecom targeting to APT44, not to Guccifer 2.0. |
| 2 | apt44-mandiant-2024 | Information Operation Troops (VIO) --targets--> logistics | (b) | Logistics targeting is stated for APT44; VIO is a GRU unit APT44 is subordinated to. |
| 3 | greyvibe-withsecure-2026 | PrincessClub --targets--> charitable foundations | (e) | "Charitable" describes the websites PrincessClub masquerades as; no victim is named. |
| 4 | industroyer2-eset-2022 | Industroyer campaign --targets--> ICS | (e) | The malware is called ICS-capable and is said to hit one energy company; no sector target for the campaign. |
| 5 | greyvibe-withsecure-2026 | PrincessClub --targets--> Armed Forces of Ukraine | (e) | The target name does not occur in the report. |
| 6 | greyvibe-withsecure-2026 | UAC-0244 --targets--> Armed Forces of Ukraine | (e) | The target name does not occur in the report. The report merges UAC-0247 into UAC-0244. |
| 7 | greyvibe-withsecure-web | PrincessClub --targets--> business | (b) | The victimology sentence describes the report's group as a whole, not PrincessClub. |
| 8 | industroyer2-eset-2022 | APT group Sandworm --targets--> industrial | (e) | The text describes an attack on an ICS network; no Sandworm target is stated. |
| 9 | apt44-mandiant-2024 | CyberArmyof --targets--> government | (e) | The targets stated for CyberArmyofRussia_Reborn are water and hydro facilities. |
| 10 | greyvibe-withsecure-2026 | LLM agent --targets--> military | (e) | "LLM agent" comes from a comment about document authorship, not a threat actor. |
| 11 | apt44-mandiant-2024 | FELIXROOT --uses--> T1112 | (d) | ATT&CK reference (S0267 to T1112). T1112 does not occur in the report. |
| 12 | greyvibe-withsecure-2026 | Phantom --targets--> Moldova | (b) | The report says the threat actor GREYVIBE targeted Moldovan organisations. "Phantom" is a name prefix of several tools. |
| 13 | apt44-mandiant-2024 | APT44 operators --targets--> military | (e) | The report links APT44 to Russia's military campaign as a participant, not as a target. |
| 14 | greyvibe-withsecure-web | Russia-nexus threat --targets--> military | (b) | The victimology sentence states military victims for the group; the source is a descriptor of GREYVIBE. |
| 15 | apt44-mandiant-2024 | ETERNALPETYA --uses--> T1083 | (d) | ATT&CK reference (S0368 to T1083). T1083 does not occur in the report. |
| 16 | greyvibe-withsecure-2026 | GREYVIBE --targets--> Venezuela | (e) | Venezuela appears in a list after a sentence that gives the focus as Ukraine. No target is stated. |
| 17 | greyvibe-withsecure-2026 | Russia-nexus --targets--> business | (b) | Same victimology sentence as #14; the source is a descriptor of GREYVIBE. |
| 18 | apt44-mandiant-2024 | CyberArmyof --targets--> industrial control | (b) | The report states APT44's capability to disrupt industrial control; the source is CyberArmyofRussia_Reborn. |
| 19 | apt44-mandiant-2024 | APT44 operations --targets--> hydroelectric facilities | (b) | The hydro OT interaction is shown for CyberArmyofRussia_Reborn, which the report links to APT44 infrastructure. |
| 20 | apt44-mandiant-2024 | APT44 --uses--> T1070.004 | (d) | ATT&CK reference (G0034 to T1070.004). T1070.004 does not occur in the report. |
| 21 | cert-polska-energy-2025 | Impacket --related-to--> tasklist | (e) | The quoted sentence lists tasklist among executed commands; Impacket is not named. |
| 22 | greyvibe-withsecure-web | Nebo --uses--> PrincessClub | (e) | The sentence lists both as GREYVIBE-associated campaigns; no use between them is stated. |
| 23 | apt44-mandiant-2024 | EMPIRE --uses--> T1027.010 | (d) | ATT&CK reference (S0363 to T1027.010). T1027.010 does not occur in the report. |
| 24 | greyvibe-withsecure-2026 | SPACESHIP --uses--> T1547.001 | (d) | ATT&CK reference (S0035 to T1547.001). T1547.001 does not occur in the report. |
| 25 | apt44-mandiant-2024 | Information Operation Troops (VIO) --targets--> Russia | (e) | VIO is described as a GRU unit; no target is stated for it. |
| 26 | apt44-mandiant-2024 | APT28 --uses--> MIMIKATZ | (d) | ATT&CK reference (G0007 to S0002). The report says a POSHC2 payload uses Mimikatz; APT28 is not linked. |
| 27 | apt44-mandiant-2024 | Solntsepek operations --targets--> Kazakhstan | (b) | The report states Kazakhstan targeting for the group; the source is a persona the report associates with APT44. |
| 28 | apt44-mandiant-2024 | APT44 operations --targets--> control systems | (e) | The sentence says the INDUSTROYER malware manipulates control systems; the actor is not the subject. |
| 29 | greyvibe-withsecure-web | GREYVIBE --uses--> PhantomClick | (c) | The report says the group briefly tried PhantomClick. The gold has the pair reversed, typed attributed-to. |
| 30 | greyvibe-withsecure-2026 | PrincessClub --targets--> Brazil | (e) | Brazil appears as the origin of a VirusTotal submission, not as a target. |

For the nine (b) rows, the gold has no `targets` relation for the correct
endpoint either. The gold holds one `targets` relation across all eight
documents (see the false-negative table), so the stated links behind these rows
are gaps of the gold too. Class (a) is empty in this reading: no sampled row is
a stated link with the same endpoints that the gold lacks, because the stated
links behind the (b) rows have the other endpoint.

## What this explains and what it does not

**Explains.**

- The co-mention `targets` links account for 66.3 % of the false positives, and
  none of them is a true positive. The bundle's own description says each is a
  cross-product of the report's threat actors and the targets it names, and that
  the report may not state it. The links are written with the Why text from
  `pipeline/edge_justification.py`; the building code is in the Stage 4 mapping
  (`pipeline/stage4_stix_mapping.py`), which was not traced line by line.
- The gold holds one `targets` relation, and the annotation guide lists
  `targets` among the annotated verbs with the rule that only stated
  relationships count. The scorer therefore compares this family with a gold
  that almost never holds it.
- The ATT&CK-reference edges (318 found, 2 true positive) and the transitive
  edges (32 found, 1 true positive) are Stage 4b edges that the bundle carries
  and the report does not state. Together they are 17.0 % of the false positives
  (316 and 31 of 2,041).
- The relations with a quote from the report (`stated in the quoted sentence`)
  have a precision of 0.307 (103 of 335), and 232 of them are false positives.
  Of the three such rows in the sample, two are not supported by the text and one
  has the wrong type and direction.
- The endpoints: under exact normalised matching, 87.1 % of the false positives
  have a target that is not a gold name, and 51.5 % have a source that is not.
  Nine of the 30 sampled rows are a right link with an endpoint that names a
  persona, a descriptor or a sibling actor (class b).
- Most false positives have no gold link between their two names at all
  (96.0 %). Pairs in the gold under another type (2.3 %) and reversed pairs
  (1.7 %) are a small part.

**Does not explain.**

- Whether `targets` relations and ATT&CK-reference edges belong in a score
  against this gold. The figures do not answer that question.
- The split between Stage 3, the document-level pass and Stage 4b. The Stage 3
  row matches cover 339 of the 2,178 relations (1,838 have no match). A missing
  match is not proof of a Stage 4 origin, and the document-level pass is not
  recorded per row in `docs/<doc>.json`, so it is not separated here.
- The true positive side and the 183 false negatives beyond their type and pair.
- The reading of the 30 samples. It is one reader's reading of 30 of 2,041
  rows, with no interval and no second reader yet.
- The effect of any change. No run was made with a different configuration.

## Reproducing the figures

- `scripts/relation_fp_breakdown.py` (commit on `claude/relation-fp-analysis`);
  its tests are in `tests/test_relation_fp_breakdown.py`.
- The breakdown JSON is a scratch output and is not committed. It holds every
  false positive with its attributes.
- The sample is `breakdown["sample"]`. The report text is
  `pipeline.stage1_ingestion.ingest` on the gold `source.*` files. The gold check
  for the (b) rows is a search of each `gold.json` relation list for the target
  names.
