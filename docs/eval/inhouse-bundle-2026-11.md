# In-house set, November 2026: the exported bundle, 0.6.0 and the 1.0 candidate

The first measurement of the bundle CTIParsor exports (ADR-0094 item 6,
ADR-0096), on the 8 reports of the in-house set, and the comparison of the
release 0.6.0 with the 1.0 candidate on the same data and configuration.

**Result.** The two releases produce the same bundles: on every report, the
same objects, with the same names, and the same relationships. Every figure
below is the same for both. Nothing in the code between 0.6.0 and the candidate
changes the extraction at this configuration, and the run is reproducible:
the same report gives the same bundle at `LLM_TEMPERATURE=0 LLM_SEED=13` on
this server.

## Setup

| | 0.6.0 | Candidate |
|---|---|---|
| Commit | `45aa96c` (the 0.6.0 release) | `fe0b0f3` (`main` on 2026-11-08) |
| Run | `inhouse-bundle-0.6.0` | `inhouse-bundle-candidate` |
| Dates (UTC) | 2026-11-08 13:29 to 18:41 | 2026-11-08 18:41 to 2026-11-09 00:36, stopped once and resumed |

Both runs:

- From the source at that commit, not from the image: no image digest applies.
- vLLM serving `Inferact/Qwen3.8-27B-NVFP4`, thinking off, `LLM_TEMPERATURE=0`,
  `LLM_SEED=13`, `WORKER_MAX_CONCURRENT=1`. Extraction prompt fingerprint
  `606528fb5beba5c6` on both sides.
- `ENABLE_STIX_VERIFICATION=true`, `ENABLE_DOCUMENT_LEVEL_RELATIONS=true`,
  `ENABLE_TTP_VERIFICATION=true` set for both, so the two runs differ by
  code only. These are the defaults of the candidate; 0.6.0 had 3d and the
  document-level relations off by default.
- `VISION_PROVIDER=none`: Stage 1f (figures) off.
- ATT&CK 19.2, the default track (`pipeline/data`).
- Commands, in each commit's checkout:
  `python -m evaluation inhouse-run --name <run>`, then
  `python -m evaluation inhouse-score --name <run> --from bundle`, then
  `python -m evaluation inhouse-compare <0.6.0 score-bundle.json> <candidate score-bundle.json>`.

Not measured here:

- The default provider, `anthropic` (ADR-0094 item 11).
- Figure reading.
- The commits merged after `fe0b0f3`: authentication, the egress policy, the
  audit trail. They do not change the extraction prompt or stages, but the
  release candidate is measured again before 1.0.

## The denominators

8 reports scored, none failed, missing or unscored. Each report declares the
4 layers: IoCs, entities, techniques, relations. The gold counts: 249 IoCs,
258 entities (23 threat actors, 104 malware, 119 tools, 12 campaigns),
229 techniques, 320 relations, 36 negative cases, 15 observables. The gold was
annotated by ChatGPT, reread by Claude and arbitrated on 40 points by the
maintainer ([inhouse-set.md](inhouse-set.md)): AI-assisted, one maintainer,
a pilot. Eight reports do not detect a small difference between two releases.

## Aggregate (micro), both releases

| Layer | Gold | Found | TP | FP | FN | Precision | Recall | F1 | 0.6.0 F1 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| IoCs | 249 | 319 | 157 | 162 | 92 | 0.492 | 0.630 | 0.553 | 0.553 |
| Entities: threat actors | 23 | 73 | 20 | 53 | 3 | 0.274 | 0.870 | 0.417 | 0.417 |
| Entities: malware | 104 | 415 | 96 | 319 | 8 | 0.231 | 0.923 | 0.370 | 0.370 |
| Entities: tools | 119 | 95 | 63 | 32 | 56 | 0.663 | 0.529 | 0.589 | 0.589 |
| Entities: campaigns | 12 | 4 | 0 | 4 | 12 | 0.000 | 0.000 | 0.000 | 0.000 |
| Techniques | 229 | 244 | 146 | 98 | 83 | 0.598 | 0.638 | 0.617 | 0.617 |
| Relations | 320 | 2178 | 137 | 2041 | 183 | 0.063 | 0.428 | 0.110 | 0.110 |

Negative cases: 17 of 36 violated (an element the gold says must not be
extracted was in the bundle). Observables: 0 of 15 exported as an Indicator.

## Per report (F1, with true positives over gold and false positives)

| Report | IoCs | Threat actors | Malware | Tools | Techniques | Relations |
|---|--:|--:|--:|--:|--:|--:|
| apt44-mandiant-2024 | 0.20 (5/8, FP 36) | 0.47 (9/11, FP 18) | 0.47 (62/66, FP 136) | 0.58 (11/22, FP 5) | 0.64 (35/53, FP 21) | 0.11 (69/121, FP 1030) |
| cert-polska-energy-2025 | 0.59 (32/40, FP 37) | 0.80 (2/2, FP 1) | 0.23 (5/6, FP 32) | 0.82 (20/22, FP 7) | 0.71 (36/44, FP 22) | 0.11 (9/27, FP 127) |
| cert-ua | 0.67 (34/51, FP 17) | 0.67 (1/1, FP 1) | 0.54 (7/8, FP 11) | 0.40 (1/2, FP 2) | 0.43 (3/9, FP 2) | 0.34 (12/35, FP 24) |
| greyvibe-withsecure-2026 | 0.35 (26/67, FP 54) | 0.32 (4/5, FP 16) | 0.15 (8/9, FP 87) | 0.53 (15/32, FP 10) | 0.64 (30/55, FP 9) | 0.04 (13/71, FP 503) |
| greyvibe-withsecure-web | 0.50 (1/3, FP 0) | 0.40 (2/2, FP 6) | 0.24 (4/4, FP 25) | 0.48 (5/16, FP 0) | 0.60 (13/24, FP 6) | 0.22 (19/36, FP 121) |
| industroyer2-eset-2022 | 0.67 (13/18, FP 8) | 0.17 (1/1, FP 10) | 0.59 (8/8, FP 11) | 0.71 (6/8, FP 3) | 0.79 (13/16, FP 4) | 0.11 (9/15, FP 136) |
| intelsq1-day0-html | 0.82 (30/41, FP 2) | 0.00 (0/0, FP 0) | 0.40 (2/3, FP 5) | 0.17 (1/9, FP 2) | 0.42 (4/11, FP 4) | 0.00 (0/2, FP 10) |
| shinyhunters-gcb-2026 | 0.71 (16/21, FP 8) | 0.67 (1/1, FP 1) | 0.00 (0/0, FP 12) | 0.53 (4/8, FP 3) | 0.41 (12/17, FP 30) | 0.11 (6/13, FP 90) |

The per-report figures are the same for 0.6.0. A cell with a gold of 0
(`0/0`) has an F1 of 0 by convention: its false positives are what it measures.

## The candidate at 5aa3e32 (2026-11-09)

The candidate above (`fe0b0f3`) predates authentication, the egress policy
and the audit trail (ADR-0097). The same run was made again on `5aa3e32`,
`main` once those were merged, to measure the release candidate itself.

| | |
|---|---|
| Commit | `5aa3e32` (`main` on 2026-11-09) |
| Image of that commit | `ghcr.io/stixaly/ctiparsor@sha256:ff0c3e88e403fc9dc1ad46332f517444154a39d793de9e5f656683f3f86df559` (`sha-5aa3e327c841a728bfa31213f1c4a413b32a97aa`, attestation verified with `gh attestation verify`) |
| Run | `inhouse-bundle-5aa3e32`, 2026-11-09 20:31 to 2026-11-10 01:43 UTC, 8 of 8 reports |
| Settings | the same as both runs above; extraction prompt fingerprint `606528fb5beba5c6` |

The run is from the source at that commit, not inside the image; the digest
names the image the same commit builds.

**Result.** `inhouse-compare` of `inhouse-bundle-candidate` against
`inhouse-bundle-5aa3e32` gives a delta of 0 on every layer, in the aggregate
and per report: every figure of the tables above holds for `5aa3e32`. The
bundles hold the same objects with the same content, and the same
relationships (source, type, target and description) on all 8 reports; only
the identifiers and timestamps of the relationships and of the report object
differ, which each build generates. ADR-0097 changes who may run and read a
report, not what is extracted from it.

## Reading

- **The comparison.** No regression and no gain between 0.6.0 and the
  candidate at this configuration. The candidate's change of defaults (3d and
  the document-level relations on) is not measured here, since both runs had
  them on; a run of 0.6.0 at its own defaults would measure it.
- **Relations.** The weakest layer: 2,178 relationships exported for 320 in
  the gold, precision 0.063. Two reports hold 1,533 of the 2,041 false
  positives (apt44-mandiant-2024, greyvibe-withsecure-2026, the two largest bundles).
  Their sources (Stage 3, the document-level pass, Stage 4b inference, the
  baseline) are not yet separated: that is the next analysis.
- **Entities.** Malware and threat actors are found (recall 0.92 and 0.87) at a
  low precision (0.23 and 0.27), as on AnnoCTR in October
  ([ner-malware-2026-10.md](ner-malware-2026-10.md)). Campaigns are not found.
- **IoCs.** Recall 0.63 and precision 0.49 on the exported bundle; the
  per-report spread is wide (0.20 to 0.82).
- **Techniques.** F1 0.617 on the bundle, Enterprise only, while the gold holds
  Mobile techniques the pipeline does not produce.

The run directories (`data/eval/inhouse-runs/inhouse-bundle-0.6.0`,
`inhouse-bundle-candidate`) and the in-house gold are git-ignored; this page
holds only the aggregates.
