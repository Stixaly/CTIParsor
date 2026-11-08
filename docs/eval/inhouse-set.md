# In-house evaluation set — the reports chosen, and why

The in-house set scores the application on the **original file** (IoCs in
tables, scanned pages, figures), and on what AnnoCTR never annotates (IoCs,
relationships, negative cases). The format and the commands are in
[README.md](README.md) and `evaluation/inhouse.py`; the rules are in
[annotation-guide.md](annotation-guide.md). This page records the selection
made on 2026-10-03, so a second annotator or a later reader knows what each
report is there to measure.

The source files stay in `data/eval/inhouse/<doc_id>/` (git-ignored): the
reports are public, but the folder also holds the annotations in progress,
and a set with a TLP-restricted report must never be committed. The
pre-annotation drafts come from `python -m evaluation preannotate <file>
--doc-id <id>`; **a draft is biased towards what the pipeline already
finds** — read the whole report.

## State on 2026-11-07

`data/eval/inhouse/` holds **8 reports**, all `status: gold`, each with the 4
layers of `LAYERS` declared (`iocs`, `entities`, `techniques`, `relations`);
`evaluation.inhouse.load()` loads all 8. Totals: 249 IoCs, 258 entities, 282
techniques, 320 relations, 36 `negatives`, plus 15 `observables`. The table
below is the selection of 2026-10-03; its *Layers* and *Double* columns are the
plan of that date. Every report now carries all 4 layers, and no double
annotation was made.

**Provenance.** ChatGPT (GPT-6) annotated. Claude then reread each report
against its source file: each element checked against the text and the
figures, missing layers completed, quotes ChatGPT invented replaced. The
maintainer then arbitrated 40 disputed points. The undisputed elements were
not reread one by one by a person. This is AI-assisted annotation arbitrated by
one maintainer, not a human-reviewed annotation. Limits to publish with any
figure: 8 reports, AI-assisted annotation arbitrated by one maintainer, a
pilot.

**Rules set by the maintainer, applied to the whole corpus:**

- a system command the attacker uses is a `tool` entity;
- ATT&CK Mobile techniques are included (21 in all). The pipeline produces
  Enterprise only, so technique recall is lower, on purpose;
- a new `observables` list holds legitimate items cited as indicators (a
  Windows binary, say) and values without an IoC type; the loader and the
  scorer do not use it yet;
- malware versions are aliases of the family;
- one technique (T1656) is absent from the local ATT&CK index.

## Selection

| doc_id | Source | Format | What it measures | Layers | Double |
|---|---|---|---|---|---|
| `industroyer2-eset-2022` | ESET, *Industroyer2: Industroyer reloaded* | PDF, 17 p, 7 tables, 7 hashes, figures | IoC tables in an ICS report; the same text is in the measurement DB as `.txt`, so file-vs-text **ingestion yield** can be measured | all | yes |
| `apt44-mandiant-2024` | Mandiant, *APT44: Unearthing Sandworm* | PDF, 40 p, 127 table cells, 18 images | many actors, aliases and malware families over a long document: entities, relationships, chunking | entities, techniques, relations | — |
| `greyvibe-withsecure-2026` | WithSecure, *GREYVIBE* | PDF, 66 p, 83 images, 34 domains, 4 image-only pages | figures as evidence (Stage 1f), domains, a recent AI-assisted campaign | iocs, entities, techniques | — |
| `greyvibe-withsecure-web` | the same report printed from the web page | PDF, 1 page | the same facts in another layout: consistency between formats | iocs, entities | — |
| `cert-polska-energy-2025` | CERT Polska, *Energy sector incident report 2025* | PDF, 46 p, 18 tables, 15 IPs, 23 hashes, 3 near-empty pages | an incident report with IoC tables and mixed pages | all | — |
| `cert-ua` | CERT-UA advisory | PDF, 4 p, 6 tables, 14 hashes, 2 IPs | a compact, table-heavy advisory: the IoC layer alone is a full annotation | iocs, techniques, relations | yes |
| `shinyhunters-gcb-2026` | Google Cloud blog, *ShinyHunters targets education sector* | PDF printed from a blog, 7 IPs | blog layout, inline IoCs, one actor | all | yes |
| `intelsq1-day0-html` | *IntelSQ1-report003: Day0* (HedgeDoc page) | HTML | an HTML source read without a PDF step. **Confirm it is shareable before any second annotator sees it** | iocs, entities | — |
| `domain-collision-caturegli-2025` (**removed 2026-11-07 by the maintainer, who judges it of no interest**) | Caturegli, *Internal domain name collision 2.0* | PDF, 93 p, research paper, 29 image-heavy pages | a **negative** case: dozens of example domains and addresses that are not indicators; annotate `iocs` (the empty set, or near it) and `negatives` only | iocs, negatives | — |
| `desert-hydra-medium-2026` (optional) | Medium, *Operation Desert Hydra — AI-assisted CTI pipeline* | PDF printed from the web, 23 MB, 37 images | a blog **about** a pipeline that quotes MuddyWater indicators as examples: `generic` negatives, and benign IoCs | iocs, negatives | — |

Three reports in double annotation (the shortest three), as the guide asks;
`python -m evaluation agreement <gold_a.json> <gold_b.json>` scores them.

## What is missing

- **French reports: none.** The audits ask for five, CERT-FR among them
  (`CERTFR-2025-CTI-00x` PDFs are public). Drop them in `data/eval/inhouse/`
  with the same commands; multilingual quality is otherwise unmeasured.
- **A dedicated negative case: none since 2026-11-07.** The Caturegli paper
  (a text full of example domains that are not IoCs) was removed. The 36
  `negatives` that remain sit inside the other reports.
- **Scanned PDFs: none fully scanned.** A scanned advisory
  (a CERT bulletin printed and scanned) is the missing case.
- The Locked Shields exercise documents on this workstation are TLP:GREEN
  and were left out on purpose.

## Commands

```bash
# one draft per report (the LLM server must be reachable; ~5-40 min each)
python -m evaluation preannotate "<file>" --doc-id <doc_id>
# then edit data/eval/inhouse/<doc_id>/gold.json, fill `layers`, set status: gold

# score a run against the gold reports
python -m evaluation inhouse-run --name inhouse-2026-10
python -m evaluation inhouse-score --name inhouse-2026-10
```

`inhouse-score` scores the reports that have a `source.*` file and a
`gold.json` with `status: gold`; a run's result for any other report (a draft)
is left out. It writes
`data/eval/inhouse-runs/<name>/score.json` and prints it: `documents` (the
reports scored), `documents_failed` (gold reports the run recorded as an
error), `documents_missing` (gold reports the run has no result for), `micro`
and `negatives`. If one of the two lists is not empty, or if no report was
scored, it then says why on stderr and exits with code 1. `inhouse-run` with
the same `--name` and `--disable` runs the missing reports; it skips a report
it already recorded, even as an error, so delete
`data/eval/inhouse-runs/<name>/docs/<doc_id>.json` to run a failed one again.

### Scoring the exported bundle

`inhouse-run` keeps Stages 4 and 5 on and writes each report's bundle to
`data/eval/inhouse-runs/<name>/bundles/<doc_id>.json` (`<doc_id>_invalid.json`
when the schemas refuse it). The record keeps `validation`, `bundle_file` and
`bundle_sha256`; `run.json` has `"format": 2`.

```bash
python -m evaluation inhouse-score --name inhouse-2026-11 --from bundle
# data/eval/inhouse-runs/inhouse-2026-11/score-bundle.json
python -m evaluation inhouse-compare \
    data/eval/inhouse-runs/<old>/score-bundle.json \
    data/eval/inhouse-runs/<new>/score-bundle.json
```

`--from run` is the default and scores the runner's predictions, as before
(`score.json`). `--from bundle` scores the bundle through
`evaluation/bundle.py`, which reads it and never executes a pattern. A report
is scored only if the run recorded no error, the verdict is `validated`, the
bundle file is in the run's folder with the recorded sha256, it reads as JSON,
and no reference in it is unresolved. Any other report is named in
`documents_unscored` with its reason and the command exits non-zero. A
format-1 run has no bundle.

`inhouse-compare A B` takes two score files. It exits 2 if their format,
source (`run` or `bundle`) or gold hashes differ. Otherwise it prints
precision, recall and F1 of A and B and the delta, by layer and by document,
with `micro_common` (documents scored on both sides) and `micro_comparable`.
Both sides must have been run: comparing with the previous release means
running both versions. Rationale: ADR-0096.
