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
| `domain-collision-caturegli-2025` | Caturegli, *Internal domain name collision 2.0* | PDF, 93 p, research paper, 29 image-heavy pages | a **negative** case: dozens of example domains and addresses that are not indicators; annotate `iocs` (the empty set, or near it) and `negatives` only | iocs, negatives | — |
| `desert-hydra-medium-2026` (optional) | Medium, *Operation Desert Hydra — AI-assisted CTI pipeline* | PDF printed from the web, 23 MB, 37 images | a blog **about** a pipeline that quotes MuddyWater indicators as examples: `generic` negatives, and benign IoCs | iocs, negatives | — |

Three reports in double annotation (the shortest three), as the guide asks;
`python -m evaluation agreement <gold_a.json> <gold_b.json>` scores them.

## What is missing

- **French reports: none.** The audits ask for five, CERT-FR among them
  (`CERTFR-2025-CTI-00x` PDFs are public). Drop them in `data/eval/inhouse/`
  with the same commands; multilingual quality is otherwise unmeasured.
- **Scanned PDFs: none fully scanned.** The Caturegli paper has 29
  image-heavy pages, which exercises Stage 1f, not OCR. A scanned advisory
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
