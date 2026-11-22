# ADR-0104: A stage that could not do its work says so: the degraded state, and ATT&CK ids written in a report

**Status:** Accepted (2026-11-22)
**Date:** 2026-11-22
**Deciders:** maintainer
**Relates to:** ADR-0059 (the stage report), ADR-0061 (the mapping ledger), ADR-0082
(held for review), ADR-0087 (ATT&CK release tracks), ADR-0097 (the TLP egress policy)

## Context

Two issues come from the same fault: a result that looks complete and is not.

- **#982: empty stages declared successful.** A text that OCR could not read, a
  missing spaCy model, a missing `iocextract`, an unreadable `gazetteer.json` or
  unreadable ATT&CK definitions each ended with an empty or narrower result, and the
  stage report said `ran`. The stage report had three states (`ran`, `skipped`,
  `failed`); none described "ran, on less than it needed". A load failure was also kept
  by a cache, so it lasted until the process stopped.
- **#980: two paths for one identifier.** Stage 2 extracts `T1059.001` from the report
  text with a regular expression, and Stage 3c resolves the techniques the model
  proposes (a revoked id is replaced by its successor). An id the report itself wrote
  took neither check: a revoked id gave an attack-pattern the release no longer
  holds, a tactic (`TA0001`) gave an attack-pattern, and the entity carried no quote
  from the report.

## Decisions

### A fourth stage state, `degraded` (#982)

1. **`degraded` means: the stage ran, its result is usable but incomplete, and the
   reason is mandatory.** `RunResult.ran()` is true for it, `not_run()` does not list
   it, and a required stage that is degraded does not raise `StageRequired`. It is
   logged at `WARNING`, as a failure is.
2. **What gives FAILED or degraded, stage by stage** (`pipeline/orchestrator.py`):

   | Stage | Condition | State |
   |---|---|---|
   | 1 | the text is empty after ingestion (OCR unavailable, OCR failed on every page, or nothing readable) | FAILED, and the run stops (`StageRequired`; Stage 1 is mandatory) |
   | 1 | OCR could not read some pages (`pages_failed`) | degraded; the reason gives "N of M pages" |
   | 1f | a figure answer names a `figure_kind` outside the contract | that figure is not read and not cached (it is retried on the next run); the stage is degraded and counts `unexpected_kind` |
   | 2 | the spaCy model is absent and `SKIP_HEAVY_MODELS` is not set, or `iocextract` is absent | degraded; the details carry `spacy_model` and `iocextract` |
   | 2b | `gazetteer.json` is missing, not valid JSON, not a list, or empty | FAILED |
   | 3f | the ATT&CK definitions cannot be read | degraded; the candidates were offered without them |
   | 2e | GLiNER cut chunks to its 384-token limit | state unchanged; counted in `truncated_chunks` and named in the message |

   A spaCy model turned off by choice (`SKIP_HEAVY_MODELS`) is not a fault. The
   "Sentence of length N has been truncated" warning of GLiNER is no longer hidden: it
   is counted per chunk, and any other warning raised in the same call is shown again.
   3f with nothing selected stays `ran` ("nothing to verify"): no definition was needed.
3. **No load failure is cached any more.** The gazetteer and the ATT&CK definitions
   are kept only after a successful read; a failed read is made again on the next
   call (`load_error()` and `definitions_error()` say why the last one failed).
4. **Where the state shows.**
   - The report page: the panel of stages that did not run (`StageRefusals`) lists a
     degraded stage with its reason ([web-ui.md](../web-ui.md)).
   - `/metrics`: `ctiparsor_jobs_with_degraded_stages` and
     `ctiparsor_jobs_with_failed_stages`, the number of jobs whose stage report holds
     such a stage ([operations.md](../operations.md)). The rows are chosen with `LIKE`
     on `run_config_json` and read in Python, so one unreadable value does not fail
     the scrape.
   - The worker's log at start: one `optional dependencies missing: ...` warning when
     OCR, `iocextract` or the spaCy model is lacking (`log_missing_optional_dependencies`).
   - The image smoke (`scripts/smoke_stage_report.py`): a degraded stage is a problem,
     required or not.
   - The evaluation (`evaluation score`): a "stages degraded" line, apart from "stages
     not run".

### ATT&CK ids written in a report (#980)

5. **`pipeline/attack_ids.resolve` classes an id the report writes, against the
   embedded release, as `known`, `revoked`, `tactic` or `unknown`.** Stage 2, the
   stored rows and Stage 4 all use it.
   - **tactic** (`TA####`): no attack-pattern, and Stage 2 emits no entity.
   - **revoked**: the object is the attack-pattern of the successor (when the index
     holds it). The id written stays on it as an `external_references` entry with
     `source_name: report` and a description ("revoked in ATT&CK <version>, replaced
     by <id>"); it is not a `mitre-attack` reference, which Stage 4b, 4c and the
     retrieval read as ids the release holds. If the model already proposed the same
     technique, the two become one object. The ledger entry has the reason
     `attack_id_revoked` and the keys `written`, `replaced_by` and `attack_release`.
   - **unknown**: the entity is held for review (ADR-0082) with `held_reason`
     "identifier absent from ATT&CK <version>: a newer technique, a deprecated one, or
     a typo", and stays out of the bundle until the analyst decides. An unknown id
     written in lower case is still dropped at Stage 2, as before.
   - ATT&CK's deprecated techniques are not in the index: they fall in `unknown`.
6. **The citation is the sentence, or the table line, that holds the id.** It is cut
   to 300 characters around the id, located in the report as a model quote is
   (ADR-0028), and labelled `reported`.

## Alternatives rejected

- A `partial` status on the job: the granularity is the stage, and a job status would
  hide which stage.
- Failing every degraded stage: a partial result is still useful to the analyst.

## Consequences

- A run with a missing optional dependency now shows it in the stage report, in
  `/metrics`, in the smoke and at worker start, instead of a clean report.
- A report whose text is empty now fails at Stage 1; before, it ran every stage on
  nothing.
- **Known limits.**
  - The command-line path has no review: `build_stix_bundle` receives the entities
    directly, and only the worker holds a row for review. An unknown id therefore still
    reaches the bundle there.
  - A re-extraction rewrites the rows and loses an analyst's decision on a held id
    (existing behaviour).
  - A checkpoint or a report made before this change has no `degraded` state.
  - The worker checks only Stage 2's own ATT&CK ids for the hold; the techniques the
    model proposes are resolved by Stage 3c as before.
- The census below lists the silent and log-only cases left outside the seven treated
  here; each group is to be handled in its own issue.

## Annex: Census of silent empty returns (2026-11-22)

#982 (item 6) asked for a list of the places where an empty value stands in for a
failure. A read-only sweep of `pipeline/stage*.py`, `vlm.py`, `ttp_retrieval.py`,
`mitre_db.py`, `aliases.py`, `attack_data.py`, `benign.py` and `llm_parse.py` found
about 80 `except` blocks that return a neutral value and about 170 guard returns.

**Treated by this ADR:** OCR (`_read_pdf_ocr`), the loading of spaCy and `iocextract`,
the gazetteer, the ATT&CK definitions of 3f, an unexpected figure kind (`vlm`), the
GLiNER truncation, and an empty text at Stage 1.

**Silent** (nothing logged, nothing in the stage report):

- `stage2c_ttp_semantic._thresholds`: a malformed `TTP_HIGH_THRESHOLD` or
  `TTP_MEDIUM_THRESHOLD` falls back to the default (the threshold applied is in the
  details).
- `stage2g_alias_list.extract_alias_list_entities`: returns `[]` when the `alias_list`
  threshold exceeds the default confidence; 2g records `ran` with 0 entities.
- `stage4b_graph_completion._attack_pairs` and `_ground_reference`: without the ATT&CK
  index, no reference edge; 4b records `reference_added=0`.
- `stage4_stix_mapping._find_embedded_sigma_rules`: a rule whose end is not found or
  whose YAML is invalid leaves no ledger entry (ADR-0061).
- `stage4c_long_distance._parse` and `infer`: an unreadable answer counts as "no link",
  with no counter.
- `stage1_ingestion.extract_reference_date`: `None`, debug log only.
- `stage2b_gazetteer._match_aho` and `_match_regex`: a span is claimed, then its entity
  is dropped (#914).

**Logged only** (a warning, nothing in the stage report):

- `benign._lists`: unreadable warning lists give no benign filter, so public IoCs reach
  the bundle.
- `stage1_ingestion._is_scanned_pdf`: a detection error reads the PDF as text, without OCR.
- `stage1_ingestion._rejoined_table_rows`: tables not read, cell IoCs lost.
- `mitre_db._revoked`: revoked ids not replaced (Stage 3c and #980 both rely on it).
- `stage1f_figures.find_figures`: figures not detected; 1f ran with `figures=0`.
- `stage2c_ttp_semantic.detect_ttps_semantic` and `_load_corpus_for`: a scoring or cache
  error gives 2c with 0 entities.
- `stage3e_consensus.consensus_enabled`: `ENABLE_CONSENSUS` without `CONSENSUS_PROVIDER`
  skips 3e as "disabled", without the reason.
- `stage4_stix_mapping._add_relationship` and `_stamp_objects`: a relation refused by
  `stix2`, or an object without context.
- `ttp_retrieval._exclusions`: an unreadable `TTP_RETRIEVAL_EXCLUDE_CITED` gives no exclusion.

**Reported** (reaches the stage report: counter, FAILED, review): the provider, empty and
invalid answers of Stage 3 (`llm_stats`), the 3f selection failures, the 3d verification,
the 2d and 2e load failures, 2f when CIRCL is unavailable, the Stage 4 drops (ledger). A
missing client or an unknown provider in `stage3_llm` counts as `extraction_empty`, not
as a provider failure.

**Intended** (an empty value is the answer): alias and id lookups, release availability,
benign checks on invalid input, multi-form JSON parsing, date and XML parsing, figure
bbox and kind guards, IPv6 candidate validation, guards of disabled stages, an unknown
CVE (404), validation filters, the rule, relation and anchor policy guards of Stage 4.

The silent and log-only cases that this ADR does not treat remain to be handled; the
follow-up is one issue for each group.
