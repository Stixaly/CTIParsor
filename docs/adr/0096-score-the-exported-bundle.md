# ADR-0096: Score the exported bundle

**Status:** Accepted
**Date:** 2026-11-08
**Deciders:** maintainer
**Relates to:** ADR-0094 item 6 (measurement of the exported bundle), ADR-0060
(the in-house set and its protocol), ADR-0095 (a legitimate observable is never
an Indicator; the `observables` list of the gold)

## Context

ADR-0094 item 6 asks for the bundle that Stages 4 and 5 produce to be scored,
per layer and per document, with every report not scored named. Until now the
in-house scorer read the runner's own record (`result.entities`, the LLM's
lists, the relations before export), not the file an analyst receives.
`python -m evaluation inhouse-run` already kept Stage 4 on, but it turned
Stage 5 off and wrote no bundle. A defect between the record and the file
(a name dropped at export, an Indicator whose pattern is refused, a relation
whose end is missing) could not show in the score.

The gold of the in-house set has four layers (`iocs`, `entities`,
`techniques`, `relations`) and, since ADR-0095, an `observables` list. A STIX
bundle spells these differently: IoCs are SCO values, CVE ids and pattern
atoms; an entity can be a `threat-actor` or an `intrusion-set`; a technique is
an `attack-pattern` with an external reference; a relation joins STIX ids.

## Decision

### 1. `inhouse-run` writes the bundle

Stage 5 stays on. For each report the run writes
`data/eval/inhouse-runs/<name>/bundles/<doc_id>.json`, or
`<doc_id>_invalid.json` when the schemas refuse the bundle. The record in
`docs/<doc_id>.json` gains `validation`, `bundle_file` and `bundle_sha256`.
`run.json` gains `"format": 2`. A bundle left by an earlier attempt at the same
report is deleted before the report is run again, so no stale file can be
recorded as this run's.

### 2. `evaluation/bundle.py` projects a bundle onto the gold's layers

`project()` reads a serialized bundle and returns:

- `iocs`: values from the SCOs, the CVE ids and the STIX patterns that use `=`;
- `indicated`: the values an Indicator alerts on (used for `observables`);
- `entities`: the names with their aliases; `threat-actor` and `intrusion-set`
  both give `threat_actor`;
- `techniques`: the ATT&CK ids;
- `relations`: both ends resolved to names; `based-on` is left out;
- `unsupported_patterns`: yara, sigma, snort and suricata rules, a pattern that
  does not parse, and a pattern over the complexity bounds (65,536 characters,
  256 joiners, 64 levels of brackets);
- `problems`: unresolved references and a malformed bundle.

It never executes a pattern. A pattern is only parsed, with `stix2patterns`.

### 3. `inhouse-score --from bundle` scores that projection

`--from run` stays the default, with its former meaning, so the scores already
recorded keep the sense they had. `--from bundle` writes
`data/eval/inhouse-runs/<name>/score-bundle.json`; `--from run` writes
`score.json`.

A report is scored only if all of these hold:

1. the run recorded no error;
2. the verdict is `validated` (`invalid` and `unverified` are not scored);
3. the bundle file named in the record exists inside the run's folder;
4. its sha256 equals `bundle_sha256`;
5. it reads as JSON and projects without error;
6. the projection has no unresolved reference.

Any other report is listed in `documents_unscored` with its reason, and the
command exits non-zero once the report is written. A format-1 run has no
bundle: every report is then unscored with "no bundle recorded". A score that
silently skipped a refused or altered bundle would flatter the release.

Both reports have the format `inhouse-score/2`: `source` (`run` or `bundle`),
`gold` (the sha256 of each `gold.json`), `run_manifest`, `per_document`, and
the totals of the four entity types even when they are zero.

### 4. Matching rules

- An alias counts as the same end of a relation. A reversed relation stays an
  error.
- An observable of the gold is neither an IoC hit nor an IoC false positive.
  `observables.as_indicator` counts the ones the bundle indicates (ADR-0095).

### 5. `inhouse-compare A B`

Takes two score files. It exits 2 and writes nothing if the formats, the
sources (`run` or `bundle`) or the gold hashes differ. Otherwise it prints, by
layer and by document, the precision, recall and F1 of A and of B and the
delta, plus `micro_common` (over the documents scored on both sides) and
`micro_comparable` (true when both sides scored the same documents).

## Consequences

- The measure of ADR-0094 item 6 is the bundle's, and a report that cannot be
  scored is named with the reason.
- A run made before this ADR (format 1) can be scored `--from run` only.
- Comparing with the previous release on the same data takes two runs, one per
  release, then `inhouse-compare`. A score computed by the old code does not
  compare with one computed by the new code on the same bundle.
- `inhouse-run` writes one file per report under `bundles/`.

## Not covered

- **No run yet.** `inhouse-run` has not been run with this code on the 8 gold
  reports, so no figure from this scorer exists yet. The first run fills the
  candidate's row of the readiness record.
- **No comparison with the previous release.** It needs both versions run on
  the same data.
- **The proof** (the "relevant passage" of the plan, section 7) is not scored.
- **The "after review" track** (the bundle from `GET /api/jobs/{id}/bundle`
  after finalization) is not scored: only the bundle a run writes is.
- The unsupported patterns (yara, sigma, snort, suricata and the unparseable
  ones) are counted and named, not matched against the gold.
- The gold is AI-assisted and arbitrated by one maintainer (ADR-0094,
  amendment of 2026-11-07); the scorer inherits that limit.

## Alternatives rejected

- **Make `--from bundle` the default.** The recorded scores would change
  meaning without the files changing.
- **Score a bundle the schemas refused.** The analyst cannot import it.
- **Execute the patterns to read their values.** Parsing is enough and runs no
  report-controlled content.
