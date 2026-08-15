# ADR-0014: Observable-Driven Detection Proposals

**Status:** Accepted
**Date:** 2026-08-15
**Deciders:** maintainer
**Relates:** extends ADR-0006 (rule store) + ADR-0008 (coverage matrix); honours ADR-0008's "no LLM in scoring"

## Context

The Review "Detections" tab and the per-report Sigma export answer one question —
*which rules should an analyst look at for this report?* — with one signal:
`rule_techniques.technique_id`. Every canonical rule tagged with any technique the
report mentions is proposed, unranked.

Measured on the two reports in the local store (11 396 rules, 8 corpora):

| Report | Techniques | Rules proposed |
|---|---|---|
| ShinyHunters / Oracle PeopleSoft (Linux) | 34 | **2 688** |
| GREYVIBE | 48 | **3 010** |

The failure is not just volume. The ShinyHunters report is a **Linux/WebLogic**
intrusion, yet its two largest buckets are `T1059.001` (760 PowerShell rules) and
`T1059` (500). Meanwhile everything that makes the report *identifiable* —
`meshagent64-azure-ops.exe`, `azurenetfiles.net`, `_fanout.sh`, `sshpass`,
`psappsrv.cfg`, `/etc/hosts`, five sequential C2 IPs, five SHA-256s — is extracted
by the pipeline, stored in `entities`, and then ignored by this stage. A proposal
list that cannot tell a PowerShell rule from a bash rule on a Linux report is not
a proposal list; it is a tag join.

Two structural causes:

1. **Rules are indexed by tag only.** The `detection:` block (`Image`,
   `CommandLine`, `TargetFilename`, `TargetObject`, `Hashes`,
   `DestinationHostname`, …) and `logsource.product` live in `detection_rules.raw`
   and are never queried. 1 049 of 11 396 rules carry no `attack.tXXXX` tag at all
   and are therefore permanently invisible — a known troubleshooting entry in
   `docs/detection-coverage.md`, not a bug to be worked around.
2. **Report observables are unused here.** `file`, `ipv4`, `sha256`, `domain`,
   `url`, `registry_key`, `mutex`, `tool`, `malware`, `cve` entities never reach
   the detection stage.

## Decision

Rule proposal becomes a **relevance ranking over the report's technical content**,
with the technique tag demoted from *sole selector* to *one signal among several*.

Three parts:

1. **Rule atom index.** During ingestion, each Sigma rule's detection block is
   reduced to normalized `(atom_class, value)` pairs — `image`, `cmdline`, `file`,
   `registry`, `hash`, `domain`, `ip`, `url`, `pipe`, `service`, `port`, `user` —
   stored in a new `rule_atoms` table. Each rule also gets a `platform` column
   derived from `logsource`. Extraction is pure YAML field mapping: no new
   dependency, no network, no model.
2. **Report observable profile.** A job's entities are normalized into the *same*
   atom vocabulary, plus an inferred report platform (windows / linux / macos /
   multi / unknown) from path shapes and file extensions.
3. **Relevance scoring.** Candidates are the union of technique-matched and
   atom-matched rules. Each candidate scores in `0..1` from IDF-weighted observable
   overlap + a technique term + a platform factor, and lands in one of three tiers:

   | Tier | Meaning |
   |---|---|
   | `direct` | matched a report observable — carries evidence |
   | `behavioural` | technique match only, platform-compatible |
   | `weak` | technique match only, platform-incompatible |

**IDF is what makes this work.** A rule matching `cmd.exe` (present in thousands
of rules) earns ≈0; a rule matching `meshagent64-azure-ops.exe` (present in ~none)
earns ≈1. Specificity is measured against the corpus, not asserted by a weight table.

Four rules keep that honest, each of which measurably broke the ranking before it
was added:

- **IDF is keyed on the matched rule atom, never on the observable.** For a
  substring match the observable is in no rule at all (`df` 0 → idf 1.0), so
  weighting it that way handed a `.exe`-fragment hit a perfect score.
- **Substring matches need length and share.** Rules hold bare fragments
  (`.exe`, `.dll`, `http`), so plain containment tied every campaign binary to
  any rule downloading *some* executable. A contained string must be ≥ 8 chars
  and cover ≥ 50% of the longer one — which keeps `meshagent` ⊂
  `meshagent64.exe` and drops the rest.
- **One source entity scores once.** A file path is emitted as `file` *and*
  `image` and may additionally hit a `cmdline` atom; counting all three let a
  single artifact saturate the noisy-OR to 1.0. Only the strongest four matches
  feed the score, for the same reason.
- **A few values can never be indicators**, and IDF structurally cannot catch
  them: `/dev/null` and `127.0.0.1` are *rare* as whole rule-field values (df 1
  and 22 of 11 385), so they read as highly specific. Pseudo-filesystem paths
  (`/dev`, `/proc`, `/sys`) and loopback / unspecified / link-local / multicast /
  reserved addresses are therefore dropped at the observable stage. RFC 1918
  ranges are deliberately kept — an internal pivot target is real content.

Every proposal carries its **match evidence** — which observable matched which
rule field — so the ranking is auditable rather than a bare number. Scoring stays
deterministic and offline, computed live per request like coverage (ADR-0008), so
it always reflects current accept/reject decisions.

## Options Considered

| Option | Signal | Verdict |
|---|---|---|
| **A — full-text search over `raw`** | substring hit anywhere in the rule | Rejected — matches authors, references and comments; no field semantics, so no evidence to show and no way to weight a hash against a username |
| **B — atom index + IDF relevance** | field-typed value overlap + platform | **Chosen** — explainable, offline, deterministic; reuses the existing ingest pass |
| **C — embed rules and observables, rank by cosine** | vector similarity | Rejected — an IoC match is exact by nature; embeddings blur precisely the distinction (this hash vs. a similar-looking hash) that matters, and add a heavy model to an offline-first path |
| **D — LLM ranks the candidate rules** | model judgment | Rejected — same reason ADR-0008 rejected LLM-drafted detections: the detection artifact must stay trustworthy |

Scoring keeps the technique term rather than replacing it: a report's behavioural
content is real signal, and reports with few IoCs must still get proposals. The
change is that the technique term no longer *selects* — it ranks.

## Consequences

- **Easier:** untagged rules become reachable (1 049 rules today); the panel can
  show a short, ordered, evidence-backed list; the export can be scoped to what
  actually matched.
- **Harder / revisit:** `rule_atoms` adds a table that must stay in sync with
  `detection_rules` — it is rebuilt by the same pass and backfillable offline from
  stored `raw`, so an existing database needs no re-clone. Atom count per rule is
  capped (auto-generated keyword corpora like `mthcht` would otherwise dominate the
  index).
- **Substring matching is scoped to the candidate set**, i.e. rules already
  reached by a technique tag or an exact atom. Containment over the whole
  242k-row index on every request costs seconds. The consequence: a rule with no
  ATT&CK tag *and* no exact match, reachable only by substring, is not surfaced.
  Exact matching already reaches untagged rules, which was the recall gap that
  mattered. Revisit if untagged IoC corpora grow.
- **Query shape matters more than indexing here.** Filtering `is_canonical` with
  a JOIN makes SQLite enter through `idx_detection_canon` — a near-constant
  column — and scan all 11k rules: 2.7s for a 3-value atom lookup. Expressed as
  an EXISTS it drives off the value index instead (~8ms). `atom_hits`,
  `atom_document_frequency` and `canonical_rule_ids_for_techniques` are written
  that way; end-to-end ranking on a real report is ~2s.
  `rule_refs_for_techniques` and `rules_for_technique` (coverage, ADR-0006/0008)
  still carry the JOIN form and the same avoidable scan.
- Coverage scoring (ADR-0008, 0–3) is **unchanged** — readiness and relevance are
  different questions and stay separate views.
- Weights and the tier thresholds live in one module constant, not scattered.

## Implementation

`pipeline/detection/atoms.py` (rule → atoms + platform),
`pipeline/detection/observables.py` (job → observable profile + platform),
`pipeline/detection/relevance.py` (candidates, IDF, scoring, tiers),
`pipeline/detection/store.py` + `api/db.py` (`rule_atoms`, `detection_rules.platform`),
`scripts/build_rule_atoms.py` (offline backfill),
`api/routes/coverage.py` (`GET /api/jobs/{id}/detections/proposals`),
`frontend/src/components/review/DetectionsPanel.tsx`.
