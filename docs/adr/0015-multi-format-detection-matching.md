# ADR-0015 — Multi-format detection matching (Suricata + YARA)

**Status:** Proposed
**Date:** 2026-08-16
**Extends:** [0006](0006-multi-corpus-detection-ingestion.md) (adapter seam),
[0010](0010-default-sigma-corpora-and-dedup.md) (dedup), [0014](0014-observable-driven-detection-proposals.md) (atom index, IDF relevance)

## Context

The detection stack was built format-agnostic on paper and single-format in
practice. Measured on the current store (2026-08-16):

| Fact | Value |
|---|---|
| Rules in `detection_rules` | 11,396 |
| Distinct values of `detection_rules.format` | **1** (`sigma`) |
| Atoms in `rule_atoms` | 241,951 |
| Canonical rules after dedup | 11,385 |

`RuleCorpusAdapter` (ADR-0006), the `format` column and the `adapter:` registry
key were all designed as the seam for a second format. None has ever been
exercised. Two capability gaps follow from that:

1. A report's **network** observables (`ipv4`, `domain`, `url`) and **file**
   observables (`sha256`, `file`) are ranked only against host-telemetry Sigma
   rules. The corpora that actually cover those observables — Suricata for the
   network, YARA for the file — are not ingested at all.
2. Reports sometimes *carry* detection rules inline. Nothing extracts them.

### What the candidate corpora actually contain

Verified by cloning and counting, not from documentation:

| Format | Corpus | Rules | Licence (verified from repo) |
|---|---|---|---|
| YARA | `Yara-Rules/rules` | 12,336 | GPL-2.0 |
| YARA | `Neo23x0/signature-base` | 5,990 | **DRL-1.1** |
| YARA | `elastic/protections-artifacts` | 2,877 | Elastic Licence 2.0 |
| YARA | `reversinglabs/reversinglabs-yara-rules` | 1,240 | MIT |
| YARA | `InQuest/yara-rules` | 39 | MIT |
| Suricata | ET Open 7.0.3 | **51,799** active (+19,479 commented-out) | BSD-style / MIT |
| **Total new** | | **74,281** | |

Two licence findings that contradict the assumption they were checked against:

- `signature-base` is **DRL-1.1** — the *same* licence as SigmaHQ, already
  ingested. It was expected to be CC BY-NC 4.0; it is not, so it carries no
  non-commercial restriction and enters as a first-class corpus.
- `ptresearch/AttackDetection` is a **Positive Technologies proprietary EULA**,
  not an open licence, and PT is a US-sanctioned entity. **Excluded.**

`EmergingThreats/et-open` and `delivr-to/detection-rules` do not exist as
repositories; ET Open is published only as a tarball.

### The consequence that forces a decision

Ingesting these takes the store from 11,396 to **85,677 rules — 7.5×** — and
drops Sigma from 100% to 13% of it. `relevance.py:354` computes IDF against
`canonical_rule_count(conn)`, a **store-wide** count, and
`atom_document_frequency` counts document frequency across **all** rules.

So loading Suricata and YARA would silently change the score of every existing
Sigma proposal on every report already analysed, without a line of ranking code
changing. That is a correctness bug, not a tuning question, and it is the reason
this ADR touches ADR-0014's scoring at all.

### Rule syntax, measured

Suricata (ET Open), sticky buffers and legacy modifiers counted across all 54
`.rules` files — the adapter must handle **both**, weighted as observed:

| Buffer | Count | | Legacy modifier | Count |
|---|---|---|---|---|
| `dns.query` | 17,990 | | `http_uri` | 932 |
| `http.uri` | 15,317 | | `http_header` | 644 |
| `tls.sni` | 10,778 | | `dns_query` | 444 |
| `http.host` | 4,348 | | | |
| `http.user_agent` | 3,240 | | `content:` (total) | 145,778 |
| `tls.cert_subject` | 1,361 | | `pcre:` | 12,021 |

YARA, across 2,655 files in the five corpora:

| Element | Count |
|---|---|
| Text strings (`$x = "…"`) | 44,889 |
| Hex strings (`$x = { … }`) | 31,083 |
| Regex strings (`$x = /…/`) | 1,756 |
| **Distinct hashes in `meta`** (`hash`, `hash1`, `reference_sample`) | **8,932** |
| `os =` meta (windows 1,825 / linux 902 / macos 95) | 2,877 |
| `import "pe"` | 311 |

The 8,932 metadata hashes are the single highest-value finding: a report hash
matches a YARA rule *directly*, which is near-proof evidence and needs no new
matching machinery — the existing `hash` atom class already carries it.

Conversely `import "pe"` covers only 311 of 22,482 rules (1.4%), so imports are
**not** a usable platform signal. Only Elastic's `os =` meta is, for 2,877 rules.

## Options considered

**A — A parallel subsystem per format.** Separate stores, separate ranking,
separate endpoints. Verdict: **rejected.** Duplicates the atom index, the dedup
pass, the export path and the coverage join three times over, and gives the
analyst three unrelated screens for one question.

**B — Force Suricata and YARA into the Sigma atom vocabulary.** Verdict:
**rejected.** A YARA text literal is not a `cmdline`; mapping it there pollutes
the document frequency of Sigma's most-used class and corrupts the IDF that
ADR-0014 depends on to separate signal from `cmd.exe`.

**C — New adapters, shared store, vocabulary extended by exactly one class,
IDF scoped per format.** Verdict: **chosen.**

**D — Defer ET Open because it is a tarball, not git.** Verdict: **rejected.**
ET Open is 70% of all new rules; dropping it to avoid ~30 lines of fetch code
would forfeit most of the network coverage this ADR exists to add.

## Decision

### 1. Two new adapters behind the existing seam

`SuricataAdapter` (`format="suricata"`) and `YaraAdapter` (`format="yara"`),
registered in `pipeline/detection/registry.py::_ADAPTERS`. The store schema
gains **no new tables** — only two additive migrations (below).

### 2. The atom vocabulary gains exactly one class: `strlit`

Everything else maps onto the existing twelve. Mapping is fixed and total:

| Source | → atom class |
|---|---|
| Suricata `dns.query`, `http.host`, `tls.sni`, `tls.cert_subject` (CN) | `domain` |
| Suricata `http.uri`, `http.request_line` | `url` |
| Suricata header literals (non-`$VAR`, non-`any`) | `ip`, `port` |
| Suricata `content:` in any other buffer, incl. `http.user_agent` | `strlit` |
| YARA `meta` `hash` / `hash1` / `reference_sample` | `hash` |
| YARA text string that parses as a domain / URL / IPv4 / path | `domain`/`url`/`ip`/`file` **and** `strlit` |
| YARA text string, otherwise | `strlit` |
| YARA `meta` `os =` | *platform*, not an atom |

**Hex and regex YARA strings are not indexed as atoms.** A report never carries
a hex byte pattern as an entity, so the 31,083 hex strings would add dead rows
to a table already at 242k. They are still hashed into `dedup_key`.

`strlit` is added to `MATCHABLE` for the `domain`, `ip`, `url`, `file`, `image`
and `name` observable classes, with `CLASS_WEIGHT` unchanged — the existing IDF
already demotes a literal that thousands of rules share.

### 3. IDF and dedup become format-scoped

- `canonical_rule_count(conn, format=…)` and `atom_document_frequency(conn, …,
  format=…)` take a format and count only within it.
- `dedup_key` payload is prefixed with the format string, so no Sigma rule can
  ever fold into a YARA one.
- `NAME_TITLE_MAX_SHARE` is evaluated per format for the same reason.

This keeps every existing Sigma score **bit-identical** after the new corpora
land — the acceptance test for this ADR (§Validation).

### 4. Proposals are grouped by format, never merged into one ranking

The API returns `{"sigma": [...], "suricata": [...], "yara": [...]}`. Scores are
comparable *within* a format and not *across* one: a YARA metadata-hash match is
near-proof, a Suricata `content` hit on a common string is weak, and a single
merged list would interleave them by a number that means different things. The
analyst also consumes them in three different tools.

### 5. ET Open arrives through a new `tarball:` registry source

`sync_corpora.py` gains a `tarball:` alternative to `git:` — download, verify,
extract into `path`. Commented-out rules (19,479 in ET Open, shipped disabled on
purpose) are **skipped** by the adapter; ingesting them would inflate the rule
count by 38%. Skipping them also handles deprecation for free: all 3,329
`ET DELETED` rules live in the commented block, and **zero** appear among the
51,799 active ones.

`sid` is the `native_key`: all 51,799 are distinct, with no repeats, so it is a
sound stable identifier — unlike Sigma, where a missing `id` forces a
content-hash fallback.

### 6. Licence is carried, never auto-enforced

Unchanged from ADR-0006: the operator decides what to export. Elastic Licence
2.0 content is flagged `restricted` on export alongside the existing `none` and
DRL-1.1 handling. `ptresearch/AttackDetection` is excluded outright.

## Consequences

**Easier**

- Network and file observables finally reach rules written for them; a report
  hash can match 8,932 YARA metadata hashes it previously could not see.
- A third format is now ~250 lines of adapter, the seam having been proven twice.
- Coverage (ADR-0008) gains Suricata/YARA per technique for free — it joins on
  `rule_techniques`, which the adapters populate like any other corpus.

**Harder**

- The store grows 7.5× (85,677 rules, an estimated ~430k atoms). Index build
  time and `cti_stix.db` size grow with it; the build must stay incremental
  per corpus (`replace_corpus_rules` already is).
- ATT&CK coverage per format is **narrow, not sparse** — the distinction matters
  and only showed up on measurement:

  | Format | Rules tagged | Distinct techniques |
  |---|---|---|
  | Sigma | 10,347 / 11,396 (90.8%) | **887** |
  | Suricata (ET Open) | 27,312 / 51,799 (52.7%) | **45** |
  | YARA | negligible | ~0 |

  ET Open tags over half its rules — but onto only 45 techniques, concentrated
  in T1071 (6,316), T1190 (6,172) and T1568 (5,914). Exactly one technique per
  tagged rule; none carry two. So Suricata adds great *depth* on a handful of
  network techniques and nothing at all elsewhere, and YARA is effectively
  untagged. The coverage matrix must therefore report per format, and the UI
  must not read "no YARA rule for T1547" as a detection gap — it is a tagging
  gap in the corpus, not a missing defence.
- A `tarball:` source has no revision to pin, unlike a git SHA. Reproducibility
  drops to "whatever ET published that day"; the fetch records the URL and a
  content hash to compensate.

**Deliberately deferred to a follow-up ADR** (this one is matching only, per the
agreed build order): extraction of rules embedded in report text, and
deterministic rule *synthesis* from report observables.

## Validation

Beyond unit tests, this ADR is not done until, on the real store:

1. **Sigma scores are unchanged.** `propose_for_job` output for both stored jobs
   is captured before ingestion and compared byte-for-byte after. Any drift means
   format-scoping (§3) is incomplete.
2. Top-10 proposals per format on a real report are read by eye and judged
   plausible by an analyst's standard — the ADR-0014 bar.
3. Endpoint latency is measured with the full 85,677-rule store, not the 11k one.
