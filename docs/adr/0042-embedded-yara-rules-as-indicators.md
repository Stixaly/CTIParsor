# ADR-0042: Embedded detection rules (YARA, Suricata, Snort, Sigma) become Indicator SDOs

**Status:** Accepted
**Date:** 2026-09-14
**Deciders:** maintainer
**Relates to:** ADR-0015 §"reports sometimes carry detection rules inline. Nothing
extracts them" (named as a gap, never built); ADR-0041 (Indicator routing, the
other recent addition to Stage 4's relationship graph); reuses
`pipeline/detection/yara_atoms.py` and `pipeline/detection/suricata_atoms.py`
(ADR-0015's own corpus parsers) as-is; `pipeline/detection/sigma.py`'s
title+detection validation for the new Sigma heuristic

## Context

CTI vendor reports — Mandiant, Google Threat Intelligence Group, and others —
routinely publish literal detection rules as part of their write-up, not just
a description of the malware. Verified on a real, just-ingested report
(`financially-motivated-threat-actor-breeze-comet-targets-brazil`, Google
Cloud blog, job `c4679b1c`): the rendered `report_text` contains **four**
complete YARA rule blocks (`M_Utility_REALBREEZE_2`, `G_Tunneler_COBALTSPIN_1`,
`G_Backdoor_BOATBEAM_1`, `G_Backdoor_MILDFROST_1`). Today none of them survive
past ingestion as anything more than prose the LLM may or may not mention —
they are not represented in the STIX bundle at all. The same is true, in
principle, of a report that embeds a Suricata/Snort or Sigma rule instead —
this workstation's own corpus (74,281 rules across YARA, Suricata and Sigma,
per ADR-0015) confirms all three formats are genuinely in circulation.

STIX 2.1 has a purpose-built representation for exactly this: an `Indicator`
object's `pattern_type` may be `"yara"`, `"suricata"`, `"snort"`, or `"sigma"`
(alongside `"stix"`), with `pattern` holding the native rule text verbatim
rather than the abstract STIX pattern grammar. Nothing needs to be invented at
the STIX-modelling layer — this ADR is entirely about extraction, and the
three formats differ enormously in how reliably that extraction can be done.

### Three formats, three different extraction problems

**YARA — solved, and already validated at scale.** A hand-rolled "find the
matching closing brace" regex breaks on real syntax in two ways: a string
literal can contain an unmatched `}` (`$s = "config}"`), and a regex
quantifier (`/foo{2,4}/`) is not a structural brace either.
`pipeline/detection/yara_atoms.split_rules()` — built for ADR-0015 and
validated against ~20,000 real corpus rules across five corpora — already
handles both correctly (comment-stripping that preserves offsets, a
string/regex-aware brace-depth counter). It is a pure function (stdlib only),
so importing it from `pipeline/stage4_stix_mapping.py` carries no
circular-import or heavy-dependency risk.

**Validated directly against the real report text** (not a synthetic
example): `split_rules(report_text)` on job `c4679b1c`'s stored text returns
all 4 rules, each with correctly parsed `meta.author` and `strings`, matching
manual inspection of the source.

**Suricata/Snort — solved, one line at a time, no new problem to solve.**
Both share the exact same one-line rule syntax (`action proto src port -> dst
port (options...)`); `SuricataAdapter.parse` already recognises a candidate
line by its first token (`alert`/`drop`/`reject`/`pass`/`log`) and validates
it with `rule_header()` — reusable verbatim on `report_text.splitlines()`
instead of a `.rules` file's lines. The one thing this project has no signal
for is telling Suricata and Snort apart — they are the same syntax by design
(ET Open ships as both). This ADR types a rule `"snort"` only when that word
appears in the 200 characters immediately before it in the report, and
`"suricata"` otherwise — a real but weak signal, stated as such rather than
pretending the two are reliably distinguishable.

**Sigma — best-effort, and the only one of the three with no real test
case.** Sigma is YAML, and YAML has no delimiter that survives being
embedded in prose the way YARA's braces or Suricata's one-line format do —
there is no character that unambiguously means "the rule ends here."
`SigmaAdapter` itself only ever parses whole files, where the file boundary
*is* the rule boundary; that assumption does not hold inside a report. The
approach taken: grow a candidate from each `title:` line to the next
`title:` (a second rule) or the end of the text, then shrink it from the end,
one line at a time, until it parses as YAML with the same `title`+`detection`
shape `SigmaAdapter._to_rule` itself requires. A candidate that never parses
that way yields nothing — a failed guess must produce no rule, never a wrong
one. **Unlike YARA, no real report in hand embeds a Sigma rule this way**;
this path is validated only against constructed examples, and that gap is
recorded rather than glossed over.

## Decision

`build_stix_bundle` (which already receives `report_text`) gains three
extraction passes, each producing `(pattern_type, pattern_text, title)`
triples, funnelled through one shared `_add_embedded_rule_indicator` helper
so the "create the Indicator, then auto-link it" logic exists once, not four
times:

1. **YARA** — `split_rules(report_text)`, skipping `rule.is_private` (same
   exclusion `YaraAdapter.parse` already applies: a private rule is an
   auxiliary predicate a public rule references, not an independent
   detection claim).
2. **Suricata/Snort** — new `_find_embedded_net_rules(report_text)`, built
   from `suricata_atoms.rule_header`/`parse_options`, typed per rule as
   described above.
3. **Sigma** — new `_find_embedded_sigma_rules(report_text)`, the
   grow-then-shrink heuristic described above, gated on the same
   `title`+`detection` validation `SigmaAdapter` uses.

For every rule found, `_add_embedded_rule_indicator`:

- Creates `stix2.Indicator(pattern_type=<format>, pattern=<verbatim text>,
  name=f"{Format} rule: {title}", indicator_types=["malicious-activity"],
  valid_from=<now>)`, with a deterministic id derived from the rule's
  **content** (`_make_deterministic_id(f"{format}_rule_{pattern}",
  "indicator", "cti")`) — not the name, matching `YaraAdapter`'s own choice to
  key corpus rules on a content hash rather than `meta.id`/name (ADR-0015: 57
  groups of corpus rules share a declared id across genuinely different
  rules; a rule's own `sid`/`id` field is documentation, not identity, here
  either).
- **Auto-links by name, not by asking the LLM.** If any already-extracted
  `malware_families`/`tools` name (≥4 characters, to keep a short tool name
  like "RDP" or "SMB" from matching a coincidental substring) appears
  case-insensitively inside the rule's title, emits
  `Indicator --indicates--> Malware/Tool` with `x_evidence_label: "observed"`
  — the rule's own identifier or `msg` field naming the malware it detects is
  a stronger, more direct claim than an LLM inference, and the existing
  evidence-label convention reserves `observed` for exactly this kind of
  structurally-certain fact (ADR-0009/0024).

**Measured on the real report, after correcting an initial mistake**: a
first check against the raw Stage-3 LLM output found none of `REALBREEZE`,
`COBALTSPIN`, `MILDFROST`, `BOATBEAM` in `malware_families` — CyNER (Stage
2d), not the LLM, is what actually extracted all four as `malware` entities,
merged into the DB-backed entity list `build_stix_bundle` really sees. All
four YARA rules link correctly once the right data source is checked
(`re_run_final_stages`'s `accepted IS NULL OR accepted=1` merge across every
extraction source, not the first table queried).

## Options considered

| Option | Verdict |
|---|---|
| **A — hand-roll new parsers for all three formats** | Rejected: YARA and Suricata/Snort already have exactly this parsing logic, validated at corpus scale; re-deriving it risks reintroducing the string/regex-brace mistakes that logic already fixed |
| **B — reuse the existing corpus parsers, add only what's missing (Sigma's boundary-finder)** (chosen) | Zero new parsing code for YARA/Suricata; the only genuinely new logic is Sigma's grow-then-shrink heuristic, which has no existing equivalent to reuse because `SigmaAdapter` never had to find a boundary before |
| **C — a new pipeline stage, mirroring Stage 1f figures** | Rejected: `build_stix_bundle` already receives `report_text`; a new stage would exist solely to hand the same string to the same function one call earlier |
| **D — skip Sigma, ship YARA + Suricata/Snort only** | Rejected: the user asked for all three: with no real counter-example and a fail-closed validation gate (must parse as valid title+detection YAML), the downside of a Sigma false negative is "nothing extracted," the same as not building it at all — so building it costs a heuristic, not correctness risk |
| **E — try to distinguish Suricata from Snort structurally** (e.g. Suricata-only "sticky buffer" keywords like `dns.query`/`tls.sni` from ADR-0015 §"rule syntax, measured") | Deferred: workable in principle, but classifying by keyword presence needs a maintained list and produces a *default*, not a certainty, no better in kind than the context-word heuristic actually shipped — not worth the complexity until a real misclassification is observed |

## Consequences

**Easier:** a report's own detection content is no longer silently discarded;
an analyst reviewing the bundle sees the exact rule the vendor published,
machine-readable, in whichever of the four formats it was written in — not
paraphrased by the LLM and not absent.

**Harder / revisit:**
- The auto-link is a plain case-insensitive substring match on the rule
  title, nothing more, shared identically across all four formats. It will
  over-link if a short malware name is also a common word fragment, and
  under-link if the report names the malware differently than the rule does.
  **Observed on the real report, not hypothesised**: two of the four YARA
  rules also linked to `backdoor` and `tunneler` — not malware names, the
  generic category words from Google's own `<Category>_<NAME>_<version>` rule
  naming convention (`G_Backdoor_MILDFROST_1`, `G_Tunneler_COBALTSPIN_1`).
  They pass the ≥4-character guard because CyNER (Stage 2d), not this ADR,
  had already mistagged both as `entity_type="malware"` for this job — a
  pre-existing extraction defect in a different stage, which this feature
  faithfully surfaces rather than causes. Not fixed here: filtering generic
  category nouns would need a maintained denylist built from evidence wider
  than one report, and the underlying mistagging belongs to Stage 2d, not to
  Stage 4's indicator creation.
- Suricata vs. Snort typing is a weak, stated-as-such heuristic (a nearby
  mention of the word "snort"), not a structural classification. Expect it to
  default to "suricata" in the common case where a report never names either
  format explicitly.
- **Sigma extraction is unvalidated against any real report** — the
  grow-then-shrink boundary heuristic is the least reliable of the three by
  construction (YAML has no self-delimiting rule-end marker), and its fail-closed
  gate means the realistic failure mode is silently extracting nothing, not
  extracting something wrong. Revisit once a real report is seen to embed one.
- No click-to-locate offsets are tracked for any of these Indicators (unlike
  `RawEntity`-based entities) — not attempted here since nothing asked for it.

## Validation

Targeted tests (new pure-function tests for each `_find_embedded_*` helper,
covering the string/regex-brace YARA cases, the Suricata/Snort context-word
typing, and Sigma's grow-then-shrink success/failure paths) plus the real-data
check already run: `build_stix_bundle` (via `re_run_final_stages`, zero LLM
cost) on job `c4679b1c` produces 4 `Indicator(pattern_type="yara")` objects,
each `pattern` byte-identical to the corresponding block in `report_text`,
each with an `indicates` edge to the correct malware SDO.
