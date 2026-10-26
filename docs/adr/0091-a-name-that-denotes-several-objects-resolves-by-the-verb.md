# ADR-0091: A name that denotes several objects resolves by the verb

**Status:** Accepted (2026-10-26). It lands with ADR-0092, which answers its
open question.
**Date:** 2026-10-26
**Deciders:** maintainer
**Amends:** ADR-0021 (the name table Stage 4 resolves through keeps one object
per STIX type), ADR-0061 (the mapping ledger gains the reason `ambiguous_name`)
**Relates to:** ADR-0012 (the observable ↔ technique guard), ADR-0041 and
ADR-0062 (observables route through their Indicator), ADR-0035 and ADR-0086
(the freshness list and its scopes), ADR-0088 (CyNER types one span two ways)

## Context

`build_stix_bundle` resolves the ends of a relationship row through a table of
lower-cased name to STIX object. It was a `dict[str, object]`: one object per
name. `_register_named` wrote `name_to_stix[name.lower()] = obj`. The aliases of
the name already went through `setdefault` (ADR-0021), so the first claim kept
them; the direct name did not. A technique's name and ATT&CK id were written the
same way.

Stage 4 writes the lists in this order: threat actors, malware, tools, then
techniques. A name in two of the LLM's lists, or in a list and a technique, kept
the last object written. Every reader of the table resolved to that object.

The audit of 2026-10-25 found two cases:

| Input | What shipped |
|---|---|
| `threat_actors=["Carbanak"]`, `malware_families=["Carbanak"]`, `targeted_countries=["France"]` | The `targets` edge left from the malware. None left from the actor. |
| `malware_families=["Mimikatz"]`, `tools=["Mimikatz"]`, row "Mimikatz uses OS Credential Dumping" | The row resolved on the Tool. `tool uses attack-pattern` is not a STIX pair, so it shipped as `related-to`. |

A name reaches two lists because the dedup is per list. On finalize,
`pipeline/named_entities.with_named_entities` merges every source's names into
the three lists, deduplicated per list only.

## Decision

**1. An index by type.** `_NameIndex` (`pipeline/stage4_stix_mapping.py`)
replaces the dict. It maps a lower-cased key to a STIX type to an object.

- Two tiers, as before. The **direct** tier (the emitted name, a technique's name
  or ATT&CK id, a raw entity's value, an observable's value) outranks the
  **alias** tier (the canonical name, the MITRE alias forms).
- Within a type, the last direct write wins and the first alias wins, as `=` and
  `setdefault` did.
- Nothing is overwritten across types.
- `of_type(key, stix_type)` returns the object of that type, direct tier first.
  `candidates(key)` returns a copy of type to object for the direct tier, else
  for the alias tier.

**2. A relationship row resolves each end by its verb.** Both ends are looked up
with `candidates`. A key with no candidate is dropped as `unresolved_*`, as
before. Then:

- **One candidate on each side**: unchanged. This is every name with one type.
- **Otherwise**, `_pick_by_verb` tries every (source, target) pair and keeps the
  pairs the verb fits. `_verb_fits` first does to the pair what the loop below
  does to it: the spurious observable ↔ technique guard (ADR-0012: only
  `indicates` passes, and the pair is turned so the observable is the source),
  then the routing of an observable through its Indicator (ADR-0041, ADR-0062).
  It then asks `stix_rel_spec.rel_is_allowed`.
- **The verb judged is the row's**, not a policy pin: a pin overrides a pair that
  is already resolved. An unknown verb is judged as `related-to`.
- **An object paired with itself** (both ends can mean it) does not count while
  another pair fits: the loop would drop it as `self_loop`. When it is the only
  pair that fits, it is the reading, and the loop drops it as `self_loop`.
- **Exactly one pair fits**: the row goes on with that pair.
- **Several pairs fit, or none**: the row is dropped, with the ledger reason
  `ambiguous_name`, `source_candidates` and `target_candidates` (the ids of every
  object each end could mean).

`related-to` fits every pair, so a `related-to` row with a multi-type end is
always ambiguous.

Examples, as the tests build them (`tests/test_stage4.py`):

| Row | Candidates | Result |
|---|---|---|
| Mimikatz uses OS Credential Dumping | malware, tool / attack-pattern | The malware. `tool uses attack-pattern` is not a pair. Emitted as `uses`. |
| Carbanak uses Phishing | threat-actor, malware / attack-pattern | Both fit. Dropped, `ambiguous_name`. |
| Mimikatz exploits OS Credential Dumping | malware, tool / attack-pattern | None fits. Dropped, `ambiguous_name`. |
| Industroyer2 attributed-to Sandworm | malware, campaign / threat-actor | The campaign. Emitted as `attributed-to`. |
| Sandworm uses Industroyer2 | threat-actor / malware, campaign | The malware. Emitted as `uses`. |

**3. The other readers take the type they mean.**

| Reader | Resolves to |
|---|---|
| The `targets` product (each listed actor × each targeted country and sector) | The threat actor of each listed actor name |
| A raw malware, actor or tool entity | Merged into the object of its own type |
| A raw technique | Deduplicated against attack-patterns only. It used to be "merged" into a tool of the same name (PowerShell). |
| CVE, campaign, targeted locations and sectors, Indicators | Their own type |
| An IoC association | The observable comes from the observable table. The malware end is the malware of that name; else the single candidate an Indicator can indicate (`rel_is_allowed("indicator", "indicates", type)`); else the association is dropped as `ambiguous_name` on the entity ledger, with `candidates`. A value that names an object of the bundle that is not an observable (a CVE, a country) is dropped as `no_pattern`, as before. |
| An embedded rule's title | Each malware-list name links the malware, each tools-list name links the tool. A name in both lists now links both objects. |

**4. The ledger and the Graph page say it.** A dropped row is drawn as a ghost
with its reason (ADR-0061). `frontend/src/components/graph/provenance.ts` has the
text of `ambiguous_name` for a relationship row and for an entity row.
`LedgerRelationship` (`frontend/src/types/index.ts`) gains `source_candidates`
and `target_candidates`. ADR-0061's list of drop reasons gains `ambiguous_name`.

**5. Kept on purpose, out of scope.** The raw-SDO loop's dedup still merges a
raw infrastructure, intrusion-set, location, identity, campaign or incident
entity into an existing object of any type with the same value. A follow-up.

## How it was measured

Date: 2026-10-26.

**Frozen scenarios.** `tests/test_stage4_reference.py` (5 scenarios) is
unchanged, and the test passes without regenerating anything. None of the five
has a name under two types.

**Real reports.** The 7 real reports of the throwaway `ctiparsor_measure`
database (150 relationship rows). Each was rebuilt by
`api.worker.re_run_final_stages` with the code before (the same tree without
this change) and after. The ledgers and the bundles were compared.

- **10 names carry two or three types** in 6 of the 7 reports, and touch 75 of
  the 150 rows.
- **55 rows change.**

| Change to a row | Rows |
|---|---:|
| Shipped, now dropped as `ambiguous_name` | 51 (30 had been emitted, 21 merged into an edge another path also built) |
| Already dropped, reason changes (`benign_observable` → `ambiguous_name`) | 3 |
| Now ships with its verb: "Industroyer2 attributed-to Sandworm", `related-to` from the malware before, `attributed-to` from the campaign after | 1 |

- **Relationship SROs: 1,390 → 1,361.** 31 extracted edges are gone and 1 is
  added.
- **118 `targets` edges move** from a malware to the threat actor of the same
  name (104 in one report, 14 in another). These are the edges of the actor ×
  targeted country/sector product: the reported bug at scale.
- One IoC association moves from a tool to a malware of the same name.
- Stage 4b's transitive edges move by +5 and −4 as a consequence.
- **Object counts are unchanged** in all 7 reports.

**Where the multi-type names come from.** All of them are upstream of Stage 4.

| Source of the second type | Names |
|---|---|
| CyNER tags the same span as both malware and threat actor | BlackFile, Falcon, Helix, Pink (one report); BREEZE COMET |
| The LLM's `campaign_name` reuses a malware name that the gazetteer or CyNER types as malware | Industroyer2 (two reports), INDUSTROYER.V2, BREEZE COMET |
| The LLM lists the name as both malware and tool | SoftEther |
| spaCy says malware, the LLM says tool | NextChat |
| A tool and a technique | PowerShell (no row touches it) |

BREEZE COMET alone accounts for 19 of the 51 rows that now drop. The 13
`indicates` rows of one report go to names CyNER typed both ways.

## Options considered

| Option | Verdict |
|---|---|
| Prefer the malware whenever it fits | Rejected. It encodes the list order the bug came from, with a different winner. |
| Emit the edge to every fitting candidate | Rejected. One claim becomes several edges. |
| Keep the last write and only annotate it | Rejected. The wrong endpoint still ships. |
| Choose one type per name before Stage 4 | Open (see below). A separate change. |

## Consequences

- **What the bundle gets.** Stage 4 no longer hangs a claim on an object of the
  wrong type. 118 `targets` edges leave the malware for the actor, and
  `tool uses attack-pattern` is no longer shipped as `related-to` for a name that
  is also a malware.
- **What it costs.** Recall, on reports whose detectors type one name two ways:
  in the 7 measured reports, 51 rows that shipped now drop.
- **What the analyst sees.** Each dropped row is a ghost on the Graph page with
  its reason and its candidates. Rejecting the wrong-typed entity row in review,
  then finalizing, resolves it: one type is left, and the row ships.
- **The freshness list.** The change alters Stage 4's output for the same input,
  so the commit that lands it is to be listed in `BUNDLE_AFFECTING`
  (`pipeline/bundle_revisions.py`) with scope `mapping` (ADR-0086), by that
  commit. This ADR does not edit the file. With that scope, a finalize at a
  revision that has the fix rebuilds the bundle with it.
- **Known limit.** The raw-SDO dedup (decision 5) still merges across types.

## Open question

Choose one type per name before Stage 4, ranked by source: analyst, then
gazetteer, then the LLM, then CyNER and spaCy. It would recover most of the rows
this ADR drops. It needs the source of each name to reach Stage 4, or a dedup in
`with_named_entities`. It is a separate change. On 2026-10-26 the maintainer
held this ADR until that change was ready. ADR-0092 is that change, and the
two land together.

## Implementation

- `pipeline/stage4_stix_mapping.py`: `_NameIndex`; `build_stix_bundle` reads and
  writes it; `_verb_fits` and `_pick_by_verb` in the relationship loop; the
  readers of decision 3; `_add_embedded_rule_indicator` takes a `_NameIndex`.
- `frontend/src/components/graph/provenance.ts`, `frontend/src/types/index.ts`:
  decision 4.
- `docs/adr/0061-bundle-view-and-mapping-ledger.md`: the reason in its list.

Tests:

- `tests/test_stage4.py`, section "A name that denotes objects of several
  types" (15 tests): the index's tiers and precedence; a name in two lists keeps
  both objects, and the `targets` edge leaves the actor; the verb picks the
  malware over the tool; a verb no pair fits is dropped; the target end resolves
  by the verb too; a raw entity merges into its own type; a raw technique is not
  merged into a tool; an IoC association indicates the malware, takes the one
  candidate an Indicator can indicate, is dropped when several could be, and
  keeps `no_pattern` for a value that is not an observable; an object paired with
  itself leaves the other reading; `related-to` and an unknown verb fit every
  pair; an observable end is turned round and routed as the loop does it; a
  direct name outranks another object's alias form.
- `tests/test_stage4_paths.py`: an embedded rule titled with a name two lists
  share indicates both objects; a raw campaign spelt with a trailing space is
  still found by its id; its helpers build a `_NameIndex`.
  `tests/test_stage4_build_failures.py` passes one too.
- `frontend/src/components/graph/provenance.test.ts`: the two `ambiguous_name`
  texts.
- Run locally on 2026-10-26: the full suite, 4,144 passed, 9 skipped, 0 failed
  (`.venv`, Python 3.14, `SKIP_HEAVY_MODELS=1`); the Stage 4 and ledger files on
  the CI-like Python 3.12 venv, 210 passed (before the review's 7 added tests);
  `ruff check` and mypy clean; eslint, `npm run typecheck` and the vitest files
  of `src/components/graph` (57 tests) pass. The 9 new tests of `tests/test_stage4.py`
  fail on the code before this change.
