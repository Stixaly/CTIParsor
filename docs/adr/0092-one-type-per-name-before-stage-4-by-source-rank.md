# ADR-0092: One type per name before Stage 4, by source rank

**Status:** Accepted (2026-10-26), implemented and measured. It lands with
ADR-0091.
**Date:** 2026-10-26
**Deciders:** maintainer
**Amends:** ADR-0055 (its source ranking is extended to the analyst, the LLM and
the campaign, and applied again where the named lists are built), ADR-0091
(answers its open question; the two land together), ADR-0061 (the mapping
ledger gains the reason `outranked_type`)
**Relates to:** ADR-0050 and ADR-0088 (CyNER's precision), ADR-0058
(`decision_origin`), ADR-0090 (the analyst's baseline rows), ADR-0035 and
ADR-0086 (the freshness list)

## Context

ADR-0091 keeps one object per name and STIX type. Each end of a relationship row
resolves to the type its verb fits. When several types fit, or none, the row is
dropped as `ambiguous_name`. On the 7 real reports of the `ctiparsor_measure`
database (150 rows), 51 rows that ship on main are dropped this way, and 3 rows
already dropped change reason. All 54 come from 10 names typed two or three
ways:

| Name | Types and sources (stored rows) | Rows |
|---|---|---:|
| BREEZE COMET | campaign (LLM `campaign_name`), malware (CyNER), threat actor (CyNER) | 19 |
| BlackFile, Falcon, Helix, Pink | malware (CyNER), threat actor (CyNER) | 18 |
| Industroyer2 (two reports) | campaign (LLM `campaign_name`), malware (gazetteer) | 10 |
| INDUSTROYER.V2 | campaign (LLM `campaign_name`), malware (CyNER) | 3 |
| NextChat | tool (LLM), malware (spaCy) | 3 |
| SoftEther | malware (LLM), tool (LLM) | 1 |

**Stage 2 already ranks the detectors.** ADR-0055's `resolve_type_conflicts`
(`pipeline/base.py`) runs once all Stage 2 sources are merged. When one value
carries several types, it keeps the types of the best-ranked source
(`_TYPE_PRECEDENCE`: `ioc`/`gazetteer`, then `semantic`, then `cyner`/`gliner`,
then `spacy`/`alias_list`, then any other source). Equal ranks keep every type.
So no conflict between two detectors of different rank reaches the store.

What reaches Stage 4 is what that pass never sees:

- **The LLM's names.** Stage 3 runs after it. Its lists are stored as `llm` rows
  (finalize) or kept in `llm_result` (a run).
- **The LLM's `campaign_name`.** On finalize, it is a stored `campaign` row
  (routed to the raw entities) and `campaign_name`; on a run, `campaign_name`.
- **The analyst's rows**: a row added in review (`manual`), the analyst's
  baseline (`baseline_stix`, ADR-0090), and the analyst's accept or reject.
- **Ties** that ADR-0055 keeps on purpose: one source typing a name two ways
  (CyNER), or two sources of equal rank.

`pipeline/named_entities.with_named_entities` then merges every source's
malware, threat-actor and tool names into the three LLM lists, deduplicated per
list only, and the source of each name is lost. It serves three paths:

- **A run** (`pipeline/orchestrator.py`): `with_named_entities(r.llm_result,
  entities)`. The base lists are the LLM's. Each `RawEntity` carries `source`.
- **Finalize** (`api/worker.re_run_final_stages`): the stored rows that ship,
  from an empty result. Each row carries `source`, `accepted` and
  `decision_origin` (`human`, `human_bulk`, `auto_policy`, `baseline_stix`, …).
- **`scripts/baseline_round_trip.py`**: a copy of finalize.

**What the LLM's type is worth.** It reads the context, but it is told not to
re-list a name the gazetteer or CyNER already found (`_SYSTEM_PROMPT`, "DO NOT
re-list"), and Stage 3's `_merge_results` drops from its three lists any name
the gazetteer or CyNER found, whatever the type. Its lists hold the names the
others missed; spaCy, GLiNER and the alias list are not in its prompt.
`campaign_name` is the one field where it re-types a name the others found.

**The campaign name.** All three campaign collisions above put an existing name
in `campaign_name`. The report calls BREEZE COMET "a financially motivated
threat actor" in its title. Industroyer2 is ATT&CK software S1072, and
INDUSTROYER.V2 is a report's spelling of it. ATT&CK 19.2 has 56 campaigns: one
shares its name with a malware (FunnyDream), one with an intrusion-set alias
(HomeLand Justice). A campaign named exactly like its malware is possible, and
rare.

**Real double names.** The gazetteer files 17 names under both malware and
threat actor, as ATT&CK does (Carbanak, Akira, Machete, Snake, Play…).

## Decision

**1. ADR-0055's ranking, extended.** Lower wins.

| Rank | Who | Sources |
|---:|---|---|
| analyst | The analyst | `manual`; `baseline_stix` (a row the baseline adds, or a row Stage 3r matched to it: `decision_origin = baseline_stix`); a row with `accepted = 1` and `decision_origin = human` |
| 0 | Deterministic lists | `ioc`, `gazetteer` (unchanged) |
| 1 | The LLM | `llm` (new; `semantic`, also 1, types techniques only) |
| 2 | Models | `cyner`, `gliner` (unchanged) |
| 3 | Weak models, assumed types | `spacy`, `alias_list` (unchanged) |
| 99 | Any other source | (unchanged) |
| last | A campaign | A `campaign` from any source but the analyst |

A bulk accept (`human_bulk`) and the auto-accept policy (`auto_policy`) do not
make a row the analyst's: they accept rows, they do not compare types. The
ranks ADR-0055 already had keep their order, so Stage 2's output does not
change.

**2. One type per name, where the ranks say so.** For each name (lower-cased,
stripped) typed as more than one of malware, threat actor, tool and campaign,
each type takes the rank of its best source. The types at the best rank stay.
The others are dropped before Stage 4: the name leaves that list, a dropped
campaign clears `campaign_name`, and the raw entities of a dropped (name, type)
leave Stage 4's input.

**3. A tie stays**, as in ADR-0055. ADR-0091 then resolves each row by its verb.
A tie is a real double name (the 17 above) or one source contradicting itself
(CyNER typing one span two ways, the LLM listing a name as malware and tool).
Neither is a reason to prefer one type.

**4. The ledger says it.** Each dropped (name, type) gets one entity entry:
outcome `dropped`, reason `outranked_type`, with `sources`, `kept_types` and
`kept_sources`. The Graph page gets the text of the reason
(`frontend/src/components/graph/provenance.ts`), and ADR-0061's list of drop
reasons gains it.

**5. Upstream of Stage 4.** `with_named_entities` makes the choice for the three
paths. It takes the source of each name and the campaign name. On finalize, the
source is the row's, read as the analyst's when decision 1 says so
(`stored_row_source`). On a run, it is `RawEntity.source`, and in enrich mode
Stage 3r's answer (`baseline_holds`): a (name, type) the baseline holds counts
as `baseline_stix`, the LLM's own names included, as their stored rows do. It
returns the lists, `campaign_name` and the dropped types; `record(ledger)` writes
their entries into the build's `MappingLedger`. The caller removes the raw
entities of a dropped (name, type) from what it passes to `build_bundle`
(spaCy's NextChat on a run, the stored campaign row on finalize), so Stage 4
records nothing more for them (no `not_in_llm_lists`). Finalize calls the helper
after reading `campaign_name`. `pipeline/stage4_stix_mapping.py` is not changed:
ADR-0091's row resolution, which the graph-completion work moves into
`_resolve_row`, is left alone.

**6. Out of scope.** Names match exactly (case and outer spaces aside). An alias
of another object is left to ADR-0091's two tiers. Techniques, intrusion sets,
infrastructure and the other raw SDO types are not ranked here. A tool that is
also a technique (PowerShell) is not touched.

## How it was measured

Date: 2026-10-26.

**Real reports.** The 7 reports of the throwaway `ctiparsor_measure` database
(150 relationship rows), rebuilt by `api.worker.re_run_final_stages(job,
quick=True)` in three states, each from a `git archive` copy: main `950313d`;
main + ADR-0091; main + ADR-0091 + this change. The ledgers were compared row by
row and the bundles edge by edge. The first two states reproduce ADR-0091's
figures (55 rows change; the same SRO counts per report).

The 54 rows ADR-0091 drops as `ambiguous_name`, with this change:

| Outcome | Rows | Names |
|---|---:|---|
| Ship again, on the same object types as on main | 13 | NextChat (3, on the Tool), Industroyer2 (7, on the Malware), INDUSTROYER.V2 (3, on the Malware) |
| Back to main's drop reason (`benign_observable`) | 3 | Industroyer2 targets three private IP addresses |
| Still `ambiguous_name` | 38 | BREEZE COMET (19), BlackFile, Falcon, Helix, Pink (18), SoftEther (1) |

No row ships on another object type than on main. All 38 left are equal-rank
ties: CyNER typing one name two ways (37), the LLM listing SoftEther as malware
and tool (1).

| Report | SROs: main → ADR-0091 → this change | Objects left out |
|---|---|---|
| NextChat report (`07d1fd30`) | 241 → 238 → 241 | the Malware NextChat (spaCy) |
| INDUSTROYER.V2 (`218d9f2d`) | 35 → 33 → 35 | the Campaign INDUSTROYER.V2 |
| Industroyer2 (`4a9b9810`) | 182 → 185 → 182 | the Campaign Industroyer2 |
| Industroyer2 (`cb72cc8e`) | 37 → 34 → 37 | the Campaign Industroyer2 |
| BREEZE COMET (`6dd16441`) | 250 → 230 → 230 | the Campaign BREEZE COMET |
| UNC6671 (`7a318c22`) | 645 → 641 → 641 | none |
| ADFS (`19a206bf`) | 0 → 0 → 0 | none |

- In the four reports whose names now have one type, the SROs are main's, edge
  for edge. "Industroyer2 attributed-to Sandworm", which ADR-0091 sent from the
  Campaign, goes back to main's `related-to` from the Malware, and the five
  Stage 4b edges from that Campaign go with it.
- In the other two, the difference from main is ADR-0091's alone: the tie rows
  it drops, and the 118 `targets` edges it moves from a malware to the actor of
  the same name.
- The ledger has one `outranked_type` entry in each report where a type was
  dropped (5 entries): the spaCy malware NextChat (kept: the LLM's tool), and
  the LLM's campaign in the four others (kept: the gazetteer's or CyNER's
  types). No `not_in_llm_lists` entry appears for them.

**Frozen scenarios.** `tests/test_stage4_reference.py` passes unchanged: none of
its five scenarios has a name under two types.

## Options considered

| Option | Verdict |
|---|---|
| The campaign at the LLM's rank | Rejected. BREEZE COMET, an actor, would become a Campaign only, and INDUSTROYER.V2 a Campaign over CyNER's malware. |
| Keep the Campaign object, but not under that name in the index | Rejected. A Campaign named like an actor or a malware still ships to OpenCTI as a second entity. |
| Break a CyNER tie by its confidence | Rejected. The stored score is the first mention's (Stage 2d deduplicates "by identity, not a ranking"). It picks 4 of the 5 names right here. |
| Break a tie in favour of the threat actor | Rejected. Right on these 5 names, wrong on the 17 real double names; a type preference is what ADR-0091 rejected. |
| A vote across CyNER's mentions at Stage 2d, keeping the type most mentions carry | Not here. It is the only lever on the 37 rows left, but it changes extraction (a new run; the LLM's prompt lists CyNER's names, and Stage 3 drops the LLM's own name for them). A follow-up, to measure on AnnoCTR. |
| Run `resolve_type_conflicts` again on the stored rows | Rejected as is: it has no rank for the LLM or the analyst, no campaign rule, and no ledger. Its table is extended instead. |
| Pass each name's sources to Stage 4 and choose there | Rejected. It would touch the row resolution the graph-completion work is moving, and the helper already serves the three paths. |
| Count only `manual` and `baseline_stix` as the analyst, not an accept | Rejected by the maintainer (2026-10-26). With an accept counted, accepting the right row settles a tie, as rejecting the wrong one already does under ADR-0091. |

## Consequences

- **Recall.** 13 of the 51 shipped rows ADR-0091 drops ship again, on main's
  object types. The 38 left are ties, shown on the Graph page as
  `ambiguous_name` ghosts.
- **The analyst settles a tie** by accepting the right row, or rejecting the
  wrong one. An accepted type outranks every type the analyst did not accept:
  to keep a Campaign and a malware of the same name, accept both rows. A bulk
  accept does not count.
- **Campaigns.** A campaign named like another object is dropped, with its ledger
  entry: 4 of the 7 reports lose theirs. A real one (FunnyDream) comes back when
  the analyst accepts its row.
- **The audit's campaign fix is reversed in practice.** The code audit of
  2026-10-25 (`2e6502a`, CHANGELOG "A campaign named like a malware") made a
  `campaign_name` equal to a malware or actor name build its own Campaign, where
  it had silently merged into the malware. Stage 4 still does that, but the
  campaign rarely reaches it now: unless the analyst accepted its row, it ranks
  below the other type and is dropped before Stage 4. The difference with the
  state before the audit: the drop is recorded (`outranked_type`, with the type
  kept), and the analyst's accept brings the Campaign back.
- **The freshness list.** The commit is listed in `BUNDLE_AFFECTING`
  (`pipeline/bundle_revisions.py`) with scope `mapping`, as ADR-0091's is.
- **Not covered.** `scripts/rebuild_bundle_provenance.py` and
  `scripts/measure_pin_allocation.py` call `build_stix_bundle` with the stored
  LLM lists, without the helper; they keep ADR-0091's behaviour.
  `scripts/baseline_round_trip.py` uses the helper, but its database has no
  `decision_origin` column, so an accept does not count there.

## Implementation

- `pipeline/base.py`: `TYPE_PRECEDENCE` and `DEFAULT_PRECEDENCE` (were
  `_TYPE_PRECEDENCE`, `_DEFAULT_PRECEDENCE`) gain `analyst`, `manual`,
  `baseline_stix` (-1) and `llm` (1). Stage 2's ranks do not move.
- `pipeline/named_entities.py`: `stored_row_source` (a row accepted with
  `decision_origin = human` counts as `analyst`, one with `baseline_stix` as
  `baseline_stix`); `with_named_entities(llm_result, entities, baseline_holds=None)`
  returns a `NamedEntities` (the completed `llm_result`, and the
  `OutrankedType`s), with `keeps(entity)` for the raw entities and
  `record(ledger)` for the entries; a campaign ranks `DEFAULT_PRECEDENCE + 1`
  unless its source is the analyst's.
- `pipeline/orchestrator.py` (a run, which passes Stage 3r's `MATCHED` answer as
  `baseline_holds`), `api/worker.py` (`re_run_final_stages`, which now calls the
  helper once `campaign_name` is read), `scripts/baseline_round_trip.py`: the
  sources, the filtered raw entities, the ledger entries.
- `frontend/src/components/graph/provenance.ts`: the text of `outranked_type`;
  `frontend/src/types/index.ts`: `sources`, `kept_types`, `kept_sources` on
  `LedgerEntity`.
- `pipeline/stage4_stix_mapping.py` is not changed.

Tests:

- `tests/test_named_entities.py`: each rank against the next, in both input
  orders; a name the LLM listed leaves its list when outranked; the campaign
  last against every source; an analyst's campaign beats a gazetteer malware,
  and both stay when both are the analyst's; equal ranks all stay (CyNER malware
  and actor, gazetteer malware and actor, LLM malware and tool); case and outer
  spaces; `stored_row_source` (`human` and `baseline_stix` count; `human_bulk`,
  `auto_policy`, an unreviewed row do not); the same names given as a run gives
  them (with Stage 3r's answer) and as a finalize reads them (with the rows'
  origins) give the same lists and dropped types; `keeps`; `record`; three runs:
  the LLM's tool ships, not spaCy's malware of the same name; in enrich mode,
  with the baseline holding the malware, the malware ships, not the LLM's tool;
  and the gazetteer's malware ships, not the LLM's campaign.
- `tests/test_worker.py`: a finalize with a gazetteer malware and an LLM campaign
  of the same name: the Malware ships; after a bulk accept of the campaign row,
  still; after an analyst's accept, the Campaign ships and the Malware is the
  outranked one.
- `tests/test_baseline_round_trip.py`: the script mirrors the worker.
- `frontend/src/components/graph/provenance.test.ts`: the text of
  `outranked_type`.
