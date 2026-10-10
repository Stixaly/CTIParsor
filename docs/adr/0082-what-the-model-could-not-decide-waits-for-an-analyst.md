# ADR-0082: What the model could not decide waits for an analyst

**Status:** Accepted
**Date:** 2026-10-10
**Deciders:** maintainer
**Amends:** ADR-0058 (decision provenance), ADR-0065 (Review shows what nobody
decided), ADR-0072 (its "Not done": a review UI for `ttp_review`)

## Context

The state-of-the-art review of 2026-10-04 (`docs/reports/`) put two gaps
third on its list of priorities:

**1. Stage 3d presented a failure as a confirmation.** `_verify_batch` in
`pipeline/stage3d_verify.py` kept a claim in `relationships`, the list that
ships, in every case except an explicit `verified: false`:

| What came back | The claim |
|---|---|
| empty answer (the call failed) | kept, as if verified |
| no JSON array | kept |
| an array without this claim's number | kept |
| `verified` missing (`v.get("verified", True)`) | kept |
| `verified: true` with no quote | kept |
| `verified: true` with a quote that is nowhere in the text | kept, and that quote became its `evidence_text` |

Nothing marked the difference. The worker stored all of them as accepted
(`default`, ADR-0058), finalize shipped them, and the bundle could not tell
a verified claim from one the verifier never answered for.

**2. Stage 3f's undecided techniques were lost.** In select mode, the default
since ADR-0072, a candidate the selector could not decide goes to
`ttp_review`: the call failed, the answer was unreadable, or the quote was
missing or not verbatim. It is kept out of the bundle, as it should be. But
`ttp_review` reached only the evaluation record. The worker never stored it,
and Review never showed it. A refused selection was a correction no analyst
could make.

Both are the same gap: the pipeline had no state for "undecided". A row
either shipped or did not exist.

**How often the quote check would fire.** The evaluation's dev runs record
each shipped relationship with its quote. Checked against the AnnoCTR text:
177 of 181 `sel-dev` quotes are in it character for character. The other 4
differ only in Markdown or punctuation: `**Filename**:` quoted as
`Filename:`, a name the converter left as a link
(`[REvil](/threat-actors/revil)`), a table row, and one paraphrase. Compared
word by word, ignoring punctuation and link targets, 179 of 181 match. Of the
2 left, one is a cut made by the record's 500-character cap (Stage 3d checks
the uncut quote); the other is a paraphrase that is not in the text
("Tianyi Credit is a subsidiary…" for "Tianyi Credit, a subsidiary…"). So on
these runs the quote check holds well under 1 % of the shipped claims, and
the ones it holds are not quotes.

## Decision

1. **A held state.** What Stage 3d or 3f could not decide is stored like any
   other row, but **pending** and with a `held_reason`, a new column on
   `entities` and `relationships` (migration v0010). A pending row with a
   reason is *held*.
2. **Stage 3d's contract** (`verify_relationships`):
   - `verified: true`, with a quote found in the text → kept, and the quote
     becomes its `evidence_text`;
   - `verified: false` → removed, as before;
   - anything else → moved to the new `LLMEnrichmentResult.rel_review` list,
     with its reason:
     - `verification call failed`
     - `verification answer unparseable`
     - `verification answer silent on this claim`
     - `verification gave no true/false verdict` (the strings `"true"` and
       `"false"` count as verdicts)
     - `verified without a quote`
     - `quote not found in the text`

   "Found in the text" is `evidence_span.stated_in`: every sentence of the
   quote (the document pass joins two with `[...]`) appears in the text word
   for word, case, punctuation, Markdown emphasis and link targets aside,
   with three words at least. A held claim keeps everything extraction gave
   it (confidence, label, dates); an unfound quote is kept as its evidence,
   for the analyst to judge. Across chunks a claim is held once, and not at
   all if any chunk or the document pass verified it, the same rule
   `ttp_review` follows.
3. **The worker stores both lists.**
   - `rel_review` becomes relationship rows with `accepted` and
     `decision_origin` NULL: nobody's decision yet.
   - `ttp_review` becomes `ttp` entity rows, graded `gap`, with the quote
     located in the report when it can be.
   - A held technique already stored from another source (an explicit
     ATT&CK id, say) is not listed twice.
4. **A held row ships only once an analyst accepts it.** One predicate,
   `pipeline.decisions.SHIPS`, decides what a report says: accepted, or
   pending and not held. Finalize, the coverage matrix, rule relevance and
   the graph-completion audit all read through it, so they cannot drift
   apart. Every other pending row still ships, as ADR-0065 decided.
5. **One card at a time.** A held row is accepted only by someone who read why
   it was held:
   - auto-accept skips it, even at 0.9 confidence;
   - accepting a type, a group or "all pending" skips it, on the server;
   - a single write labelled `human_bulk` is refused with 409;
   - Review's type, group and selection accepts leave it out.

   Rejecting a group may include it.
6. **Review shows it.** A `held` chip on the entity card and on the
   relationship rail, with the reason in its tooltip. It sits in "pending",
   where ADR-0065's "to review" count already places it.

Stage 3f's verify mode (`TTP_MODE=verify`, no longer the default) still keeps
the claims its failed calls could not judge; it has no review list, and its
stage record says so.

## Options rejected

- **Ship the undecided claim with a marker** (a lower confidence, a `gap`
  label or an `x_` property). The bundle would still assert it. OpenCTI
  imports the relationship whatever its confidence. A failure would still
  reach a partner as a fact. That is what the review asked to stop.
- **Drop it.** This is what select mode's bundle does. But a failed call says
  nothing about the claim: on a provider outage it would drop every
  relationship of the report, silently, where today it keeps them all,
  silently.
- **An exact-match quote check**, as select mode does for techniques
  (`_norm(q) in text_n`). It would have held 4 of 181 dev claims, three of
  them only for Markdown the converter put in the text.
- **Hold rows in a separate table.** The rows already have everything Review
  needs: the endpoints, the quote, the dates, the decision journal. A table of
  their own would duplicate that, and the accept path with it.

## Consequences

- **A failure is never shipped as a confirmation.** A provider outage during
  Stage 3d leaves every claim of the affected batches pending, out of the
  bundle, in Review, where it used to ship them all. The stage report counts
  them (`3d … held`).
- Before any re-run, the dev runs held at most 2 of 181 claims (the quote
  check). The failure paths add only what fails: those runs had 61/61 usable
  verification calls.
- Rows stored before this version have no reason and keep shipping (nullable
  column, no backfill).
- `rel_review` is in each evaluation record. It is not in `relations`, which
  is what ships.
- Calibration (ADR-0051) reads only one-card human decisions, so an
  analyst's accept of a held row is a label it learns from. That is the
  point: these are the rows the model was unsure of.

## Validation

- The new and rewritten tests:
  - `tests/test_stage3d_verify.py`: each reason, the verdict forms, the
    quote check, the merge across chunks;
  - `tests/test_evidence_span.py`: `stated_in` on the four real misses, a
    paraphrase, whole words, non-Latin text;
  - `tests/test_held_for_review.py`: storage, finalize before and after an
    accept, coverage, auto-accept, the three group accepts and the 409;
  - `tests/test_migrations.py`, which assumed that the history ended at the
    schema ADR-0077 froze (version 9). This is the first version after it.
- The frontend's chip tests and `heldPending`.
- Not measured on a live run. The LLM server was unreachable on 2026-10-10.
  The next dev run (docs/eval/baseline-2026-10.md, "Next" 1) records
  `rel_review`.
