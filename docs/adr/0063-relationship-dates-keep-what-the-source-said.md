# ADR-0063 — A relationship date keeps what the source said: partial values, their own quote, a status the pipeline computes, and native STIX bounds only where the source fixes them

**Status:** Proposed
**Date:** 2026-09-28
**Deciders:** maintainer
**Relates to:** ADR-0009 (evidence labels), ADR-0028 (quote, don't describe),
ADR-0029 (captured URLs), ADR-0035 (bundle staleness), ADR-0038 (backend-owned
policy defaults), ADR-0057 (document-level relations), ADR-0058 (decision
provenance), ADR-0060 (evaluation protocol), ADR-0061 (mapping ledger)

## Context

Stage 3 asks the LLM to fill `start_time` / `stop_time` on each relationship.
The model must find the date, write it in ISO 8601, and keep year or month
precision when that is all the text gives. It must also resolve simple relative
expressions against a "document reference date" (`pipeline/stage3_llm.py:455`).
The code then turns the answer into a `datetime`, and Stage 4 writes it on the
SRO.

This proposal was reviewed over several rounds with a second model. Every code
fact below was checked at `8bde0a2`. None of it has been measured on output:
the database was not reachable on 2026-09-28. How many relationships carry a
date today is therefore unknown, and that is Phase 0.

### What the code does today

1. **Our code discards the precision the model is allowed to give.** The prompt
   accepts `YYYY` and `YYYY-MM`. `parse_flexible_date` (`pipeline/dates.py:34`)
   then pads them to `YYYY-01-01` and `YYYY-MM-01`, and
   `RelationshipExtracted.start_time` is a `datetime`. After that point, "2021"
   and "1 January 2021" cannot be told apart.
2. **The padding creates silent losses, and the prompt invites them.** The
   prompt's own example is "active in 2021".
   - If the model answers start = stop = `2021`, both become `2021-01-01`, and
     the `stop <= start` guard (`stage3_llm.py:1103`) drops both.
   - If it answers start only, a year becomes "true since 1 January 2021, no
     end".
   - "until June 2023" becomes `stop = 2023-06-01`, which cuts June off.

   Beyond the padding, "active in 2021" is not a bound at all: it places a fact
   somewhere inside a window. The prompt teaches the model to write a window
   as a start and an end.
3. **A date has no evidence of its own.**
   - The only check is whether the year appears in the relationship's
     `evidence_text`, and it is logged at `debug` level
     (`stage3_llm.py:1118`).
   - Stage 3d gives the verifier the triple without its dates, then replaces
     `evidence_text` with the verifier's quote (`stage3d_verify.py:196`). The
     quote that carried the date can be swapped for one that does not.
   - `evidence_span.locate` cannot serve dates: it refuses quotes shorter than
     three words and accepts 60 % word coverage.
4. **The model does the arithmetic.** Relative expressions are resolved by the
   LLM, and nothing checks the result.
5. **The anchor is the weakest source available, and only where it is
   weakest.**
   - `extract_reference_date` (`stage1_ingestion.py:157`) returns the PDF
     `CreationDate`/`ModDate` or the DOCX `created` date, and `None` for HTML,
     TXT and MD.
   - A captured URL is ingested as `{job}.txt` (`api/routes/ingest.py:271`),
     so it has no anchor. Yet the rendered page's publication metadata was in
     the browser at capture time (`web_capture.py:794` reads only the body
     text).
   - An uploaded HTML file goes through `html_to_text`
     (`stage1_ingestion.py:405`), which never reads `<meta>`.
   - Pasted text has no anchor either.

   Only an uploaded PDF or DOCX gets an anchor, and that anchor is when the
   file was produced, not when the report was published.
6. **Merge keeps one episode.**
   - Duplicates of a triple are resolved by `_prefer`
     (`stage3_llm.py:1742`): evidence rank first, then confidence. The losing
     copy's dates are dropped.
   - Stage 4 then prefers the copy that has dates (`stage4_stix_mapping.py:1103`).
     So "in 2021" in chunk 3 and "in 2024" in chunk 9 leave a single date.
   - Chunks overlap by 400 characters and `chunk_text` returns bare strings
     (`stage1_ingestion.py:424`). The same occurrence can therefore be read
     twice, with no way to tell that it was one occurrence.
7. **The analyst path forces a day.** The review rail uses
   `<input type="date">` (`frontend/src/components/review/RelationshipRail.tsx:100`),
   and the API parses through the same padding function
   (`api/routes/relationships.py:51`). An analyst cannot record "March 2023".
8. **The reload path would drop partial values silently.** The finalize rebuild
   reads the stored text with `datetime.fromisoformat` (`api/worker.py:1007`).
   That call raises on `"2023-03"` and `"2023"` (checked on Python 3.14), and
   the helper then returns `None`. A fix that stores partial values in the
   existing columns would lose them on every rebuild, without an error.
9. **`Report.published = now()`** (`stage4_stix_mapping.py:1200`) is *not* a
   defect. The Report's `created_by_ref` is the CTIParsor identity, and STIX
   defines `published` as the date of publication by the Report's creator.
   What is missing is the source's publication date, which is recorded
   nowhere.

### What the benchmark can and cannot measure

AnnoCTR ships a TimeML layer (`data/annoctr-repo/AnnoCTR/time/`), and
`evaluation/annoctr.py` does not read it.

| Split | In-text expressions | Document creation times | Total |
|---|---|---|---|
| train | 710 | 70 | 780 |
| dev | 147 | 16 | 163 |
| test | 272 | 34 | 306 |
| **all** | **1 129** | **120** | **1 249** |

- Every expression is of type `DATE`.
- 358 have year precision and 338 month precision: 61.6 % of the in-text
  expressions.
- 34 are relative ("last month", "a year ago") and carry their resolved value.
- Some tags are shifted by one character (`i<TIMEX3>n 2019.</TIMEX3>`).

AnnoCTR therefore measures detection, normalisation, and relative resolution
when the anchor is supplied. It says nothing about recovering the anchor from a
file, about the role of a date, about which claim it belongs to, or about
export.

### What the consumer does with an absent bound

OpenCTI's platform source defines `FROM_START_STR = '1970-01-01T00:00:00.000Z'`
and `UNTIL_END_STR = '5138-11-16T09:46:40.000Z'`. Its `buildPeriodFromDates`
widens an undefined bound to "unbounded". An omitted bound therefore reads as
*open*, not as wrong. OpenCTI also rejects `start_time == stop_time` (issue
#4130). This was read from the source, not tested by an import.

## Decision

### 1. A temporal assertion is a record of its own

`RelationshipExtracted.start_time` / `stop_time` give way to a
`times: list[TemporalAssertion]` list. No `datetime` exists before export (§7).

| Field | Meaning |
|---|---|
| `role` | `start` / `end`: a bound of the relationship. `within`: the fact happened at some point in the window. `throughout`: it holds over the whole window, bounds unstated. `observed`: an observation in the window, with an optional `first` / `last` flag |
| `time_text` | The expression, copied verbatim from the chunk, preposition included ("since March 2023") |
| `value` | The date as far as the source fixes it, written in EDTF (ISO 8601-2): `2023`, `2023-03`, `2023-03-12`, or a timestamp with its offset. Quarters and halves use EDTF level-2 codes. Nothing is padded |
| `precision` | `year` / `half` / `quarter` / `month` / `day` / `instant`, so no consumer has to parse EDTF codes |
| `qualifier` | `none` / `approx` / `early` / `mid` / `late` / `before` / `after` / `by` |
| `anchor` | `explicit` / `document` / `none` (`event` is reserved and not produced in v1), plus the anchor's value and source (§4) |
| `evidence_label` | The ADR-0009 scale, applied to the temporal claim ("probably began" = `assessed`). Defaults to the relationship's label |
| `status` | `verified` / `ambiguous` / `unresolved` / `conflict`. **Computed by the pipeline (§3) or set by an analyst (§9); never taken from the model** |
| `reason` | Why a status is not `verified`: `not_found`, `boundary`, `unparsed`, `value_mismatch`, `numeric_order`, `no_anchor`, `weak_anchor`, `year_from_context`, `contradicts`, `legacy` |
| `doc_offset` | Where `time_text` sits in the document text (§6) |
| `origin` | `llm` / `analyst` / `legacy` |

Storage is a side table, `relationship_times`, with one row per assertion and a
foreign key to `relationships.id`. The existing TEXT columns are not reused:
see defect 8, and a relationship can carry several assertions. The old columns
are read only for rows that have no assertion (§10).

### 2. The model names and places the date; the code computes it

The output schema becomes, per relationship, `times: [{role, time_text, value?}]`.
The prompt changes as follows:

- **`time_text` is copied character for character**, under the rule ADR-0028
  set for TTP quotes.
- **Each role comes with its definition and its counter-examples.**
  - "active in 2021" → `within`;
  - "active throughout June" → `throughout`;
  - "observed in March" → `observed`, never `start`;
  - "no activity observed since March" is **not** a `start`.
- **`value` is optional.** It is the model's reading, and it serves as a
  cross-check (§3).
- **No arithmetic.** Relative expressions are copied, not resolved. The
  document reference date leaves the prompt (`stage3_llm.py:1448`), which also
  removes the risk of the model anchoring on a print timestamp.
- The ADR-0057 document-level call uses the same schema.

### 3. The status comes from a deterministic check

A new module, `pipeline/temporal.py`, checks each assertion against its chunk,
in this order:

1. **Locate.** `time_text` must occur in the chunk exactly.
   - Only whitespace and typographic characters are normalised (NBSP, thin
     space, en/em dash, curly quotes); a digit or a letter is never
     approximated.
   - The match must stand on word boundaries: `2021` inside `CVE-2021-44228`
     is not found (`boundary`).
   - Not found → `conflict` / `not_found`.
   - Found but not normalisable (an OCR `2O23`) → `unresolved` / `unparsed`.
   - "Found" does not mean "attached to the right claim". Association is
     measured (§11), not asserted.
2. **Normalise `time_text`.** It produces `value`, `precision` and `qualifier`.
   Rules come first; dateparser is admitted only if it wins on AnnoCTR
   train+dev (Options).
   - **Numeric day/month.** When both numbers are ≤ 12 and differ → `ambiguous`
     / `numeric_order`. Another date in the same format with a component above
     12 fixes the order only inside a homogeneous table, passage or source,
     never document-wide by default.
   - **Relative expressions.** They are resolved against the document anchor
     (§4) only when that anchor is publication-grade. A file-metadata anchor
     gives `unresolved` / `weak_anchor`; no anchor gives `unresolved` /
     `no_anchor`. Never today's date.
   - **Day and month without a year.** → `unresolved` / `year_from_context`.
     The model's candidate is kept but never exported.
   - **Unparseable.** → `unresolved` / `unparsed`. The model's value is kept
     as a candidate for the analyst.
3. **Compare with the model's `value`.** A mismatch gives `conflict` /
   `value_mismatch`. Agreement never lifts an `ambiguous` reading: the model
   and a month/day parser can both pick 4 March for `03/04/2023`.
4. **Check consistency within the relationship.** A start later than an end,
   compared at their precisions (June vs March), marks both `conflict` /
   `contradicts`. Equality at a coarse precision (start 2021, end 2021) is
   compatible, not a conflict.

Anything else is `verified`. Each status is counted in `llm_stats`, following
ADR-0060's call accounting.

### 4. The document anchor has a source, and the file timestamp comes last

Candidates are listed in order of preference. Each one is stored on the job
with its source:

1. **Captured URL.** Publication metadata read from the rendered DOM at capture
   time: `article:published_time`, JSON-LD `datePublished` / `dateModified`,
   `<time datetime>`, `<meta name="date">`.
2. **Uploaded HTML.** The same metadata, read before `html_to_text` drops the
   markup.
3. **Header line.** An explicit "Published / Posted / Updated <date>" line
   near the top of the text. It is located and checked like any other quote.
4. **Analyst entry** on the review page, which counts as publication-grade.
5. **PDF/DOCX metadata.** Kept and shown, labelled `file_metadata`, but never
   used to resolve (§3).

When candidates disagree (published vs updated vs header), the disagreement is
recorded. Resolution uses the *published* value unless the analyst chooses
another. A relative expression inside a quotation of an older report belongs
to that report's anchor. v1 cannot detect this case, and B6 measures how often
it occurs.

### 5. Stage 3d leaves temporal evidence alone

The verifier still replaces `evidence_text` and never touches `times`. Adding
the temporal assertion to the claim line, so that 3d also judges which claim a
date belongs to, is a Phase 4 option, adopted only if the evaluation shows a
gain.

### 6. Merge accumulates assertions and counts an occurrence once

- `_prefer` still chooses the relationship's evidence.
- `times` becomes the union across duplicates, deduplicated on
  `(role, value, doc_offset)`. A single occurrence seen through two overlapping
  chunks is one assertion with one quote, not two independent ones. This needs
  document offsets for chunks: `chunk_text` must return each chunk's start
  offset.
- Distinct values for one role are all kept. When their windows are
  incompatible, they are marked `conflict`. They are never merged by
  min/max, which would fabricate continuity.
- Stage 4's duplicate handling takes the same union instead of "prefer the
  copy with dates".
- Stage 4b inferred edges carry no temporal assertion. This is already true
  (`stage4b_graph_completion.py` never mentions a date) and becomes a tested
  invariant.

### 7. Export: faithful by default, day projection on request

A `temporal_export` block joins the relationship policy. Its default is owned
by the backend: ADR-0038 found that the Policy page displays defaults the
backend does not run until someone saves.

```json
"temporal_export": { "mode": "faithful" }      // or "day"
```

- **`faithful` (default).** `start_time` / `stop_time` are set only from
  assertions that meet every condition below:
  - role `start` / `end`;
  - status `verified`;
  - `evidence_label` neither `gap` nor `inferred`;
  - precision `instant`: an explicit time with an established offset,
    converted to UTC without changing the instant;
  - anchor `explicit` or publication-grade;
  - no `conflict` on the relationship.

  Nothing else reaches a native field.
- **`day` (option).** Verified day-precision bounds are also projected onto
  the whole civil day in UTC: start `00:00:00.000Z`, stop `23:59:59.999Z`. The
  projection is labelled as such in the extension and in the ledger, because
  the time and the zone are added, not read. Month and year are never
  projected in v1.
- **In both modes:**
  - Equal bounds give no native pair (STIX requires `stop_time > start_time`,
    and OpenCTI rejects equality). No artificial offset is added.
  - Every assertion ships on the SRO as `x_temporal_assertions`: text, value,
    precision, qualifier, role, anchor, status, and the projection when one was
    applied. This follows the project's existing `x_` properties
    (`x_evidence_label`, `x_inference_rule`). An `extension-definition` can
    come later.
  - Windows (`within`, `throughout`, `observed`) never become `start_time`,
    `stop_time`, `first_seen`, `last_seen` or a Sighting in v1.
  - `Report.published` stays the build time, a documented convention since the
    Report is CTIParsor's product. The source's publication date and its
    source go on the Report as `x_source_published`.

In `faithful` mode, native relationship dates will almost always be empty:
prose rarely states an instant. That is the intended trade. The dates remain in
the bundle and in the analyst views; they are simply not asserted in fields
that cannot carry their precision.

### 8. The ledger says what happened to each date

The `changes` list of a ledger relationship entry (ADR-0061) gains a `time`
kind:

```json
{"kind": "time", "role": "start", "value": "2023-03", "precision": "month",
 "status": "verified", "outcome": "withheld", "reason": "precision_below_policy"}
```

- Outcomes: `exported`, `projected`, `withheld`.
- Reasons: `precision_below_policy`, `window_role`, `status_<status>`,
  `equal_bounds`, `conflict`.

The Graph page's row detail shows these entries. This extends the ledger's
current contract, which today records no temporal decision.

### 9. Analyst entry keeps the analyst's precision

- The review rail replaces the day-only input with a precision selector (year,
  month or day, plus an optional time).
- The API accepts partial values together with their precision.
- An analyst-entered assertion is `verified` with `origin: analyst`, recorded
  in the ADR-0058 decision journal. An analyst can also verify or reject an
  LLM assertion.

### 10. Rows written before this change

If the store holds rows (unknown on 2026-09-28), each existing
`start_time` / `stop_time` becomes an assertion with `origin: legacy`, precision
unknown, and status `unresolved` / `legacy`. It is never re-interpreted: a
1 January stays a 1 January of unknown precision, not a year.

Under `faithful`, rebuilding an old job therefore drops its native dates.
Re-extraction is the way to recover them. This change goes on the ADR-0035
list of output-affecting revisions.

### 11. Evaluation (ADR-0060)

- **Phase 0 census**, before any change: share of relationships with a date,
  pairs dropped by the `stop <= start` guard, share of dates on a 1st of the
  month or a 1 January, and the year-not-in-evidence rate. For that, the
  `debug` log at `stage3_llm.py:1118` becomes an `llm_stats` counter. Two
  cautions:
  - a year missing from a quote is a diagnostic signal, not proof of error,
    since a correct relative expression carries no year;
  - a cluster on day 1 is a signal too, since some dates really are the 1st.

  The census also reads 20 dated passages the pipeline left undated. A low
  count of dated relationships can mean few dates in the reports, missed dates,
  dates dropped after extraction, or dates that belong to entities.
- **AnnoCTR time layer.**
  - A loader is added.
  - The normaliser (rules vs dateparser) is chosen on train+dev, and test is
    run once on the frozen choice.
  - Scores: exact value, exact granularity, and relative resolution with the
    document creation time supplied.
  - Span matching tolerates one character of offset.
- **In-house set.** A new `times` layer, which is backward compatible because
  an absent layer is not scored. Per relation it records role, value,
  precision and quote. Negatives are dates in the text that belong to no
  relation or to another one. The layer also records the report's publication
  date.
  - Scores: role accuracy, value accuracy, association accuracy,
    unjustified native export rate, coverage (gold assertions recovered with
    any status) and abstention rate.
  - The sample includes relationships the pipeline left undated and passages
    where no date must be produced.
  - About 40 assertions make a pilot. They do not settle rare errors.

## Acceptance cases

**A — Contract tests.** Code only, with a fixed model answer and an anchor
fixed in the test. All must pass.

| # | Given | Expected |
|---|---|---|
| A1 | `start 2021`, `end 2021` | Both assertions kept with year precision; no conflict inferred from equality; nothing silently dropped; no native field under `faithful` |
| A2 | `start` "in March 2023" | `2023-03`, month; no native `start_time`; ledger `withheld` / `precision_below_policy` |
| A3 | `start` "on 12 March 2023" | `faithful`: withheld. `day`: `2023-03-12T00:00:00.000Z`, marked projected |
| A4 | `end` "on 20 June 2023" | `faithful`: withheld. `day`: `2023-06-20T23:59:59.999Z`, marked projected |
| A5 | `time_text` "2021"; the chunk has only `CVE-2021-44228` | `conflict` / `boundary` |
| A6 | `value 2023-04`, `time_text` "March 2023" | `conflict` / `value_mismatch` |
| A7 | NBSP inside "March 2023" in the source; separately, "2O23" copied from OCR | The first is found and verified; the second is found but `unresolved` / `unparsed` |
| A8 | "03/04/2023", no other numeric date in the section | `ambiguous`, not exported |
| A9 | Same, in a homogeneous table that also holds "17/04/2023" and no contrary cue | `verified`, 3 April |
| A10 | `start` June 2023 and `end` March 2023 on one relationship | Both `conflict`, both kept, no native field |
| A11 | Same triple: "in 2021" in one chunk, "in 2024" in another | Two assertions, no 2021–2024 span |
| A12 | One occurrence seen through the overlap of two chunks | One assertion, one quote |
| A13 | Stage 3d replaces `evidence_text` | `times` unchanged |
| A14 | "last month", anchor = HTML `datePublished` 2024-06-15 | `2024-05`, month, anchor `document`/`publication_meta`, `verified`; withheld (month) |
| A15 | "last month", anchor = PDF `CreationDate` only | `unresolved` / `weak_anchor` |
| A16 | "last month", no anchor | `unresolved` / `no_anchor`, never the current date |
| A17 | "2023-06-20T14:32:00+02:00" | `instant`; exported under `faithful` as `2023-06-20T12:32:00Z` |
| A18 | Two exact, equal instants as start and end | Kept; no native pair; ledger `equal_bounds` |
| A19 | A status of `verified` supplied by the model | Ignored; the status is recomputed |

**Chain tests.** Assertions, precision, status and origin must survive:
storage and reload through the finalize rebuild; an analyst edit through the
API; a bundle rebuild; relationship merge; and their display in the ledger.

**B — Model behaviour.** Measured on the in-house set; these are rates, not
assertions.

| # | Text | Expected role |
|---|---|---|
| B1 | "active in 2021" | `within`, never `start`/`end` |
| B2 | "observed in March 2023" | `observed`, never `first` |
| B3 | "first observed in March 2023" | `observed` + `first` |
| B4 | "active throughout June 2023" | `throughout` |
| B5 | "no activity observed since March 2023" | No `start` |
| B6 | A 2024 report quoting a 2019 report's "last month" | Not anchored on 2024 |

## Options considered

| Option | Verdict |
|---|---|
| Keep the schema, tighten the prompt | Rejected: the precision is lost in `dates.py`, in the reload and in the API, not in the prompt |
| A deterministic detector before the model, handing it candidate ids | Deferred: it helps detection, which is not the demonstrated defect, and it costs prompt tokens plus offset mapping before the call. Revisit if B shows dates the model misses and a detector finds |
| HeidelTime / SUTime | Rejected for now: a JVM in a Python image, for a gain that lies in detection |
| dateparser as the normaliser | Candidate, decided against rules on AnnoCTR train+dev. Only on `time_text`, with `PREFER_DAY_OF_MONTH` and `RELATIVE_BASE` pinned and the period read from `DateDataParser`: by default "March 2023" gets today's day of the month |
| Store partial values in the existing TEXT columns | Rejected: the reload drops them silently (defect 8), and one relationship can hold several assertions |
| Envelope as the default export (start of window for start, end of window for stop) | Rejected as a default: a consumer that ignores the extension reads possibility bounds as asserted bounds. Kept for internal search |
| Day projection as the default | Rejected as a default for the same reason at a smaller scale; offered as `day` |
| A `verified` boolean | Rejected: agreement between the model and a parser does not resolve `03/04/2023` |
| Windows to `malware.first_seen` | Rejected: "observed in March" is not "first seen in March" |
| Sightings for observations in v1 | Deferred for integration cost; the standard allows them (`where_sighted_refs` is optional) |

## Consequences

**Easier:**
- A date says what the source said, with its own quote, a status the pipeline
  can justify, and a reason when it is not exported.
- Relative dates are computed by code that tests can pin.
- Captured URLs and HTML get the anchor they always had and never used.
- The analyst can record "March 2023".

**Harder / revisit:**
- Native `start_time` / `stop_time` will be almost always empty under
  `faithful`, which is a visible change for any consumer that used them. An
  import into the target OpenCTI decides whether `day` should become the
  default.
- `chunk_text` must carry offsets, which touches Stage 1 and the Stage 3
  checkpoint fingerprint (ADR-0059).
- New table, schema, prompt and UI work; the prompt change resets checkpoints.
- Rebuilding an old job drops its native dates (§10).
- Out of scope: dates on entities (`first_seen` of malware or campaigns),
  Sightings, and dates anchored on another event ("three days later").

## Phases

0. **Census** (§11) and reading of undated passages. The only code change is
   the counters.
1. **Representation, evidence, check, ledger and `faithful` export**, plus the
   side table, the reload, the 3d invariant and the merge union. Validated by
   A1–A19 and the chain tests.
2. **Anchors** (capture and HTML metadata, header line) and code-side relative
   resolution.
3. **Analyst entry** with precision.
4. **Measured options:** `day` as the default, temporal claims in 3d, entity
   dates and Sightings.

## Validation

Not implemented. The code facts were checked at `8bde0a2` on 2026-09-28. The
AnnoCTR counts were recounted per tag, not per line. OpenCTI's behaviour was
read from its source and issues and has not been tested by an import.
