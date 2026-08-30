# ADR-0032: Figures are evidence, and they enter through `report_text`

**Status:** Proposed
**Date:** 2026-08-27
**Deciders:** maintainer

## Context

### The pipeline is blind to 141 figures in 200 pages

`scripts/measure_image_surface.py` over the 21 documents in `uploads/` + `input/`:

| | |
|---|---|
| documents | 21 |
| pages | 200 |
| characters of text extracted | 754 246 |
| images | 341 |
| — icons / logos (< 48 pt on a side, or < 2 % of the page) | 194 (**56.9 %**) |
| — banners (aspect ratio > 6:1) | 6 |
| — **figures** | **141** |
| figures per 10 pages | **7.0** |

Four reports carry most of it:

| report | pages | chars | figures | figure share of page area |
|---|---|---|---|---|
| `c3a0ccb2` (uploaded, never processed) | 66 | 111 118 | 75 | 19.9 % |
| `CERT_Polska_Energy_Sector_Incident_Report_2025` | 46 | 57 473 | 27 | 8.2 % |
| `industroyer-v2-…-mandiant` | 25 | 21 136 | 10 | 3.5 % |
| `apt44-unearthing-sandworm` | 40 | 105 869 | 8 | 3.5 % |

`industroyer-v2` is the extreme: **845 characters of text per page**. What the
pipeline reads there is a caption track wrapped around content that lives
entirely inside the images.

The 56.9 % icon share is the first design constraint, not a footnote. It matches
what MM-AttacKG (arXiv:2506.16968) had to build by hand — a filter for "logos,
advertisements, watermarks, weakly informative samples, poor quality, cropped
graphics" — before any model could be pointed at a CTI report's images.

### What is actually inside them — measured, not assumed

`scripts/probe_vlm_figures.py` renders the highest-figure-area page of a report
at 150 DPI and asks the **already-resident** `qwen3.8` (27.3 B Q4_K_M, ships a
vision encoder) for JSON: figure kind, verbatim text, edges, observables.

| page | fig_area | verdict | latency |
|---|---|---|---|
| `apt44` p1 | 1.00 | `logo` — it is the cover | 22.1 s |
| `industroyer` p24 | 0.22 | `none` — blog footer, "related articles" | 14.7 s |
| `CERT_Polska` p24 | 0.40 | `screenshot` — **transcribed** | 23.9 s |
| `c3a0ccb2` p1 | 1.00 | `attack-chain` — **6 nodes, 5 directed edges** | 74.5 s |
| `c3a0ccb2` p16 | 0.60 | `screenshot` — Ukrainian lure UI, **1 payload** | 48.6 s |
| `c3a0ccb2` p66 | 1.00 | `none` — "About WithSecure" back matter | 30.6 s |
| `f227f7ef` p3 | 0.54 | **empty** — see below | 89.9 s |
| `f227f7ef` p1 | 0.08 | **empty** — see below | 100.2 s |

From that third page, verbatim, out of two FortiGate console screenshots:

```
show system admin | grep "password ENC"
config system interface / edit "wan2" / set allowaccess https ping
config system admin / edit … / unset two-factor / unset trusthost1
```

Three techniques that are **absent from the text layer**: credential access on
the appliance (T1552), exposure of the WAN management interface, and removal of
two-factor plus the trusted-host restriction (T1556 / T1562). The prose beside
the figure says only "a script used to retrieve the password of a privileged
user" — a description, which ADR-0028 established is precisely what does *not*
locate.

From `c3a0ccb2` p16, a lure page rendered entirely in Ukrainian, one `file` SCO
that appears nowhere in the report's text layer:

```
K-Lite_Codec_Pack_1905_Basic.exe
```

And from `c3a0ccb2` p1, an actual graph — six kill-chain nodes and the five
directed edges between them. Edge extraction is therefore **possible**, with the
caveat that a numbered linear chain is the easiest graph there is; nothing here
shows a branching topology with labelled arrows being read correctly.

Three conclusions. The value is real, and it is exactly the evidence class the
schema already names: `EvidenceLabel.OBSERVED` — *"directly shown in
telemetry/sample/log/screenshot"*. Stage 1f would be the first producer in the
pipeline entitled to emit it. The naive "largest image on the page" selector
picks cover pages and back matter, so triage is not optional.

### And whole-page input fails outright on the capture path

`f227f7ef` is an ADR-0029 web capture: one tall sheet, 20.3 % figure area. At
150 DPI its pages render to **6 MB PNGs**, and on both of them the model spent
90 s and 100 s to return `figure_kind: "none"` with every list empty. That is not
a rejection — it is a failure to see anything at all.

The cause is geometry, not capability. That page is **960 × 14 400 pt — a 1:15
aspect ratio**. Any pipeline that normalises an image by its long edge to 1568 px
turns it into a **105-pixel-wide column**. There is nothing left to read.

The Anthropic API refuses the same file outright:

```
400 invalid_request_error — messages.0.content.0.image.source.base64.data:
At least one of the image dimensions exceed max allowed size: 8000 pixels
```

Which is the better failure. A 400 naming the reason can be caught and routed to
the crop path; a plausible-looking empty JSON after 100 s cannot be distinguished
from a page that genuinely held no figure.

So sending the page is not merely the slow option. For the ingestion route this
project just built in ADR-0029, it is the broken one — on both backends. Stage 1f
must send the **crop**, and that is a correctness requirement, not an
optimisation.

Latency across all eight probed pages: 404 s, mean 50 s/page, and the two worst
are the two that returned nothing.

### The same probe against the Anthropic API says the model is not the variable

Same eight pages would be ideal; six were run (the two tall sheets are covered
below). Same prompt, same PNGs, `--backend anthropic`:

| page | qwen3.8 27 B | Opus 5 | Haiku 4.5 |
|---|---|---|---|
| `apt44` p1 | `logo` | `logo` | `logo` |
| `CERT_Polska` p24 | `screenshot`, all commands | `screenshot`, all commands **+ `[REDACTED]` preserved** | `screenshot`, two console lines fused |
| `industroyer` p24 | `none` | **`screenshot`** | `none` |
| `c3a0ccb2` p1 | `attack-chain`, 5 edges | `attack-chain`, **the same 5 edges** | — |
| `c3a0ccb2` p16 | `screenshot`, payload + 3 UI edges | `screenshot`, payload + **the same 3 UI edges** | — |
| `c3a0ccb2` p66 | `none` | `none` | — |

Two differences are real. Claude preserved the redaction —
`show system admin [REDACTED] | grep "password ENC"` — where qwen3.8 emitted the
command without it, which reads as a complete command that was never on screen.
And on the blog footer Opus 5 answered `screenshot` where both qwen3.8 and Haiku
answered `none`; the prompt does not settle whether a rendered web page counts as
a figure, so this is a contract gap, not a model error.

Everything else matched, **including the failure**. Both models read layout
adjacency on the screenshot montage as causal edges (`chat notification → chat
window → codec installer`). The Tier 2 over-reading is not a capability gap that
a better model closes — which is the evidence for grading figure edges `inferred`
and keeping the tier behind a flag.

Cost, from observed token usage: **$0.028/page on Opus 5, $0.0027 on Haiku 4.5** —
$3.93 and $0.39 respectively for a full 141-figure pass. Neither number is a
reason to design anything differently. Latency over three pages: 60.7 s local,
38.9 s Opus 5, 31.0 s Haiku 4.5.

**Conclusion: Tier 1's model is a configuration choice, not an architectural one.**
Stage 1f goes through the `LLM_PROVIDER` abstraction Stage 3 already has
(`anthropic | mistral | ollama`) — the pipeline already crosses that trust
boundary for text, and the deployments where the local model is mandatory
(air-gapped, TLP:RED) are ones this project supports.

### The hard part is the evidence contract, not the model

ADR-0028 made every TTP carry an `evidence_text` that must be a verbatim quote,
resolved by `pipeline/evidence_span.py` to an `evidence_start` offset **into
`report_text`**. ADR-0027 gates pin materialisation on that offset; ADR-0030
gates the whole coverage panel on it. A quote that cannot be located is demoted.

An entity read out of a figure has no offset in `report_text`. So the design
question is not "which VLM" — it is **which coordinate system figure evidence
lives in**. Two answers:

| | inject into `report_text` | separate evidence space |
|---|---|---|
| Stage 2 / 2b / 2c / 2e | unchanged | must be re-run per figure |
| Stage 3 LLM prompt | sees the figure text in its chunk | needs a second prompt path |
| `evidence_span.resolve` | unchanged | needs a second locator |
| ADR-0027 / 0030 gates | unchanged | every gate learns a second space |
| UI highlight | needs a marker | needs a second renderer |
| provenance | needs a side table | native |

Injection is the only option that costs one new table and one new stage instead
of touching six.

## Decision

### 1. Stage 1f transcribes figures into `report_text`

`ingest()` gains a second return channel. Each figure becomes a delimited block:

```
⟦figure 7 · screenshot⟧
show system admin | grep "password ENC"
⟦/figure 7⟧
```

`⟦` and `⟧` (U+27E6 / U+27E7) occur **0 times in the 415 981 characters of
`jobs.report_text`** across the twelve ingested reports, so they cannot be
produced by a defang, a chunk boundary, or a quote. They are in neither
`_CHAR_MAP` nor `_LIGATURES`, so `evidence_span._normalise` passes them through
one-for-one and the offset invariant holds.

Everything downstream is unchanged: `chunk_text` chunks it, Stage 2's regexes
match IoCs in it, Stage 3 quotes it, `resolve_span` locates the quote.

**Blocks are appended after the document text, not woven in at the figure's
position — a measured retreat from this ADR's first draft.** Inline placement
needs per-page text, and only `pdfplumber` gives page boundaries; `markitdown`
returns one blob. Switching ingestion to `pdfplumber` costs **18.2% of the
characters** across the corpus (892 974 → 730 801). Observable retention looks
survivable at 98.1% — until you look at what the 1.9% is:

```
uploads/dac56b35 — lost by pdfplumber:
  - sha256:2ab684d93c1553fad87041b4dea97188a97e78589deee2a7bacff905564f3a35
  - sha256:68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309
  - sha256:c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f
  - sha256:d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f
  - sha256:f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc
```

All five are hashes, broken across lines by a wrapped table column — the exact
failure ADR-0029 characterised ("9 of 12 hashes lost to a wrapped table
column"), on the single observable class ADR-0030's `CLASS_WEIGHT` scores at
1.00. Trading hashes for figure placement is a bad trade at any retention rate.

So `inject_append` is the default and `inject` (page-wise) stays for a caller
that has per-page text and has accepted that cost. Reading-order *position* is
lost; reading-order *sequence* is kept, and `report_figures` still records every
figure's page and bbox, so the UI can say "figure 7, page 24" regardless.

### 2. Provenance lives in a side table, keyed by offset

```sql
CREATE TABLE report_figures (
    id          TEXT PRIMARY KEY,
    job_id      TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    ordinal     INTEGER NOT NULL,   -- 1-based, reading order
    page        INTEGER NOT NULL,   -- 1-based
    bbox        TEXT NOT NULL,      -- "x0,top,x1,bottom" in PDF points
    kind        TEXT NOT NULL,      -- network-diagram|attack-chain|screenshot|
                                    -- code-listing|table|chart|logo|none
    char_start  INTEGER NOT NULL,   -- offset into jobs.report_text, inclusive
    char_end    INTEGER NOT NULL,   -- exclusive
    model       TEXT NOT NULL,      -- e.g. "qwen3.8"
    sha256      TEXT NOT NULL,      -- of the cropped PNG, for cache + audit
    UNIQUE (job_id, ordinal)
);
CREATE INDEX idx_report_figures_span ON report_figures(job_id, char_start);
```

A side table, **not** columns on `jobs`: `jobs.report_text` is a large blob and
a column added after it is paid for on every read.

Any `evidence_start` can now be resolved back to a figure by a range lookup, so
nothing needs a per-entity provenance column. That single index answers "was
this evidence read from an image?" for entities, relationships and coverage
alike.

### 3. Three tiers, and the free one does most of the work

**Tier 0 — geometric triage, no model.** `pdfplumber` gives every image its
bbox. Reject `width < 48 pt or height < 48 pt`, `area < 2 %` of the page,
aspect > 6:1, and any image whose SHA-256 repeats on ≥ 3 pages (running headers
and footers). On the measured corpus this discards **194 of 341 images (56.9 %)
for free**, and it is the only tier that scales with corpus size.

**Tier 1 — transcription, on the crop and never the page.** One call per
surviving figure, on `page.crop(bbox)`, asking for the JSON contract the probe
already validates. This is the tier the measurements support: verbatim text,
`figure_kind`, and observables. The comparison above shows the model choice does
not change the design, and the local model is the only option under TLP:RED — so
the call goes through a provider abstraction. **ADR-0033 supersedes what this
paragraph first said.** Reusing `LLM_PROVIDER` looked right and is wrong: the
Stage-3 defaults (`OLLAMA_MODEL=llama3.2`, `.env.example`'s `mistral`) have no
vision at all, and a text model handed an image does not raise — it invents.
Stage 1f gets `VISION_PROVIDER` / `VISION_MODEL` and a capability probe.

**Tier 2 — graph extraction, same call, gated on `figure_kind`.** `edges` are
read only when Tier 1 returns `attack-chain` or `network-diagram`.

They enter `report_text` **as text**, one `src -> dst` line per arrow, inside the
figure's own block. Not as typed relationships written straight into the bundle:
that would bypass Stage 3's evidence contract, Stage 3d's self-verification and
Stage 3e's consensus — every hallucination gate this pipeline was built around.
Rendered as text, an arrow is quotable, locatable, and gated exactly like a
sentence of prose.

The arrow is ASCII (` -> `) on purpose. `_normalise` rewrites a table of Unicode
punctuation one-for-one and leaves it alone; the surrounding spaces keep it clear
of `_HYPHEN_LINEBREAK`. A rendered edge reaches `report_text` byte for byte, and
`locate()` finds it exactly — which is what makes the relationship traceable back
to its figure by offset.

Numeric labels are dropped. Diagram numbering ("1", "2") is step order, and
repeating it invites the LLM to read it as a relationship verb.

### 4. Figure-derived evidence is graded `observed`, and never corroborates prose

A `screenshot`, `code-listing` or `console` figure is the strongest evidence the
Admiralty scale in `EvidenceLabel` admits, and Stage 1f is entitled to it.

But ADR-0030's `corroboration(r)` sums over *distinct discriminating
observables*, and a caption that repeats its figure's content would let one fact
support itself twice. So: an observable whose `evidence_start` falls inside a
`report_figures` span **does not corroborate** an observable of the same value
outside one. It admits, it grades, it does not count twice.

## Consequences

- **Latency — measured, and it settles the question.** The crop-vs-page delta on
  `CERT_Polska` (21 figures found by Tier 0), six read with `claude-haiku-4-5`:

  | | page-level | crop-level |
  |---|---|---|
  | input tokens per read | 2 191 | **977** |
  | six figures, wall clock | ~74 s (serial) | **15.5 s** (concurrency 4) |
  | `figure_kind` returned | one blanket `screenshot` | `table`, `code-listing`, `screenshot` |

  Crops are cheaper, ~5× faster, and **better classified** — a page holding three
  figures gets one verdict, a crop gets the right one each time. Geometry alone
  shrinks the image 2.5–2.7× in bytes and **4.3–9.3× in pixels**, which is what
  the token count actually tracks.

  The whole 46-page report is ~21 crops, ≈ $0.058 and well under a minute. That
  is negligible beside Stage 3, so **Stage 1f can default on** where a vision
  backend is configured — the opt-in this ADR first specified was a hedge against
  a number that has now been measured.
- **`report_text` stops being "what the PDF text layer said".** Offsets stored
  before this change still resolve, because injection happens during ingestion
  and a report is ingested once. Re-ingesting an existing job invalidates its
  stored offsets — the migration is "do not re-ingest", not a backfill.
- **The UI must render the marker.** A raw `⟦figure 7 · screenshot⟧` leaking
  into the report pane is a bug, not a feature.
- **Tier 2 is proven on diagrams, and it changes what the pipeline can see.**
  `silkparasite-tracking-a-china-nexus-apt-across-central-asia` is the case this
  ADR was missing: a 2-page capture whose 12 figures include **seven
  `attack-chain` diagrams and one `network-diagram`**, carrying 35 arrows that
  describe seven complete DLL-sideloading chains. Its text yields only
  **+4 observables** — the value there is entirely in the links.

  Before the arrows were rendered, all 35 were dropped by `render_block`.
  After, Stage 3 turned the figure-bearing chunks into 26 relationships, of which
  **24 have evidence landing inside a figure block**:

  ```
  mpclient.dll      --delivers-->   DriveSilkRAT   <- figure 5
  calibre-launcher.dll --delivers--> SpiceRAT      <- figure 6
  tak_deco_lib.dll  --delivers-->   CookiETagRAT   <- figure 7
  dsp_ippv2_x64.dll --delivers-->   BloodAlchemy   <- figure 8
  scansts.dll       --delivers-->   NomadRAT       <- figure 9
  SpiceRAT          --beacons-to--> C2 server      <- figure 6
  ```

  Note where the good verbs come from. An arrow the model quoted verbatim
  (`Mp3tag.exe -> tak_deco_lib.dll`) becomes `related-to`, the weakest verb in
  the vocabulary, because ` -> ` carries no semantics. The `delivers`,
  `drops` and `beacons-to` edges were inferred from the figure's *caption text*
  sitting in the same block. **The arrow supplies the edge; the surrounding
  transcription supplies the verb** — which is an argument for keeping both in
  the block, and for a later prompt revision that asks the VLM to name the action
  on the connector when the diagram shows one.
- **Tier 2's earlier caveat, for the record.** One linear kill-chain came back correctly; no
  branching topology was tested, and on a screenshot montage the model invented
  plausible UI-flow edges (`Chat notification → Chat window`) that are a reading
  of the layout, not a claim the report makes. That is why edges are `inferred`
  and the tier is flagged off. If it does not hold up, the alternative is
  `dots.mocr` (3 B, MIT, arXiv:2603.13032 — 83.9 on olmOCR-Bench, image→SVG),
  which recovers arrows geometrically instead of asking a language model to see
  them, and which at 3 B leaves room beside the 27 B on the same 128 GB.
- **What gets harder.** Any future change to `evidence_span`'s normalisation has
  to keep the sentinel characters intact, and the ADR-0030 gate now has a
  conditional that only fires on documents with figures — a branch that will be
  under-tested until the corpus has more of them.

## Implementation status

Built, tested and wired: `pipeline/vlm.py` (the provider layer, ADR-0033),
`pipeline/stage1f_figures.py` (Tier 0 triage, crop, concurrent read, block
rendering, injection), `pipeline/figure_store.py` (the read cache and the
provenance rows), the two tables in `api/db.py`, and the Stage 1f block in
`api/worker.py`.

**Order in the worker is load-bearing.** Stage 1f runs *after* `refang` and
before chunking, and figure lines are refanged on the same terms via
`map_verbatim` before injection. `refang` rewrites `[.]` to `.` and therefore
**shortens** the text: injecting first and refanging afterwards would leave every
stored offset pointing at the wrong characters.

End-to-end on `CERT_Polska`, eight figures, `claude-haiku-4-5`:

```
text        : 63 458 -> 69 033 chars (+5 575)
figures     : 8 read, 8 spans persisted
  OK ord=1 p9  table        [63460:64088] lookup=hit
  OK ord=4 p16 code-listing [66457:67050] lookup=hit
  … 8/8 land on a sentinel, 8/8 resolve by offset
observables : 121 -> 147 (+26)
  + file:c:\inetpub\pub\dynamom_update.exe
  + file:wblrxx.bin
  + file:c:\users\[redacted]\downloads\fgt60f-[redacted]-7-4_2829_20251225i509.conf
```

Three defects worth recording, all found by running the thing rather than by
reading it:

- `read_figures` submitted `backend.read_figure, png, None` to the executor. Every
  call returned `400 — messages.0.content.1.text.text: Input should be a valid
  string`. The unit tests passed throughout, because the fake backend's own
  signature defaulted `prompt` to `None`. The fixture made the wrong behaviour
  look right; it now mirrors the real signature and asserts the prompt.
- `inject` concatenated page texts with no separator at all, so the last token of
  one page ran into the first of the next. The placement test passed anyway — it
  only checked ordering.
- `tests/test_figure_store.py`'s first fixture ran **against the project's real
  `cti_stix.db`**. `get_conn()` caches its connection in thread-local storage, so
  patching `DB_PATH` after anything has connected does nothing. It surfaced as a
  `jobs.id` UNIQUE collision rather than as data loss — the real database still
  holds its 12 jobs and no `j1` — but the fixture now drops the cached handle on
  the way in and on the way out.

## Still open

- **The capture path needs its own answer.** Two problems compound there. The one
  HTML upload in the corpus has 9 `<img>` with `https://storage.googleapis.com/…`
  sources and **0 `data:image` URIs**, so Stage 1f would have to re-fetch them —
  from inside the pipeline, which `web_capture.py` deliberately does not do. And
  its printed PDF is one tall sheet, which is what defeated the model above.
  That capture predates `82c259d`; whether the current path inlines the images,
  and whether Tier 0's bbox geometry means anything on a sheet that is one page
  tall, are both unverified.
- **An arrow can be quoted as evidence for a claim it does not make.** Stage 3
  emitted `DriveSilkRAT --related-to--> NomadRAT` citing
  `DriveSilkRAT -> Acrobatlog.exe`, and Stage 3d let it through. The conclusion
  is right — figure 9 does chain those three — but the quote does not support
  the pair as stated. A rendered arrow is short and syntactically uniform, which
  makes it easy for the verifier to accept as "supporting" almost any edge among
  the nodes in the same figure. Worth measuring across more diagram-heavy
  reports before it is called a pattern.
- **Figure text is denser in filenames than prose, and Stage 2 misreads them as
  domains.** The same run that gained 26 observables also produced
  `domain:lsass.dm`, `domain:pagefile.sys`, `domain:default.rdp` and
  `domain:zone.identifier` — a filename with a dot matching the domain regex.
  The false positive predates this ADR; what changes is its frequency, because a
  console screenshot is mostly paths. It needs a TLD check in the extractor, not
  a patch here.
- **Figure-only reports.** `industroyer-v2` at 845 chars/page suggests a class of
  document where the *text* is the supplement. Nothing here changes the fact that
  such a report is chunked, scored and gated as if its prose were the substance.
- **`c3a0ccb2` — 66 pages, 75 figures — has never been run through the pipeline.**
  It is the natural before/after subject and it is sitting in `uploads/`.

## Amendment (2026-08-28) — the capture path, measured

"Still open" asked whether Tier 0's bbox geometry means anything on a sheet that
is one page tall. It does not, and the answer was worse than the question
implied: **the capture path reached Tier 0 in only one of two senses, and failed
both.**

**Stage 1f never ran on a capture at all.** `worker.py` gated it on the ingested
file's suffix, and ADR-0029 ingests `{job_id}.txt`. `{job_id}.pdf` — the archive,
where the figures are — was never opened. The two ADRs did not compose. Fixed by
resolving the archive beside the ingested text: prose still comes from the DOM,
figures now come from the PDF, which is what each ADR wanted separately.

**And had it run, the area test would have thrown most of them away.**
`MIN_AREA_RATIO` divides by page area, and the SilkParasite capture is
960 × 14400 pt — 17× an A4:

| figure (pt) | share of the sheet | share of an A4 | old verdict |
|---|---|---|---|
| 576×384 | 1.60% | 44% | discarded |
| 576×443 | 1.85% | 51% | discarded |
| 576×425 | 1.77% | 49% | discarded ×2 |
| 576×418 | 1.74% | 48% | discarded |
| 450×253 | 0.83% | 23% | discarded |
| 576×661 | 2.75% | 76% | kept |

Six half-page diagrams lost, and the five survivors cleared the bar by 12–37% —
a slightly longer article would have taken those too.

The fix is `MIN_FIGURE_AREA_PT2 = 40_000` (≈200×200 pt) as an **OR** with the
ratio. Chosen so it cannot regress anything: on a normal page an image of that
area is already 8% of an A4, well over the 2% bar, so the disjunct never fires
where the ratio did not already pass. Measured over every PDF on disk, which is
the property being claimed:

| | old | new |
|---|---|---|
| 4 normal PDFs | 10, 8, 75, 27 | **identical** |
| 13 tall captures | 146 | **214 (+47%)** |

Several captures went from **0 figures to 5–7**: Tier 0 had been finding nothing
at all on them. These are candidates offered to the model, not confirmed
figures — a `logo` or `none` still renders an empty block — so the cost is model
calls and the benefit is not silently discarding real diagrams.

This also corrects the Context table above. Its 341 images / 141 figures were
counted with the page-relative rule over a corpus that already contained
captures, so the figure count there is an undercount for that subset.

**Tier 2 remains unbuilt.** There is no flag and no consumer: `FigureEdge` is
extracted by the prompt, carried through `figure_store`'s cache JSON, and then
dropped, because `render_block` injects only `verbatim_text`. A schema's node
labels therefore reach STIX as ordinary text, and its arrows do not.

## Amendment (2026-08-30) — the first production run, and what `iocs` is for

The numbers above came from a probe. This is the first time Stage 1f ran through
`read_figures` with a configured backend (`VISION_PROVIDER=ollama`,
`qwen3.8` on the local station), over two stored reports:
`scripts/measure_figure_iocs.py`.

### `iocs` is redundant, and that is the argument for not injecting it

The schema requires four keys, and §3 above describes the fourth as
"observables", which reads as though they were an extraction source. They are
not: `render_block` injects `verbatim_text` and the rendered edges, never
`read.iocs`.

Measured over the 15 figures that carried content:

```
iocs total        39
grounded          39   (present in the figure's own verbatim_text)
ungrounded         0
                 100.0%
```

Every value the model listed as an indicator was already in the text it had just
transcribed. So injecting the list would add **nothing** — the values already
reach Stage 2 through `report_text`, and are extracted by the same regexes, with
the same defanging and the same deduplication, as any indicator in the body.

That makes the decision cheap and settles it in the safe direction: an entry
appearing in `iocs` but *not* in `verbatim_text` would be a claim the model
cannot support from its own reading, and no later stage could check it —
Stage 3b matches names against the source text, and figure `iocs` would have no
source text to match against. **`iocs` is not an extraction path. It is a
cross-check**: a value listed there and absent from the transcription is
evidence of a transcription gap, worth a log line, never an entity.

The 100% is one sample of 39 on two reports and is not a guarantee. It is enough
to say that injecting buys no recall today, which is what the decision needed.

### Half of what the triage passes, the model discards

```
figures cached    29
  code-listing     9  }
  table            5  }  15 carried content
  screenshot       1  }
  none             9  }  14 produced an empty block
  logo             5  }
errors             0
```

Tier 0 is doing what it was designed to do — be cheap and permissive — and the
model is the real filter, rejecting 48% of what reaches it. One of the two
reports had 8 candidates and **zero** kept figures, so a report can pay the
latency and gain nothing. Every call returned; none of this is failure.

### Cost, which §3 never stated

652 s across the 15 figures that carried content, on the local 27B —
**~43 s each**. The harness sums `elapsed_s` only over kept figures, so the six
crops the model answered with `logo`/`none` cost real time that this figure does
not include: the true wall clock for that report is higher, and the per-call
cost is lower than 43 s. Order of magnitude either way, a 40-figure report — the
cap — spends **tens of minutes** in Stage 1f.

That is why `VISION_PROVIDER` defaults to `none`. The stage is opt-in on cost,
not only on availability, and the cap is a time budget as much as a token one.

### Correction to the 2026-08-28 amendment

That amendment closed with "**Tier 2 remains unbuilt** … `render_block` injects
only `verbatim_text` … its arrows do not [reach STIX]". That is no longer true.
`render_block` calls `render_edges`, and the arrows of an `attack-chain` or
`network-diagram` are rendered as `src -> dst` lines inside the figure's block,
capped at `MAX_EDGES_PER_FIGURE = 24`.

Neither report in this run contained either kind, so the arrow path contributed
nothing here — its value remains the `silkparasite` measurement recorded in the
CHANGELOG, not something this run reproduces.

### Second report, and the failure mode the 100% did not show

A second run over `aff898bc` (18 candidates, 11 with content) found the first
ungrounded entry:

```
iocs 25   grounded 24   ungrounded 1      96.0%
aggregate over both reports: 63 of 64      98.4%
```

The one that failed is worth quoting, because it is not a hallucinated
indicator — it is a **mangled** one:

```
accounts.gooq e.com/A3/signin/?de=ntifier?op_params=K252F&dsh=...
```

A Google-lookalike phishing URL read off a screenshot, with a space inserted
mid-domain, a doubled `?` separator and corrupted query characters. The model
transcribed the same URL twice — once into `verbatim_text`, once into `iocs` —
and the two do not agree, so the `iocs` copy matches nothing.

This sharpens the decision rather than weakening it. Injecting `iocs` would not
have added a missing indicator here; it would have added a **corrupted domain
that does not exist** to the bundle as an Indicator, with no stage able to catch
it — Stage 3b matches against source text, and this string is in none. The
grounding check is therefore doing exactly the job the amendment above claimed:
the 1.6% it rejects is transcription damage, not recall.

Kinds across both runs, 47 cached reads:

```
none 16 · screenshot 10 · code-listing 9 · table 5 · logo 5 · attack-chain 2
```

`attack-chain` appears for the first time, so the arrow path does fire on this
corpus — it simply had no input in the first run.

### Concurrency: measured, and rejected

ADR-0033 §5 set Ollama to `max_concurrency=1` against 4 for the API backends,
on the grounds that there is one GPU and it is also the delegation target the
project's workflow depends on. That reason is about *sharing* the box. This
measurement asks the narrower question — whether concurrency would even pay for
itself if the GPU were free — and finds it would not, so the two arguments agree.

A synthetic benchmark argued for raising it: two 120-token text generations took
7.4s concurrently against 17.5s sequentially, **2.34x**.

On the real workload it does not hold. At 4:

| | sequential | concurrency 4 |
|---|---|---|
| wall clock | 1053s / 29 calls | 737s / 18 calls |
| **per call** | **36.3s** | **40.9s** |
| overlap achieved | — | 1.89x |

The pool genuinely overlaps — per-call times sum to 1392.7s inside 737s of wall
clock — but each call inflates from ~43s to ~127s and per-figure throughput ends
up slightly *worse*. A figure read ships a 600–2400 token image and generates
hundreds of tokens back, so four in flight contend for memory bandwidth instead
of filling an idle pipe. The station is bandwidth-bound here, not latency-bound,
and the short-prompt benchmark measured the wrong thing.

The default stays 1, now for a recorded reason, and becomes overridable through
`VISION_CONCURRENCY` for hosts where the arithmetic differs.

## Amendment (2026-08-30, second) — the figure gets its surrounding text

MM-AttacKG's ablation (arXiv:2506.16968, Table 3) isolates what the prompt's
context is worth. Removing both of its context sources costs:

| | Entity F1 |
|---|---|
| full | 0.7716 |
| without Global-Context | 0.7106 |
| without Image-Aware-Context | 0.7221 |
| **without both** | **0.7022** |

About seven points, for two strings in the prompt and no extra call. Stage 1f
sent the crop with a fixed prompt and nothing else, so it was giving that up.

`prompt_with_context` now appends two blocks, and `read_figures` takes a
`global_context`. With neither, it returns `PROMPT` byte-for-byte: a caller that
passes nothing gets exactly the previous behaviour.

### The context is a band around the figure, not its page

The first implementation read the whole page, and real data refused it. On the
stored capture `aff898bc`, page 1 holds **18 371 characters and 18 figures**, so
every figure was handed the same first 1 200 characters — the site's navigation
menu — and none received the prose that introduces it.

Cropping to a band of ±250 pt around the figure's bbox fixes it:

| | whole page | band |
|---|---|---|
| distinct contexts across 18 figures | 1 | **18** |
| median context length | 1 200 (truncated) | 851 chars |

The band is also what makes the 1 200-character cap almost never fire: measured
medians are 851 and 715 characters on the two reports.

`test_two_figures_on_one_page_get_different_context` locks it; reverting to a
page-wide band fails it.

### What this costs, and the one risk it creates

The prompt grows from 837 to ~2 432 characters, roughly +400 input tokens.
Latency here is dominated by generation (~9.7 output tok/s measured), so the
input growth should be minor — that is an expectation, not a measurement.

The real risk is not cost. Handing the model page text invites it to transcribe
that text as though it had read it off the image, which would push report prose
back into `report_text` a second time wearing a figure block's clothes. The
context block therefore opens with an explicit prohibition naming
`verbatim_text`, `iocs` and `edges`, and
`test_context_block_forbids_copying_into_verbatim_text` keeps it there.

### Cache

`PROMPT_VERSION` goes to 2, so the 47 reads cached against the context-free
prompt are not served against a contract they did not answer.

The key gains a `context_sha` term, folded in by `figure_store._cache_key`. It
had to: the same crop read under two different bands is two different answers,
and the old key could not tell them apart. `report_figures.sha256` keeps holding
the crop hash alone — that is the figure's identity, not a cache detail. An
empty `context_sha` reproduces the old key exactly.

This does weaken the cross-report reuse claimed in the 2026-08-30 amendment
above: the same figure appearing in two reports now has two contexts, so it is
read twice. Re-running one report still costs nothing.
