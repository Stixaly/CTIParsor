# ADR-0029: Pasted text and captured URLs as ingestion sources

**Status:** Proposed
**Date:** 2026-08-25
**Deciders:** maintainer

## Context

A report reaches the pipeline exactly one way: `POST /api/upload` with a file,
which lands at `uploads/{job_id}{suffix}` and is handed to `run_pipeline_async`.
Everything downstream — Stage 1 ingestion, the Review page's source viewer,
`_delete_job_files`, the STIX mapping's `source_hash` — is keyed on that file
existing on disk.

Two things an analyst actually has are not files:

- **an excerpt** — a paragraph from a mail, a chat message, a section of a
  longer PDF they do not want to run whole;
- **a URL** — most CTI is published as a web page, and turning it into a file
  today means the analyst printing it to PDF by hand.

### Reading a web page is harder than it looks

The pipeline already reads HTML (`_read_html` in `stage1_ingestion.py`), so the
first design considered was: fetch the URL with `httpx`, store the `.html`, done.
Measured against two real CTI publishers:

| page | plain HTTP fetch | `soup.get_text()` | `article`/`main` heuristic |
|---|---|---|---|
| thedfirreport.com (WordPress) | 200, 191,738 B | 50,800 chars | **506 chars** |
| microsoft.com/security/blog | **403** | — | — |

Two findings, both fatal to the simple design:

1. **The obvious main-content heuristic destroys the report.** The DFIR Report
   page has **no `<article>` element at all**; `main` matches a wrapper holding
   1% of the text. Scoring candidate containers by text length against link
   density finds the real body — `div.entry-content-wrapper`, **46,284 chars of
   the 50,800** — but that is a content-extraction engine, and writing one is
   how `trafilatura` and `readability` became libraries.
2. **A plain HTTP client is refused outright** by a major vendor blog. No
   choice of output format changes that; the request never gets a body.

A headless browser answers both: it is the content-extraction engine (it *is*
the renderer), and it presents as a browser. Rendering to PDF also gives the job
an immutable artefact — CTI pages get edited and taken down — and lands on the
richest viewer the app has, `PdfViewer` with entity highlighting.

The cost is that ingestion would then read text back out of a PDF, which this
codebase already fights (`_join_hyphen_linebreaks` exists because PDFs split
domain names across line breaks). That cost was measured, and it decided the
design.

### The PDF keeps the prose and destroys the observables

`scripts/measure_web_capture.py` captures a page, ingests the PDF, and compares
what survives against the rendered DOM. Over 7 CTI reports (Google Cloud
Threat Intelligence ×3, WeLiveSecurity, Unit 42 ×2, CERT-UA):

| | value |
|---|---|
| captured | 6 / 7 |
| **character retention (median)** | **99.6%** |
| **observables surviving** | **72.2%** — 15 of 54 lost |

The two numbers disagree because they measure different things. On the COLDRIVER
report — 98% of characters retained — **9 of 12 SHA-256 hashes are gone**. The
IOC table renders in a narrow column, so each 64-character hash wraps into
24-character fragments, and the PDF text layer then interleaves those fragments
with the cells beside them:

```
ee46b503db\nfrom\nDecember\n2023\nBinary that\nexecutes\nLOSTKEYS\n02ce477a07681ee1671c7164\n…
```

`ClCou2 dfrom` in the same extract is two columns merged character by character.
A report's IOC table is the part the analyst came for. Keeping the prose and
losing the table is the worst available trade, and only the observable ratio
sees it — character retention scores that page at 98%.

**So the PDF is not what gets ingested.** It is the archive; the rendered DOM
text is the input. The DOM has no columns to wrap in and keeps all 12.

### Rendering a hostile page on the analyst's machine

The URL comes from a report about an adversary. Pointing a browser at it from
the server is the feature and the risk in the same sentence. Building it
surfaced one defect that would have shipped silently:

**Playwright disables the Chromium sandbox by default.** `browser_type.launch()`
takes `chromium_sandbox` and it defaults to `False`; Playwright appends
`--no-sandbox` to the command line itself. Careful `args` are not enough — the
first real launch showed `--no-sandbox` sitting in the argument list next to the
flags written specifically to avoid it. The renderer sandbox is the boundary
between a malicious page and the host, so it is forced back on explicitly.

## Decision

Add `api/routes/ingest.py` with two endpoints that both terminate in the same
place `POST /api/upload` does — a file under `uploads/{job_id}`, a `jobs` row,
`run_pipeline_async`. **Nothing downstream of Stage 1 learns that a third and
fourth entry point exist.**

### `POST /api/ingest/text`

Stored as `.md` when at least 2 of 6 Markdown signals match (ATX heading, list
item, fence, table row, inline link, bold), `.txt` otherwise — the source viewer
renders both, and the chunker's paragraph cascade needs the blank lines either
way. CRLF is normalised. Bounds: 20 chars minimum (below that it is a mis-paste
that would run five stages to produce an empty bundle), 2 MB maximum.

### `POST /api/ingest/url`

Renders the page with Playwright Chromium and writes **two artefacts**:

| file | role |
|---|---|
| `uploads/{job_id}.pdf` | the archive — laid out as published, streamed by `/jobs/{id}/source` into the review viewer |
| `uploads/{job_id}.txt` | the rendered DOM text — **this is what the pipeline reads** |

`original_filename` stays `*.pdf`, because that is what the source viewer keys
its renderer off. `/jobs/{id}/source` now sorts its glob to prefer the `.pdf`
rather than trusting filesystem order, and skips `.pdf.part`.

A capture whose DOM renders fewer than 200 characters is **refused**, with a
message naming JavaScript as the likely cause. cert.gov.ua is why: it is fully
client-rendered, so with JS off it produced a valid 944-byte PDF containing a
blank page, from which Stage 1 extracts nothing. A zero-byte check does not
catch that, and the pipeline would run all five stages to build an empty bundle.

Four boundaries, in order:

1. **`validate_url`, before any network access** — scheme in {http, https};
   port in {80, 443, 8080, 8443}; no credentials in the URL; hostname not in the
   blocked set (`localhost`, `.internal`, `.local`, cloud metadata names); and
   **every address the host resolves to must be public**. One private answer out
   of several rejects the URL — a DNS rebinding record that returns
   `93.184.216.34` *and* `10.1.2.3` must not pass, which is what
   `test_rejects_when_any_resolved_ip_is_private` locks.
2. **JavaScript off by default.** `java_script_enabled=False` removes the script
   attack surface and the beacons with it. A per-capture opt-in exists for pages
   that render nothing server-side, with the warning shown in the UI.

   It turns out this is also what makes the captures *work*. On
   unit42.paloaltonetworks.com the JS-enabled body is **0 characters** — bot
   protection blanks the page for a headless browser — against **25,909 with JS
   off**, because the script that does the blanking never runs. The security
   default and the functional default are the same default.
3. **A request filter on the browser context.** Only `document`, `stylesheet`,
   `image`, `font` are allowed through (plus `script`/`xhr`/`fetch` when JS is
   opted into), and **every subresource URL is re-run through `validate_url`** —
   so a page cannot reach the LAN through an `<img src>`. Refusals are counted
   and returned to the caller as `blocked_requests`.
4. **`chromium_sandbox=True`**, plus an ephemeral context, `service_workers`
   blocked, `accept_downloads=False`, `ignore_https_errors=False`. The escape
   hatch for containers that cannot grant user namespaces is the env var
   `CTIPARSOR_CAPTURE_UNSANDBOXED`, which logs a warning naming the consequence.

Error codes separate policy from failure without ever inspecting an exception
message: `validate_url` is called first and its `CaptureError` is a **400**;
anything raised by the capture itself is a **502**; a missing Playwright is a
**503**; the wall-clock deadline is a **504**.

### The capture is synchronous, and renders to a staging name

The endpoint blocks for up to 45 s. `asyncio` cannot cancel the thread the
capture runs in, so on deadline the render is still going and will finish
writing whatever path it was given. It is therefore given `{job_id}.pdf.part`
and promoted with `Path.replace` only on success — a timed-out capture cannot
leave a half-rendered PDF at the name the pipeline reads.

### Playwright is an optional dependency

`requirements-optional.txt`, not `requirements.txt`. Absent, `/api/ingest/url`
answers 503 with text telling the analyst to paste the report instead, and the
File and Paste tabs are unaffected.

## Options considered

| option | verdict |
|---|---|
| Fetch with `httpx`, store `.html` | **rejected.** 403 from a major vendor blog, and no main-content extraction. |
| Ditto + vendor `trafilatura`/`readability` | **rejected.** Adds a content-extraction dependency and still gets the 403. |
| Headless Chromium → PDF, ingest the PDF | **rejected on measurement.** 99.6% of characters, 72.2% of observables. The renderer is right; reading the report back out of its own printout is not. |
| Chromium → **ingest the DOM text, keep the PDF for display** | **chosen.** Recovers 9 of 12 hashes on the COLDRIVER report. The cost is that the analyst reviews a PDF whose text layer differs slightly from what the extractor read, so a hash entity may not highlight in the archive — a known and acceptable degradation, and an honest signal that the PDF mangled it. |
| Capture inside the worker subprocess, job status `fetching` | **deferred.** Better UX (no 45 s blocking request) at the cost of teaching `worker.py` about URLs. The UI shows a "Capturing page…" spinner meanwhile. |

## Consequences

**Easier.** A URL or an excerpt becomes a job in one action. All three sources
share one surface and one TLP/PAP control — first `IngestPanel.tsx`, then the
`NewReportModal.tsx` described below — and the Dashboard loses the upload state
it used to own.

**The three-tab panel became one modal, and markings became a gate.** A design
pass replaced the inline panel with a `New report` modal: one field detects
whether it was given prose, a URL, or a dropped file, so the tab strip
disappears along with the click it cost before the most common action. (Its handoff
bundle sits in `docs/design/`, which this repo gitignores — handoffs are
inputs, and this one carries generated build output. What it decided is
recorded here instead, which is the point of this file.)

The consequential part is not the layout. **TLP and PAP previously defaulted to
`AMBER`** — every job created before this pass carried a marking nobody chose.
They now start `null` and gate submission: the button reads "Set TLP & PAP to
continue" and stays disabled until both are picked. What lands in the bundle's
`object_marking_refs` is now always a decision, never a default.

Markings also reset every time the modal opens. The handoff specified a reset on
success only, but its own interaction table says a fresh modal has markings
unset — and the two cannot both hold after a Cancel, which would reopen with the
submit button already armed. The stricter reading wins here for the same reason
the gate exists: a level inherited from a cancelled job is exactly the silent
mis-marking this change is meant to remove. The pasted text is *not* reset, so
an accidental Escape cannot destroy a long paste.

**The panel needed a second surface.** A dashboard panel that is the right size
for a drop zone is the wrong size for pasting a report: measured at 1280×620,
the inline textarea is 180 px and the submit button falls 34 px below the fold,
with TLP/PAP 88 px below that. Rather than let the panel grow — it shares the
page with the kanban — the Paste tab gained an **Expand** button opening a modal
composer that fills the viewport (363 px of textarea on the same window) and
carries its own TLP/PAP and submit controls. State is shared with the inline
tab, so opening or closing it never loses what was typed.

**Harder — and the honest list:**

- **A job now owns two files instead of one.** `_delete_job_files` already globs
  `{job_id}.*` so cleanup was free, but any future code that assumes one
  artefact per job is wrong. `/jobs/{id}/source` was one such place.
- **The archive and the extracted text can disagree.** That is the trade taken
  knowingly above: entity highlighting in the PDF viewer matches by string, and
  a hash the PDF fragmented will not highlight there.
- **The harness measured the wrong thing first, and said so confidently.** Its
  original verdict came from character retention and printed "PDF round-trip is
  faithful" over a page that had lost 75% of its hashes. Two defects behind it,
  both in the spec rather than the implementation: the verdict keyed on the
  wrong ratio, and the DOM reference was read with JavaScript *enabled* while
  the capture ran with it disabled — which silently scored both Unit 42 rows at
  0% retention. The verdict is now driven by observable survival, and the
  reference matches the capture's conditions.
- **The installer grew a step that needs root.** `playwright install chromium`
  succeeds without the system libraries and Chromium then dies at launch with an
  opaque linker error. `setup.sh` therefore ends its capture section with a real
  launch smoke test, and `make check` reports the stage — because "the package
  imports" proves nothing here.
- **A rendered PDF is a fixed viewport.** Content behind tabs, accordions, or
  infinite scroll is not in the capture. With JS off, so is anything
  client-rendered; that is the trade the opt-in exists for.
- **Bot protection still wins sometimes.** Chromium gets past a User-Agent check
  but not an interactive challenge. The 502 says so, and the Paste tab is the
  answer.
- **The API must not run as root.** Forcing `chromium_sandbox=True` has a
  deployment consequence that only showed up at runtime: Chromium refuses to run
  as root *with* the sandbox, so a server started from a `sudo su` shell answers
  503 on every capture. Dropping root is the fix; `CTIPARSOR_CAPTURE_UNSANDBOXED`
  exists for containers that cannot grant user namespaces and logs a warning per
  capture. Verified as uid 1000: a sandboxed capture of a Unit 42 report returns
  2.4 MB and 25,909 characters in 6.8 s with no escape hatch set.
- **Browsers are installed per-account.** `playwright install` writes under the
  invoking user's HOME, so an install done as root is invisible to an API running
  as a user, and vice versa. This produced a 500 with an ASGI traceback until the
  launch was guarded; it now raises `CaptureUnavailable` → 503, and the message
  distinguishes the three causes (root+sandbox, missing browser, missing library)
  and always carries the underlying Playwright error.
- **A new attack surface exists that did not before.** The server now fetches
  attacker-chosen URLs. The four boundaries above are the mitigation; the
  sandbox default found during this work is the reason to distrust the library's
  defaults rather than the intent of the flags.

## Follow-ups

1. Move the capture into the worker so the request returns immediately and the
   existing SSE progress modal covers the fetch.
2. Sweep stale `uploads/*.pdf.part` on startup.
3. Re-run the harness against a page whose IOCs are *not* in a table, to see
   whether the 72.2% figure is dominated by that one layout or is general.
4. Consider offering a JS retry from the UI when a capture is refused for
   rendering nothing — the error already names the cause, but the analyst has to
   tick the box and resubmit by hand.
