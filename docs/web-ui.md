# Web UI

A tour of the analyst interface, page by page. Screenshots are in the
[README](../README.md#screenshots).

**Browsers.** The UI's styles are built with Tailwind CSS 4, which needs
Chrome or Edge 111, Safari 16.4 or Firefox 128, or later (all from 2023–2024).
An older browser skips the parts of the stylesheet it does not support
(cascade layers, among them Tailwind's reset), and the pages look off.

## Workflow

```
Ingest — one of three (ADR-0029)
  │   File   drag-and-drop or file picker (PDF/DOCX/HTML/TXT/MD, 50 MB)
  │   Paste  plain text, Markdown, or HTML source — markup is stripped
  │   URL    headless Chromium renders the page server-side; the PDF is
  │          archived for review, its DOM text is what gets ingested
  │
  ▼
Processing  ─── Real-time 5-stage progress bar (SSE)
  │               Stage 1: Ingestion   → chars + chunks
  │               Stage 2: Extraction  → IoCs + NER counts
  │               Stage 3: LLM         → chunk N/total (live)
  │               Stage 4: STIX mapping (+ 4b graph completion)
  │               Stage 5: Validation
  ▼
For Review  ──►  Reviewing  ──►  Completed
  (Kanban)       (Review page)   (Graph + Download)
```

A report whose bundle Stage 5 refuses (the STIX 2.1 JSON schemas, ADR-0084) does not reach Completed, and its bundle is not served. Finalize, the Graph page and the download show the refusal and its first errors, where they used to show a bundle that was not built yet. A rebuild that passes clears it.

## Review page

Four view modes toggled at the top of the document pane:

| Mode | Content |
|---|---|
| **Text** | Annotated source text — entity occurrences highlighted by type, click to focus in marginalia, keyboard shortcuts |
| **Preview** | Rendered markdown — VS Code-like typography (headings, tables, code blocks, task lists). Works on all file types; most useful for `.md` reports |
| **Source** | The original file, rendered inline for every supported format: **PDF** (pdf.js pages), **HTML/HTM** (sandboxed iframe), **TXT/MD** (raw source). PDF and TXT/MD carry the same entity highlights as the Text view and support click-to-locate; **DOCX** falls back to a download link (no browser-native rendering) |
| **Detections** | Sigma rules **ranked by this report's own technical content** — hashes, domains, binaries, paths, registry keys, CVEs — and by platform, each with the evidence behind its rank (ADR-0014) |

**Entity interaction:**
- Entities highlighted inline with type-colour coding
- Click a mark in the text → scroll + focus in the marginalia panel
- Click a card in the marginalia → scroll + highlight in the text
- Entities not found verbatim in text (e.g. LLM-paraphrased campaign names) → brief "not found" hint displayed

**Keyboard shortcuts:**

| Key | Action |
|---|---|
| `J` / `↓` | Next pending entity |
| `K` / `↑` | Previous pending entity |
| `A` | Accept focused entity |
| `R` | Reject focused entity |
| `U` | Reset to pending |
| `G` | Open STIX graph |
| `C` | Open the detection-coverage page |
| `F` | Finalize the bundle — once the review is completed, download it |
| `?` | Show shortcut help |
| `Esc` | Close the help, the drawer, and clear the focus |

**Entity states:**
- **Pending** (default) — included in bundle
- **Accepted** ✓ — explicitly confirmed, included
- **Rejected** ✗ — excluded from bundle

**Held for review** (ADR-0082): a relationship Stage 3d could not decide, or a technique Stage 3f's selection could not, is stored pending with a `held` chip whose tooltip says why (the verification call failed, the answer said nothing about it, its quote is not in the text…). Unlike other pending rows it is **not** in the bundle until you accept it, and only on its own card: accepting a type, a group or a selection skips it, and auto-accept never takes it. Rejecting a group may include it.

**Auto-accept:** when a job finishes, the worker accepts its entities with confidence ≥ 90% and records them as `auto_policy` (ADR-0058); opening the page writes nothing. A banner shows the count with an Undo option, and each card carries an `auto` chip. About one in ten of those entities (`REVIEW_CONTROL_SAMPLE_RATE`, default 0.10) is left pending with a `confirm` chip: your verdict on it measures how often auto-accept is right (`GET /api/thresholds` → `auto_accept_audit`).

**Drag-to-relate:** Drag from one entity mark to another → opens relationship creator pre-filled with source and target.

**Shift-click:** Shift-click two entity marks → opens relationship creator.

**Text selection:** Select text spanning two entities → opens relationship creator with the selected text as evidence.

## Enrich mode (ADR-0090)

The New report modal offers a second pipeline only when the server runs with
`STIX_ENRICHMENT_ENABLED` on (`GET /api/baselines/status`; off by default):

- **Full extraction** (the default): CTIParsor builds the bundle from the report alone.
- **Enrich an existing STIX 2.1 bundle**: CTIParsor merges what the report adds
  into a bundle you already hold. What the bundle holds is shown, not duplicated.

**In the modal.** Add the bundle as a `.json` file, by drop or by browsing. The
modal reads it at once through `POST /api/baselines/inspect`, which stores
nothing, and shows what the job would keep: the objects by type, the objects
outside the report's scope, the dangling references, the excluded objects with
their reason, and the warnings. The preview does not run the STIX JSON schemas:
they run when the job starts, and an object they refuse is left out then. A
bundle with several reports asks which one to enrich. The bundle's minimum TLP
and PAP are preselected, and a weaker level is disabled, because a lower marking
would weaken what the bundle already says. Switching back to full extraction
removes the bundle, and a level the bundle set is unset again.

**On the Review page** (enrich jobs only):

- The ribbon's enrich line counts entities and relationships against the bundle:
  in STIX (the extracted rows that match a bundle object, plus the bundle objects
  found in the text), STIX only, and + New.
- The filter "Any source · + New · In STIX · STIX only" sits in the margin notes
  and in the relationships rail. A row you add by hand counts as + New.
- Badges: `+ new` (CTIParsor adds it), `in STIX` (the bundle already holds it),
  `STIX only` (from the bundle, not in the report text).
- A row from the bundle can be accepted or rejected. Its type, and for a
  relationship its verb and dates, are read-only: the server refuses an edit
  to them with 409, and the change belongs in the source bundle. The hover
  chip's "Change type" is off for them too.
- A banner says when the bundle already covers everything CTIParsor found.

**On the Graph page** (bundle view of an enrich job; the **Against your bundle**
button appears only there):

- An object your bundle supplied has a thin outer ring. The origin legend
  counts them as "From your STIX bundle" and "Added by CTIParsor".
- A relationship from your bundle is a link kind, "From your STIX bundle".
- **Against your bundle** opens a panel with four groups:
  - **Added by CTIParsor**: the objects and links that ship and were not in your
    bundle.
  - **Matched to your objects**: a CTIParsor object, and the object of yours that
    ships in its place.
  - **Left out of your bundle**: a rejected object, or an object whose reference
    left, named by that object; the report when none of its references ships, so
    it is not re-issued; the intake exclusions, with "and N more" past the listed
    ones. A note says that a rejection removes the object from this bundle only,
    because OpenCTI's upsert never removes a reference. The Differences panel
    lists the same objects with their reasons.
  - **Your report, re-issued**: the Report under its own id, with the references
    it adds and removes.
- A row imported from your bundle is joined to its object by STIX id, so a
  freshly built enrich bundle shows no ghost and no "out of date" for it.
- A relationship imported from your bundle cannot be deleted here: its Delete
  button is disabled and says to reject it in the review. If the server refuses a
  delete, the editor shows "Not deleted:" with the reason.

**On the dashboard**: an enrich job's card carries an **Enrich** badge.

**Dropping files**: a report and a STIX bundle dropped together, on the dashboard
or in the New report modal, open the modal in enrich mode with both. The bundle
is told apart by its content: a `.json` object that says `"type": "bundle"` in
its first 64 KB or its last 4 KB (UTF-8, or UTF-16 with its byte-order mark);
the modal's size limit (the `max_bytes` the status reports) then applies. A
bundle alone keeps the pasted text, and a chosen report stays. The modal names
every `.json` it does not use: one that is not a STIX bundle, and any bundle
after the first (one per job). With `STIX_ENRICHMENT_ENABLED` off, the modal
says the bundle was not used; when the server's status cannot be read, it says
that instead.

## Graph page

Custom **d3-force SVG graph** (not the OASIS stix-visualization iframe):

| Feature | Details |
|---|---|
| **Node icons** | Official OASIS STIX 2.1 icons (White/normal/SVG) for all SDO types; lucide-react stroke paths for SCO types (IPv4, Domain, URL, …) |
| **Layout modes** | Force (physics simulation) · Hierarchical (tier-based) · Radial (BFS from root) |
| **Type legend** | Click to toggle visibility · Double-click to solo a type |
| **Node search** | Search by name or type, jump-animate to result |
| **Relationship editor** | Accept / Reject / Reset / Delete relationships in the side panel; Add new relationships with evidence text. A relationship from your STIX bundle cannot be deleted (Delete is disabled, with the reason) |
| **Origin legend** (enrich jobs, bundle view) | Counts the objects from your STIX bundle (thin outer ring) and those added by CTIParsor |
| **Against your bundle** (enrich jobs, bundle view) | Panel: added by CTIParsor, matched to your objects, left out of your bundle, your report re-issued (see Enrich mode) |
| **Labels** | Toggle all labels; strategic nodes (tier 0–1) always show labels |
| **Fit button** | Animate to fit all nodes in viewport |
| **Download** | Download STIX bundle directly from the graph page (a pending rebuild runs first) |
| **Bundle view** (default) | The bundle that ships (ADR-0061): links coloured by why they exist — from the report, from your STIX bundle, Stage 4 mapping, policy rule, ATT&CK reference, inferred — rows Stage 4 rewrote in amber, rows and entities it dropped drawn as hollow dashed ghosts with the reason, and a **Differences** panel listing everything dropped, rewritten, merged, or not yet rebuilt |
| **Review view** | The stored rows the analyst edits, each marked with its fate in the bundle; a link's panel jumps to it in the bundle view |
| **Auto-rebuild** | Every link edit schedules a quick finalize (4 s debounce), as on the Review page |

## Policy page

Reached from the **Policy** entry in the sidebar (`/policy`) — a global setting,
not a per-report one. It edits the relationship policy the pipeline applies at
Stage 4: which `source → verb → target` triples are **pinned** (the analyst
states the link, and the pin always wins over anything inference produces) and
which are left on **auto**.

- **Enforce my model / Full auto** — the `global` switch. On auto the rule list
  is ignored entirely.
- **Pinned links** — the rule table: add, filter by type or verb, enable or
  disable each triple.
- **Pin budget** — how `max_pinned_edges` is split between rules
  (`fair-share` by default, `sequential` for the legacy behaviour).
- **Evidence gate** — the `pin_evidence` window: how many sentences apart two
  objects may be and still be pinned together.
- **Completion** — the Stage 4b toggles (`alias`, `reference`, `transitive`,
  `long_distance`, `fuzzy_alias`, `semantic_alias`, `max_new_edges`).

Every field maps onto the payload documented under
[Relationship policy](api.md#relationship-policy); the page is a typed editor over it,
and the last run's per-rule accounting is read back from
`/api/relationship-policy/last-run`.

## Coverage page

Per-report **detection-coverage matrix** (`/coverage/:jobId`). The report's
extracted ATT&CK techniques are laid out in ATT&CK-tactic columns and coloured by
a **readiness score** (not lab validation):

| Score | Meaning |
|---|---|
| 3 — Corroborated | a rule tagged with the technique exists in **≥ 2** corpora |
| 2 — Covered | a rule tagged with the technique exists in **1** corpus |
| 1 — Telemetry only | reserved for an ATT&CK data-source mapping with no rule; nothing computes it yet, so no cell shows it |
| 0 — No coverage | technique extracted, no rule |

The score follows the rules' ATT&CK tags, but the rules listed under each
technique are only those that hold a value the report contains (ADR-0030). A
cell can therefore read *Covered* and list no rule: a rule carries the tag,
none matches this report. Rules promoted from the Review page's **Detections**
tab join the selection in a group of their own. A banner makes the
"readiness ≠ validation" distinction explicit.

Below the matrix, the selection table and the export panel build the ZIP of
rules to deploy. The artifact view of ADR-0025 — coverage scored per hash,
domain or path rather than per technique — is not on this page; it is served by
`GET /api/jobs/{id}/coverage/artifacts`. Walkthrough:
[docs/detection-coverage.md](detection-coverage.md).

## Settings page

Manage **detection-rule corpora** (`/settings`): list configured Sigma repos with
live rule counts, add a repo (written to the gitignored local overlay), remove /
disable one, and **Rebuild index** to re-ingest the local clones. See
[Detection coverage](detection-coverage.md).
