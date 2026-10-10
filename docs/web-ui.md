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

## Graph page

Custom **d3-force SVG graph** (not the OASIS stix-visualization iframe):

| Feature | Details |
|---|---|
| **Node icons** | Official OASIS STIX 2.1 icons (White/normal/SVG) for all SDO types; lucide-react stroke paths for SCO types (IPv4, Domain, URL, …) |
| **Layout modes** | Force (physics simulation) · Hierarchical (tier-based) · Radial (BFS from root) |
| **Type legend** | Click to toggle visibility · Double-click to solo a type |
| **Node search** | Search by name or type, jump-animate to result |
| **Relationship editor** | Accept / Reject / Reset / Delete relationships in the side panel; Add new relationships with evidence text |
| **Labels** | Toggle all labels; strategic nodes (tier 0–1) always show labels |
| **Fit button** | Animate to fit all nodes in viewport |
| **Download** | Download STIX bundle directly from the graph page (a pending rebuild runs first) |
| **Bundle view** (default) | The bundle that ships (ADR-0061): links coloured by why they exist — from the report, Stage 4 mapping, policy rule, ATT&CK reference, inferred — rows Stage 4 rewrote in amber, rows and entities it dropped drawn as hollow dashed ghosts with the reason, and a **Differences** panel listing everything dropped, rewritten, merged, or not yet rebuilt |
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
