# Handoff: Dashboard ingest redesign

## Overview

The dashboard's report-ingestion UI is being restructured. Today
`src/components/IngestPanel.tsx` renders a permanent three-tab card (File /
Paste / URL) inline on `src/pages/Dashboard.tsx`, between the stat ribbon and
the kanban board. It pushes the board below the fold, forces a tab click before
the most common action (dropping a file), buries the TLP/PAP selectors in a
footer where they are easy to miss, and gives pasted text a cramped 9-row box
with a separate "expand" composer as a workaround.

The redesign collapses all three inputs into one modal behind a **New report**
button, replaces the tab strip with a single self-detecting input, promotes
TLP/PAP to a required gate on job creation, and tightens the kanban cards.

This is a **modification to an existing codebase**, not a greenfield build. The
implementation target is the React + TypeScript app under `frontend/`.

## About the design files

`Dashboard.dc.html` in this folder is a **design reference created in HTML** — a
working prototype of the intended look and behavior, with seeded fake jobs. It
is not production code and should not be copied into the app. Open it in a
browser, exercise it (click New report, paste text, paste a URL, drop a file on
the page, try to submit without markings), then recreate the design in the app's
own environment using its established patterns.

Prototype conventions that must be translated, not copied:
- It uses hand-inlined SVG paths for icons. The app uses **lucide-react** — use
  the real components (`Plus`, `X`, `GitGraph`, `ShieldCheck`, `Download`,
  `Trash2`, `Loader2`, `AlertTriangle`, `Upload`, `Link2`, `ClipboardPaste`).
- It redeclares the `:root` token block so it can render standalone. The app
  already has these tokens in `src/index.css` — do not duplicate them.
- Its accent/primary buttons are inline-styled. The app has `.btn-primary` and
  `.btn-ghost` — use those.
- Its job data is seeded in the component. The app uses react-query
  (`fetchJobs`, `refetchInterval: 3000`) — keep that.

## Fidelity

**High-fidelity.** Colors, type, spacing, radii and states below are final and
come from the app's own token set. Match them. Where a value is expressed as a
`var(--*)` token, use the token, never the resolved hex.

---

## Screens / views

### 1. Dashboard page — `src/pages/Dashboard.tsx`

Purpose: triage extracted intelligence; entry point for new ingestion.

Layout (unchanged structure, two removals and two additions):

```
topbar         border-bottom 1px var(--rule), padding 9px 26px, bg var(--bg-elev)
               left:  "Dashboard" / "Reports" breadcrumb
               right: avatar only          <-- CHANGED (count + button moved out)
body           flex column, gap 20, padding 24px 30px 60px, overflow-y auto
  page head    h1 "Threat reports" + sub, and right-aligned drop hint  <-- NEW hint
  stat ribbon  unchanged (5 tiles)
  action row   [New report ⌘N]  "N reports"       <-- NEW (was in topbar)
  activity     unchanged grid, restyled cards
  kanban       3 columns, denser cards
```

**Removals**
- `<IngestPanel onJobCreated={...} />` and its import.
- The `{jobs.length} reports` span and any ingest affordance from the topbar's
  right cluster — the topbar right side keeps only the 28px avatar circle
  (`border-radius: 50%`, `background: var(--accent-soft)`, `color: var(--accent)`,
  `font-size: 11px`, `font-weight: 700`).

**Additions**

*Page-head drop hint* — right-aligned in the same flex row as the h1, so the
page-wide drop target is discoverable:
- 14×9px box, `border: 1px dashed var(--ink-4)`, `border-radius: 2px`
- text "Drop a PDF anywhere on this page to start", 11.5px, `var(--ink-4)`, gap 6

*Action row* — its own flex row, `gap: 12`, `align-items: center`, placed after
the stat ribbon and before the Activity strip. Must render whether or not the
Activity strip is present.
- **New report** button: `.btn-primary`, `padding: 7px 12px 7px 11px`,
  `font-size: 12.5px`, `font-weight: 600`, `border-radius: 7px`, `gap: 8`,
  `letter-spacing: .01em`; hover `filter: brightness(.93)`.
  Contents in order: `<Plus size={14} strokeWidth={2.4} />`, the label
  "New report", then a ⌘N badge — `font-family: 'JetBrains Mono'`, 10px,
  `padding: 1px 4px`, `border-radius: 4px`,
  `background: rgba(255,255,255,.16)`, `border: 1px solid rgba(255,255,255,.22)`.
  Render the badge label as `⌘N` on Mac and `Ctrl+N` elsewhere
  (`navigator.platform`), or drop the badge on touch.
- Report count: `{jobs.length + activityJobs.length} reports`, 11px,
  `font-family: 'JetBrains Mono'`, `color: var(--ink-3)`.

*Page-level drop target* — `onDragOver` / `onDragLeave` / `onDrop` on the
page root:
- `onDragOver`: `preventDefault()`, set `pageDrag = true`
- `onDragLeave`: `preventDefault()`; only clear when `e.relatedTarget === null`
  (otherwise it flickers across child boundaries)
- `onDrop`: `preventDefault()`, take `e.dataTransfer.files[0]`, open the modal
  with that file attached, clear `pageDrag`
- While `pageDrag`: a fixed full-screen overlay, `z-index: 80`,
  `background: color-mix(in oklab, var(--accent) 12%, rgba(250,247,241,.86))`,
  `backdrop-filter: blur(2px)`, `pointer-events: none`, fade-in 120ms.
  Centered card: `border: 2px dashed var(--accent)`, `border-radius: 16px`,
  `padding: 36px 56px`, `background: var(--bg-elev)`,
  `box-shadow: var(--shadow-pop)`; headline "Drop to start a report" in
  `'Source Serif 4'` 22px/600; sub "PDF · DOCX · HTML · TXT · MD" in
  `'JetBrains Mono'` 12px `var(--ink-3)`.

*Keyboard*: a `keydown` listener on `document` — `(metaKey || ctrlKey) && key === 'n'`
opens the modal (`preventDefault()`); `Escape` closes the modal and clears
`pageDrag`. Remove the listener on unmount.

---

### 2. New report modal — new file `src/components/NewReportModal.tsx`

Replaces `IngestPanel.tsx` entirely (delete that file, and its `IngestTab` type).
Keeps its three mutations and the `onJobCreated(jobId, filename)` prop contract
so `ProgressModal` wiring on the Dashboard is untouched.

**Shell**
- Backdrop: `position: fixed; inset: 0`, `z-index: 90`,
  `background: rgba(20,12,4,.5)`, `backdrop-filter: blur(4px)`, centered flex,
  `padding: 28px`; fade-in 120ms. Closes on mousedown when
  `e.target === e.currentTarget` only.
- Dialog: `width: min(940px, 100%)`, `height: min(700px, 100%)`, flex column,
  `background: var(--bg-elev)`, `border: 1px solid var(--rule)`,
  `border-radius: 16px`, `box-shadow: var(--shadow-pop)`, `overflow: hidden`;
  enter animation `translateY(8px) → 0` + opacity, 160ms ease-out.
  `role="dialog" aria-modal="true" aria-label="New report"`.
  The generous height is the point — it is what makes pasting a full report
  comfortable and lets the old expand-composer be deleted.

**Header** — `padding: 14px 18px 12px`, `border-bottom: 1px solid var(--rule)`
- Title "New report": `'Source Serif 4'` 18px/600, `color: var(--ink)`
- Sub: "Drop a file, paste the text, or paste a link — one field takes all three.",
  11.5px `var(--ink-3)`, `margin-top: 3px`
- Close: 26×26, `border: 1px solid var(--rule)`, `border-radius: 6px`,
  `<X size={14} />`, `color: var(--ink-3)`; hover `background: var(--bg-soft)`,
  `color: var(--ink)`

**Body** — `flex: 1; min-height: 0`, `padding: 14px 18px`, flex column, `gap: 10`

*Source row* (`display: flex; align-items: center; gap: 8`):
- Label "Source": 10px/600, `letter-spacing: .1em`, uppercase, `var(--ink-3)`
- Detected-mode chip: `'JetBrains Mono'` 10.5px, `padding: 2px 8px`,
  `border-radius: 20px`. Empty → label "nothing yet",
  `color: var(--ink-3)`, `background: var(--bg-soft)`,
  `border: 1px solid var(--rule-soft)`. Any detected mode → label
  "file upload" | "pasted text" | "url capture", `color: var(--accent)`,
  `background: var(--accent-soft)`,
  `border: 1px solid color-mix(in oklab, var(--accent) 30%, transparent)`.
- Spacer, then **Browse files…** — `.btn-ghost`, `padding: 4px 10px`, 11px;
  clicks a hidden `<input type="file" accept=".pdf,.docx,.html,.htm,.txt,.md">`
  (reset `e.target.value = ''` after each pick so re-picking the same file fires).

*Mode detection* — one derived value, no tabs, no user toggle:
```ts
const trimmed = value.trim()
const mode: 'empty' | 'file' | 'url' | 'text' =
  file                                    ? 'file'
  : !trimmed                              ? 'empty'
  : /^(https?:\/\/|www\.)\S+$/i.test(trimmed) ? 'url'
  :                                         'text'
```
Attaching a file clears `value`; "Remove" on the file card clears `file` and
returns to the composer.

*File state* (`mode === 'file'`) — the composer is replaced by a centered card
in a `flex: 1` well (`border: 1px solid var(--rule)`, `border-radius: 12px`,
`background: var(--bg-soft)`):
- Card: `background: var(--bg-elev)`, `border: 1px solid var(--rule)`,
  `border-radius: 12px`, `padding: 16px 20px`, `gap: 14`,
  `box-shadow: var(--shadow-card)`
- Page glyph: 38×46, `border: 1px solid var(--rule)`, `border-radius: 4px`,
  `background: var(--bg)`, extension in `'JetBrains Mono'` 9px `var(--ink-3)`
  bottom-centered
- Name: 13.5px/600 `var(--ink)`, `max-width: 420px`, ellipsis
- Meta: `(size / 1048576).toFixed(2) + ' MB · ' + EXT`, `'JetBrains Mono'` 11px
  `var(--ink-3)`
- **Remove**: `.btn-ghost` 11px; hover `color`/`border-color: var(--no)`

*Composer state* (`mode !== 'file'`) — `flex: 1; min-height: 0`, column, gap 8:
- Title input, only when `mode === 'text'`: full width, `padding: 8px 10px`,
  `border-radius: 8px`, `border: 1px solid var(--rule)`,
  `background: var(--bg)`, 13px; placeholder
  "Title (optional) — defaults to the first line"
- Textarea: `flex: 1; min-height: 0; resize: none`, `padding: 12px 14px`,
  `border-radius: 12px`, `border: 1px solid var(--rule)`,
  `background: var(--bg)`, `'JetBrains Mono'` 12.5px, `line-height: 1.6`.
  Placeholder: "Paste the report text here, or paste a URL — plain text,
  Markdown, or a link. You can also drop a file anywhere in this window."
  Autofocus on open.
- Status line (`min-height: 20px`, `'JetBrains Mono'` 11px):
  empty → "nothing pasted yet" `var(--ink-4)`;
  url → "link detected — no typing needed, just paste" `var(--ink-4)`;
  text under 20 trimmed chars → "need at least 20 characters" `var(--warn)`;
  otherwise → `${chars.toLocaleString()} chars` `var(--ink-4)`.
- URL options, only when `mode === 'url'` — a pill toggle replacing the old
  checkbox: `border-radius: 20px`, `padding: 3px 10px 3px 4px`, 11px,
  `border: 1px solid var(--rule)` (→ `var(--warn)` when on); track 26×15
  `border-radius: 20px`, `background: var(--rule)` → `var(--warn)`; knob 11×11
  circle `background: var(--bg-elev)`, `left: 2px` → `13px`, both transition
  140ms ease. Label "Run page JavaScript". Trailing hint 10.5px `var(--ink-4)`:
  off → "off by default"; on → "the page will execute scripts — use only when
  it renders nothing otherwise".

**Markings band** — the core behavior change. `padding: 12px 18px`,
`border-top: 1px solid var(--rule)`, flex column, `gap: 9`.
- Band background is a live nudge: unset →
  `color-mix(in oklab, var(--warn) 6%, var(--bg-soft))`; both set →
  `var(--bg-elev)`.
- Header row: "MARKINGS" 10px/600 `letter-spacing: .1em` uppercase
  `var(--ink-3)`; state chip `'JetBrains Mono'` 10px `padding: 1px 6px`
  `border-radius: 4px` — unset: "required", `color: var(--warn)`,
  `background: color-mix(in oklab, var(--warn) 15%, transparent)`; set: "set",
  `color: var(--ok)`, `background: color-mix(in oklab, var(--ok) 12%, transparent)`.
  Right-aligned note "Applied to every object in the bundle", 10.5px
  `var(--ink-4)`.
- Two rows, TLP then PAP: row label 11px/600 `var(--ink-2)` `width: 26px`, then
  four pills `gap: 5` in the order **WHITE · GREEN · AMBER · RED** (from
  `MARKING_LEVELS` in `src/types/index.ts`, which is declared RED-first —
  reverse it for display, do not reorder the constant).
- Pill: `'JetBrains Mono'` 10.5px/600, `letter-spacing: .04em`,
  `padding: 4px 11px`, `border-radius: 6px`, transition 120ms.
  Unselected: `background: var(--bg)`, `color: var(--ink-3)`,
  `border: 1px solid var(--rule)`.
  Selected: `background: color-mix(in oklab, TONE 16%, var(--bg-elev))`,
  `color: TONE`, `border: 1px solid TONE` — where TONE is
  WHITE `var(--ink-3)`, GREEN `var(--ok)`, AMBER `var(--warn)`, RED `var(--no)`.
  Hover `filter: brightness(.97)`.
- Both default to `null`. **Never pre-select AMBER.** Radiogroup semantics:
  `role="radiogroup"` on each row with an `aria-label`, `aria-checked` per pill.

**Footer** — `padding: 11px 18px`, `border-top: 1px solid var(--rule)`,
`background: var(--bg-elev)`, flex row `gap: 12`
- Left summary, `'JetBrains Mono'` 11px `var(--ink-3)`, `flex: 1`:
  empty → "awaiting a file, some text, or a link";
  file → "will be parsed server-side, then queued for extraction";
  url → "page rendered to PDF, scripts blocked" / "…with scripts enabled";
  text → `${chars.toLocaleString()} chars → stored as a reviewable source`.
- **Cancel**: `.btn-ghost`, `padding: 7px 13px`, 12px, `border-radius: 7px`
- **Submit**: `.btn-primary`, `padding: 7px 15px`, 12.5px, `border-radius: 7px`.
  Label is "Create job" — except when the source is ready but markings are not,
  where it reads "Set TLP & PAP to continue". Disabled unless
  `sourceReady && tlp && pap`; disabled style `opacity: .45`,
  `cursor: not-allowed`.
  `sourceReady` = file present, OR mode url, OR mode text with ≥20 trimmed chars.

**Submit dispatch** — reuse the existing react-query mutations verbatim:
```
file  → uploadFile(file, { tlpLevel: tlp, papLevel: pap })
text  → ingestText({ text: value, title: title.trim() || null,
                     tlp_level: tlp, pap_level: pap })
url   → ingestUrl({ url: value.trim(), enable_js: enableJs,
                    tlp_level: tlp, pap_level: pap })
```
On success: `qc.invalidateQueries({ queryKey: ['jobs'] })`, reset all local state
(including `tlp`/`pap` back to `null`), close the modal, call
`onJobCreated(d.job_id, d.filename)`. On error: keep the modal open, keep the
input, show the existing error banner (`errorDetail(e)`, `AlertTriangle`,
`var(--no)` at 10% background / 35% border) directly under the header.
Disable the marking pills and both footer buttons while any mutation is pending;
show `<Loader2 className="animate-spin" size={12} />` in the submit button.

---

### 3. Kanban card density — `KanbanCard` in `src/pages/Dashboard.tsx`

The current card is ~6 stacked rows: icon+title, meta, footer (time + status
pill), action row. The status pill is redundant with the column it sits in, so
it becomes a dot and one row disappears.

Target, top to bottom:
- Card: `background: var(--bg)`, `border: 1px solid var(--rule-soft)`,
  `border-radius: 9px`, `padding: 9px 10px`, `gap: 6`, flex column,
  `cursor: pointer`, transition `border-color .12s, box-shadow .12s`.
  Hover `border-color: var(--rule)`. Selected `border-color: var(--accent)` +
  `box-shadow: 0 0 0 2px color-mix(in oklab, var(--accent) 20%, transparent)`.
- Title row: 6px status dot (`border-radius: 50%`, `margin-top: 5px`,
  `flex-shrink: 0`; color = the column accent — for_review `var(--warn)`,
  reviewing `var(--accent)`, completed `var(--ok)`) + `<h3>` in
  `'Source Serif 4'` 14px/600, `line-height: 1.28`, 2-line clamp
  (`-webkit-line-clamp: 2`), `gap: 7`. The `FileText` icon is dropped — the dot
  carries the state and the title carries the identity.
- Meta row, indented `padding-left: 13px` to align under the title:
  `'JetBrains Mono'` 10px `var(--ink-3)`, `gap: 5`, **`flex-wrap: nowrap`** and
  `overflow: hidden`, each span `white-space: nowrap`. Content:
  `${ents} ent · ${rels} rel` + `·` + relative time (`var(--ink-4)`).
  Nothing else goes in this row — at a 250px column the body is ~232px and a
  fourth item wraps to a second line, which costs the density this pass is for.
  Keep the existing `relTime()` helper; keep "awaiting extraction" when
  `entity_count` is undefined.
- Action row, same `padding-left: 13px`, `gap: 3`, `stopPropagation()` on the
  row so buttons don't toggle selection:
  - Primary text button — "Analyse" (for_review) / "Resume" (reviewing) /
    "Open" (completed): `background: transparent`,
    `border: 1px solid var(--rule)`, `color: var(--accent)`, 10.5px/600,
    `padding: 3px 8px`, `border-radius: 5px`; hover
    `background: var(--accent-soft)`, `border-color: var(--accent)`.
  - Completed only, three 22×22 icon buttons (`border: 1px solid var(--rule-soft)`,
    `border-radius: 5px`, `color: var(--ink-3)`, `size={12}` icons; hover
    `background: var(--bg-soft)`, `color: var(--ink)`): `GitGraph` (title
    "Graph"), `ShieldCheck` ("Coverage"), `Download` ("Download bundle").
    Every icon-only button needs a `title` and an `aria-label`.
  - Spacer.
  - TLP pill: `'JetBrains Mono'` 9.5px, `padding: 1px 4px`,
    `border-radius: 3px`, `letter-spacing: .03em`, `white-space: nowrap`,
    `color: TONE`, `border: 1px solid color-mix(in oklab, TONE 30%, var(--rule-soft))`
    (same TONE map as the marking pills). Source: `job.tlp_level`; omit the pill
    when the field is null.
  - `Trash2` 22×22, `border: 1px solid transparent`, `color: var(--ink-4)`;
    hover `color: var(--no)`,
    `border-color: color-mix(in oklab, var(--no) 30%, transparent)`.
- Column body `padding: 9`, `gap: 8` (was 11/11).

### 4. Activity card — same file

Only two changes; leave the data flow alone.
- Leading indicator distinguishes the two states, since in the warm theme
  `var(--accent)` and `var(--no)` are both reddish: processing →
  `<Loader2 size={14} className="animate-spin" />` in `var(--accent)`; failed →
  `<AlertTriangle size={14} />` in `var(--no)`.
- Add a 3px `border-radius: 2px` progress rail
  (`background: var(--rule-soft)`, fill `var(--accent)`) driven by the existing
  SSE stage percentage, and a small TLP chip on the second row
  (`'JetBrains Mono'` 10px `var(--ink-4)`,
  `border: 1px solid var(--rule-soft)`, `border-radius: 4px`, `padding: 1px 5px`).
  Card padding tightens to `10px 12px`, `gap: 6`. Failed card keeps
  `background: color-mix(in oklab, var(--no) 4%, var(--bg-elev))` and
  `border-color: color-mix(in oklab, var(--no) 35%, var(--rule))`.

---

## Interactions & behavior

| Trigger | Result |
|---|---|
| Click **New report** | Modal opens, textarea focused, markings unset |
| ⌘N / Ctrl+N | Same (`preventDefault`) |
| `Escape` | Modal closes, `pageDrag` clears |
| Backdrop mousedown | Closes only when the event target is the backdrop itself |
| Drag file over the page | Full-screen dashed overlay, 120ms fade |
| Drop file on the page | Modal opens with the file attached, overlay clears |
| Drop file on the modal | Same attach path |
| Paste prose in the textarea | Mode → text; title field appears; char counter |
| Paste a bare URL | Mode → url; JS toggle appears; counter switches copy |
| Type <20 chars | Counter turns `var(--warn)`; submit stays disabled |
| Pick a file, then Remove | Returns to the composer with previous text cleared |
| Submit with markings unset | Impossible — button disabled, label states why |
| Submit success | Modal closes, jobs query invalidated, ProgressModal opens |
| Submit failure | Modal stays open, input preserved, error banner |

Transitions: 120ms ease for color/border/background, 140ms for the toggle knob,
160ms ease-out for the modal enter, 120ms for overlay fades. No other motion.

Responsive: the modal is `min(940px, 100%)` × `min(700px, 100%)` with 28px
backdrop padding, so it degrades on narrow viewports without new breakpoints.
Under ~900px the marking rows should wrap (`flex-wrap: wrap`, `gap: 22`).

Accessibility: `role="dialog" aria-modal="true"`; focus moves to the textarea on
open and returns to **New report** on close; focus trapped inside the dialog;
marking rows are radiogroups; every icon-only button has `title` + `aria-label`.

## State management

New local state in `NewReportModal`:

| State | Type | Notes |
|---|---|---|
| `value` | `string` | textarea — text or URL |
| `title` | `string` | text mode only |
| `file` | `File \| null` | from drop or picker |
| `enableJs` | `boolean` | url mode, default `false` |
| `tlp` | `MarkingLevel \| null` | **starts null** |
| `pap` | `MarkingLevel \| null` | **starts null** |
| `error` | `string \| null` | from `errorDetail(e)` |

Derived, not stored: `mode`, `sourceReady`, `canSubmit`, char count, summary
string, submit label.

New in `Dashboard`: `modalOpen: boolean`, `pendingFile: File | null` (a file
dropped on the page, handed to the modal on open), `pageDrag: boolean`.
`activeJobId` / `activeFilename` / `selectedId` and all queries stay as they are.
Deleted with `IngestPanel`: `tab`, `dragOver`, `composerOpen`, and the
duplicated TLP/PAP state in the composer footer.

## Design tokens

All already defined on `:root` in `src/index.css` — reference the tokens, not
the hexes. Warm default shown for review only:

`--bg` #FAF7F1 · `--bg-soft` #F3EFE6 · `--bg-elev` #FFFCF6 ·
`--ink` #1B1714 · `--ink-2` #4A413B · `--ink-3` #7A6E64 · `--ink-4` #B8AC9F ·
`--rule` #DCD2C0 · `--rule-soft` #ECE3D2 · `--accent` #8B3A2F ·
`--accent-soft` #F2DDD7 · `--ok` #2F6B3A · `--no` #983131 · `--warn` #8A6A12 ·
`--shadow-card` · `--shadow-pop`

Every value must survive the other four themes (`ember`, `parchment`, `cool`,
`dark`) — that is why nothing here is a literal hex and mixes go through
`color-mix(in oklab, …)`. The only literals allowed are the white-on-accent
values inside `.btn-primary` (`rgba(255,255,255,.16)` / `.22` on the ⌘N badge)
and the modal scrim `rgba(20,12,4,.5)`.

Type: `'Source Serif 4'` for headings and card titles; `Inter` for UI;
`'JetBrains Mono'` for counts, timestamps, markings and technical strings.
Sizes used: 30 / 22 / 18 / 14 / 13.5 / 13 / 12.5 / 12 / 11.5 / 11 / 10.5 / 10 / 9.5.
Radii: 3 / 4 / 5 / 6 / 7 / 8 / 9 / 12 / 14 / 16 / 20(pill) / 50%.
Spacing: 2 / 3 / 5 / 6 / 7 / 8 / 9 / 10 / 12 / 14 / 18 / 20 / 22 / 26 / 28.

## Assets

None new. Icons come from `lucide-react`, already a dependency. Fonts are
already loaded via the preconnect + stylesheet link in `index.html`.

## Files

In this bundle:
- `README.md` — this spec
- `CLAUDE_CODE_PROMPT.md` — a paste-ready prompt for Claude Code
- `Dashboard.dc.html` — the HTML design reference (open in a browser)

To change in the app:
- `src/pages/Dashboard.tsx` — topbar, action row, page drop target, ⌘N,
  `KanbanCard`, `ActivityCard`
- `src/components/IngestPanel.tsx` — **delete**
- `src/components/NewReportModal.tsx` — **new**

Do not change: `src/api/client.ts` signatures, `src/types/index.ts`
(`MARKING_LEVELS` stays RED-first — reverse only for display),
`src/components/ProgressModal.tsx`, routes, backend.

## Out of scope

The stat ribbon, Review / Graph / Coverage / Policy / Settings pages, the theme
switcher, and the API contract. Bulk / multi-file queueing was considered and
deliberately left out — the modal takes one source at a time.
