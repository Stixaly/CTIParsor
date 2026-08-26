# Paste this into Claude Code

Copy everything between the lines into Claude Code from the root of the repo that
contains `frontend/src/pages/Dashboard.tsx`. The design reference and the full
spec live in `design_handoff_dashboard_ingest/` — put that folder in the repo (or
point Claude Code at wherever you unzipped it).

---

Read `design_handoff_dashboard_ingest/README.md` and
`design_handoff_dashboard_ingest/Dashboard.dc.html` (a working HTML prototype —
open it in a browser to see the behavior; do NOT copy its code, it is a reference).

Then implement the redesign it describes in this codebase, using our existing
patterns: React + TypeScript, react-query mutations already in
`src/api/client.ts`, `lucide-react` icons, inline styles with the `var(--*)`
tokens from `src/index.css`, and the `.btn-primary` / `.btn-ghost` classes.

Scope, in order:

1. Replace `src/components/IngestPanel.tsx` with a modal-based `NewReportModal.tsx`.
   The three tabs (file / paste / URL) go away: one textarea accepts pasted text
   OR a pasted URL and detects which; files arrive by drop or a Browse button.
   Keep all three existing mutations (`uploadFile`, `ingestText`, `ingestUrl`)
   and the `onJobCreated(jobId, filename)` callback contract unchanged.
2. TLP and PAP must start UNSET and gate submission — no AMBER default anywhere.
   The type is `MarkingLevel` from `src/types/index.ts`; the API fields stay
   `tlp_level` / `pap_level`.
3. In `src/pages/Dashboard.tsx`: remove the inline `<IngestPanel />`, add a
   "New report" primary button, wire ⌘N / Ctrl+N, and add a page-level drop
   target that opens the modal with the dropped file already attached.
4. Tighten `KanbanCard` to the density spec in the README (status dot replaces
   the pill, one mono meta line, 22px icon action row).

Do not change the backend, the API client signatures, the routes, or any other
page. Work through it step by step and show me a diff per file before moving on.

---
