/**
 * SourceViewer — renders the ORIGINAL uploaded file inline in the Review page's
 * "Source" tab, for every supported format (not just PDF).
 *
 *   pdf        → PdfViewer (pdf.js canvases, entity highlights)
 *   html/htm   → sandboxed <iframe> rendering the original page (scripts disabled)
 *   txt/md     → raw file text in a themed <pre>, with the same entity
 *                highlights the Text view uses (via buildRanges)
 *   docx/other → download fallback (browsers can't render these inline and no
 *                converter is bundled)
 *
 * Splitting the dispatch out of Review.tsx keeps that file focused on review
 * state and makes `sourceKind` unit-testable.
 */
import { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import { FileText, Loader2, AlertTriangle } from 'lucide-react'
import PdfViewer from './PdfViewer'
import { buildRanges, typeSoft, typeDot } from './review/tokens'
import { sourceKind } from './sourceKind'
import type { Entity } from '../types'

const MONO = "'JetBrains Mono', ui-monospace, 'Cascadia Code', Consolas, monospace"

// ── raw-text source (txt / md) ──────────────────────────────────────────────

/**
 * Overlay entity highlights on raw source text.  Reuses `buildRanges` (the same
 * matcher the Text view uses, defanged-IOC variants included), so a token
 * highlighted there is highlighted here too whenever it survives verbatim in
 * the original file.
 */
function highlightText(
  text: string,
  entities: Entity[],
  focusedId: string | null,
  onFocusEntity: (id: string) => void,
  registerMark: (id: string, el: HTMLElement | null) => void,
): React.ReactNode {
  const ranges = buildRanges(text, entities).sort((a, b) => a.start - b.start)
  if (!ranges.length) return text

  const byId = new Map(entities.map(e => [e.id, e]))
  const nodes: React.ReactNode[] = []
  const seen = new Set<string>()   // register only the first occurrence per entity
  let cursor = 0

  ranges.forEach((r, i) => {
    if (r.start < cursor) return          // defensive: skip any overlap
    if (r.start > cursor) nodes.push(text.slice(cursor, r.start))
    const e = byId.get(r.entityId)
    const seg = text.slice(r.start, r.end)
    const isFirst = !seen.has(r.entityId)
    seen.add(r.entityId)
    nodes.push(
      <mark
        key={i}
        ref={isFirst ? (el => registerMark(r.entityId, el)) : undefined}
        data-eid={r.entityId}
        title={e?.value}
        onClick={() => onFocusEntity(r.entityId)}
        style={{
          background: e ? typeSoft(e.entity_type) : 'var(--accent-soft)',
          borderBottom: `2px solid ${e ? typeDot(e.entity_type) : 'var(--accent)'}`,
          borderRadius: 2,
          color: 'inherit',
          cursor: 'pointer',
          boxShadow: focusedId === r.entityId ? '0 0 0 2px var(--accent)' : undefined,
        }}
      >
        {seg}
      </mark>,
    )
    cursor = r.end
  })
  if (cursor < text.length) nodes.push(text.slice(cursor))
  return nodes
}

interface TextSourceProps {
  url: string
  filename: string
  entities: Entity[]
  focusedId: string | null
  onFocusEntity: (id: string) => void
  onEntityNotInText?: (id: string) => void
}

function TextSource({ url, filename, entities, focusedId, onFocusEntity, onEntityNotInText }: TextSourceProps) {
  const [text, setText]   = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  // first-occurrence <mark> element per entity id — used to scroll the focused
  // entity into view, mirroring the Text view (DocumentReader).
  const markRefs = useRef<Record<string, HTMLElement | null>>({})
  const registerMark = useCallback((id: string, el: HTMLElement | null) => {
    if (el) markRefs.current[id] = el
    else delete markRefs.current[id]
  }, [])

  useEffect(() => {
    let cancelled = false
    setText(null); setError(null)
    markRefs.current = {}
    fetch(url)
      .then(res => { if (!res.ok) throw new Error(`${res.status}`); return res.text() })
      .then(t => { if (!cancelled) setText(t) })
      .catch(() => { if (!cancelled) setError('Could not load the source file.') })
    return () => { cancelled = true }
  }, [url])

  // Scroll the focused entity's first occurrence into view when it changes
  // (e.g. clicking an entity in the marginalia).  If the entity has no verbatim
  // occurrence in the raw source, notify the parent so it can show the hint.
  useEffect(() => {
    if (!focusedId || text == null) return
    const node = markRefs.current[focusedId]
    if (node) node.scrollIntoView({ behavior: 'smooth', block: 'center' })
    else onEntityNotInText?.(focusedId)
  }, [focusedId, text, onEntityNotInText])

  const body = useMemo(
    () => (text != null ? highlightText(text, entities, focusedId, onFocusEntity, registerMark) : null),
    [text, entities, focusedId, onFocusEntity, registerMark],
  )

  if (error) return <CenteredNotice icon={<AlertTriangle size={32} />} title={filename} note={error} tone="error" />
  if (text == null) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--ink-3)', padding: 40, fontSize: 13 }}>
        <Loader2 size={16} className="animate-spin" />
        Loading source…
      </div>
    )
  }

  return (
    <div style={{ padding: '12px 56px 40px', minWidth: 0 }}>
      <pre
        style={{
          fontFamily: MONO,
          fontSize: 13,
          lineHeight: 1.7,
          color: 'var(--ink-2)',
          background: 'var(--bg-soft)',
          border: '1px solid var(--rule)',
          borderRadius: 8,
          padding: '18px 20px',
          margin: 0,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
        }}
      >
        {body}
      </pre>
    </div>
  )
}

// ── rendered HTML source (html / htm) ───────────────────────────────────────

function HtmlSource({ url, filename }: { url: string; filename: string }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: '80vh', padding: '12px 0 40px' }}>
      <iframe
        src={url}
        title={filename}
        // Fully sandboxed: renders the original markup but blocks scripts,
        // forms, popups and same-origin access — safe for untrusted uploads.
        sandbox=""
        style={{
          flex: 1,
          width: '100%',
          minHeight: '80vh',
          border: '1px solid var(--rule)',
          borderRadius: 8,
          background: '#fff',   // HTML reports assume a light page background
        }}
      />
    </div>
  )
}

// ── download fallback (docx / anything else) ────────────────────────────────

function DownloadFallback({ url, filename }: { url: string; filename: string }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center',
      padding: '60px 40px', gap: 14, color: 'var(--ink-3)',
    }}>
      <FileText size={40} style={{ color: 'var(--ink-4)' }} />
      <p style={{ margin: 0, fontSize: 14, color: 'var(--ink-2)' }}>{filename}</p>
      <p style={{ margin: 0, fontSize: 12 }}>
        This format can't be previewed inline — download it to view the original.
      </p>
      <a
        href={url}
        download={filename}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          padding: '7px 14px', borderRadius: 7,
          background: 'var(--accent-soft)', color: 'var(--accent)',
          fontSize: 12, fontWeight: 600, textDecoration: 'none',
        }}
      >
        Download original file
      </a>
    </div>
  )
}

function CenteredNotice({ icon, title, note, tone }: {
  icon: React.ReactNode; title: string; note: string; tone?: 'error'
}) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      padding: '60px 40px', gap: 12, color: tone === 'error' ? 'var(--no)' : 'var(--ink-3)',
    }}>
      {icon}
      <p style={{ margin: 0, fontSize: 14, color: 'var(--ink-2)' }}>{title}</p>
      <p style={{ margin: 0, fontSize: 12 }}>{note}</p>
    </div>
  )
}

// ── dispatcher ──────────────────────────────────────────────────────────────

interface SourceViewerProps {
  url: string
  filename: string
  entities: Entity[]
  focusedId: string | null
  onFocusEntity: (id: string) => void
  /** Called when a focused entity has no verbatim occurrence in the source. */
  onEntityNotInText?: (id: string) => void
}

export default function SourceViewer({
  url, filename, entities, focusedId, onFocusEntity, onEntityNotInText,
}: SourceViewerProps) {
  const kind = sourceKind(filename)

  switch (kind) {
    case 'pdf':
      return (
        <PdfViewer
          url={url}
          filename={filename}
          entities={entities}
          focusedId={focusedId}
          onFocusEntity={onFocusEntity}
        />
      )
    case 'html':
      return <HtmlSource url={url} filename={filename} />
    case 'text':
      return (
        <TextSource
          url={url}
          filename={filename}
          entities={entities}
          focusedId={focusedId}
          onFocusEntity={onFocusEntity}
          onEntityNotInText={onEntityNotInText}
        />
      )
    default:
      return <DownloadFallback url={url} filename={filename} />
  }
}
