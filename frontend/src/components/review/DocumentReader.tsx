import { useMemo, useRef, useEffect, useCallback, type CSSProperties } from 'react'
import type { Entity } from '../../types'
import { typeColor, buildRanges } from './tokens'
import RelationshipOverlay from './RelationshipOverlay'
import type { Relationship } from '../../types'

interface HoverTarget { id: string; x: number; y: number }

interface Props {
  text: string
  title?: string
  byline?: string
  entities: Entity[]
  highlightStyle: 'underline' | 'block'
  focusedId: string | null
  setFocusedId: (id: string | null) => void
  setHoverEntity: (h: HoverTarget | null) => void
  onAccept: (id: string) => void
  onReject: (id: string) => void
  onReset: (id: string) => void
  onChangeType: (id: string, t: string) => void
  onCreate: (text: string, x: number, y: number) => void
  onMarkShiftClick: (eid: string, x: number, y: number) => void
  onMarkDragStart: (eid: string, from: { x: number; y: number }, evt: PointerEvent) => void
  onSelectionRelate: (payload: { srcId: string; tgtId: string; x: number; y: number; evidenceText: string }) => void
  relEvidence: string[]
  relsForOverlay: Relationship[]
  showRelArrows: boolean
  /** Called when the focused entity has no occurrence in the document text. */
  onEntityNotInText?: (entityId: string) => void
}

export default function DocumentReader({
  text, title, byline, entities, highlightStyle,
  focusedId, setFocusedId, setHoverEntity,
  onAccept, onReject, onReset, onChangeType,
  onCreate, onMarkShiftClick, onMarkDragStart, onSelectionRelate,
  relEvidence, relsForOverlay, showRelArrows,
  onEntityNotInText,
}: Props) {
  const ranges = useMemo(() => buildRanges(text, entities), [text, entities])
  const markRefs = useRef<Record<string, HTMLElement>>({})
  const lastSelRef = useRef(false)

  // ── evidence spans ───────────────────────────────────────────────────────
  const evidenceSpans = useMemo(() => {
    if (!relEvidence.length) return []
    const spans: Array<{ start: number; end: number }> = []
    for (const ev of relEvidence) {
      const needle = ev.replace(/^…\s*/, '').replace(/\s*…\s*$/, '')
      if (needle.length < 12) continue
      const idx = text.indexOf(needle)
      if (idx !== -1) {
        spans.push({ start: idx, end: idx + needle.length })
      } else {
        const head = needle.slice(0, 40)
        const idx2 = text.indexOf(head)
        if (idx2 !== -1) {
          const dot = text.indexOf('.', idx2)
          spans.push({ start: idx2, end: dot === -1 ? idx2 + 200 : dot + 1 })
        }
      }
    }
    return spans.sort((a, b) => a.start - b.start)
  }, [relEvidence, text])

  const isInEvidence = useCallback((pos: number) => {
    return evidenceSpans.some(s => pos >= s.start && pos < s.end)
  }, [evidenceSpans])

  // ── scroll focused mark into view ────────────────────────────────────────
  useEffect(() => {
    if (!focusedId) return
    const node = markRefs.current[`${focusedId}__0`]
    if (node) {
      // Always scroll to the entity — removes the old "only scroll if near edge"
      // restriction that caused visible-but-unfocused entities to give no feedback.
      node.scrollIntoView({ behavior: 'smooth', block: 'center' })
    } else {
      // Entity exists in the list but has no occurrence in the document text.
      // This is normal for LLM-extracted entities (malware names, actor names,
      // campaign names, TTP descriptions) that are paraphrased from context rather
      // than copied verbatim.  Notify the parent so it can show a hint to the user.
      onEntityNotInText?.(focusedId)
    }
  }, [focusedId, onEntityNotInText])

  // ── text selection ────────────────────────────────────────────────────────
  const handleMouseUp = (e: React.MouseEvent) => {
    const sel = window.getSelection()
    const t = sel?.toString().trim() ?? ''
    if (t.length < 2) return
    // Guard: rangeCount can be 0 if the selection was cleared between the
    // toString() call and now (e.g. by a concurrent focus change or React update)
    if (!sel || sel.rangeCount === 0) return
    const r = sel.getRangeAt(0).getBoundingClientRect()
    lastSelRef.current = true
    setTimeout(() => { lastSelRef.current = false }, 250)

    const lowerSel = t.toLowerCase()
    // Sort by position in the selected text so the entity that appears first
    // in the selection becomes the source.  The entity array is sorted by
    // type/confidence, which does not match text order and would silently
    // flip relationship direction (e.g. "MalwareX targets Server_Y" could
    // create Server_Y → MalwareX if Server_Y has a lower array index).
    const mentioned = entities
      .filter(en => en.accepted !== false && lowerSel.includes(en.value.toLowerCase()))
      .sort((a, b) =>
        lowerSel.indexOf(a.value.toLowerCase()) - lowerSel.indexOf(b.value.toLowerCase())
      )
    if (mentioned.length >= 2 && onSelectionRelate) {
      onSelectionRelate({
        srcId: mentioned[0].id,
        tgtId: mentioned[1].id,
        x: r.left + r.width / 2,
        y: r.bottom,
        evidenceText: t,
      })
      sel!.removeAllRanges()
      return
    }
    onCreate(t, r.left + r.width / 2, r.bottom)
    sel!.removeAllRanges()
  }

  // ── render segments ───────────────────────────────────────────────────────
  const occCount: Record<string, number> = {}
  const segments: React.ReactNode[] = []
  let cursor = 0

  const emitPlain = (start: number, end: number) => {
    if (!evidenceSpans.length) {
      segments.push(<span key={`t-${start}`}>{text.slice(start, end)}</span>)
      return
    }
    let c = start
    while (c < end) {
      const span = evidenceSpans.find(s => s.start < end && s.end > c)
      if (!span) {
        segments.push(<span key={`t-${c}`}>{text.slice(c, end)}</span>)
        return
      }
      if (span.start > c) segments.push(<span key={`t-${c}`}>{text.slice(c, span.start)}</span>)
      const segStart = Math.max(c, span.start)
      const segEnd = Math.min(end, span.end)
      segments.push(<span key={`ev-${segStart}`} className="rel-ev-hl">{text.slice(segStart, segEnd)}</span>)
      c = segEnd
    }
  }

  for (const range of ranges) {
    if (range.start > cursor) emitPlain(cursor, range.start)
    const entity = entities.find(e => e.id === range.entityId)
    if (!entity) { cursor = range.end; continue }

    const occ = occCount[entity.id] = (occCount[entity.id] ?? -1) + 1
    const isFocused = focusedId === entity.id
    const isAccepted = entity.accepted === true
    const isRejected = entity.accepted === false

    const style: CSSProperties = highlightStyle === 'underline' || isAccepted
      ? typeColor(entity.entity_type, 'underline')
      : typeColor(entity.entity_type, 'block')

    if (isRejected) {
      style.opacity = 0.35
      style.textDecoration = 'line-through'
      style.background = 'transparent'
      style.borderBottom = '1px dashed currentColor'
    }
    if (isFocused) {
      style.boxShadow = '0 0 0 2px var(--accent)'
      style.borderRadius = '3px'
    }

    const key = `${entity.id}__${occ}`
    segments.push(
      <mark
        key={`m-${range.start}`}
        ref={node => { if (node) markRefs.current[key] = node; else delete markRefs.current[key] }}
        data-eid={entity.id}
        className={`tok ${isAccepted ? 'tok-accepted' : ''} ${entity.accepted === null ? 'tok-pending' : ''}`}
        style={style}
        onMouseEnter={ev => {
          const rect = (ev.currentTarget as HTMLElement).getBoundingClientRect()
          setHoverEntity({ id: entity.id, x: rect.left + rect.width / 2, y: rect.top })
        }}
        onMouseLeave={() => setHoverEntity(null)}
        onPointerDown={ev => {
          if (ev.button !== 0 || ev.shiftKey) return
          const rect = (ev.currentTarget as HTMLElement).getBoundingClientRect()
          onMarkDragStart(entity.id, {
            x: rect.left + rect.width / 2,
            y: rect.top + rect.height / 2,
          }, ev.nativeEvent)
        }}
        onClick={ev => {
          if (lastSelRef.current) return
          ev.stopPropagation()
          if (ev.shiftKey) {
            const rect = (ev.currentTarget as HTMLElement).getBoundingClientRect()
            onMarkShiftClick(entity.id, rect.left + rect.width / 2, rect.bottom)
            return
          }
          setFocusedId(entity.id)
        }}
      >
        {text.slice(range.start, range.end)}
      </mark>,
    )
    cursor = range.end
  }
  if (cursor < text.length) emitPlain(cursor, text.length)

  // ── split into paragraphs ─────────────────────────────────────────────────
  const paragraphs: React.ReactNode[][] = []
  let buf: React.ReactNode[] = []
  segments.forEach((seg, i) => {
    const child = (seg as React.ReactElement).props?.children
    if (typeof child === 'string' && child.includes('\n\n')) {
      const parts = child.split('\n\n')
      buf.push(<span key={`p-${i}-0`}>{parts[0]}</span>)
      paragraphs.push(buf)
      for (let k = 1; k < parts.length - 1; k++) {
        paragraphs.push([<span key={`p-${i}-${k}`}>{parts[k]}</span>])
      }
      buf = parts.length > 1 ? [<span key={`p-${i}-last`}>{parts[parts.length - 1]}</span>] : []
    } else {
      buf.push(seg)
    }
  })
  if (buf.length) paragraphs.push(buf)

  return (
    <article
      className="doc"
      onMouseUp={handleMouseUp}
      onClick={() => setFocusedId(null)}
    >
      <RelationshipOverlay rels={relsForOverlay} show={showRelArrows} />
      {title && <h1 className="doc-title">{title}</h1>}
      {byline && <p className="doc-byline">{byline}</p>}
      {paragraphs.map((p, i) => (
        <p key={`para-${i}`} className="doc-para">{p}</p>
      ))}
    </article>
  )
}
