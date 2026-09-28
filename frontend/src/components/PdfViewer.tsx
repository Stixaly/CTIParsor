/**
 * Inline PDF viewer — mirrors OpenCTI's file viewer: pages are rendered as
 * canvases via pdf.js (react-pdf) instead of the browser's native PDF plugin,
 * so the toolbar and surrounding chrome follow the app's theme.
 *
 * All pages are stacked in a single scrollable column (continuous scroll),
 * with the toolbar's page indicator and Previous/Next controls tracking
 * whichever page is currently most visible.
 */

import { useState, useCallback, useMemo, useEffect, useRef } from 'react'
import { Document, Page, pdfjs } from 'react-pdf'
import type { DocumentProps, TextContent } from 'react-pdf'
import 'react-pdf/dist/Page/AnnotationLayer.css'
import 'react-pdf/dist/Page/TextLayer.css'
import {
  ChevronLeft, ChevronRight, ZoomIn, ZoomOut, RotateCw, MoveHorizontal,
  Loader2, AlertTriangle,
} from 'lucide-react'
import { useAppTheme } from '../context/ThemeContext'
import { typeDot, typeSoft } from './review/tokens'
import { itemMarks, anchorMarkup, mostVisiblePage, fitWidthScale } from './pdfGeometry'
import type { Entity } from '../types'

// pdf.js needs its worker bundle — load it from the package via Vite's
// `?url` import so it's included in the build output.
pdfjs.GlobalWorkerOptions.workerSrc = new URL(
  'pdfjs-dist/build/pdf.worker.min.mjs',
  import.meta.url,
).toString()

const MONO = "'JetBrains Mono', ui-monospace, monospace"

const ZOOM_STEPS = [0.5, 0.75, 1, 1.25, 1.5, 1.75, 2, 2.5, 3]

type DocumentCallback = Parameters<NonNullable<DocumentProps['onLoadSuccess']>>[0]

function ToolbarButton({ onClick, disabled, title, active, children }: {
  onClick: () => void
  disabled?: boolean
  title: string
  active?: boolean
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      aria-pressed={active}
      style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        width: 28, height: 28, padding: 0,
        border: `1px solid ${active ? 'var(--accent)' : 'var(--rule)'}`, borderRadius: 6,
        background: active ? 'var(--accent-soft)' : 'var(--bg)',
        color: disabled ? 'var(--ink-4)' : active ? 'var(--accent)' : 'var(--ink-2)',
        cursor: disabled ? 'default' : 'pointer',
        opacity: disabled ? 0.5 : 1,
      }}
    >
      {children}
    </button>
  )
}

// ── entity-highlight overlay geometry ──────────────────────────────────────

interface PdfHighlight {
  left: number
  top: number
  width: number
  height: number
  entityId: string
}

// ── single page + its highlight overlay ────────────────────────────────────

interface PdfPageViewProps {
  pageNumber: number
  scale: number
  rotation: number
  pageFilter?: string
  entities: Entity[]
  focusedId?: string | null
  onFocusEntity?: (id: string) => void
  onHighlightsMeasured: () => void
  registerRef: (pageNumber: number, el: HTMLDivElement | null) => void
}

function PdfPageView({
  pageNumber, scale, rotation, pageFilter, entities, focusedId, onFocusEntity,
  onHighlightsMeasured, registerRef,
}: PdfPageViewProps) {
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const [textContent, setTextContent] = useState<TextContent | null>(null)
  const [boxes, setBoxes] = useState<PdfHighlight[]>([])

  const byId  = useMemo(() => new Map(entities.map(e => [e.id, e])), [entities])
  const marks = useMemo(() => itemMarks(textContent?.items, entities), [textContent, entities])

  // Anchor each occurrence inside pdf.js's own text layer…
  const renderText = useCallback(
    ({ str, itemIndex }: { str: string; itemIndex: number }) => anchorMarkup(str, marks.get(itemIndex)),
    [marks],
  )

  // …then measure the anchors once it is laid out: the boxes follow the real
  // glyph widths and the run's rotation.
  const measure = useCallback(() => {
    requestAnimationFrame(() => {
      const wrap = wrapRef.current
      if (!wrap) return
      const origin = wrap.getBoundingClientRect()
      const out: PdfHighlight[] = []
      wrap.querySelectorAll<HTMLElement>('mark.pdf-anchor').forEach(m => {
        for (const r of Array.from(m.getClientRects())) {
          if (!r.width || !r.height) continue
          out.push({
            left: r.left - origin.left, top: r.top - origin.top,
            width: r.width, height: r.height,
            entityId: m.dataset.eid ?? '',
          })
        }
      })
      setBoxes(out)
      onHighlightsMeasured()
    })
  }, [onHighlightsMeasured])

  // Boxes measured at another zoom, rotation or entity set would be misplaced
  // until the text layer re-renders and is measured again.
  useEffect(() => { setBoxes([]) }, [scale, rotation, marks])

  return (
    <div
      ref={el => { wrapRef.current = el; registerRef(pageNumber, el) }}
      data-page-number={pageNumber}
      style={{ position: 'relative', alignSelf: 'center', marginBottom: 16 }}
    >
      <div style={{ boxShadow: 'var(--shadow-card)', filter: pageFilter }}>
        <Page
          pageNumber={pageNumber}
          scale={scale}
          rotate={rotation}
          renderAnnotationLayer
          renderTextLayer
          customTextRenderer={renderText}
          onGetTextSuccess={setTextContent}
          onRenderTextLayerSuccess={measure}
        />
      </div>

      {/* Entity highlight overlay — positioned in page pixels, outside the
          dark-mode invert filter above.  Accepted: solid underline; pending:
          dashed and lighter.  Rejected entities are not highlighted. */}
      {boxes.length > 0 && (
        <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }}>
          {boxes.map((h, i) => {
            const e = byId.get(h.entityId)
            if (!e) return null
            const accepted = e.accepted === true
            return (
              <div
                key={`${h.entityId}-${i}`}
                data-hl={h.entityId}
                title={`${e.value} — ${accepted ? 'accepted' : 'pending review'}`}
                onClick={() => onFocusEntity?.(h.entityId)}
                style={{
                  position: 'absolute',
                  left: h.left, top: h.top, width: h.width, height: h.height,
                  background: typeSoft(e.entity_type),
                  borderBottom: `2px ${accepted ? 'solid' : 'dashed'} ${typeDot(e.entity_type)}`,
                  opacity: accepted ? 0.6 : 0.45,
                  boxShadow: focusedId === h.entityId ? '0 0 0 2px var(--accent)' : undefined,
                  borderRadius: 2,
                  cursor: onFocusEntity ? 'pointer' : 'default',
                  pointerEvents: 'auto',
                }}
              />
            )
          })}
        </div>
      )}
    </div>
  )
}

interface PdfViewerProps {
  url: string
  filename?: string
  /** Entities to highlight on the rendered pages (same set as the Text view). */
  entities?: Entity[]
  /** Currently focused entity — outlined, and scrolled into view when off screen. */
  focusedId?: string | null
  /** Called when a highlight is clicked — typically `setFocusedId`. */
  onFocusEntity?: (id: string) => void
}

export default function PdfViewer({ url, filename, entities, focusedId, onFocusEntity }: PdfViewerProps) {
  const { isDark } = useAppTheme()
  const [numPages, setNumPages] = useState<number | null>(null)
  const [currentPage, setCurrentPage] = useState(1)
  // null = fit the page to the available width (the default): a landscape
  // page, or any page zoomed in, used to overflow both sides of the column.
  const [zoomIdx, setZoomIdx] = useState<number | null>(null)
  const [rotation, setRotation] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [baseSize, setBaseSize] = useState<{ w: number; h: number } | null>(null)
  const [available, setAvailable] = useState(0)
  const [measureTick, setMeasureTick] = useState(0)

  const containerRef = useRef<HTMLDivElement | null>(null)
  const pageRefs = useRef(new Map<number, HTMLDivElement>())

  const fitScale = fitWidthScale(available, baseSize, rotation)
  const scale = zoomIdx == null ? fitScale : ZOOM_STEPS[zoomIdx]
  const nextUp   = ZOOM_STEPS.findIndex(s => s > scale + 0.005)
  const nextDown = ZOOM_STEPS.map((s, i) => (s < scale - 0.005 ? i : -1)).filter(i => i >= 0).pop() ?? -1

  // Wait for page 1's size before rendering, so a fit-to-width opening does
  // not render every page at 100 % first.
  const onDocLoadSuccess = useCallback((pdf: DocumentCallback) => {
    setError(null)
    setCurrentPage(1)
    pdf.getPage(1)
      .then(p => {
        const v = p.getViewport({ scale: 1 })
        setBaseSize({ w: v.width, h: v.height })
      })
      .catch(() => setBaseSize(null))
      .finally(() => setNumPages(pdf.numPages))
  }, [])

  const onLoadError = useCallback((err: Error) => {
    setError(err.message || 'Failed to load PDF')
  }, [])

  const registerPageRef = useCallback((pageNumber: number, el: HTMLDivElement | null) => {
    if (el) pageRefs.current.set(pageNumber, el)
    else pageRefs.current.delete(pageNumber)
  }, [])

  const scrollToPage = useCallback((page: number) => {
    pageRefs.current.get(page)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [])

  const onHighlightsMeasured = useCallback(() => setMeasureTick(t => t + 1), [])

  // Width the pages can use, for fit-to-width.  Debounced: each change
  // re-renders every page.
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const read = () => setAvailable(Math.max(0, el.clientWidth - 2))
    read()
    if (typeof ResizeObserver === 'undefined') return
    let t: ReturnType<typeof setTimeout> | null = null
    const ro = new ResizeObserver(() => {
      if (t) clearTimeout(t)
      t = setTimeout(read, 150)
    })
    ro.observe(el)
    return () => { ro.disconnect(); if (t) clearTimeout(t) }
  }, [])

  // Track whichever page is most visible in the scroll container, so the
  // toolbar's "X / Y" indicator and Previous/Next reflect actual scroll
  // position instead of a separately-tracked "current page".
  //
  // Every page's visible height is measured on each scroll or resize (one
  // frame at most).  An IntersectionObserver only reported the pages that
  // crossed a ratio threshold: a page that grew while fully on screen (its
  // canvas loading) was never re-reported, and the indicator named the page
  // below it.
  //
  // The page surface itself doesn't scroll vertically — `.stage-wrapper`
  // (Review.tsx's layout container) is the actual scroll container, same as
  // Marginalia's position-sort effect relies on.
  useEffect(() => {
    if (!numPages) return
    const surface = containerRef.current
    const root = surface?.closest<HTMLElement>('.stage-wrapper') ?? null
    const target: HTMLElement | Window = root ?? window
    let frame = 0
    const update = () => {
      frame = 0
      const view = root ? root.getBoundingClientRect() : { top: 0, bottom: window.innerHeight }
      const visible = new Map<number, number>()
      pageRefs.current.forEach((el, page) => {
        const r = el.getBoundingClientRect()
        visible.set(page, Math.max(0, Math.min(r.bottom, view.bottom) - Math.max(r.top, view.top)))
      })
      const best = mostVisiblePage(visible)
      if (best != null) setCurrentPage(best)
    }
    const schedule = () => { if (!frame) frame = requestAnimationFrame(update) }
    target.addEventListener('scroll', schedule, { passive: true })
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(schedule) : null
    if (ro) {
      if (surface) ro.observe(surface)
      if (root) ro.observe(root)
    }
    schedule()
    return () => {
      target.removeEventListener('scroll', schedule)
      ro?.disconnect()
      if (frame) cancelAnimationFrame(frame)
    }
  }, [numPages])

  // Bring the focused entity on screen when none of its highlights is — a
  // pick in the margin used to outline an occurrence pages away and leave the
  // view where it was.  Retried as pages finish measuring, once per focus.
  const focusHandled = useRef<string | null>(null)
  useEffect(() => { focusHandled.current = null }, [focusedId])
  useEffect(() => {
    if (!focusedId || focusHandled.current === focusedId) return
    const surface = containerRef.current
    if (!surface) return
    const hits = Array.from(surface.querySelectorAll<HTMLElement>('[data-hl]'))
      .filter(el => el.dataset.hl === focusedId)
    if (!hits.length) return
    focusHandled.current = focusedId
    const root = surface.closest<HTMLElement>('.stage-wrapper')
    const view = root ? root.getBoundingClientRect() : { top: 0, bottom: window.innerHeight }
    const onScreen = hits.some(el => {
      const r = el.getBoundingClientRect()
      return r.bottom > view.top && r.top < view.bottom
    })
    if (!onScreen) hits[0].scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' })
  }, [focusedId, measureTick])

  // Dark theme: invert the rendered page so white PDF pages don't glow
  // against the dark UI — same trick OpenCTI applies to its PDF canvas.
  // Applied only to the page wrapper, not the highlight overlay, so
  // highlight colours (already theme-aware) aren't double-inverted.
  const pageFilter = useMemo(
    () => (isDark ? 'invert(0.92) hue-rotate(180deg)' : undefined),
    [isDark],
  )

  return (
    // Match the sibling tabs (.doc / MarkdownPreview): sit on the app background
    // with the same horizontal padding, rather than in a distinct gray "stage".
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minWidth: 0, minHeight: '80vh', padding: '12px 36px 40px' }}>
      {/* Toolbar — sticky so page/zoom controls stay reachable while scrolling */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '8px 12px',
        position: 'sticky', top: 0, zIndex: 5,
        border: '1px solid var(--rule)', borderRadius: 8,
        background: 'var(--bg-soft)',
        flexWrap: 'wrap',
      }}>
        <ToolbarButton
          onClick={() => scrollToPage(currentPage - 1)}
          disabled={currentPage <= 1}
          title="Previous page"
        >
          <ChevronLeft size={14} />
        </ToolbarButton>

        <span style={{ fontSize: 12, fontFamily: MONO, color: 'var(--ink-2)', minWidth: 70, textAlign: 'center' }}>
          {numPages ? `${currentPage} / ${numPages}` : '— / —'}
        </span>

        <ToolbarButton
          onClick={() => scrollToPage(currentPage + 1)}
          disabled={!numPages || currentPage >= numPages}
          title="Next page"
        >
          <ChevronRight size={14} />
        </ToolbarButton>

        <div style={{ width: 1, height: 18, background: 'var(--rule)', margin: '0 4px' }} />

        <ToolbarButton
          onClick={() => setZoomIdx(nextDown)}
          disabled={nextDown < 0}
          title="Zoom out"
        >
          <ZoomOut size={14} />
        </ToolbarButton>

        <span
          style={{ fontSize: 12, fontFamily: MONO, color: 'var(--ink-2)', minWidth: 44, textAlign: 'center' }}
          title={zoomIdx == null ? 'Fitted to the width' : undefined}
        >
          {Math.round(scale * 100)}%
        </span>

        <ToolbarButton
          onClick={() => setZoomIdx(nextUp)}
          disabled={nextUp < 0}
          title="Zoom in"
        >
          <ZoomIn size={14} />
        </ToolbarButton>

        <ToolbarButton
          onClick={() => setZoomIdx(null)}
          active={zoomIdx == null}
          title="Fit to width"
        >
          <MoveHorizontal size={14} />
        </ToolbarButton>

        <ToolbarButton
          onClick={() => setRotation(r => (r + 90) % 360)}
          title="Rotate"
        >
          <RotateCw size={14} />
        </ToolbarButton>

        {filename && (
          <span style={{
            fontSize: 11, fontFamily: MONO, color: 'var(--ink-4)',
            marginLeft: 'auto', overflow: 'hidden', textOverflow: 'ellipsis',
            whiteSpace: 'nowrap', maxWidth: 240,
          }}>
            {filename}
          </span>
        )}
      </div>

      {/* Page surface — all pages stacked in a single column; `.stage-wrapper`
          (Review.tsx's layout container) is what scrolls vertically.  Pages
          wider than the column scroll sideways here (see .pdf-doc) instead of
          overflowing both edges, where the left one could not be reached. */}
      <div
        ref={containerRef}
        style={{
          flex: 1,
          minWidth: 0,
          overflowX: 'auto',
          padding: '20px 0 0',
          // Transparent so the pages read against the app background, like the
          // Text/Preview tabs — no distinct gray panel behind them.
          background: 'transparent',
        }}
      >
        {error ? (
          <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            justifyContent: 'center', gap: 10, color: 'var(--no)', padding: 40,
          }}>
            <AlertTriangle size={32} />
            <span style={{ fontSize: 13 }}>{error}</span>
          </div>
        ) : (
          <Document
            className="pdf-doc"
            file={url}
            onLoadSuccess={onDocLoadSuccess}
            onLoadError={onLoadError}
            loading={
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8,
                color: 'var(--ink-3)', padding: 40, fontSize: 13,
              }}>
                <Loader2 size={16} className="animate-spin" />
                Loading PDF…
              </div>
            }
          >
            {Array.from({ length: numPages ?? 0 }, (_, i) => (
              <PdfPageView
                key={i + 1}
                pageNumber={i + 1}
                scale={scale}
                rotation={rotation}
                pageFilter={pageFilter}
                entities={entities ?? []}
                focusedId={focusedId}
                onFocusEntity={onFocusEntity}
                onHighlightsMeasured={onHighlightsMeasured}
                registerRef={registerPageRef}
              />
            ))}
          </Document>
        )}
      </div>
    </div>
  )
}
