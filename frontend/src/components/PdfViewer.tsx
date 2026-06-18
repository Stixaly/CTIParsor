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
import type { PageProps, TextContent, TextItem } from 'react-pdf'
import 'react-pdf/dist/Page/AnnotationLayer.css'
import 'react-pdf/dist/Page/TextLayer.css'
import {
  ChevronLeft, ChevronRight, ZoomIn, ZoomOut, RotateCw,
  Loader2, AlertTriangle,
} from 'lucide-react'
import { useAppTheme } from '../context/ThemeContext'
import { buildRanges, typeDot, typeSoft } from './review/tokens'
import type { Entity } from '../types'

// pdf.js needs its worker bundle — load it from the package via Vite's
// `?url` import so it's included in the build output.
pdfjs.GlobalWorkerOptions.workerSrc = new URL(
  'pdfjs-dist/build/pdf.worker.min.mjs',
  import.meta.url,
).toString()

const MONO = "'JetBrains Mono', ui-monospace, monospace"

const ZOOM_STEPS = [0.5, 0.75, 1, 1.25, 1.5, 1.75, 2, 2.5, 3]

// react-pdf doesn't export `PageCallback` directly — derive it from the
// `onLoadSuccess` prop type instead (it's `PDFPageProxy & { width, height, ... }`).
type PageCallback = Parameters<NonNullable<PageProps['onLoadSuccess']>>[0]

function ToolbarButton({ onClick, disabled, title, children }: {
  onClick: () => void
  disabled?: boolean
  title: string
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        width: 28, height: 28, padding: 0,
        border: '1px solid var(--rule)', borderRadius: 6,
        background: 'var(--bg)', color: disabled ? 'var(--ink-4)' : 'var(--ink-2)',
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
  entityType: string
  accepted: boolean | null
  label: string
}

/**
 * Map entity occurrences found in the page's extracted text onto viewport
 * pixel rectangles, by walking pdf.js's per-run TextItems.
 *
 * Matching reuses `buildRanges` (same algorithm as the Text-view highlights,
 * including defanged-IOC variants), so a token highlighted in one view is
 * highlighted in the other whenever the PDF's own text extraction agrees
 * with the report's extracted text.  Each match is split across every
 * TextItem it overlaps, with the sub-rectangle within an item approximated
 * by linear interpolation over `item.width` (uniform character width).
 */
function buildPdfHighlights(
  textContent: TextContent | null,
  page: PageCallback | null,
  scale: number,
  rotation: number,
  entities: Entity[],
): PdfHighlight[] {
  if (!textContent || !page) return []
  const items = textContent.items.filter((it): it is TextItem => 'str' in it)
  if (!items.length) return []

  let pageText = ''
  const itemRanges: Array<{ start: number; end: number; item: TextItem }> = []
  for (const item of items) {
    const start = pageText.length
    pageText += item.str
    itemRanges.push({ start, end: pageText.length, item })
    if (item.hasEOL) pageText += '\n'
  }
  if (!pageText.trim()) return []

  const ranges = buildRanges(pageText, entities)
  if (!ranges.length) return []

  const byId = new Map(entities.map(e => [e.id, e]))
  const viewport = page.getViewport({ scale, rotation })
  const highlights: PdfHighlight[] = []

  for (const range of ranges) {
    const entity = byId.get(range.entityId)
    if (!entity) continue
    for (const ir of itemRanges) {
      const ovStart = Math.max(range.start, ir.start)
      const ovEnd = Math.min(range.end, ir.end)
      if (ovEnd <= ovStart) continue
      const { item } = ir
      const len = item.str.length
      if (len === 0 || !item.width) continue

      const fracStart = (ovStart - ir.start) / len
      const fracEnd = (ovEnd - ir.start) / len
      const x = item.transform[4]
      const y = item.transform[5]
      const x0 = x + fracStart * item.width
      const x1 = x + fracEnd * item.width
      const y1 = y + (item.height || 0)

      const rect = viewport.convertToViewportRectangle([x0, y, x1, y1])
      highlights.push({
        left: Math.min(rect[0], rect[2]),
        top: Math.min(rect[1], rect[3]),
        width: Math.abs(rect[2] - rect[0]),
        height: Math.abs(rect[3] - rect[1]),
        entityId: entity.id,
        entityType: entity.entity_type,
        accepted: entity.accepted,
        label: entity.value,
      })
    }
  }
  return highlights
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
  registerRef: (pageNumber: number, el: HTMLDivElement | null) => void
}

function PdfPageView({
  pageNumber, scale, rotation, pageFilter, entities, focusedId, onFocusEntity, registerRef,
}: PdfPageViewProps) {
  const [pdfPage, setPdfPage] = useState<PageCallback | null>(null)
  const [textContent, setTextContent] = useState<TextContent | null>(null)

  const highlights = useMemo(
    () => buildPdfHighlights(textContent, pdfPage, scale, rotation, entities),
    [textContent, pdfPage, scale, rotation, entities],
  )

  return (
    <div
      ref={el => registerRef(pageNumber, el)}
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
          onLoadSuccess={setPdfPage}
          onGetTextSuccess={setTextContent}
        />
      </div>

      {/* Entity highlight overlay — positioned in viewport pixels,
          independent of the dark-mode invert filter above. */}
      {highlights.length > 0 && (
        <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }}>
          {highlights.map((h, i) => (
            <div
              key={`${h.entityId}-${i}`}
              title={h.label}
              onClick={() => onFocusEntity?.(h.entityId)}
              style={{
                position: 'absolute',
                left: h.left, top: h.top, width: h.width, height: h.height,
                background: typeSoft(h.entityType),
                borderBottom: `2px solid ${typeDot(h.entityType)}`,
                opacity: h.accepted === true ? 0.55 : 0.4,
                boxShadow: focusedId === h.entityId ? '0 0 0 2px var(--accent)' : undefined,
                borderRadius: 2,
                cursor: onFocusEntity ? 'pointer' : 'default',
                pointerEvents: 'auto',
              }}
            />
          ))}
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
  /** Currently focused entity — gets an accent outline on the PDF too. */
  focusedId?: string | null
  /** Called when a highlight is clicked — typically `setFocusedId`. */
  onFocusEntity?: (id: string) => void
}

export default function PdfViewer({ url, filename, entities, focusedId, onFocusEntity }: PdfViewerProps) {
  const { isDark } = useAppTheme()
  const [numPages, setNumPages] = useState<number | null>(null)
  const [currentPage, setCurrentPage] = useState(1)
  const [zoomIdx, setZoomIdx] = useState(2) // 1.0
  const [rotation, setRotation] = useState(0)
  const [error, setError] = useState<string | null>(null)

  const scale = ZOOM_STEPS[zoomIdx]
  const containerRef = useRef<HTMLDivElement | null>(null)
  const pageRefs = useRef(new Map<number, HTMLDivElement>())

  const onDocLoadSuccess = useCallback(({ numPages: n }: { numPages: number }) => {
    setNumPages(n)
    setCurrentPage(1)
    setError(null)
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

  // Track whichever page is most visible in the scroll container, so the
  // toolbar's "X / Y" indicator and Previous/Next reflect actual scroll
  // position instead of a separately-tracked "current page".
  //
  // The page surface itself doesn't scroll — `.stage-wrapper` (Review.tsx's
  // layout container) is the actual scroll container, same as Marginalia's
  // position-sort effect relies on.
  useEffect(() => {
    if (!numPages) return
    const root = containerRef.current?.closest<HTMLElement>('.stage-wrapper') ?? null
    const observer = new IntersectionObserver(
      entries => {
        let best: { page: number; ratio: number } | null = null
        for (const entry of entries) {
          const page = Number((entry.target as HTMLElement).dataset.pageNumber)
          if (entry.isIntersecting && entry.intersectionRatio > (best?.ratio ?? 0)) {
            best = { page, ratio: entry.intersectionRatio }
          }
        }
        if (best) setCurrentPage(best.page)
      },
      { root, threshold: [0.1, 0.25, 0.5, 0.75, 1] },
    )
    for (const el of pageRefs.current.values()) observer.observe(el)
    return () => observer.disconnect()
  }, [numPages, scale, rotation])

  // Dark theme: invert the rendered page so white PDF pages don't glow
  // against the dark UI — same trick OpenCTI applies to its PDF canvas.
  // Applied only to the page wrapper, not the highlight overlay, so
  // highlight colours (already theme-aware) aren't double-inverted.
  const pageFilter = useMemo(
    () => (isDark ? 'invert(0.92) hue-rotate(180deg)' : undefined),
    [isDark],
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: '80vh' }}>
      {/* Toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '8px 12px', marginTop: 12,
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
          onClick={() => setZoomIdx(i => Math.max(0, i - 1))}
          disabled={zoomIdx <= 0}
          title="Zoom out"
        >
          <ZoomOut size={14} />
        </ToolbarButton>

        <span style={{ fontSize: 12, fontFamily: MONO, color: 'var(--ink-2)', minWidth: 44, textAlign: 'center' }}>
          {Math.round(scale * 100)}%
        </span>

        <ToolbarButton
          onClick={() => setZoomIdx(i => Math.min(ZOOM_STEPS.length - 1, i + 1))}
          disabled={zoomIdx >= ZOOM_STEPS.length - 1}
          title="Zoom in"
        >
          <ZoomIn size={14} />
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
          (Review.tsx's layout container) is what actually scrolls. */}
      <div
        ref={containerRef}
        style={{
          flex: 1,
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          padding: '16px 0 40px',
          background: 'var(--bg-soft)',
          borderRadius: 8,
          marginTop: 8,
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
                registerRef={registerPageRef}
              />
            ))}
          </Document>
        )}
      </div>
    </div>
  )
}
