/**
 * Pure helpers behind PdfViewer: where entity occurrences fall in pdf.js's
 * text items, the markup that anchors them in the text layer, which page is
 * the most visible, and the fit-to-width scale.
 */
import { buildRanges } from './review/tokens'

/** One entity occurrence inside a text item, as offsets into its `str`. */
export interface ItemMark { start: number; end: number; entityId: string }

type TextItemLike = { str: string; hasEOL?: boolean }
type EntityLike = { id: string; value: string; entity_type: string; accepted: boolean | null }

/**
 * Entity occurrences on one page, per text item — keyed by the item's index
 * in `items` (marked-content entries included), which is the `itemIndex`
 * react-pdf's `customTextRenderer` receives.
 *
 * The page text is rebuilt the way pdf.js reads it (runs joined, a newline at
 * each end of line) and matched with `buildRanges`, the Text view's matcher,
 * so the two views highlight the same tokens.  An occurrence spanning several
 * runs is split across them.
 */
export function itemMarks(items: ReadonlyArray<object> | null | undefined, entities: EntityLike[]): Map<number, ItemMark[]> {
  const out = new Map<number, ItemMark[]>()
  if (!items?.length) return out
  let pageText = ''
  const runs: Array<{ index: number; start: number; end: number }> = []
  items.forEach((it, index) => {
    if (!('str' in it)) return
    const item = it as TextItemLike
    const start = pageText.length
    pageText += item.str
    runs.push({ index, start, end: pageText.length })
    if (item.hasEOL) pageText += '\n'
  })
  if (!pageText.trim()) return out
  for (const r of buildRanges(pageText, entities)) {
    for (const run of runs) {
      const s = Math.max(r.start, run.start), e = Math.min(r.end, run.end)
      if (e <= s) continue
      const list = out.get(run.index) ?? []
      list.push({ start: s - run.start, end: e - run.start, entityId: r.entityId })
      out.set(run.index, list)
    }
  }
  out.forEach(list => list.sort((a, b) => a.start - b.start))
  return out
}

const escapeHtml = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
   .replace(/"/g, '&quot;').replace(/'/g, '&#39;')

/**
 * HTML for one text-layer run: its text, with each occurrence wrapped in an
 * invisible `<mark data-eid>`.  pdf.js lays the run out to the glyphs' real
 * advance widths (and its rotation), so measuring the marks places the
 * highlight on the word — unlike splitting the run's width evenly per
 * character, which drifted in proportional fonts ("iiii" vs "WWWW").
 */
export function anchorMarkup(str: string, marks: ItemMark[] | undefined): string {
  if (!marks?.length) return escapeHtml(str)
  let html = '', cursor = 0
  for (const m of marks) {
    if (m.start < cursor) continue
    html += escapeHtml(str.slice(cursor, m.start))
    html += `<mark class="pdf-anchor" data-eid="${escapeHtml(m.entityId)}">${escapeHtml(str.slice(m.start, m.end))}</mark>`
    cursor = m.end
  }
  return html + escapeHtml(str.slice(cursor))
}

/**
 * The page showing the most of itself on screen, from the visible height of
 * every page (0 when off screen).  Ties go to the earlier page.
 */
export function mostVisiblePage(visible: ReadonlyMap<number, number>): number | null {
  let best: number | null = null, bestH = 0
  visible.forEach((h, page) => {
    if (h > bestH || (h === bestH && h > 0 && best != null && page < best)) { best = page; bestH = h }
  })
  return best
}

/** Scale at which a page of `base` size (at scale 1) fills `available` px of width. */
export function fitWidthScale(
  available: number,
  base: { w: number; h: number } | null,
  rotation: number,
  min = 0.25,
  max = 3,
): number {
  if (!base || available <= 0) return 1
  const w = rotation % 180 === 0 ? base.w : base.h
  if (w <= 0) return 1
  const k = Math.floor((available / w) * 100) / 100
  return Math.min(max, Math.max(min, k))
}
