/**
 * sourceKind — classify an uploaded filename into a Source-view rendering
 * strategy.  Kept in its own module (no React / pdf.js imports) so it can be
 * unit-tested in jsdom without pulling in the heavy PdfViewer dependency chain.
 */

export type SourceKind = 'pdf' | 'html' | 'text' | 'docx' | 'other'

const HTML_EXTS = new Set(['html', 'htm'])
const TEXT_EXTS = new Set(['txt', 'md', 'markdown'])

/** Classify a filename by its extension into a rendering strategy. */
export function sourceKind(filename: string): SourceKind {
  const ext = filename.toLowerCase().split('.').pop() ?? ''
  if (ext === 'pdf') return 'pdf'
  if (HTML_EXTS.has(ext)) return 'html'
  if (TEXT_EXTS.has(ext)) return 'text'
  if (ext === 'docx') return 'docx'
  return 'other'
}
