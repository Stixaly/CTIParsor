import { describe, it, expect } from 'vitest'
import { sourceKind } from './sourceKind'

describe('sourceKind', () => {
  it('classifies PDF', () => {
    expect(sourceKind('report.pdf')).toBe('pdf')
    expect(sourceKind('REPORT.PDF')).toBe('pdf')
  })

  it('classifies HTML', () => {
    expect(sourceKind('page.html')).toBe('html')
    expect(sourceKind('page.htm')).toBe('html')
  })

  it('classifies plain text and markdown', () => {
    expect(sourceKind('notes.txt')).toBe('text')
    expect(sourceKind('README.md')).toBe('text')
    expect(sourceKind('README.markdown')).toBe('text')
  })

  it('classifies DOCX', () => {
    expect(sourceKind('brief.docx')).toBe('docx')
  })

  it('falls back to "other" for unknown or extensionless names', () => {
    expect(sourceKind('archive.zip')).toBe('other')
    expect(sourceKind('noextension')).toBe('other')
  })

  it('handles multi-dot filenames by using the final extension', () => {
    expect(sourceKind('apt29.report.final.pdf')).toBe('pdf')
    expect(sourceKind('threat.intel.2024.md')).toBe('text')
  })
})
