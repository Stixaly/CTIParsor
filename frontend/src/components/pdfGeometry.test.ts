import { describe, it, expect } from 'vitest'
import { itemMarks, anchorMarkup, mostVisiblePage, fitWidthScale } from './pdfGeometry'

const ent = (id: string, value: string, accepted: boolean | null = null) =>
  ({ id, value, entity_type: 'malware', accepted })

describe('itemMarks', () => {
  it('keys occurrences by the item index, marked-content entries included', () => {
    const items = [
      { type: 'beginMarkedContent' },
      { str: 'APT29 used ', hasEOL: false },
      { str: 'WellMess', hasEOL: true },
    ]
    const m = itemMarks(items, [ent('a', 'APT29'), ent('w', 'WellMess')])
    expect(m.get(1)).toEqual([{ start: 0, end: 5, entityId: 'a' }])
    expect(m.get(2)).toEqual([{ start: 0, end: 8, entityId: 'w' }])
    expect(m.has(0)).toBe(false)
  })

  it('splits an occurrence across the runs it spans', () => {
    const m = itemMarks([{ str: 'Cobalt ' }, { str: 'Strike beacon' }], [ent('c', 'Cobalt Strike')])
    expect(m.get(0)).toEqual([{ start: 0, end: 7, entityId: 'c' }])
    expect(m.get(1)).toEqual([{ start: 0, end: 6, entityId: 'c' }])
  })

  it('does not anchor rejected entities', () => {
    expect(itemMarks([{ str: 'APT29' }], [ent('a', 'APT29', false)]).size).toBe(0)
  })
})

describe('anchorMarkup', () => {
  it('wraps each occurrence and escapes the text around it', () => {
    expect(anchorMarkup('<b> APT29 & co', [{ start: 4, end: 9, entityId: 'a"1' }]))
      .toBe('&lt;b&gt; <mark class="pdf-anchor" data-eid="a&quot;1">APT29</mark> &amp; co')
  })

  it('returns plain escaped text when nothing matches', () => {
    expect(anchorMarkup('a < b', undefined)).toBe('a &lt; b')
  })
})

describe('mostVisiblePage', () => {
  it('picks the page with the most visible height', () => {
    expect(mostVisiblePage(new Map([[1, 589], [2, 55]]))).toBe(1)
    expect(mostVisiblePage(new Map([[1, 120], [2, 700], [3, 0]]))).toBe(2)
  })

  it('prefers the earlier page on a tie and returns null when nothing shows', () => {
    expect(mostVisiblePage(new Map([[3, 400], [2, 400]]))).toBe(2)
    expect(mostVisiblePage(new Map([[1, 0]]))).toBeNull()
  })
})

describe('fitWidthScale', () => {
  it('fits the page width, or its height once rotated a quarter turn', () => {
    expect(fitWidthScale(842, { w: 842, h: 595 }, 0)).toBe(1)
    expect(fitWidthScale(595, { w: 842, h: 595 }, 90)).toBe(1)
    expect(fitWidthScale(700, { w: 842, h: 595 }, 0)).toBe(0.83)
  })

  it('stays within bounds and falls back to 1 without a size', () => {
    expect(fitWidthScale(10_000, { w: 100, h: 100 }, 0)).toBe(3)
    expect(fitWidthScale(0, { w: 100, h: 100 }, 0)).toBe(1)
    expect(fitWidthScale(500, null, 0)).toBe(1)
  })
})
