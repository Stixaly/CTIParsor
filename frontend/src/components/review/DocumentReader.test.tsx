import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import DocumentReader from './DocumentReader'
import type { Entity } from '../../types'

// A SHA-256 as a narrow PDF table cell wraps it: three fragments separated by
// blank lines.  Every hash in a real extracted report looks like this — the
// stored value is de-wrapped, the document text is not.
const HASH = '2ab684d93c1553fada97188a97e78589deee2a7bacff905564f3a35a1b2c3d4e'
const WRAPPED = `${HASH.slice(0, 26)}\n\n${HASH.slice(26, 52)}\n\n${HASH.slice(52)}`

const entity = (over: Partial<Entity> = {}): Entity => ({
  id: 'e1',
  value: HASH,
  entity_type: 'sha256',
  context: '',
  confidence: 1,
  mitre_id: null,
  accepted: null,
  source: 'ioc',
  ...over,
} as Entity)

const noop = () => {}

function renderReader(
  text: string,
  entities: Entity[],
  extra: { focusedId?: string | null; onEntityNotInText?: (id: string) => void } = {},
) {
  return render(
    <DocumentReader
      text={text}
      entities={entities}
      highlightStyle="underline"
      focusedId={extra.focusedId ?? null}
      onEntityNotInText={extra.onEntityNotInText}
      setFocusedId={noop}
      setHoverEntity={noop}
      onAccept={noop}
      onReject={noop}
      onReset={noop}
      onChangeType={noop}
      onCreate={noop}
      onMarkShiftClick={noop}
      onMarkDragStart={noop}
      onSelectionRelate={noop}
      relEvidence={[]}
      relsForOverlay={[]}
      showRelArrows={false}
    />,
  )
}

describe('DocumentReader — wrapped hash highlighting', () => {
  // jsdom has no layout, so scrollIntoView is not implemented.
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn()
  })

  it('highlights each fragment of a wrapped hash, not the gaps between them', () => {
    const { container } = renderReader(`File Hash\n\n${WRAPPED}\n\nmeshagent.exe`, [entity()])
    const marks = [...container.querySelectorAll('mark')]
    expect(marks).toHaveLength(3)
    // No mark may contain whitespace: a mark spanning the wrap paints the gap
    // between the lines and, in the PDF view, the cells beside the hash.
    for (const mark of marks) {
      expect(mark.textContent).not.toMatch(/\s/)
    }
    expect(marks.map(m => m.textContent).join('')).toBe(HASH)
  })

  it('points every fragment at the same entity', () => {
    const { container } = renderReader(WRAPPED, [entity()])
    const ids = [...container.querySelectorAll('mark')].map(m => m.getAttribute('data-eid'))
    expect(ids).toEqual(['e1', 'e1', 'e1'])
  })

  it('keeps the paragraph breaks a wrapped hash sits on, and highlights inside them', () => {
    // The gaps are blank lines, so they must still break paragraphs — and each
    // fragment must stay highlighted once split.  A single range across the wrap
    // put the blank lines inside the <mark>, and the paragraph splitter (which
    // only understands plain text runs) then dropped the <mark> altogether: the
    // hash rendered as ordinary unhighlighted text with no way to click it.
    const { container } = renderReader(`File Hash\n\n${WRAPPED}\n\nmeshagent.exe`, [entity()])
    const paras = [...container.querySelectorAll('p.doc-para')]
    expect(paras.map(p => p.textContent)).toEqual([
      'File Hash',
      HASH.slice(0, 26),
      HASH.slice(26, 52),
      HASH.slice(52),
      'meshagent.exe',
    ])
    // The three hash paragraphs carry the highlight; the text rows do not.
    expect(paras.map(p => p.querySelector('mark')?.textContent ?? null)).toEqual([
      null,
      HASH.slice(0, 26),
      HASH.slice(26, 52),
      HASH.slice(52),
      null,
    ])
  })

  it('highlights a hash wrapped on blank lines at all', () => {
    // Every hash extracted from a real PDF report wraps on blank lines, so this
    // is the common case, not an edge case.
    const { container } = renderReader(WRAPPED, [entity()])
    expect(container.querySelectorAll('mark').length).toBeGreaterThan(0)
  })

  it('scrolls to the first line of a wrapped hash when the entity is focused', () => {
    // Clicking a SHA-256 in the entity rail sets focusedId; the reader must
    // scroll to the occurrence and NOT fall back to the "not found in text"
    // hint, which is what happened while the wrapped hash had no <mark>.
    const notInText = vi.fn()
    const { container } = renderReader(
      `File Hash\n\n${WRAPPED}\n\nmeshagent.exe`,
      [entity()],
      { focusedId: 'e1', onEntityNotInText: notInText },
    )
    expect(notInText).not.toHaveBeenCalled()
    const scrolled = (Element.prototype.scrollIntoView as ReturnType<typeof vi.fn>).mock
      .instances[0] as HTMLElement
    expect(scrolled.tagName).toBe('MARK')
    // The scroll target is the first fragment, so the view lands on the start
    // of the hash rather than partway through it.
    expect(scrolled.textContent).toBe(HASH.slice(0, 26))
    expect(container.querySelectorAll('mark')).toHaveLength(3)
  })

  it('reports a genuinely absent hash as not-in-text', () => {
    const notInText = vi.fn()
    renderReader('Narrative report with no indicator tables.', [entity()], {
      focusedId: 'e1',
      onEntityNotInText: notInText,
    })
    expect(notInText).toHaveBeenCalledWith('e1')
  })

  it('still highlights a contiguous hash as a single mark', () => {
    const { container } = renderReader(`File Hash: ${HASH} (SHA-256)`, [entity()])
    const marks = [...container.querySelectorAll('mark')]
    expect(marks).toHaveLength(1)
    expect(marks[0].textContent).toBe(HASH)
  })

  it('highlights stacked hashes in a column on their own rows', () => {
    const a = 'd41d8cd98f00b204e9800998ecf8427e'
    const b = '5d41402abc4b2a76b9719d911017c592'
    const { container } = renderReader(`File Hash\n\n${a}\n\n${b}\n`, [
      entity({ id: 'a', value: a, entity_type: 'md5' }),
      entity({ id: 'b', value: b, entity_type: 'md5' }),
    ])
    const marks = [...container.querySelectorAll('mark')]
    expect(marks.map(m => m.textContent)).toEqual([a, b])
    expect(marks.map(m => m.getAttribute('data-eid'))).toEqual(['a', 'b'])
  })
})
