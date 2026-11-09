import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest'
import { render } from '@testing-library/react'
import DocumentReader from './DocumentReader'
import type { Entity, Relationship } from '../../types'

// #629: the arrow for a relationship must be drawn even when the document shows
// the IoC defanged ("evil[.]com") while the entity value is "evil.com".

const ent = (over: Partial<Entity>): Entity => ({
  job_id: 'j1',
  context: '',
  confidence: 1,
  mitre_id: null,
  accepted: true,
  source: 'ioc',
  ...over,
} as Entity)

const evil = ent({ id: 'e1', value: 'evil.com', entity_type: 'domain' })
const ip = ent({ id: 'e2', value: '203.0.113.7', entity_type: 'ipv4' })

const rel: Relationship = {
  id: 'r1',
  job_id: 'j1',
  source_value: 'evil.com',
  target_value: '203.0.113.7',
  relationship_type: 'communicates_with',
  confidence: 1,
  accepted: true,
  evidence_text: null,
} as Relationship

const TEXT = 'The actor used evil[.]com to reach 203.0.113.7 during the campaign.'

// jsdom has no layout: give the document and each mark a fixed box, keyed by entity id.
const rectFor = (el: Element) => {
  let left = 0, top = 0, width = 0, height = 0
  if (el.classList.contains('doc')) { width = 800; height = 600 }
  if (el.tagName === 'MARK') {
    height = 16
    if (el.getAttribute('data-eid') === 'e1') { left = 100; top = 100; width = 80 }
    if (el.getAttribute('data-eid') === 'e2') { left = 300; top = 200; width = 100 }
  }
  return { left, top, width, height, right: left + width, bottom: top + height, x: left, y: top, toJSON() { return this } } as DOMRect
}

describe('RelationshipOverlay — deobfuscated IoC arrows (#629)', () => {
  const originalRect = HTMLElement.prototype.getBoundingClientRect
  const originalRO = (globalThis as { ResizeObserver?: unknown }).ResizeObserver

  beforeAll(() => {
    HTMLElement.prototype.getBoundingClientRect = function () { return rectFor(this) }
    Element.prototype.scrollIntoView = vi.fn()
    ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
  })

  afterAll(() => {
    HTMLElement.prototype.getBoundingClientRect = originalRect
    ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver = originalRO
  })

  const renderReader = (focusedRelId?: string | null) => render(
    <DocumentReader
      text={TEXT}
      entities={[evil, ip]}
      highlightStyle="underline"
      focusedId={null}
      setFocusedId={() => {}}
      setHoverEntity={() => {}}
      onAccept={() => {}}
      onReject={() => {}}
      onReset={() => {}}
      onChangeType={() => {}}
      onCreate={() => {}}
      onMarkShiftClick={() => {}}
      onMarkDragStart={() => {}}
      onSelectionRelate={() => {}}
      relEvidence={[]}
      relsForOverlay={[rel]}
      showRelArrows={true}
      focusedRelId={focusedRelId}
    />,
  )

  it('shows the mark text defanged while the entity value is refanged', () => {
    const { container } = renderReader()
    const mark = container.querySelector('mark[data-eid="e1"]')
    expect(mark?.textContent).toBe('evil[.]com')
  })

  it('draws a path for a relationship whose source is a defanged mark', () => {
    const { container } = renderReader()
    const paths = container.querySelectorAll('svg.rel-overlay g.rel-arrow path')
    expect(paths.length).toBe(1)
    expect(paths[0].getAttribute('d')).toMatch(/^M /)
  })

  it('marks the arrow of focusedRelId as focused', () => {
    const { container } = renderReader('r1')
    expect(container.querySelector('g.rel-arrow.focused')).not.toBeNull()
  })

  it('draws no focused arrow when focusedRelId is null', () => {
    const { container } = renderReader(null)
    expect(container.querySelectorAll('svg.rel-overlay g.rel-arrow path').length).toBe(1)
    expect(container.querySelector('g.rel-arrow.focused')).toBeNull()
  })
})
