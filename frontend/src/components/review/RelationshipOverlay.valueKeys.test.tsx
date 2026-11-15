import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest'
import { render } from '@testing-library/react'
import DocumentReader from './DocumentReader'
import type { Entity, Relationship } from '../../types'

// The arrows are keyed by entity value.  A value that is a property name of
// Object.prototype ("constructor", "__proto__") must still get its own box, not
// the inherited Object property, or the arrow is drawn with NaN coordinates.

const ent = (over: Partial<Entity>): Entity => ({
  job_id: 'j1',
  context: '',
  confidence: 1,
  mitre_id: null,
  accepted: true,
  source: 'test',
  ...over,
} as Entity)

const ip = ent({ id: 'e2', value: '203.0.113.7', entity_type: 'ipv4' })

const rectFor = (el: Element) => {
  let left = 0, top = 0, width = 0, height = 0
  if (el.classList.contains('doc')) { width = 800; height = 600 }
  if (el.tagName === 'MARK') {
    height = 16
    if (el.getAttribute('data-eid') === 'e3') { left = 100; top = 100; width = 80 }
    if (el.getAttribute('data-eid') === 'e2') { left = 300; top = 200; width = 100 }
  }
  return { left, top, width, height, right: left + width, bottom: top + height, x: left, y: top, toJSON() { return this } } as DOMRect
}

describe('RelationshipOverlay — values named like Object.prototype keys', () => {
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

  it.each(['constructor', '__proto__'])('draws a finite arrow from an entity named "%s" (#885)', value => {
    const named = ent({ id: 'e3', value, entity_type: 'malware' })
    const rel: Relationship = {
      id: 'r1', job_id: 'j1', source_value: value, target_value: '203.0.113.7',
      relationship_type: 'communicates_with', confidence: 1, accepted: true, evidence_text: null,
    } as Relationship
    const { container } = render(
      <DocumentReader
        text={`The ${value} reached 203.0.113.7 today.`}
        entities={[ip, named]}
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
        focusedRelId={null}
      />,
    )
    const paths = container.querySelectorAll('svg.rel-overlay g.rel-arrow path')
    expect(paths.length).toBe(1)
    expect(paths[0].getAttribute('d')).not.toMatch(/NaN/)
  })
})
