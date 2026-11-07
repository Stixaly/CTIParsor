import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import InlineHoverChip from './InlineHoverChip'
import { IMPORTED_TITLE } from './MarginaliaCard'
import type { Entity } from '../../types'

// An imported row (ADR-0090) keeps its type: the server answers 409, so the chip's
// Change type control is off and says why, as the margin card's does.

const ent = (over: Partial<Entity> = {}): Entity => ({
  id: 'e1', job_id: 'job-1', value: 'APT29', entity_type: 'ttp', context: '', confidence: 0.9,
  mitre_id: null, accepted: null, source: 'llm', ...over,
})

function renderChip(entity: Entity) {
  return render(
    <InlineHoverChip
      entity={entity} x={100} y={200}
      onAccept={vi.fn()} onReject={vi.fn()} onReset={vi.fn()} onOpen={vi.fn()} onChangeType={vi.fn()}
      onEnterChip={vi.fn()} onLeaveChip={vi.fn()}
    />,
  )
}

describe('InlineHoverChip — imported rows (ADR-0090)', () => {
  it.each(['baseline_in_text', 'baseline_only'] as const)('turns Change type off for an imported row (%s), and says why', status => {
    renderChip(ent({ enrichment_status: status }))

    expect(screen.getByTitle(IMPORTED_TITLE)).toBeDisabled()
    expect(screen.getByTitle('Accept (A)')).toBeEnabled()
    expect(screen.getByTitle('Reject (R)')).toBeEnabled()
  })

  it('keeps Change type on for a row the analyst can retype', () => {
    renderChip(ent({ enrichment_status: 'new' }))

    expect(screen.getByTitle('Change type')).toBeEnabled()
  })
})

// #558: the type menu closes on Escape, on a press outside the chip, and when the chip moves to another entity.
describe('InlineHoverChip — type menu closes (#558)', () => {
  const openMenu = () => fireEvent.click(screen.getByTitle('Change type'))
  const menuIsOpen = () => screen.queryByText('Change type') !== null

  it('closes the type menu on Escape', () => {
    renderChip(ent())
    openMenu()
    expect(menuIsOpen()).toBe(true)

    fireEvent.keyDown(document.body, { key: 'Escape' })
    expect(menuIsOpen()).toBe(false)
  })

  it('closes the type menu on a press outside the chip', () => {
    renderChip(ent())
    openMenu()

    fireEvent.mouseDown(document.body)
    expect(menuIsOpen()).toBe(false)
  })

  it('keeps the type menu open on a press inside the chip', () => {
    renderChip(ent())
    openMenu()

    fireEvent.mouseDown(screen.getByText('Change type'))
    expect(menuIsOpen()).toBe(true)
  })

  it('closes the type menu when the chip moves to another entity', () => {
    const { rerender } = renderChip(ent())
    openMenu()
    expect(menuIsOpen()).toBe(true)

    rerender(
      <InlineHoverChip
        entity={ent({ id: 'e2', value: 'Emotet' })} x={100} y={200}
        onAccept={vi.fn()} onReject={vi.fn()} onReset={vi.fn()} onOpen={vi.fn()} onChangeType={vi.fn()}
        onEnterChip={vi.fn()} onLeaveChip={vi.fn()}
      />,
    )
    expect(menuIsOpen()).toBe(false)
  })
})
