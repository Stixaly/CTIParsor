import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import MarginaliaCard from './MarginaliaCard'
import type { Entity } from '../../types'

const entity = (over: Partial<Entity> = {}): Entity => ({
  id: 'e1', job_id: 'job-1', value: 'APT29', entity_type: 'threat_actor', context: '', confidence: 0.9,
  mitre_id: null, accepted: null, source: 'llm',
  ...over,
})

function renderCard(e: Entity = entity()) {
  return render(
    <MarginaliaCard
      entity={e} collapsed={false} focused={false}
      onClick={vi.fn()} onToggleCollapse={vi.fn()}
      onAccept={vi.fn()} onReject={vi.fn()} onReset={vi.fn()} onChangeType={vi.fn()}
    />,
  )
}

const popupIsOpen = () => document.querySelector('.type-picker-popup') !== null

// #563: the "⋯" type menu closes on Escape, as it does on a click outside, a scroll and a resize.
describe('MarginaliaCard — type menu (#563)', () => {
  it('closes the type menu on Escape', () => {
    renderCard()
    fireEvent.click(screen.getByTitle('Change type'))
    expect(popupIsOpen()).toBe(true)

    fireEvent.keyDown(document, { key: 'Escape' })
    expect(popupIsOpen()).toBe(false)
  })

  it('leaves the type menu open on another key', () => {
    renderCard()
    fireEvent.click(screen.getByTitle('Change type'))

    fireEvent.keyDown(document, { key: 'Enter' })
    expect(popupIsOpen()).toBe(true)
  })

  it('closes the type menu on a click outside it', () => {
    renderCard()
    fireEvent.click(screen.getByTitle('Change type'))

    fireEvent.click(document.body)
    expect(popupIsOpen()).toBe(false)
  })
})
