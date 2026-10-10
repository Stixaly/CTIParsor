import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import TypeRail from './TypeRail'
import type { Entity } from '../../types'

const ent = (id: string, over: Partial<Entity> = {}): Entity => ({
  id, job_id: 'job-1', value: id, entity_type: 'ttp', context: '', confidence: 0.9,
  mitre_id: null, accepted: null, source: 'llm', ...over,
})

const noop = () => {}

function renderRail(entities: Entity[]) {
  return render(
    <TypeRail entities={entities} activeTypes={[]} toggleType={noop}
              onAcceptAllOfType={noop} onRejectAllOfType={noop} />,
  )
}

describe('TypeRail — rows held for review (ADR-0082)', () => {
  it("counts a held row out of its type's accept, and says where to accept it", () => {
    renderRail([ent('a'), ent('b', { held_reason: 'selection call failed' })])
    const accept = screen.getByText('✓ 1')
    expect(accept.getAttribute('title')).toBe(
      'Accept all 1 pending TTP (1 held for review: accept those on their own cards)')
    expect(screen.getByTitle('Reject all 2 pending TTP')).toBeTruthy()
  })

  it('offers no accept for a type whose only pending rows are held', () => {
    renderRail([ent('b', { held_reason: 'selection call failed' })])
    expect(screen.queryByText(/^✓/)).toBeNull()
    expect(screen.getByTitle('Reject all 1 pending TTP')).toBeTruthy()
  })
})
