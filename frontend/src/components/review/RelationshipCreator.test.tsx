import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import RelationshipCreator from './RelationshipCreator'
import { suggestRelType, verbsForPair } from './tokens'
import type { Entity } from '../../types'

const entity = (id: string, value: string, entity_type: string): Entity => ({
  id, job_id: 'job-1', value, entity_type, context: '', confidence: 0.9,
  mitre_id: null, accepted: null, source: 'llm',
})

const ENTITIES: Entity[] = [
  entity('a', 'APT29', 'threat_actor'),
  entity('m', 'WellMess', 'malware'),
]

function renderCreator(entities: Entity[] = ENTITIES) {
  const props = {
    entities,
    initial: { srcId: 'a', tgtId: 'm', x: 300, y: 300 },
    onCancel: vi.fn(), onCreate: vi.fn(), onAddEntity: vi.fn(),
  }
  const view = render(<RelationshipCreator {...props} />)
  return { ...view, props }
}

const verbSelect = () => screen.getByRole('combobox') as HTMLSelectElement

const TARGET_TYPES = ['ipv4', 'vulnerability', 'campaign', 'malware', 'identity', 'tool', 'ttp']
const SUGGESTED = suggestRelType('threat_actor', 'malware')
// A verb the pair offers that is not the suggestion, if the pair has one
const CHOSEN = verbsForPair('threat_actor', 'malware').valid.find(v => v !== SUGGESTED) ?? SUGGESTED

describe('RelationshipCreator — the chosen verb (#555)', () => {
  it('has another valid verb to choose for this pair', () => {
    expect(CHOSEN).not.toBe(SUGGESTED)
  })

  it('keeps the verb the analyst chose when the entities list is refreshed', () => {
    const { rerender, props } = renderCreator()
    fireEvent.change(verbSelect(), { target: { value: CHOSEN } })
    expect(verbSelect().value).toBe(CHOSEN)

    // A refresh: same entities, new array and new objects
    rerender(<RelationshipCreator {...props} entities={ENTITIES.map(e => ({ ...e }))} />)
    expect(verbSelect().value).toBe(CHOSEN)
  })

  it('keeps the chosen verb when the new target still offers it', () => {
    const keep = TARGET_TYPES.find(t => verbsForPair('threat_actor', t).valid.includes(CHOSEN) && suggestRelType('threat_actor', t) !== CHOSEN)!
    expect(suggestRelType('threat_actor', keep)).not.toBe(CHOSEN)
    renderCreator([...ENTITIES, entity('z', 'Zed', keep)])

    fireEvent.change(verbSelect(), { target: { value: CHOSEN } })
    pickTarget('Zed')

    expect(verbSelect().value).toBe(CHOSEN)
  })

  it('suggests the verb for the pair again when the new target does not offer the chosen verb', () => {
    // A verb of this pair that some target type does not offer
    let lost: { verb: string; type: string } | undefined
    for (const verb of verbsForPair('threat_actor', 'malware').valid) {
      const type = TARGET_TYPES.find(t => !verbsForPair('threat_actor', t).valid.includes(verb))
      if (type) { lost = { verb, type }; break }
    }
    expect(lost).toBeDefined()
    const { verb, type } = lost!
    renderCreator([...ENTITIES, entity('z', 'Zed', type)])

    fireEvent.change(verbSelect(), { target: { value: verb } })
    pickTarget('Zed')

    expect(verbSelect().value).toBe(suggestRelType('threat_actor', type))
  })
})

// Clear the target chip, then pick the entity named `value` from the search
function pickTarget(value: string) {
  const clearButtons = document.querySelectorAll<HTMLButtonElement>('.rc-chip-x')
  fireEvent.click(clearButtons[clearButtons.length - 1])
  fireEvent.change(screen.getByPlaceholderText('Search entities…'), { target: { value } })
  fireEvent.mouseDown(screen.getByRole('button', { name: new RegExp(value) }))
}
