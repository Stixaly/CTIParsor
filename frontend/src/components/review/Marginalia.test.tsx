import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import Marginalia from './Marginalia'
import { IMPORTED_TITLE } from './MarginaliaCard'
import { ENRICHMENT_BADGE } from './tokens'
import type { Entity } from '../../types'

const entity = (id: string, over: Partial<Entity> = {}): Entity => ({
  id, job_id: 'job-1', value: id, entity_type: 'malware', context: '', confidence: 0.9,
  mitre_id: null, accepted: null, source: 'llm',
  ...over,
})

// One row of each view, and the two imported kinds.
const ENTITIES: Entity[] = [
  entity('WellMess', { enrichment_status: 'new' }),
  entity('APT29', { entity_type: 'threat_actor', enrichment_status: 'matched' }),
  entity('Emotet', { enrichment_status: 'baseline_in_text', accepted: true, decision_origin: 'baseline_stix' }),
  entity('Ryuk', { enrichment_status: 'baseline_only', accepted: true, decision_origin: 'baseline_stix' }),
]

function renderMarginalia(entities: Entity[], over: Record<string, unknown> = {}) {
  const props = {
    entities, focusedId: null, setFocusedId: vi.fn(),
    onAccept: vi.fn(), onReject: vi.fn(), onReset: vi.fn(), onChangeType: vi.fn(),
    sortMode: 'type' as const, setSortMode: vi.fn(),
    ...over,
  }
  render(<Marginalia {...props} />)
  return props
}

const valueOf = (value: string) => screen.queryByRole('button', { name: value })

describe('Marginalia — the STIX bundle filter (ADR-0090)', () => {
  it('shows the filter only when some row has a bundle status', () => {
    renderMarginalia([entity('Plain')])
    expect(screen.queryByRole('group', { name: 'Filter by STIX bundle' })).toBeNull()
  })

  it('counts each view on its segment', () => {
    renderMarginalia(ENTITIES)
    expect(screen.getByRole('button', { name: 'Any source 4' })).toBeTruthy()
    expect(screen.getByRole('button', { name: '+ New 1' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'In STIX 2' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'STIX only 1' })).toBeTruthy()
  })

  it('shows only the cards of the chosen view', async () => {
    renderMarginalia(ENTITIES)
    expect(valueOf('WellMess')).toBeTruthy()
    expect(valueOf('Ryuk')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: '+ New 1' }))
    expect(valueOf('WellMess')).toBeTruthy()
    expect(valueOf('APT29')).toBeNull()
    expect(valueOf('Emotet')).toBeNull()
    expect(valueOf('Ryuk')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'In STIX 2' }))
    expect(valueOf('WellMess')).toBeNull()
    expect(valueOf('APT29')).toBeTruthy()
    expect(valueOf('Emotet')).toBeTruthy()
    expect(valueOf('Ryuk')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'STIX only 1' }))
    expect(valueOf('Ryuk')).toBeTruthy()
    expect(valueOf('Emotet')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Any source 4' }))
    expect(valueOf('WellMess')).toBeTruthy()
    expect(valueOf('Ryuk')).toBeTruthy()
  })

  it('leaves the header count as the whole list', () => {
    renderMarginalia(ENTITIES)
    fireEvent.click(screen.getByRole('button', { name: '+ New 1' }))
    expect(screen.getByText('(4)')).toBeTruthy()
  })
})

describe('Marginalia — badges and imported rows (ADR-0090)', () => {
  it('labels each badge, with its title', () => {
    renderMarginalia(ENTITIES)
    expect(screen.getByText(ENRICHMENT_BADGE.new.label).getAttribute('title'))
      .toBe(ENRICHMENT_BADGE.new.title)
    const inStix = screen.getAllByText(ENRICHMENT_BADGE.in_stix.label)
    expect(inStix).toHaveLength(2)
    inStix.forEach(b => expect(b.getAttribute('title')).toBe(ENRICHMENT_BADGE.in_stix.title))
    expect(screen.getByText(ENRICHMENT_BADGE.stix_only.label).getAttribute('title'))
      .toBe(ENRICHMENT_BADGE.stix_only.title)
  })

  it('shows no badge on a row with no bundle status', () => {
    renderMarginalia([entity('Plain')])
    expect(screen.queryByText(ENRICHMENT_BADGE.new.label)).toBeNull()
    expect(screen.queryByText(ENRICHMENT_BADGE.in_stix.label)).toBeNull()
    expect(screen.queryByText(ENRICHMENT_BADGE.stix_only.label)).toBeNull()
  })

  it('disables Change type on an imported row, and keeps it on matched and new rows', () => {
    renderMarginalia(ENTITIES)
    const disabled = screen.getAllByTitle(IMPORTED_TITLE)
    expect(disabled).toHaveLength(2)
    disabled.forEach(b => expect(b).toBeDisabled())

    const enabled = screen.getAllByTitle('Change type')
    expect(enabled).toHaveLength(2)
    enabled.forEach(b => expect(b).toBeEnabled())
  })

  it('keeps accept and reject on an imported row', () => {
    renderMarginalia(ENTITIES)
    expect(screen.getAllByTitle('Accept (A)')).toHaveLength(4)
    expect(screen.getAllByTitle('Reject (R)')).toHaveLength(4)
  })

  it('passes a click on a row to setFocusedId with its id', () => {
    const props = renderMarginalia(ENTITIES)
    fireEvent.click(screen.getByRole('button', { name: 'Ryuk' }))
    expect(props.setFocusedId).toHaveBeenCalledWith('Ryuk')
  })
})
