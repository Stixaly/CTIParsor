import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
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
