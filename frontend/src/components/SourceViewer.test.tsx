import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { Entity } from '../types'
import SourceViewer from './SourceViewer'

// The raw-text source (txt / md) of the dispatcher, rendered through its public
// component: TextSource is not exported.

const api = vi.hoisted(() => ({ apiFetch: vi.fn() }))

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  apiFetch: api.apiFetch,
}))

const TEXT = 'The APT29 report describes a phishing campaign.'

function entity(id: string, value: string, accepted: boolean | null = null): Entity {
  return {
    id, job_id: 'job-1', value, entity_type: 'threat-actor', context: '', confidence: 0.9,
    mitre_id: null, accepted, source: 'test',
  }
}

// APT29 is in the text; Lazarus is not, so focusing it has no mark to scroll to.
const APT29 = entity('e1', 'APT29')
const LAZARUS = entity('e2', 'Lazarus')

beforeEach(() => {
  api.apiFetch.mockReset()
  api.apiFetch.mockResolvedValue({ ok: true, text: () => Promise.resolve(TEXT) })
})

describe('SourceViewer — raw text, entity not in the text (#827)', () => {
  it('notifies once for a focused entity missing from the text, not again when the entities change', async () => {
    const onEntityNotInText = vi.fn()
    const props = { url: '/files/notes.txt', filename: 'notes.txt', focusedId: 'e2', onFocusEntity: vi.fn(), onEntityNotInText }
    const { rerender } = render(<SourceViewer {...props} entities={[APT29, LAZARUS]} />)
    await screen.findByText(/describes a phishing campaign/)
    await vi.waitFor(() => expect(onEntityNotInText).toHaveBeenCalledTimes(1))

    rerender(<SourceViewer {...props} entities={[{ ...APT29, accepted: true }, LAZARUS]} />)
    rerender(<SourceViewer {...props} entities={[{ ...APT29, accepted: false }, LAZARUS]} />)

    expect(onEntityNotInText).toHaveBeenCalledTimes(1)
    expect(onEntityNotInText).toHaveBeenCalledWith('e2')
  })

  it('notifies again when the analyst focuses the missing entity once more', async () => {
    const onEntityNotInText = vi.fn()
    const props = { url: '/files/notes.txt', filename: 'notes.txt', entities: [APT29, LAZARUS], onFocusEntity: vi.fn(), onEntityNotInText }
    const { rerender } = render(<SourceViewer {...props} focusedId="e2" />)
    await screen.findByText(/describes a phishing campaign/)
    await vi.waitFor(() => expect(onEntityNotInText).toHaveBeenCalledTimes(1))

    rerender(<SourceViewer {...props} focusedId={null} />)
    rerender(<SourceViewer {...props} focusedId="e2" />)

    expect(onEntityNotInText).toHaveBeenCalledTimes(2)
  })
})
