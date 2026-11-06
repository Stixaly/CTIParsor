import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Policy from './Policy'

// The relationship policy page saves with a full PUT: two changes made close
// together must both reach the server (#354), and a change still waiting for
// its debounce must not be lost by leaving the page (#294).
const api = vi.hoisted(() => ({
  getRelationshipPolicy: vi.fn(),
  putRelationshipPolicy: vi.fn(),
  getPolicyLastRun: vi.fn(),
}))
vi.mock('../api/client', async (orig) => ({ ...(await orig<object>()), ...api }))

const STORED = {
  version: 1, global: 'enforce', rules: [], pin_budget_mode: 'fair-share',
  pin_evidence: { mode: 'cooccurrence', window: 3 }, completion: { alias: true },
}

function renderPolicy() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter><Policy /></MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  api.getRelationshipPolicy.mockReset().mockResolvedValue(STORED)
  api.getPolicyLastRun.mockReset().mockResolvedValue({ available: false })
  api.putRelationshipPolicy.mockReset()
})

describe('Policy page — saving', () => {
  it('keeps the first of two close changes in the second PUT (#354)', async () => {
    const resolvers: Array<(v: unknown) => void> = []
    api.putRelationshipPolicy.mockImplementation(body => new Promise(r => { resolvers.push(() => r(body)) }))
    renderPolicy()
    await waitFor(() => expect(api.getRelationshipPolicy).toHaveBeenCalled())
    await act(async () => { await Promise.resolve() })                 // the stored policy is in
    fireEvent.click(await screen.findByRole('button', { name: 'Sequential' }))
    await waitFor(() => expect(api.putRelationshipPolicy).toHaveBeenCalledTimes(1))
    fireEvent.click(screen.getByRole('button', { name: 'Off' }))     // while the first PUT is in flight

    await act(async () => { resolvers[0](undefined) })
    await waitFor(() => expect(api.putRelationshipPolicy).toHaveBeenCalledTimes(2))
    const second = api.putRelationshipPolicy.mock.calls[1][0]
    expect(second.pin_budget_mode).toBe('sequential')
    expect(second.pin_evidence.mode).toBe('cartesian')
    expect(second.completion).toEqual({ alias: true })                // unknown keys survive
    await act(async () => { resolvers[1](undefined) })
  })

  it('sends a change still waiting for its debounce when the page is left (#294)', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      api.putRelationshipPolicy.mockResolvedValue(undefined)
      const { unmount } = renderPolicy()
      fireEvent.click(await screen.findByRole('button', { name: /Full auto/ }))
      expect(api.putRelationshipPolicy).not.toHaveBeenCalled()
      unmount()
      await act(async () => { await vi.advanceTimersByTimeAsync(10) })
      await waitFor(() => expect(api.putRelationshipPolicy).toHaveBeenCalledTimes(1))
      expect(api.putRelationshipPolicy.mock.calls[0][0].global).toBe('auto')
      await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
      expect(api.putRelationshipPolicy).toHaveBeenCalledTimes(1)        // not twice
    } finally {
      vi.useRealTimers()
    }
  })
})
