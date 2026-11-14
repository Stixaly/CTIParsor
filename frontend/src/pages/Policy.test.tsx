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

  it('a reset made while a debounced save waits stays the last PUT (#498, #544)', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      api.putRelationshipPolicy.mockResolvedValue(undefined)
      renderPolicy()
      fireEvent.click(await screen.findByRole('button', { name: /Full auto/ }))   // debounce armed
      fireEvent.click(screen.getByRole('button', { name: 'Reset' }))              // before 1.5 s
      await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
      await waitFor(() => expect(api.putRelationshipPolicy).toHaveBeenCalled())
      await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
      // The timer armed by "Full auto" must not send `auto` after the reset.
      expect(api.putRelationshipPolicy).toHaveBeenCalledTimes(1)
      const calls = api.putRelationshipPolicy.mock.calls
      const last = calls[calls.length - 1][0]
      expect(last.global).toBe('enforce')
      expect(last.rules.length).toBeGreaterThan(0)
    } finally {
      vi.useRealTimers()
    }
  })

  it('an immediate save cancels the debounced save it overlaps (#544)', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      api.putRelationshipPolicy.mockResolvedValue(undefined)
      renderPolicy()
      fireEvent.click(await screen.findByRole('button', { name: /Full auto/ }))   // debounce armed
      fireEvent.click(screen.getByRole('button', { name: 'Sequential' }))         // immediate save
      await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
      await waitFor(() => expect(api.putRelationshipPolicy).toHaveBeenCalledTimes(1))
      expect(api.putRelationshipPolicy.mock.calls[0][0]).toMatchObject({
        global: 'auto', pin_budget_mode: 'sequential',
      })
      await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
      expect(api.putRelationshipPolicy).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('the Import/Export download is attached to the body while clicked (#546)', async () => {
    const urls = { created: [] as string[], revoked: [] as string[] }
    const clicked: Array<{ attached: boolean; download: string }> = []
    URL.createObjectURL = vi.fn(() => { urls.created.push('blob:policy'); return 'blob:policy' })
    URL.revokeObjectURL = vi.fn((u: string) => { urls.revoked.push(u) })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push({ attached: document.body.contains(this), download: this.download })
    })
    try {
      renderPolicy()
      fireEvent.click(await screen.findByRole('button', { name: /Import \/ Export/ }))
      fireEvent.click(screen.getByRole('button', { name: /Download/ }))
      expect(clicked).toEqual([{ attached: true, download: 'relationship-policy.json' }])
      expect(document.querySelectorAll('a[download]').length).toBe(0)           // removed again
      await waitFor(() => expect(urls.revoked).toEqual(['blob:policy']))
    } finally {
      click.mockRestore()
    }
  })
})

// #814: the stored policy arrives after the page has rendered. Until it does,
// nothing may be edited, or its answer overwrites the edit.
describe('Policy page — before the stored policy arrives (#814)', () => {
  it('disables the mode switch, Reset and the rule editor until the GET answers', async () => {
    let answer: (v: unknown) => void = () => {}
    api.getRelationshipPolicy.mockImplementation(() => new Promise(r => { answer = r }))
    renderPolicy()
    expect(screen.getByRole('button', { name: /Full auto/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: /Enforce my model/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Reset' })).toBeDisabled()
    expect(document.querySelector('[inert]')).not.toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /Full auto/ }))   // no-op before the answer
    await act(async () => { answer(STORED) })
    await waitFor(() => expect(screen.getByRole('button', { name: /Full auto/ })).toBeEnabled())
    expect(screen.getByRole('button', { name: 'Reset' })).toBeEnabled()
    expect(document.querySelector('[inert]')).toBeNull()
    expect(api.putRelationshipPolicy).not.toHaveBeenCalled()
  })
})

// #814, the other save paths: the budget and evidence controls and the import
// Apply button each save the page's rules, so each waits for the stored policy too.
describe('Policy page — budget, evidence and import before the stored policy arrives (#814)', () => {
  it('disables the budget, evidence and import controls until the GET answers', async () => {
    let answer: (v: unknown) => void = () => {}
    api.getRelationshipPolicy.mockImplementation(() => new Promise(r => { answer = r }))
    renderPolicy()
    expect(screen.getByRole('button', { name: 'Sequential' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Fair share' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Off' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Wide' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: /Import \/ Export/ }))
    fireEvent.click(screen.getByRole('button', { name: 'import' }))
    fireEvent.change(document.querySelector('textarea') as HTMLTextAreaElement, {
      target: { value: JSON.stringify({ rules: [{ src: 'malware', verb: 'uses', tgt: 'tool' }] }) },
    })
    expect(screen.getByRole('button', { name: 'Apply policy' })).toBeDisabled()
    await act(async () => { answer(STORED) })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Sequential' })).toBeEnabled())
    expect(screen.getByRole('button', { name: 'Off' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Wide' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Apply policy' })).toBeEnabled()
    expect(api.putRelationshipPolicy).not.toHaveBeenCalled()
  })

  it('says why nothing is editable when the GET fails, and retries on demand', async () => {
    api.getRelationshipPolicy.mockRejectedValueOnce(new Error('network down'))
    renderPolicy()
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be loaded')
    expect(screen.getByRole('button', { name: /Full auto/ })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByRole('button', { name: /Full auto/ })).toBeEnabled())
    expect(api.getRelationshipPolicy).toHaveBeenCalledTimes(2)
    expect(screen.queryByRole('alert')).toBeNull()
  })
})

// #815: a rule whose source type is in no group was counted but never shown, and
// a non-string field in an imported or stored rule crashed the editor.
describe('Policy page — rule types and malformed fields (#815)', () => {
  it('shows a rule whose source is network-traffic', async () => {
    api.getRelationshipPolicy.mockResolvedValue({
      ...STORED, rules: [{ src: 'network-traffic', verb: 'related-to', tgt: 'url', mode: 'pin', enabled: true }],
    })
    renderPolicy()
    expect(await screen.findByText('Net Traffic')).toBeInTheDocument()
  })

  it('files a rule whose source type is in no group under Other', async () => {
    api.getRelationshipPolicy.mockResolvedValue({
      ...STORED, rules: [{ src: 'x-custom', verb: 'related-to', tgt: 'url', mode: 'pin', enabled: true }],
    })
    renderPolicy()
    expect(await screen.findByText('Other')).toBeInTheDocument()
  })

  it('rejects an imported rule with non-string fields without crashing', async () => {
    renderPolicy()
    fireEvent.click(await screen.findByRole('button', { name: /Import \/ Export/ }))
    fireEvent.click(screen.getByRole('button', { name: 'import' }))
    fireEvent.change(document.querySelector('textarea') as HTMLTextAreaElement, {
      target: { value: JSON.stringify({ rules: [{ src: 123, tgt: 'file', verb: 456 }] }) },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Apply policy' }))
    expect(await screen.findByText(/no valid rules/)).toBeInTheDocument()
    expect(api.putRelationshipPolicy).not.toHaveBeenCalled()
  })

  it('a search over a stored rule with a non-string verb does not throw', async () => {
    api.getRelationshipPolicy.mockResolvedValue({
      ...STORED, rules: [{ src: 'malware', verb: 456, tgt: 'file', mode: 'pin', enabled: true }],
    })
    renderPolicy()
    expect(await screen.findByText('Capability')).toBeInTheDocument()
    fireEvent.change(screen.getByPlaceholderText('Filter by type or verb…'), { target: { value: 'zzz' } })
    expect(screen.getByText('No rules match "zzz".')).toBeInTheDocument()
  })
})
