/**
 * useMitreSearch reads the ATT&CK index of the release the API runs
 * (GET /api/attack/index, ADR-0087), not a static copy: on 20.0 it finds the
 * techniques 20.0 added.
 */
import { afterEach, describe, it, expect, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'

import { useMitreSearch } from './useMitreSearch'

const EXECUTION = { id: 'TA0002', name: 'Execution', domain: 'enterprise-attack', shortname: 'execution' }
const T1059 = { id: 'T1059', name: 'Command and Scripting Interpreter', domain: 'enterprise-attack', tactics: ['execution'] }
// New in ATT&CK v20.0.
const T1698 = { id: 'T1698', name: 'Indirect Prompt Injection', domain: 'enterprise-attack', tactics: ['execution'] }

function serve(release: string, techniques: object[]) {
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
    ok: true, status: 200, headers: new Headers({ 'X-Attack-Release': release }),
    json: () => Promise.resolve({ tactics: [EXECUTION], techniques }),
  })))
}

function render() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  )
  return { qc, ...renderHook(() => useMitreSearch(), { wrapper }) }
}

describe('useMitreSearch', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('searches the index the API serves, on ATT&CK 20.0', async () => {
    serve('20.0', [T1059, T1698])
    const { result } = render()
    await waitFor(() => expect(result.current.ready).toBe(true))
    expect(vi.mocked(fetch)).toHaveBeenCalledWith('/api/attack/index')
    expect(result.current.release).toBe('20.0')
    expect(result.current.search('T1698').map(e => e.id)).toEqual(['T1698'])
    expect(result.current.search('prompt injection').map(e => e.id)).toEqual(['T1698'])
  })

  it('finds no T1698 on the default track, where it does not exist', async () => {
    serve('19.2', [T1059])
    const { result } = render()
    await waitFor(() => expect(result.current.ready).toBe(true))
    expect(result.current.release).toBe('19.2')
    expect(result.current.search('T1698')).toEqual([])
    // Tactics first among the id matches, then by name.
    expect(result.current.search('t').map(e => e.id)).toEqual(['TA0002', 'T1059'])
  })

  it('is not ready, and finds nothing, when the index cannot be fetched', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: false, status: 404, statusText: 'Not Found',
      text: () => Promise.resolve('{"detail":"ATT&CK 20.0 has no mitre_index.json"}'),
    })))
    const { qc, result } = render()
    // Failed, not still loading: both leave `ready` false.
    await waitFor(() => expect(qc.getQueryState(['attack-index'])?.status).toBe('error'))
    expect(result.current.ready).toBe(false)
    expect(result.current.release).toBeNull()
    expect(result.current.search('T1059')).toEqual([])
  })
})
