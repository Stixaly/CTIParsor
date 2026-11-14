import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { FINALIZE_DEBOUNCE_MS, useDebouncedFinalize } from './useDebouncedFinalize'

const api = vi.hoisted(() => ({ finalizeJobQuick: vi.fn() }))
vi.mock('../api/client', () => ({
  finalizeJobQuick: api.finalizeJobQuick,
  BundleRefusedError: class extends Error {},
}))

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

beforeEach(() => { vi.useFakeTimers(); api.finalizeJobQuick.mockReset() })
afterEach(() => { vi.useRealTimers() })

describe('useDebouncedFinalize', () => {
  it('flush waits for the rebuild already in flight (#292)', async () => {
    let resolve!: () => void
    api.finalizeJobQuick.mockImplementation(() => new Promise<void>(r => { resolve = r }))
    const { result } = renderHook(() => useDebouncedFinalize('job-1'), { wrapper })
    act(() => result.current.markDirty())
    await act(async () => { vi.advanceTimersByTime(FINALIZE_DEBOUNCE_MS) })
    expect(api.finalizeJobQuick).toHaveBeenCalledTimes(1)

    let settled = false
    const flushed = result.current.flush().then(() => { settled = true })
    await act(async () => { await Promise.resolve() })
    expect(settled).toBe(false)
    await act(async () => { resolve(); await flushed })
    expect(settled).toBe(true)
    expect(result.current.pending).toBe(false)
  })

  it('an edit made during a rebuild stays pending and is rebuilt by flush', async () => {
    const resolvers: Array<() => void> = []
    api.finalizeJobQuick.mockImplementation(() => new Promise<void>(r => { resolvers.push(r) }))
    const { result } = renderHook(() => useDebouncedFinalize('job-1'), { wrapper })
    act(() => result.current.markDirty())
    await act(async () => { vi.advanceTimersByTime(FINALIZE_DEBOUNCE_MS) })
    act(() => result.current.markDirty())                     // a newer edit, timer armed again
    await act(async () => { resolvers[0]() })
    expect(result.current.pending).toBe(true)

    const flushed = result.current.flush()
    await act(async () => { await Promise.resolve(); await Promise.resolve() })
    expect(api.finalizeJobQuick).toHaveBeenCalledTimes(2)
    await act(async () => { resolvers[1](); await flushed })
    expect(result.current.pending).toBe(false)
  })

  // Guard (#821): rebuild() calls that pile up during a request run one after the other.
  it('never has two rebuilds in flight when rebuild() is called again during one', async () => {
    const resolvers: Array<() => void> = []
    let open = 0
    let most = 0
    api.finalizeJobQuick.mockImplementation(() => {
      open += 1
      most = Math.max(most, open)
      return new Promise<void>(r => { resolvers.push(() => { open -= 1; r() }) })
    })
    const { result } = renderHook(() => useDebouncedFinalize('job-1'), { wrapper })
    act(() => result.current.markDirty())
    await act(async () => { vi.advanceTimersByTime(FINALIZE_DEBOUNCE_MS) })
    expect(api.finalizeJobQuick).toHaveBeenCalledTimes(1)

    act(() => { void result.current.rebuild(); void result.current.rebuild(); void result.current.rebuild() })
    await act(async () => { for (let k = 0; k < 10; k++) await Promise.resolve() })
    expect(api.finalizeJobQuick).toHaveBeenCalledTimes(1)

    for (let n = 0; n < 4; n++) {
      await act(async () => { resolvers[n]() })
      await act(async () => { for (let k = 0; k < 10; k++) await Promise.resolve() })
      expect(most).toBe(1)
    }
    expect(api.finalizeJobQuick).toHaveBeenCalledTimes(4)
  })
})
