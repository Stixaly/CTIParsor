import { describe, it, expect, vi, afterEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useSSE } from './useSSE'

const api = vi.hoisted(() => ({ checkSession: vi.fn() }))
vi.mock('../api/client', () => ({ checkSession: api.checkSession }))

// #293: five transport errors end the stream, but say nothing about the run.
class FakeEventSource {
  static last: FakeEventSource | null = null
  onerror: (() => void) | null = null
  listeners = new Map<string, (e: MessageEvent) => void>()
  closed = false
  // 0 CONNECTING, 1 OPEN, 2 CLOSED (a refused handshake, #819).
  readyState = 1
  constructor(public url: string) { FakeEventSource.last = this }
  addEventListener(type: string, fn: (e: MessageEvent) => void) { this.listeners.set(type, fn) }
  removeEventListener(type: string) { this.listeners.delete(type) }
  close() { this.closed = true }
  emit(type: string, data: object) { this.listeners.get(type)?.({ data: JSON.stringify(data) } as MessageEvent) }
}

afterEach(() => { vi.unstubAllGlobals(); api.checkSession.mockClear() })

describe('useSSE', () => {
  it('marks a stream given up after repeated errors as lost, not as a finished run', () => {
    vi.stubGlobal('EventSource', FakeEventSource)
    const { result } = renderHook(() => useSSE('job-1'))
    act(() => { for (let i = 0; i < 5; i++) FakeEventSource.last!.onerror!() })
    expect(result.current.done).toBe(true)
    expect(result.current.lost).toBe(true)
    expect(FakeEventSource.last!.closed).toBe(true)
  })

  // #819: a refused handshake is CLOSED and fires one error; no retry comes, so it ends at once.
  it('a refused stream (CLOSED on the first error) is lost at once, not after five errors (#819)', () => {
    vi.stubGlobal('EventSource', FakeEventSource)
    const { result } = renderHook(() => useSSE('job-1'))
    FakeEventSource.last!.readyState = 2
    act(() => { FakeEventSource.last!.onerror!() })
    expect(result.current.done).toBe(true)
    expect(result.current.lost).toBe(true)
    expect(FakeEventSource.last!.closed).toBe(true)
    expect(api.checkSession).toHaveBeenCalledTimes(1)
  })

  it('a done event is a finished run', () => {
    vi.stubGlobal('EventSource', FakeEventSource)
    const { result } = renderHook(() => useSSE('job-1'))
    act(() => { FakeEventSource.last!.onerror!(); FakeEventSource.last!.emit('done', { status: 'completed' }) })
    expect(result.current.done).toBe(true)
    expect(result.current.lost).toBe(false)
  })
})

// #548: the job id is one encoded path segment, and no id resets the stream.
describe('useSSE follows the job id (#548)', () => {
  it('encodes the job id in the progress URL', () => {
    vi.stubGlobal('EventSource', FakeEventSource)
    renderHook(() => useSSE('a/b c'))
    expect(FakeEventSource.last!.url).toBe('/api/jobs/a%2Fb%20c/progress')
  })

  it('forgets the previous job\'s events and done state when the id goes back to null', () => {
    vi.stubGlobal('EventSource', FakeEventSource)
    const { result, rerender } = renderHook(
      ({ jobId }: { jobId: string | null }) => useSSE(jobId),
      { initialProps: { jobId: 'job-1' as string | null } },
    )
    act(() => { FakeEventSource.last!.emit('done', { status: 'completed' }) })
    expect(result.current.done).toBe(true)

    rerender({ jobId: null })
    expect(result.current.done).toBe(false)
    expect(result.current.events).toEqual([])
  })
})
