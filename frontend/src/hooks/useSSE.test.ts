import { describe, it, expect, vi, afterEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useSSE } from './useSSE'

// #293: five transport errors end the stream, but say nothing about the run.
class FakeEventSource {
  static last: FakeEventSource | null = null
  onerror: (() => void) | null = null
  listeners = new Map<string, (e: MessageEvent) => void>()
  closed = false
  constructor(public url: string) { FakeEventSource.last = this }
  addEventListener(type: string, fn: (e: MessageEvent) => void) { this.listeners.set(type, fn) }
  removeEventListener(type: string) { this.listeners.delete(type) }
  close() { this.closed = true }
  emit(type: string, data: object) { this.listeners.get(type)?.({ data: JSON.stringify(data) } as MessageEvent) }
}

afterEach(() => { vi.unstubAllGlobals() })

describe('useSSE', () => {
  it('marks a stream given up after repeated errors as lost, not as a finished run', () => {
    vi.stubGlobal('EventSource', FakeEventSource)
    const { result } = renderHook(() => useSSE('job-1'))
    act(() => { for (let i = 0; i < 5; i++) FakeEventSource.last!.onerror!() })
    expect(result.current.done).toBe(true)
    expect(result.current.lost).toBe(true)
    expect(FakeEventSource.last!.closed).toBe(true)
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
