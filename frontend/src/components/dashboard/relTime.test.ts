import { describe, it, expect, vi, afterEach } from 'vitest'
import { relTime } from './relTime'

// The clock is pinned so each bucket is exact.
const NOW = Date.parse('2026-11-02T12:00:00Z')

describe('relTime', () => {
  afterEach(() => vi.useRealTimers())

  it('reads a past timestamp in minutes, hours, then days', () => {
    vi.useFakeTimers()
    vi.setSystemTime(NOW)
    expect(relTime('2026-11-02T11:59:30Z')).toBe('just now')
    expect(relTime('2026-11-02T11:30:00Z')).toBe('30m ago')
    expect(relTime('2026-11-02T09:00:00Z')).toBe('3h ago')
    expect(relTime('2026-11-01T12:00:00Z')).toBe('yesterday')
    expect(relTime('2026-10-29T12:00:00Z')).toBe('4d ago')
  })

  it('keeps a future timestamp at just now', () => {
    vi.useFakeTimers()
    vi.setSystemTime(NOW)
    expect(relTime('2026-11-02T13:00:00Z')).toBe('just now')
  })

  it('shows an em dash for a date it cannot read', () => {
    expect(relTime('not a date')).toBe('—')
    expect(relTime('')).toBe('—')
  })
})
