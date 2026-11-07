/**
 * Synchronisation of `usePromotedRules` between instances (#366).
 *
 * The Review page and its Detections panel each call the hook for the same
 * job. Before the shared store, each kept its own state: a promotion in the
 * panel left the Detection rules button at its old count until a remount.
 */
import { act, renderHook } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'

import { usePromotedRules } from './usePromotedRules'

const KEY = 'coverage.promoted.jobA'

describe('usePromotedRules shared between instances (#366)', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('shows a toggle made in one instance to the other, both ways', () => {
    const panel = renderHook(() => usePromotedRules('jobA'))
    const bar = renderHook(() => usePromotedRules('jobA'))

    act(() => panel.result.current.toggle('new-rule'))
    expect(panel.result.current.count).toBe(1)
    expect(bar.result.current.count).toBe(1)
    expect(bar.result.current.isPromoted('new-rule')).toBe(true)

    act(() => bar.result.current.toggle('new-rule'))
    expect(panel.result.current.count).toBe(0)
    expect(bar.result.current.count).toBe(0)
    expect(panel.result.current.isPromoted('new-rule')).toBe(false)
  })

  it('shows promote and demote made in one instance to the other', () => {
    const panel = renderHook(() => usePromotedRules('jobA'))
    const bar = renderHook(() => usePromotedRules('jobA'))

    act(() => panel.result.current.promote(['r1', 'r2']))
    expect(bar.result.current.count).toBe(2)

    act(() => bar.result.current.demote(['r1']))
    expect(panel.result.current.promoted).toEqual(new Set(['r2']))
    expect(bar.result.current.count).toBe(1)
  })

  it('persists each mutation in localStorage under the job key', () => {
    const { result } = renderHook(() => usePromotedRules('jobA'))

    act(() => result.current.toggle('new-rule'))
    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual(['new-rule'])

    act(() => result.current.clear())
    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual([])
  })

  it('keeps the loaded set on mount instead of overwriting it with empty', () => {
    localStorage.setItem(KEY, JSON.stringify(['kept']))

    const { result } = renderHook(() => usePromotedRules('jobA'))

    expect(result.current.count).toBe(1)
    expect(result.current.isPromoted('kept')).toBe(true)
    expect(localStorage.getItem(KEY)).toBe(JSON.stringify(['kept']))
  })

  it('does not leak a promotion from one job into another', () => {
    const jobA = renderHook(() => usePromotedRules('jobA'))
    const jobB = renderHook(() => usePromotedRules('jobB'))

    act(() => jobA.result.current.toggle('new-rule'))
    expect(jobA.result.current.count).toBe(1)
    expect(jobB.result.current.count).toBe(0)
    expect(localStorage.getItem('coverage.promoted.jobB')).toBeNull()
  })
})
