/**
 * Persistence invariants of `useRuleSelection` (bug-hunt 2026-08).
 *
 * The sibling hook `usePromotedRules` carries an emphatic comment: persistence
 * must happen in the MUTATORS, never in an effect on the state, because an
 * effect also fires on the mount pass while its closure still holds the initial
 * empty value. These tests check whether that hazard is live here too — a job's
 * stored selection must never be written under another job's key, and must
 * never be flattened to empty by a mount.
 */
import { act, renderHook } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { useRuleSelection, type SelectableRule } from './useRuleSelection'

function rule(id: string): SelectableRule {
  return {
    id,
    format: 'sigma',
    corpus: 'sigmahq',
    license: 'DRL',
    severity: 'high',
    title: id,
    bytes: 100,
    techniques: ['T1059'],
  }
}

const RULES_A = [rule('a1'), rule('a2')]
const RULES_B = [rule('b1'), rule('b2')]

/** Every localStorage.setItem call made during the block, in order. */
function recordWrites(): Array<[string, string]> {
  const writes: Array<[string, string]> = []
  const original = Storage.prototype.setItem
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(function (
    this: Storage,
    k: string,
    v: string,
  ) {
    writes.push([k, v])
    original.call(this, k, v)
  })
  return writes
}

describe('useRuleSelection persistence', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  it('never writes one job\'s exclusions under another job\'s key', () => {
    localStorage.setItem('coverage.selection.jobB', JSON.stringify(['b1']))
    const writes = recordWrites()

    const { result, rerender } = renderHook(
      ({ jobId, rules }: { jobId: string; rules: SelectableRule[] }) =>
        useRuleSelection(jobId, rules),
      { initialProps: { jobId: 'jobA', rules: RULES_A } },
    )

    act(() => {
      result.current.toggleScope(['a1', 'a2'])
    })
    expect(result.current.excluded.has('a1')).toBe(true)

    // Switch job. `useCoverage` has no placeholderData, so the new job's rules
    // are not there yet — this is the real shape of the transition.
    rerender({ jobId: 'jobB', rules: [] })

    const bWrites = writes.filter(([k]) => k === 'coverage.selection.jobB')
    const leaked = bWrites.filter(([, v]) => {
      const parsed = JSON.parse(v) as string[]
      return parsed.includes('a1') || parsed.includes('a2')
    })
    expect(leaked).toEqual([])
  })

  it('does not flatten a stored selection to empty on mount', () => {
    localStorage.setItem('coverage.selection.jobB', JSON.stringify(['b1']))
    const writes = recordWrites()

    renderHook(() => useRuleSelection('jobB', RULES_B))

    const emptied = writes.filter(
      ([k, v]) => k === 'coverage.selection.jobB' && v === '[]',
    )
    expect(emptied).toEqual([])
  })

  // The three tests around this one all assert that something is NEVER written,
  // so every one of them passes when persistence is removed outright — verified
  // by making `saveStringSet` a no-op, which they did not catch. This is the
  // positive direction: a mutation must actually reach storage.
  it('writes the exclusion to this job\'s key when one is toggled', () => {
    const writes = recordWrites()

    const { result } = renderHook(() => useRuleSelection('jobA', RULES_A))
    act(() => {
      result.current.toggleScope(['a1'])
    })

    const aWrites = writes.filter(([k]) => k === 'coverage.selection.jobA')
    expect(aWrites.length).toBeGreaterThan(0)
    const last = JSON.parse(aWrites[aWrites.length - 1][1]) as string[]
    expect(last).toContain('a1')
  })

  it('keeps the stored selection readable after a job switch and back', () => {
    localStorage.setItem('coverage.selection.jobB', JSON.stringify(['b1']))

    const { result, rerender } = renderHook(
      ({ jobId, rules }: { jobId: string; rules: SelectableRule[] }) =>
        useRuleSelection(jobId, rules),
      { initialProps: { jobId: 'jobA', rules: RULES_A } },
    )
    rerender({ jobId: 'jobB', rules: [] })
    rerender({ jobId: 'jobB', rules: RULES_B })

    expect(result.current.excluded.has('b1')).toBe(true)
    expect(result.current.isSelected('b1')).toBe(false)
    expect(result.current.isSelected('b2')).toBe(true)
  })
})
