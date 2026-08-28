import { useCallback, useEffect, useMemo, useState } from 'react'

import type { DetectionFormat } from '../types'

/** One selectable rule, flattened from the per-technique coverage groups.
 *  `techniques` lists every report technique the rule covers — the same rule id
 *  can appear under several techniques, but it is ONE selection entry and ONE
 *  file in the export. */
export interface SelectableRule {
  id: string
  format: DetectionFormat
  corpus: string
  license: string
  severity: string
  title: string
  bytes: number
  techniques: string[]
}

export interface RuleSelection {
  /** Rule ids explicitly removed from the default select-everything state. */
  excluded: ReadonlySet<string>
  isSelected: (id: string) => boolean
  selectedCount: number
  totalCount: number
  selectedBytes: number
  /** How many of these ids are currently selected. */
  selectedOf: (ids: readonly string[]) => number
  /** Selected byte volume among these ids. */
  bytesOf: (ids: readonly string[]) => number
  /** All selected → exclude the whole scope; anything else → include it all. */
  toggleScope: (ids: readonly string[]) => void
  selectAll: () => void
  clearAll: () => void
}

/** Tri-state marker: '✓' all selected · '–' partial · '' none (or empty scope). */
export function markOf(sel: number, total: number): '✓' | '–' | '' {
  if (total === 0 || sel === 0) return ''
  return sel === total ? '✓' : '–'
}

/**
 * Selection over the coverage rule set, modelled as exclusions so "everything
 * that matches the report" stays the default and an empty storage key means
 * select-all — matching the export's existing semantics (ADR-0022). Persists
 * per job under `coverage.selection.{jobId}`.
 */
export function useRuleSelection(
  jobId: string | undefined,
  rules: readonly SelectableRule[],
): RuleSelection {
  const [excluded, setExcluded] = useState<Set<string>>(new Set())

  // Load persisted exclusions whenever the job changes.
  useEffect(() => {
    if (jobId === undefined) return
    try {
      const raw = localStorage.getItem(`coverage.selection.${jobId}`)
      setExcluded(raw ? new Set(JSON.parse(raw) as string[]) : new Set())
    } catch {
      setExcluded(new Set())
    }
  }, [jobId])

  // Persisted by the MUTATORS, never by an effect on `excluded` — the same rule
  // `usePromotedRules` documents, and for the same reason. An effect with
  // `[excluded, jobId]` deps also fires on the pass where jobId has ALREADY
  // changed but `excluded` still holds the previous job's value, so it wrote
  // job A's exclusions under job B's key; and on the mount pass its closure
  // holds the initial empty set, so it wrote `[]` over the stored selection.
  // Both were reproduced in useRuleSelection.test.ts before this changed.
  const persist = useCallback((next: ReadonlySet<string>) => {
    if (jobId === undefined) return
    try {
      localStorage.setItem(`coverage.selection.${jobId}`, JSON.stringify([...next]))
    } catch {
      // Quota exceeded — ignore silently.
    }
  }, [jobId])

  // Prune stale ids only after rules have loaded.
  // TRAP: never prune while `rules` is empty — rules arrive asynchronously, and
  // purging on the empty array would wipe the persisted selection on first render.
  useEffect(() => {
    if (rules.length === 0) return
    const validIds = new Set(rules.map(r => r.id))
    setExcluded(prev => {
      const next = new Set(prev)
      let changed = false
      for (const id of next) {
        if (!validIds.has(id)) {
          next.delete(id)
          changed = true
        }
      }
      if (!changed) return prev
      persist(next)
      return next
    })
  }, [rules, persist])

  const byId = useMemo(() => new Map(rules.map(r => [r.id, r])), [rules])

  const isSelected = useCallback((id: string) => !excluded.has(id), [excluded])

  const { selectedCount, selectedBytes } = useMemo(() => {
    let count = 0
    let bytes = 0
    for (const rule of rules) {
      if (!excluded.has(rule.id)) {
        count++
        bytes += rule.bytes
      }
    }
    return { selectedCount: count, selectedBytes: bytes }
  }, [rules, excluded])

  const selectedOf = useCallback((ids: readonly string[]) => {
    let n = 0
    for (const id of ids) {
      if (!excluded.has(id)) n++
    }
    return n
  }, [excluded])

  const bytesOf = useCallback((ids: readonly string[]) => {
    let sum = 0
    for (const id of ids) {
      if (!excluded.has(id)) {
        const rule = byId.get(id)
        if (rule) sum += rule.bytes
      }
    }
    return sum
  }, [excluded, byId])

  const toggleScope = useCallback((ids: readonly string[]) => {
    if (ids.length === 0) return
    const sel = selectedOf(ids)
    setExcluded(prev => {
      const next = new Set(prev)
      if (sel === ids.length) {
        for (const id of ids) next.add(id)
      } else {
        for (const id of ids) next.delete(id)
      }
      persist(next)
      return next
    })
  }, [selectedOf, persist])

  const selectAll = useCallback(() => {
    const next = new Set<string>()
    setExcluded(next)
    persist(next)
  }, [persist])

  const clearAll = useCallback(() => {
    const next = new Set(rules.map(r => r.id))
    setExcluded(next)
    persist(next)
  }, [rules, persist])

  return useMemo(() => ({
    excluded,
    isSelected,
    selectedCount,
    totalCount: rules.length,
    selectedBytes,
    selectedOf,
    bytesOf,
    toggleScope,
    selectAll,
    clearAll,
  }), [excluded, isSelected, selectedCount, rules.length, selectedBytes,
       selectedOf, bytesOf, toggleScope, selectAll, clearAll])
}
