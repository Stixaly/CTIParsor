import { useCallback, useEffect, useMemo, useState } from 'react'

import { loadStringSet, saveStringSet, toggleInSet } from './sets'

export interface PromotedRules {
  promoted: ReadonlySet<string>
  isPromoted: (id: string) => boolean
  toggle: (id: string) => void
  promote: (ids: readonly string[]) => void
  demote: (ids: readonly string[]) => void
  clear: () => void
  count: number
}

/**
 * Manages the set of rules promoted from proposals into the coverage selection.
 *
 * IMPORTANT: The storage key is `coverage.promoted.${jobId}`, which is
 * DIFFERENT from `coverage.selection.${jobId}` (used by `useRuleSelection`).
 * The two sets have OPPOSITE semantics: `useRuleSelection` stores EXCLUSIONS
 * (rules to remove from coverage), while this hook stores PROMOTIONS (rules
 * to ADD to coverage). Confusing them would empty the analyst's selection.
 *
 * NEVER purge this set against a list of known rules. A promoted rule is by
 * definition ABSENT from the coverage set, so purging would immediately
 * delete it. This is the trap of this file.
 */
export function usePromotedRules(
  jobId: string | undefined
): PromotedRules {
  const [promoted, setPromoted] = useState<ReadonlySet<string>>(
    () => new Set()
  )

  // Load from localStorage on mount and when jobId changes
  useEffect(() => {
    if (jobId === undefined) {
      setPromoted(new Set())
      return
    }

    setPromoted(loadStringSet(`coverage.promoted.${jobId}`))
  }, [jobId])

  // Persisted by the MUTATORS, never by an effect on `promoted` — see the
  // header of `hooks/sets.ts` for the race that rule prevents.
  const persist = useCallback((next: ReadonlySet<string>) => {
    if (jobId === undefined) return
    saveStringSet(`coverage.promoted.${jobId}`, next)
  }, [jobId])

  const isPromoted = useCallback(
    (id: string) => promoted.has(id),
    [promoted]
  )

  const toggle = useCallback(
    (id: string) => {
      setPromoted((prev) => {
        const next = toggleInSet(prev, id)
        persist(next)
        return next
      })
    },
    [persist]
  )

  const promote = useCallback((ids: readonly string[]) => {
    setPromoted((prev) => {
      const next = new Set(prev)
      for (const id of ids) {
        next.add(id)
      }
      persist(next)
      return next
    })
  }, [persist])

  const demote = useCallback((ids: readonly string[]) => {
    setPromoted((prev) => {
      const next = new Set(prev)
      for (const id of ids) {
        next.delete(id)
      }
      persist(next)
      return next
    })
  }, [persist])

  const clear = useCallback(() => {
    const next: ReadonlySet<string> = new Set()
    setPromoted(next)
    persist(next)
  }, [persist])

  return useMemo(
    () => ({
      promoted,
      isPromoted,
      toggle,
      promote,
      demote,
      clear,
      count: promoted.size,
    }),
    [promoted, isPromoted, toggle, promote, demote, clear]
  )
}
