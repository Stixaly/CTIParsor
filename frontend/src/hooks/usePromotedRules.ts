// Rules the analyst promoted from the proposed detections, kept per job in
// localStorage (coverage.promoted.<job id>). Every instance of the hook shares one
// store (useSyncExternalStore), so the review page, the coverage page and the export
// read the same set. The reason is in the comment on the store below.

import { useCallback, useMemo, useSyncExternalStore } from 'react'

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
 * Shared store behind every instance of the hook (#366). The Review page and
 * its Detections panel each call `usePromotedRules` for the same job; with a
 * local `useState` in each, a promotion made in one was invisible to the other
 * until a remount, so the Detection rules button and its ZIP ignored it.
 *
 * Each snapshot remembers the raw localStorage string it was read from. A set
 * is only re-read when that string changed underneath it, so `getSnapshot`
 * returns the same object across renders. When the write did not stick
 * (storage unavailable or full), the snapshot keeps the in-memory set, since
 * the stored string still matches what was recorded.
 */
const listeners = new Set<() => void>()
const snapshots = new Map<string, { raw: string | null; set: ReadonlySet<string> }>()

function readRaw(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    // localStorage unavailable (private browsing): the in-memory set is the only copy.
    return null
  }
}

function snapshotFor(key: string): ReadonlySet<string> {
  const raw = readRaw(key)
  const hit = snapshots.get(key)
  if (hit && hit.raw === raw) return hit.set
  const set = loadStringSet(key)
  snapshots.set(key, { raw, set })
  return set
}

// Persisted by the MUTATORS, never by an effect on the state — see the header
// of `hooks/sets.ts` for the race that rule prevents.
function writeSnapshot(key: string, next: ReadonlySet<string>): void {
  saveStringSet(key, next)
  snapshots.set(key, { raw: readRaw(key), set: next })
  listeners.forEach((listener) => listener())
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

const EMPTY: ReadonlySet<string> = new Set()

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
 *
 * Every instance for the same job shares one set (see `snapshotFor`), so a
 * promotion or a removal shows up at once in each mounted consumer.
 */
export function usePromotedRules(
  jobId: string | undefined
): PromotedRules {
  const key = jobId === undefined ? undefined : `coverage.promoted.${jobId}`

  const current = useCallback(
    (): ReadonlySet<string> => (key === undefined ? EMPTY : snapshotFor(key)),
    [key]
  )
  const promoted = useSyncExternalStore(subscribe, current)

  const persist = useCallback((next: ReadonlySet<string>) => {
    if (key === undefined) return
    writeSnapshot(key, next)
  }, [key])

  const isPromoted = useCallback(
    (id: string) => promoted.has(id),
    [promoted]
  )

  const toggle = useCallback(
    (id: string) => persist(toggleInSet(current(), id)),
    [current, persist]
  )

  const promote = useCallback((ids: readonly string[]) => {
    const next = new Set(current())
    for (const id of ids) {
      next.add(id)
    }
    persist(next)
  }, [current, persist])

  const demote = useCallback((ids: readonly string[]) => {
    const next = new Set(current())
    for (const id of ids) {
      next.delete(id)
    }
    persist(next)
  }, [current, persist])

  const clear = useCallback(() => {
    persist(new Set())
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
