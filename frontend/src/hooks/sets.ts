/** Helpers for the `Set<string>` state shared by the coverage hooks and the
 *  review panels.
 *
 *  `loadStringSet` / `saveStringSet` existed twice, once in
 *  `usePromotedRules` and once in `useRuleSelection`, each carrying its own
 *  comment about the same bug: persisting from a `useEffect` fires on the
 *  mount pass too, and its closure still holds the initial empty set, so it
 *  wrote `[]` over the value just loaded. Persist from the MUTATORS. */

export function toggleInSet<T>(prev: ReadonlySet<T>, item: T): Set<T> {
  const next = new Set(prev)
  if (next.has(item)) next.delete(item)
  else next.add(item)
  return next
}

export function loadStringSet(key: string): Set<string> {
  try {
    const raw = localStorage.getItem(key)
    if (!raw) return new Set()
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return new Set()
    const strings = parsed.filter((x): x is string => typeof x === 'string')
    return new Set(strings)
  } catch {
    // localStorage may be unavailable (private browsing) or the stored value
    // may be corrupt; fall back to an empty set rather than crashing the app.
    return new Set()
  }
}

export function saveStringSet(key: string, next: ReadonlySet<string>): void {
  try {
    localStorage.setItem(key, JSON.stringify([...next]))
  } catch {
    // Quota exceeded or storage unavailable; ignore.
  }
}
