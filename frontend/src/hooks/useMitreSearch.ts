import { useCallback } from 'react'

import type { MitreEntry } from '../types'
import { useAttackIndex } from './useAttackIndex'

/**
 * Search the ATT&CK index of the release the API runs (ADR-0087): tactics and
 * techniques by id prefix first, then by name.  `release` is that index's
 * version; `ready` stays false while it loads or if it could not be fetched.
 */
export function useMitreSearch() {
  const { data: index } = useAttackIndex()

  const search = useCallback((query: string, limit = 12): MitreEntry[] => {
    if (!index) return []
    const q = query.toLowerCase().trim()
    if (!q) return []

    const results: MitreEntry[] = []
    const seen = new Set<string>()
    const all = [...index.tactics, ...index.techniques]

    // ID prefix matches first (highest signal)
    for (const e of all) {
      if (!seen.has(e.id) && e.id.toLowerCase().startsWith(q)) {
        results.push(e)
        seen.add(e.id)
      }
    }
    // Name contains
    for (const e of all) {
      if (!seen.has(e.id) && e.name.toLowerCase().includes(q)) {
        results.push(e)
        seen.add(e.id)
      }
    }
    return results.slice(0, limit)
  }, [index])

  return { search, ready: !!index, release: index?.release ?? null }
}
