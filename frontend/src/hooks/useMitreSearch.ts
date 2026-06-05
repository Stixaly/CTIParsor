import { useState, useEffect, useCallback } from 'react'

export interface MitreEntry {
  id: string
  name: string
  domain: string
  tactics?: string[]
  is_subtechnique?: boolean
  parent_id?: string | null
  description?: string
  shortname?: string
}

interface MitreIndex {
  techniques: MitreEntry[]
  tactics: MitreEntry[]
}

// Module-level singleton so the index is fetched at most once per page load
let _cache: MitreIndex | null = null
let _inflight: Promise<MitreIndex> | null = null

function fetchIndex(): Promise<MitreIndex> {
  if (_cache) return Promise.resolve(_cache)
  if (_inflight) return _inflight
  _inflight = fetch('/mitre_index.json')
    .then(r => r.json() as Promise<MitreIndex>)
    .then(data => {
      // Only cache when we actually received entries.  If we cached the empty
      // fallback that the catch handler returns, _cache would be truthy forever
      // and all subsequent calls would short-circuit to the empty object,
      // permanently breaking MITRE search after any transient network error.
      if (data.techniques.length || data.tactics.length) {
        _cache = data
      }
      _inflight = null
      return data
    })
    .catch(() => {
      _inflight = null   // reset so the next call can retry
      return { techniques: [], tactics: [] } as MitreIndex
    })
  return _inflight
}

export function useMitreSearch() {
  const [index, setIndex] = useState<MitreIndex | null>(_cache)

  useEffect(() => {
    if (_cache) return
    fetchIndex().then(setIndex)
  }, [])

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

  return { search, ready: !!index }
}
