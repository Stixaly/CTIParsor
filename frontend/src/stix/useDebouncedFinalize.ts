/**
 * Rebuild the stored bundle a few seconds after the last review edit.
 *
 * The Graph page edits relationship rows but never rebuilt the bundle, so its
 * bundle view and its Download button served a bundle that ignored the edits
 * (ADR-0061).  Same debounce and quick finalize as the Review page's
 * auto-finalize; `flush()` runs a pending rebuild now (before a download).
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { finalizeJobQuick } from '../api/client'

export const FINALIZE_DEBOUNCE_MS = 4000

export function useDebouncedFinalize(jobId: string | undefined) {
  const qc = useQueryClient()
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  /** True from the first edit until a rebuild succeeds. */
  const [pending, setPending] = useState(false)
  const [running, setRunning] = useState(false)
  const [failed, setFailed] = useState(false)

  const run = useCallback(async () => {
    if (timer.current) { clearTimeout(timer.current); timer.current = null }
    if (!jobId) return
    setRunning(true)
    try {
      await finalizeJobQuick(jobId)
      setPending(false)
      setFailed(false)
      qc.invalidateQueries({ queryKey: ['bundle', jobId] })
      qc.invalidateQueries({ queryKey: ['bundle-ledger', jobId] })
      qc.invalidateQueries({ queryKey: ['jobs'] })
    } catch {
      // Keep `pending`: the stored bundle is still behind the edits.
      setFailed(true)
    } finally {
      setRunning(false)
    }
  }, [jobId, qc])

  const markDirty = useCallback(() => {
    setPending(true)
    if (timer.current) clearTimeout(timer.current)
    timer.current = setTimeout(run, FINALIZE_DEBOUNCE_MS)
  }, [run])

  /** Rebuild now if an edit is waiting for one. */
  const flush = useCallback(async () => {
    if (timer.current) await run()
  }, [run])

  // Leaving the page must not drop a pending rebuild: run it on the way out.
  useEffect(() => () => {
    if (timer.current) { clearTimeout(timer.current); if (jobId) void finalizeJobQuick(jobId).catch(() => {}) }
  }, [jobId])

  return { markDirty, flush, rebuild: run, pending, running, failed }
}
