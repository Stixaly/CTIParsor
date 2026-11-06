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
import { BundleRefusedError, finalizeJobQuick } from '../api/client'

export const FINALIZE_DEBOUNCE_MS = 4000

export function useDebouncedFinalize(jobId: string | undefined) {
  const qc = useQueryClient()
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  /** True from the first edit until a rebuild succeeds. */
  const [pending, setPending] = useState(false)
  const [running, setRunning] = useState(false)
  const [failed, setFailed] = useState(false)

  // The rebuild in flight, so `flush()` can wait for it: `run` clears the
  // timer as it starts, and a flush during the request used to return at once,
  // so the Graph page downloaded the bundle from before the edit (#292).
  const inFlight = useRef<Promise<void> | null>(null)
  // Edits counted, so a rebuild that started before an edit does not mark it saved.
  const edits = useRef(0)

  const run = useCallback(async () => {
    if (timer.current) { clearTimeout(timer.current); timer.current = null }
    if (!jobId) return
    // One rebuild at a time: the next one starts from the edits after the last.
    while (inFlight.current) await inFlight.current
    const seq = edits.current
    const attempt = (async () => {
      setRunning(true)
      try {
        await finalizeJobQuick(jobId)
        // An edit made during the request is not in this build: still pending.
        if (edits.current === seq) setPending(false)
        setFailed(false)
        qc.invalidateQueries({ queryKey: ['bundle', jobId] })
        qc.invalidateQueries({ queryKey: ['bundle-ledger', jobId] })
        qc.invalidateQueries({ queryKey: ['jobs'] })
      } catch (e) {
        // Keep `pending`: the stored bundle is still behind the edits.
        setFailed(true)
        // A refused rebuild is stored all the same: the view must say so rather
        // than keep drawing the previous build.
        if (e instanceof BundleRefusedError) {
          qc.invalidateQueries({ queryKey: ['bundle', jobId] })
          qc.invalidateQueries({ queryKey: ['bundle-ledger', jobId] })
        }
      } finally {
        setRunning(false)
      }
    })()
    inFlight.current = attempt
    try { await attempt } finally { if (inFlight.current === attempt) inFlight.current = null }
  }, [jobId, qc])

  const markDirty = useCallback(() => {
    edits.current += 1
    setPending(true)
    if (timer.current) clearTimeout(timer.current)
    timer.current = setTimeout(run, FINALIZE_DEBOUNCE_MS)
  }, [run])

  /** Wait for a rebuild in flight, then rebuild now if an edit is waiting for one. */
  const flush = useCallback(async () => {
    while (inFlight.current) await inFlight.current
    if (timer.current) await run()
  }, [run])

  // Leaving the page must not drop a pending rebuild: run it on the way out.
  useEffect(() => () => {
    if (timer.current) { clearTimeout(timer.current); if (jobId) void finalizeJobQuick(jobId).catch(() => {}) }
  }, [jobId])

  return { markDirty, flush, rebuild: run, pending, running, failed }
}
