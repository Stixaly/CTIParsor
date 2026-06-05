import { useEffect, useRef, useState } from 'react'
import type { ProgressEvent } from '../types'

// Maximum number of consecutive SSE errors before giving up and marking done.
const MAX_ERRORS = 5

export function useSSE(jobId: string | null) {
  const [events, setEvents] = useState<ProgressEvent[]>([])
  const [done, setDone] = useState(false)
  const errorCountRef = useRef(0)

  useEffect(() => {
    if (!jobId) return
    setEvents([])
    setDone(false)
    errorCountRef.current = 0

    const es = new EventSource(`/api/jobs/${jobId}/progress`)

    const handleStage = (e: MessageEvent) => {
      // A successful message resets the error counter
      errorCountRef.current = 0
      try {
        setEvents(prev => [...prev, JSON.parse(e.data) as ProgressEvent])
      } catch { /* ignore malformed data */ }
    }

    const handleDone = (e: MessageEvent) => {
      try {
        setEvents(prev => [...prev, JSON.parse(e.data) as ProgressEvent])
      } catch { /* ignore */ }
      setDone(true)
      es.close()
    }

    es.addEventListener('stage', handleStage)
    es.addEventListener('done', handleDone)

    // Only close and mark done after repeated consecutive errors — a single
    // error is usually a transient network blip; EventSource will auto-reconnect.
    es.onerror = () => {
      errorCountRef.current += 1
      if (errorCountRef.current >= MAX_ERRORS) {
        setDone(true)
        es.close()
      }
    }

    return () => {
      es.removeEventListener('stage', handleStage)
      es.removeEventListener('done', handleDone)
      es.close()
    }
  }, [jobId])

  const latestStage = events.filter(e => e.stage !== undefined).slice(-1)[0]

  return { events, done, latestStage }
}
