import { useEffect, useRef, useState } from 'react'
import { checkSession } from '../api/client'
import type { PartialGraphEvent, ProgressEvent } from '../types'

// Maximum number of consecutive SSE errors before giving up on the stream.
const MAX_ERRORS = 5

export function useSSE(jobId: string | null) {
  const [events, setEvents] = useState<(ProgressEvent | PartialGraphEvent)[]>([])
  const [done, setDone] = useState(false)
  // The stream was given up after repeated errors: `done` too, but the
  // pipeline's outcome is unknown, so it must not read as a success (#293).
  const [lost, setLost] = useState(false)
  const errorCountRef = useRef(0)

  useEffect(() => {
    // Reset before the guard: a jobId that goes back to null must not leave the
    // previous job's events and `done` behind (#548).
    setEvents([])
    setDone(false)
    setLost(false)
    errorCountRef.current = 0
    if (!jobId) return

    const es = new EventSource(`/api/jobs/${encodeURIComponent(jobId)}/progress`)

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

    const handlePartialGraph = (e: MessageEvent) => {
      errorCountRef.current = 0
      try {
        const payload = JSON.parse(e.data)
        const event: PartialGraphEvent = { _type: 'partial_graph', ...payload }
        setEvents(prev => [...prev, event])
      } catch { /* ignore malformed data */ }
    }

    es.addEventListener('stage', handleStage)
    es.addEventListener('done', handleDone)
    es.addEventListener('partial_graph', handlePartialGraph)

    // Only close and mark done after repeated consecutive errors — a single
    // error is usually a transient network blip; EventSource will auto-reconnect.
    es.onerror = () => {
      // The browser does not retry a refused stream (readyState CLOSED): a 401 ends the
      // session, and asking /api/auth/me says so (the client then goes to /login).
      if (es.readyState === 2) void checkSession()
      errorCountRef.current += 1
      if (errorCountRef.current >= MAX_ERRORS) {
        setLost(true)
        setDone(true)
        es.close()
      }
    }

    return () => {
      es.removeEventListener('stage', handleStage)
      es.removeEventListener('done', handleDone)
      es.removeEventListener('partial_graph', handlePartialGraph)
      es.close()
    }
  }, [jobId])

  const latestStage = events.filter(e => e.stage !== undefined).slice(-1)[0]
  const partialGraphEvents = events.filter(
    (e): e is PartialGraphEvent => '_type' in e && e._type === 'partial_graph')

  return { events, done, lost, latestStage, partialGraphEvents }
}
