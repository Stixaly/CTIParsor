import { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Loader2, FileText, AlignLeft, BookOpen } from 'lucide-react'
import MarkdownPreview from '../components/MarkdownPreview'
import PdfViewer from '../components/PdfViewer'

import {
  fetchJob, fetchEntities, fetchRelationships,
  updateEntity, createEntity,
  createRelationship, updateRelationship,
  finalizeJob, finalizeJobQuick, sourceUrl, bulkUpdateEntities,
} from '../api/client'
import type { Entity, Relationship } from '../types'
import { useAppTheme } from '../context/ThemeContext'

import TopChrome from '../components/review/TopChrome'
import PipelineRibbon, { type StageInfo } from '../components/review/PipelineRibbon'
import AutoAcceptBanner from '../components/review/AutoAcceptBanner'
import TypeRail from '../components/review/TypeRail'
import DocumentReader from '../components/review/DocumentReader'
import Marginalia from '../components/review/Marginalia'
import InlineHoverChip from '../components/review/InlineHoverChip'
import RelationshipRail from '../components/review/RelationshipRail'
import RelationshipCreator from '../components/review/RelationshipCreator'
import DragRubberBand from '../components/review/DragRubberBand'
import KeyboardHelp from '../components/review/KeyboardHelp'
import { typeDot, typeLabel, confPct } from '../components/review/tokens'
import EntityPopover from '../components/EntityPopover'

// ── Review-specific types ─────────────────────────────────────────────────────
// Theme type is re-exported from ThemeContext; imported via useAppTheme()
type SortMode = 'position' | 'type'

const AUTO_ACCEPT_THRESHOLD = 90   // percent

// ── tiny localStorage hook ───────────────────────────────────────────────────
function usePref<T>(key: string, init: T): [T, (v: T) => void] {
  const [val, setVal] = useState<T>(() => {
    try { const s = localStorage.getItem(key); return s ? JSON.parse(s) : init }
    catch { return init }
  })
  const set = (v: T) => { setVal(v); try { localStorage.setItem(key, JSON.stringify(v)) } catch {} }
  return [val, set]
}

// ── ClientEntity extends Entity with local auto-accept flag ─────────────────
interface ClientEntity extends Entity {
  autoAccepted?: boolean
}

interface ClientRelationship extends Relationship {
  _localOnly?: boolean   // true for manually-created, not yet persisted
}

interface Point { x: number; y: number }
interface HoverTarget { id: string; x: number; y: number }
interface RelCreatorState {
  srcId?: string
  tgtId?: string
  x: number
  y: number
  evidenceText?: string
}
interface PopoverState {
  mode: 'create'
  text: string
  x: number
  y: number
}

// ═══════════════════════════════════════════════════════════════════════════
export default function Review() {
  const { jobId } = useParams<{ jobId: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()

  // ── prefs (persisted) ───────────────────────────────────────────────────
  // theme + accent come from the shared ThemeContext so changes carry across all pages
  const { theme, setTheme } = useAppTheme()
  const [fontFamily, setFontFamily] = usePref<'serif' | 'sans'>('review.font', 'serif')
  const [density, setDensity]       = usePref<'compact' | 'comfortable' | 'spacious'>('review.density', 'comfortable')
  const [margSort, setMargSort]     = usePref<SortMode>('review.margSort', 'position')
  const [showRibbon]                = usePref('review.ribbon', true)

  // Apply Review-specific data attributes (density, font) — theme/accent are synced by ThemeContext.
  // useEffect keeps this out of the render phase (render must be pure) and
  // ensures the DOM mutation only fires when the values actually change.
  useEffect(() => {
    document.documentElement.dataset.density = density
    document.documentElement.dataset.font    = fontFamily
  }, [density, fontFamily])

  // ── remote data ─────────────────────────────────────────────────────────
  const { data: job, isLoading: jobLoading } = useQuery({
    queryKey: ['job', jobId],
    queryFn: () => fetchJob(jobId!),
    enabled: !!jobId,
  })

  const { data: remoteEntities = [], isLoading: entLoading } = useQuery({
    queryKey: ['entities', jobId],
    queryFn: () => fetchEntities(jobId!),
    enabled: !!jobId,
  })

  const { data: remoteRels = [], isLoading: relsLoading } = useQuery({
    queryKey: ['relationships', jobId],
    queryFn: () => fetchRelationships(jobId!),
    enabled: !!jobId,
  })

  // ── local entity state — overlay auto-accept on top of server state ─────
  const [localEntities, setLocalEntities] = useState<ClientEntity[]>([])
  const bootstrappedRef = useRef(false)

  useEffect(() => {
    if (!remoteEntities.length || bootstrappedRef.current) return
    bootstrappedRef.current = true
    const autoAcceptIds: string[] = []
    setLocalEntities(remoteEntities.map(e => {
      const pct = confPct(e.confidence)
      const autoAccepted = pct >= AUTO_ACCEPT_THRESHOLD && e.accepted === null
      if (autoAccepted) autoAcceptIds.push(e.id)
      return { ...e, accepted: autoAccepted ? true : e.accepted, autoAccepted }
    }))
    // Persist entity auto-accepts to DB so the STIX bundle includes them.
    // Without this the server retains accepted=null and may exclude them at finalize.
    if (autoAcceptIds.length > 0) {
      Promise.all(autoAcceptIds.map(id => updateEntity(jobId!, id, { accepted: true })))
        .then(() => qc.invalidateQueries({ queryKey: ['entities', jobId] }))
        .catch(() => { /* non-blocking — local state is already correct */ })
    }
  }, [remoteEntities])

  // Merge server updates while preserving local accepted/autoAccepted
  useEffect(() => {
    if (!bootstrappedRef.current) return
    setLocalEntities(prev => {
      const prevMap: Record<string, ClientEntity> = {}
      prev.forEach(e => { prevMap[e.id] = e })
      return remoteEntities.map(e => prevMap[e.id] ? { ...e, accepted: prevMap[e.id].accepted, autoAccepted: prevMap[e.id].autoAccepted } : e)
    })
  }, [remoteEntities])

  // ── local relationship state ─────────────────────────────────────────────
  const [localRels, setLocalRels] = useState<ClientRelationship[]>([])
  // Always-current snapshot used by setRelAccepted / setRelType to avoid
  // stale-closure reads of localRels inside non-memoised handlers.
  const localRelsRef = useRef<ClientRelationship[]>([])
  useEffect(() => { localRelsRef.current = localRels }, [localRels])

  // Guards the one-time bootstrap (auto-accept pass) for relationships —
  // mirrors the same pattern used for entities above.
  const bootstrappedRelsRef = useRef(false)

  // Initial bootstrap: run the auto-accept pass exactly once on first load.
  useEffect(() => {
    if (!remoteRels.length || bootstrappedRelsRef.current) return
    bootstrappedRelsRef.current = true
    const autoAcceptIds: string[] = []
    setLocalRels(remoteRels.map(r => {
      const pct = confPct(r.confidence)
      // Promotion threshold (evidence-graded): "observed" claims auto-accept;
      // otherwise require high confidence AND a label that isn't a weak one.
      // "inferred"/"gap" never auto-promote — they always wait for a reviewer.
      const label = r.evidence_label ?? 'reported'
      const shouldAutoAccept =
        r.accepted === null &&
        (label === 'observed' ||
          (pct >= 90 && label !== 'gap' && label !== 'inferred'))
      if (shouldAutoAccept) autoAcceptIds.push(r.id)
      return { ...r, accepted: shouldAutoAccept ? true : r.accepted }
    }))
    // Persist relationship auto-accepts so the STIX bundle includes them
    if (autoAcceptIds.length > 0) {
      Promise.all(autoAcceptIds.map(id => updateRelationship(jobId!, id, { accepted: true })))
        .then(() => qc.invalidateQueries({ queryKey: ['relationships', jobId] }))
        .catch(() => { /* non-blocking — server may re-read on finalize */ })
    }
  }, [remoteRels])

  // Subsequent updates: merge server state while preserving the locally-set
  // `accepted` value so rapid mutations (accept A then B before the first
  // refetch lands) don't silently revert B back to null.
  useEffect(() => {
    if (!bootstrappedRelsRef.current) return
    setLocalRels(prev => {
      const prevMap: Record<string, ClientRelationship> = {}
      prev.forEach(r => { prevMap[r.id] = r })
      return remoteRels.map(r =>
        prevMap[r.id] ? { ...r, accepted: prevMap[r.id].accepted } : r
      )
    })
  }, [remoteRels])

  // ── ui state ────────────────────────────────────────────────────────────
  const [viewMode, setViewMode]   = useState<'text' | 'preview' | 'source'>('text')
  const [focusedId, setFocusedId] = useState<string | null>(null)
  const [hoverEntity, setHoverEntity] = useState<HoverTarget | null>(null)
  const [activeTypes, setActiveTypes] = useState<string[]>([])
  const [kbdOpen, setKbdOpen] = useState(false)
  const [finalizing, setFinalizing] = useState(false)
  const [finalized, setFinalized] = useState(false)
  const [popover, setPopover] = useState<PopoverState | null>(null)
  const [relCreator, setRelCreator] = useState<RelCreatorState | null>(null)
  const [dragState, setDragState] = useState<{ srcId: string; from: Point; to: Point } | null>(null)
  const [relInDoc, setRelInDoc] = useState(false)
  const dragStateRef = useRef<typeof dragState>(null)
  /** Brief "not found in text" hint shown when a focused entity has no text mark. */
  const [notInTextHint, setNotInTextHint] = useState<string | null>(null)
  const notInTextTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  /** True after any mutation until the background auto-finalize succeeds. */
  const [bundleStale,    setBundleStale]    = useState(false)
  /** True while the background quick-finalize API call is in-flight. */
  const [autoFinalizing, setAutoFinalizing] = useState(false)
  const autoFinalizeTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // ── derived ─────────────────────────────────────────────────────────────
  const docEntities = useMemo(() =>
    activeTypes.length === 0 ? localEntities : localEntities.filter(e => activeTypes.includes(e.entity_type)),
  [localEntities, activeTypes])

  const counts = useMemo(() => ({
    pending:  localEntities.filter(e => e.accepted === null).length,
    accepted: localEntities.filter(e => e.accepted === true).length,
    rejected: localEntities.filter(e => e.accepted === false).length,
    rels:     localRels.length,
  }), [localEntities, localRels])

  // ── stage info for PipelineRibbon ────────────────────────────────────────
  const stageInfo = useMemo((): StageInfo => {
    const chars = job?.report_text?.length ?? 0
    const approxChunks = chars > 0 ? Math.max(1, Math.round(chars / 3000)) : 0
    const iocCount  = localEntities.filter(e => e.source === 'ioc').length
    const nerCount  = localEntities.filter(e =>
      e.source === 'gazetteer' || e.source === 'semantic' ||
      e.source === 'gliner'    || e.source === 'cyner'
    ).length
    const llmCount  = localEntities.filter(e => e.source === 'llm').length
    const ttpCount  = localEntities.filter(e =>
      e.entity_type === 'technique' || e.entity_type === 'ttp' ||
      e.entity_type === 'tactic'    || e.entity_type === 'procedure'
    ).length
    return { chars, approxChunks, iocCount, nerCount, llmCount, ttpCount, relCount: localRels.length }
  }, [job, localEntities, localRels])

  const autoAcceptedCount = localEntities.filter(e => e.autoAccepted && e.accepted === true).length

  // ── entity mutations ─────────────────────────────────────────────────────
  const updateMutation = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: object }) => updateEntity(jobId!, id, patch),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['entities', jobId] }); markDirty() },
  })

  const createEntityMutation = useMutation({
    mutationFn: (body: Parameters<typeof createEntity>[1]) => createEntity(jobId!, body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['entities', jobId] }); markDirty() },
    onError: (err: Error) => {
      console.error('[createEntity] failed:', err.message)
      alert(`Could not create entity: ${err.message}`)
    },
  })

  const createRelMutation = useMutation({
    mutationFn: (body: Parameters<typeof createRelationship>[1]) => createRelationship(jobId!, body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['relationships', jobId] }); markDirty() },
  })

  const updateRelMutation = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: object }) => updateRelationship(jobId!, id, patch),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['relationships', jobId] }); markDirty() },
  })

  // ── local-first entity mutations ─────────────────────────────────────────
  const setAccepted = (id: string, val: boolean | null) => {
    setLocalEntities(es => es.map(e => e.id === id ? { ...e, accepted: val, autoAccepted: false } : e))
    updateMutation.mutate({ id, patch: { accepted: val } })
  }
  const accept      = useCallback((id: string) => setAccepted(id, true), [])
  const reject      = useCallback((id: string) => setAccepted(id, false), [])
  const reset       = useCallback((id: string) => setAccepted(id, null), [])

  const changeType = (id: string, entity_type: string) => {
    setLocalEntities(es => es.map(e => e.id === id ? { ...e, entity_type } : e))
    updateMutation.mutate({ id, patch: { entity_type } })
  }

  const undoAutoAccept = () => {
    // Collect which entities need to be reset BEFORE updating local state so
    // the list is captured at call-time and not affected by the setState call.
    const toReset = localEntities.filter(e => e.autoAccepted)
    setLocalEntities(es => es.map(e => e.autoAccepted ? { ...e, accepted: null, autoAccepted: false } : e))
    // Persist to the server — without these PATCH calls the entities remain
    // accepted=true in the DB and will re-appear as accepted on next page load.
    if (toReset.length > 0) {
      Promise.all(toReset.map(e => updateEntity(jobId!, e.id, { accepted: null })))
        .then(() => qc.invalidateQueries({ queryKey: ['entities', jobId] }))
        .catch(() => { /* non-blocking — local state is already correct */ })
    }
  }

  // ── bulk mutations (one API call per type, not N individual PATCHes) ──────
  const bulkByTypeMutation = useMutation({
    mutationFn: ({ entity_type, action }: { entity_type: string; action: 'accept' | 'reject' | 'reset' }) =>
      bulkUpdateEntities(jobId!, entity_type, action, 'pending'),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['entities', jobId] }); markDirty() },
  })

  /** Accept all pending entities of type `t` — local-first, single API call. */
  const acceptAllOfType = (t: string) => {
    setLocalEntities(es => es.map(e =>
      e.entity_type === t && e.accepted === null
        ? { ...e, accepted: true, autoAccepted: false }
        : e
    ))
    bulkByTypeMutation.mutate({ entity_type: t, action: 'accept' })
  }

  /** Reject all pending entities of type `t` — local-first, single API call. */
  const rejectAllOfType = (t: string) => {
    setLocalEntities(es => es.map(e =>
      e.entity_type === t && e.accepted === null
        ? { ...e, accepted: false, autoAccepted: false }
        : e
    ))
    bulkByTypeMutation.mutate({ entity_type: t, action: 'reject' })
  }

  const toggleType = (t: string) =>
    setActiveTypes(curr => curr.includes(t) ? curr.filter(x => x !== t) : [...curr, t])

  // ── relationship mutations ───────────────────────────────────────────────
  const setRelAccepted = (id: string, val: boolean | null) => {
    setLocalRels(rs => rs.map(r => r.id === id ? { ...r, accepted: val } : r))
    // Use the always-current ref so we never read stale localRels from a closure
    if (!localRelsRef.current.find(r => r.id === id)?._localOnly) {
      updateRelMutation.mutate({ id, patch: { accepted: val } })
    }
  }

  const setRelType = (id: string, relationship_type: string) => {
    setLocalRels(rs => rs.map(r => r.id === id ? { ...r, relationship_type } : r))
    if (!localRelsRef.current.find(r => r.id === id)?._localOnly) {
      updateRelMutation.mutate({ id, patch: { relationship_type } })
    }
  }

  const createRel = ({ src, tgt, type, evidence }: { src: string; tgt: string; type: string; evidence: string }) => {
    setRelCreator(null)
    createRelMutation.mutate({
      source_value: src,
      relationship_type: type,
      target_value: tgt,
      confidence: 1.0,   // API expects 0.0–1.0 scale; was wrongly 100
      evidence_text: evidence || null,
    })
  }

  // ── hover grace timer ─────────────────────────────────────────────────────
  const hoverTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const showHover = (id: string, x: number, y: number) => {
    if (hoverTimerRef.current) { clearTimeout(hoverTimerRef.current); hoverTimerRef.current = null }
    setHoverEntity({ id, x, y })
  }
  const scheduleHide = (delay = 220) => {
    if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current)
    hoverTimerRef.current = setTimeout(() => setHoverEntity(null), delay)
  }
  const cancelHide = () => {
    if (hoverTimerRef.current) { clearTimeout(hoverTimerRef.current); hoverTimerRef.current = null }
  }

  // ── drag-to-relate ───────────────────────────────────────────────────────
  const onMarkDragStart = (eid: string, fromPoint: Point, evt: PointerEvent) => {
    let moved = false
    const startX = evt.clientX, startY = evt.clientY
    dragStateRef.current = { srcId: eid, from: fromPoint, to: fromPoint }

    const onMove = (e: PointerEvent) => {
      if (!moved && Math.hypot(e.clientX - startX, e.clientY - startY) > 8) {
        moved = true; setHoverEntity(null)
      }
      if (moved) {
        const next = { srcId: eid, from: fromPoint, to: { x: e.clientX, y: e.clientY } }
        dragStateRef.current = next
        setDragState(next)
      }
    }
    const onUp = (e: PointerEvent) => {
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', onUp)
      if (!moved) { dragStateRef.current = null; setDragState(null); return }
      const el = document.elementFromPoint(e.clientX, e.clientY)
      const mark = el?.closest('mark[data-eid]')
      const tgtId = (mark as HTMLElement)?.dataset?.eid
      dragStateRef.current = null; setDragState(null)
      if (tgtId && tgtId !== eid) {
        setRelCreator({ srcId: eid, tgtId, x: e.clientX, y: e.clientY })
      }
    }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
  }

  // ── shift-click to relate ─────────────────────────────────────────────────
  const openRelCreatorFromShiftClick = (eid: string, x: number, y: number) => {
    if (!relCreator) {
      setRelCreator({ srcId: eid, x, y })
    } else if (!relCreator.tgtId && relCreator.srcId !== eid) {
      setRelCreator({ ...relCreator, tgtId: eid, x, y })
    } else {
      setRelCreator({ srcId: eid, x, y })
    }
  }

  // ── keyboard navigation ───────────────────────────────────────────────────
  const orderedEntityIds = useMemo(() => {
    const text = job?.report_text ?? ''
    return [...localEntities]
      .sort((a, b) => {
        const ai = text.indexOf(a.value)
        const bi = text.indexOf(b.value)
        return (ai === -1 ? 9e9 : ai) - (bi === -1 ? 9e9 : bi)
      })
      .map(e => e.id)
  }, [localEntities, job?.report_text])

  const goNextPending = useCallback((dir: 1 | -1) => {
    const ids = orderedEntityIds
    const N = ids.length
    const startIdx = focusedId ? ids.indexOf(focusedId) : -1
    for (let i = 1; i <= N; i++) {
      const k = ((startIdx + dir * i) % N + N) % N
      const e = localEntities.find(x => x.id === ids[k])
      if (e?.accepted === null) { setFocusedId(ids[k]); return }
    }
  }, [orderedEntityIds, focusedId, localEntities])

  const jumpToValue = (value: string) => {
    const match = localEntities.find(e => e.value === value)
    if (match) setFocusedId(match.id)
  }

  // ── finalize ──────────────────────────────────────────────────────────────
  // Declared before the keyboard effect so the dep array reference is valid.
  const handleFinalize = useCallback(async () => {
    if (!jobId) return
    // Cancel any pending auto-finalize — manual takes precedence and includes
    // the full lexicon re-scan that the quick auto-finalize skips.
    if (autoFinalizeTimer.current) clearTimeout(autoFinalizeTimer.current)
    setFinalizing(true)
    try {
      await finalizeJob(jobId)   // full finalize with lexicon re-scan
      qc.invalidateQueries({ queryKey: ['jobs'] })
      setBundleStale(false)      // bundle is now definitively current
      setFinalized(true)
      // Return to the Dashboard so the user sees the report move to "Completed".
      // The graph is still accessible from the Completed kanban card.
      setTimeout(() => {
        setFinalized(false)
        navigate('/dashboard')
      }, 1800)
    } catch {
      alert('Finalize failed — check server logs')
    } finally {
      setFinalizing(false)
    }
  }, [jobId, qc, navigate])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (e.key === '?')                              { setKbdOpen(true); e.preventDefault() }
      else if (e.key === 'Escape')                    { setKbdOpen(false); setFocusedId(null) }
      else if (e.key === 'j' || e.key === 'ArrowDown'){ goNextPending(1); e.preventDefault() }
      else if (e.key === 'k' || e.key === 'ArrowUp')  { goNextPending(-1); e.preventDefault() }
      else if (focusedId && (e.key === 'a' || e.key === 'A')) { accept(focusedId); goNextPending(1) }
      else if (focusedId && (e.key === 'r' || e.key === 'R')) { reject(focusedId); goNextPending(1) }
      else if (focusedId && (e.key === 'u' || e.key === 'U')) { reset(focusedId) }
      else if (e.key === 'g' || e.key === 'G')        { navigate(`/graph/${jobId}`) }
      else if (e.key === 'f' || e.key === 'F')        { handleFinalize() }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [focusedId, orderedEntityIds, goNextPending, handleFinalize])

  // ── auto-finalize (debounced) ─────────────────────────────────────────────
  //
  // Every entity/relationship mutation calls markDirty(), which:
  //   1. Sets bundleStale=true so the TopChrome shows "⚠ Bundle outdated"
  //   2. Resets a 4-second debounce timer
  // When the timer fires (4 s of no further changes), triggerAutoFinalize()
  // calls POST /finalize?quick=true (skips lexicon re-scan for speed).
  // On success, bundleStale resets to false → "✓ Bundle current".

  const triggerAutoFinalize = async () => {
    if (!jobId) return
    setAutoFinalizing(true)
    try {
      await finalizeJobQuick(jobId)
      qc.invalidateQueries({ queryKey: ['jobs'] })
      setBundleStale(false)
    } catch {
      // Non-blocking — keep stale=true so the user knows the bundle is outdated.
      // They can always click the manual Finalize button.
    } finally {
      setAutoFinalizing(false)
    }
  }

  const markDirty = () => {
    setBundleStale(true)
    if (autoFinalizeTimer.current) clearTimeout(autoFinalizeTimer.current)
    autoFinalizeTimer.current = setTimeout(triggerAutoFinalize, 4000)
  }

  // Cancel all pending timers when the component unmounts to prevent calling
  // setState after unmount (React 18 Strict Mode logs these as errors).
  useEffect(() => () => {
    if (autoFinalizeTimer.current) clearTimeout(autoFinalizeTimer.current)
    if (hoverTimerRef.current)     clearTimeout(hoverTimerRef.current)
    if (notInTextTimer.current)    clearTimeout(notInTextTimer.current)
  }, [])

  // ── create entity from text selection ────────────────────────────────────
  // value = technique name (ATT&CK) or selected text (other types)
  const finishCreate = (value: string, type: string, mitreId?: string) => {
    createEntityMutation.mutate({
      value, entity_type: type,
      context: '', confidence: 1.0, source: 'manual', mitre_id: mitreId ?? null,
    })
    setPopover(null)
  }

  // ── loading ───────────────────────────────────────────────────────────────
  if (jobLoading || entLoading || relsLoading) {
    return (
      <div className="review-loading">
        <Loader2 size={22} className="animate-spin" />
        Loading…
      </div>
    )
  }

  const relEvidence = relInDoc
    ? localRels.filter(r => r.accepted !== false).map(r => r.evidence_text ?? '').filter(Boolean)
    : []

  return (
    <div className="app">
      {/* ── top chrome ── */}
      <TopChrome
        title={job?.original_filename ?? ''}
        pendingCount={counts.pending}
        finalizing={finalizing}
        theme={theme}
        onBack={() => navigate('/dashboard')}
        onGraph={() => navigate(`/graph/${jobId}`)}
        onFinalize={handleFinalize}
        onThemeToggle={() => setTheme(theme === 'dark' ? 'warm' : 'dark')}
        bundleStale={bundleStale}
        autoFinalizing={autoFinalizing}
      />

      {/* ── pipeline ribbon ── */}
      {showRibbon && (
        <PipelineRibbon
          filename={job?.original_filename ?? ''}
          counts={counts}
          stageInfo={stageInfo}
        />
      )}

      {/* ── auto-accept banner ── */}
      <AutoAcceptBanner
        count={autoAcceptedCount}
        threshold={AUTO_ACCEPT_THRESHOLD}
        onUndo={undoAutoAccept}
      />

      {/* ── scrollable content area ── */}
      <div className="stage-wrapper">
        <div className="stage">
          {/* left — type filter rail */}
          <TypeRail
            entities={localEntities}
            activeTypes={activeTypes}
            toggleType={toggleType}
            onAcceptAllOfType={acceptAllOfType}
            onRejectAllOfType={rejectAllOfType}
          />

          {/* centre — document reader / source viewer */}
          <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>

            {/* View-mode toggle — sits above the document */}
            {jobId && (() => {
              // Preview is shown for all file types — for .md it renders markdown,
              // for PDF/DOCX/HTML/TXT it renders the extracted text with light
              // markdown-like formatting (headers, bold, code fences, etc.).
              const tabs: { id: 'text' | 'preview' | 'source'; icon: React.ReactNode; label: string }[] = [
                { id: 'text',    icon: <AlignLeft size={12} />, label: 'Text'    },
                { id: 'preview', icon: <BookOpen  size={12} />, label: 'Preview' },
                { id: 'source',  icon: <FileText  size={12} />, label: 'Source'  },
              ]
              return (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 4,
                  padding: '8px 56px 0',   // aligns with .doc left/right padding
                }}>
                  <div style={{
                    display: 'inline-flex', borderRadius: 7,
                    border: '1px solid var(--rule)', overflow: 'hidden',
                    background: 'var(--bg-soft)',
                  }}>
                    {tabs.map(opt => (
                      <button
                        key={opt.id}
                        onClick={() => setViewMode(opt.id)}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 5,
                          padding: '4px 10px',
                          fontSize: 11, fontWeight: 500, border: 'none',
                          cursor: 'pointer', transition: 'background .12s, color .12s',
                          background: viewMode === opt.id ? 'var(--accent-soft)' : 'transparent',
                          color:      viewMode === opt.id ? 'var(--accent)'      : 'var(--ink-3)',
                        }}
                      >
                        {opt.icon}
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </div>
              )
            })()}

            {/* Text annotation view */}
            {viewMode === 'text' && (
              <DocumentReader
                text={job?.report_text ?? ''}
                title={job?.original_filename ?? ''}
                byline={`Ingested at ${job?.created_at ?? ''}`}
                entities={docEntities}
                highlightStyle="underline"
                focusedId={focusedId}
                setFocusedId={setFocusedId}
                setHoverEntity={h => h ? showHover(h.id, h.x, h.y) : scheduleHide()}
                onAccept={accept}
                onReject={reject}
                onReset={reset}
                onChangeType={changeType}
                onCreate={(text, x, y) => setPopover({ mode: 'create', text, x, y })}
                onMarkShiftClick={openRelCreatorFromShiftClick}
                onMarkDragStart={onMarkDragStart}
                onSelectionRelate={payload => setRelCreator(payload)}
                relEvidence={relEvidence}
                relsForOverlay={localRels}
                showRelArrows={relInDoc}
                onEntityNotInText={id => {
                  // LLM-extracted entities (malware names, actor names, TTPs, campaign
                  // names) are paraphrased from context and often don't appear verbatim
                  // in the source text.  Show a brief, self-dismissing hint.
                  const entity = localEntities.find(e => e.id === id)
                  if (!entity) return
                  if (notInTextTimer.current) clearTimeout(notInTextTimer.current)
                  setNotInTextHint(`"${entity.value}" not found verbatim in document text`)
                  notInTextTimer.current = setTimeout(() => setNotInTextHint(null), 3000)
                }}
              />
            )}

            {/* Markdown preview — VS Code-style rendered view (only for .md files) */}
            {viewMode === 'preview' && (
              <MarkdownPreview source={job?.report_text ?? ''} />
            )}

            {/* Source file view — inline for PDF, download link for other types */}
            {viewMode === 'source' && jobId && (() => {
              const filename = job?.original_filename ?? ''
              const isPdf = filename.toLowerCase().endsWith('.pdf')
              const url   = sourceUrl(jobId)
              return isPdf ? (
                <PdfViewer
                  url={url}
                  filename={filename}
                  entities={docEntities}
                  focusedId={focusedId}
                  onFocusEntity={setFocusedId}
                />
              ) : (
                <div style={{
                  display: 'flex', flexDirection: 'column',
                  alignItems: 'center', justifyContent: 'center',
                  padding: '60px 40px', gap: 14, color: 'var(--ink-3)',
                }}>
                  <FileText size={40} style={{ color: 'var(--ink-4)' }} />
                  <p style={{ margin: 0, fontSize: 14, color: 'var(--ink-2)' }}>
                    {filename}
                  </p>
                  <p style={{ margin: 0, fontSize: 12 }}>
                    Inline preview is only available for PDF files.
                  </p>
                  <a
                    href={url}
                    download={filename}
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: 6,
                      padding: '7px 14px', borderRadius: 7,
                      background: 'var(--accent-soft)', color: 'var(--accent)',
                      fontSize: 12, fontWeight: 600, textDecoration: 'none',
                    }}
                  >
                    Download original file
                  </a>
                </div>
              )
            })()}

          </div>

          {/* right — marginalia */}
          <Marginalia
            entities={docEntities}
            focusedId={focusedId}
            setFocusedId={setFocusedId}
            onAccept={accept}
            onReject={reject}
            onReset={reset}
            onChangeType={changeType}
            sortMode={margSort}
            setSortMode={setMargSort}
          />
        </div>

        {/* ── relationship rail (sticky bottom) ── */}
        <RelationshipRail
          rels={localRels}
          onAccept={id => setRelAccepted(id, true)}
          onReject={id => setRelAccepted(id, false)}
          onReset={id => setRelAccepted(id, null)}
          onJump={jumpToValue}
          onChangeType={setRelType}
          showInDoc={relInDoc}
          setShowInDoc={setRelInDoc}
          onNewRelationship={(x, y) => setRelCreator({ x, y })}
          getEntityType={value =>
            localEntities.find(e => e.value === value)?.entity_type
          }
        />
      </div>

      {/* ── inline hover chip ── */}
      {hoverEntity && (() => {
        const e = localEntities.find(x => x.id === hoverEntity.id)
        return e ? (
          <InlineHoverChip
            entity={e}
            x={hoverEntity.x}
            y={hoverEntity.y}
            onAccept={accept}
            onReject={reject}
            onReset={reset}
            onOpen={id => { setFocusedId(id); setHoverEntity(null) }}
            onChangeType={changeType}
            onEnterChip={cancelHide}
            onLeaveChip={() => scheduleHide(150)}
          />
        ) : null
      })()}

      {/* ── select-to-create popover ── */}
      {popover && createPortal(
        <EntityPopover
          state={popover}
          onClose={() => setPopover(null)}
          onCreate={finishCreate}
        />,
        document.body,
      )}

      {/* ── drag rubber-band ── */}
      {dragState && (
        <DragRubberBand from={dragState.from} to={dragState.to} />
      )}

      {/* ── relationship creator popover ── */}
      {relCreator && (
        <RelationshipCreator
          entities={localEntities}
          initial={relCreator}
          onCancel={() => setRelCreator(null)}
          onCreate={createRel}
          onAddEntity={async (value, entity_type) => {
            // Create the entity on the server.  Pass source: 'manual' so the
            // source badge in MarginaliaCard shows correctly instead of blank.
            const result = await createEntity(jobId!, {
              value,
              entity_type,
              confidence: 1.0,
              source: 'manual',
              context: '',
            })
            // Optimistic local insert — the picker sees it immediately without
            // waiting for the invalidateQueries refetch to complete
            setLocalEntities(prev => [
              ...prev,
              { ...result, accepted: null, autoAccepted: false },
            ])
            // Background refetch to sync server state
            qc.invalidateQueries({ queryKey: ['entities', jobId] })
            return result
          }}
        />
      )}

      {/* ── keyboard help ── */}
      <KeyboardHelp open={kbdOpen} onClose={() => setKbdOpen(false)} />

      {/* ── "not in text" hint — shown when focused entity has no text occurrence ── */}
      {notInTextHint && (
        <div
          style={{
            position: 'fixed', bottom: 80, left: '50%', transform: 'translateX(-50%)',
            background: 'var(--bg-elev)',
            border: '1px solid var(--rule)',
            borderRadius: 8,
            padding: '8px 14px',
            fontSize: 12,
            color: 'var(--ink-3)',
            boxShadow: 'var(--shadow-card)',
            pointerEvents: 'none',
            zIndex: 50,
            display: 'flex', alignItems: 'center', gap: 7,
            maxWidth: 420, textAlign: 'center',
            animation: 'fadeIn .15s ease',
          }}
        >
          <span style={{ fontSize: 14 }}>💬</span>
          {notInTextHint}
        </div>
      )}

      {/* ── finalize toast ── */}
      {finalized && (
        <div className="toast">
          ✓ Review completed — STIX 2.1 bundle ready · returning to dashboard…
        </div>
      )}
    </div>
  )
}
