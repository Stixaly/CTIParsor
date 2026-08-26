import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Loader2 } from 'lucide-react'
import { fetchJobs, updateJobStatus, deleteJob, fetchBundle } from '../api/client'
import type { Job, JobStatus } from '../types'
import ProgressModal from '../components/ProgressModal'
import NewReportModal from '../components/NewReportModal'
import KanbanCard from '../components/dashboard/KanbanCard'
import ActivityCard from '../components/dashboard/ActivityCard'

// ── Design tokens (fonts as constants — avoids repeating the fallback stack) ──

const SERIF = "'Source Serif 4', Georgia, serif"

// Shortcut badge on the New report button.  Empty on touch, where there is no
// keyboard to press it with and the badge would just be noise.
const NEW_REPORT_HINT: string =
  typeof navigator === 'undefined' ? ''
    : /iPhone|iPad|Android/i.test(navigator.userAgent) ? ''
    : /Mac/i.test(navigator.platform) ? '⌘N'
    : 'Ctrl+N'
const MONO  = "'JetBrains Mono', ui-monospace, monospace"

// ── Column definitions ────────────────────────────────────────────────────────

const KANBAN_COLS: { id: JobStatus; label: string; accent: string }[] = [
  { id: 'for_review', label: 'For review', accent: 'var(--warn)' },
  { id: 'reviewing',  label: 'Reviewing',  accent: 'var(--accent)' },
  { id: 'completed',  label: 'Completed',  accent: 'var(--ok)' },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

/** ISO timestamp → "3m ago / 2h ago / yesterday / 4d ago" */
function relTime(iso: string): string {
  const mins = (Date.now() - new Date(iso).getTime()) / 60_000
  if (mins < 1)    return 'just now'
  if (mins < 60)   return `${Math.round(mins)}m ago`
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`
  const d = Math.round(mins / 1440)
  return d === 1 ? 'yesterday' : `${d}d ago`
}

/**
 * Average pipeline duration (created_at → updated_at) for completed jobs.
 * Returns null if no completed jobs have a positive, realistic duration.
 * Durations > 24 h are excluded (likely stale/paused, not actual run time).
 */
function computeAvgTurnaround(jobs: Job[]): string | null {
  const diffs = jobs
    .filter(j => j.status === 'completed')
    .map(j => (new Date(j.updated_at).getTime() - new Date(j.created_at).getTime()) / 60_000)
    .filter(m => m > 0 && m < 1440)
  if (!diffs.length) return null
  const avg = diffs.reduce((a, b) => a + b, 0) / diffs.length
  if (avg < 1)  return '< 1m'
  if (avg < 60) return `${Math.round(avg)}m`
  return `${(avg / 60).toFixed(1)}h`
}

// ── StatTile ──────────────────────────────────────────────────────────────────

function StatTile({ n, label, sub, tone, borderLeft }: {
  n: string | number
  label: string
  sub?: string
  tone?: string
  borderLeft?: boolean
}) {
  return (
    <div style={{
      flex: 1,
      display: 'flex', flexDirection: 'column',
      padding: '12px 18px',
      borderLeft: borderLeft ? '1px solid var(--rule-soft)' : undefined,
    }}>
      <div style={{
        fontFamily: SERIF, fontSize: 30, fontWeight: 600,
        lineHeight: 1, letterSpacing: '-0.01em',
        color: tone ?? 'var(--ink)',
      }}>
        {n}
      </div>
      <div style={{
        fontSize: 11, fontWeight: 500, color: 'var(--ink-3)', marginTop: 7,
      }}>
        {label}
      </div>
      {sub && (
        <div style={{ fontSize: 10, fontFamily: MONO, color: 'var(--ink-4)', marginTop: 2 }}>
          {sub}
        </div>
      )}
    </div>
  )
}

// ── Dashboard page ────────────────────────────────────────────────────────────

export default function Dashboard() {
  const navigate = useNavigate()
  const qc = useQueryClient()

  // Local state.  Everything an ingestion needs — the source, the markings, the
  // file input — lives inside NewReportModal.  The Dashboard keeps only what it
  // owns: which job the progress modal follows, which card is selected, and the
  // page-level drag that opens the modal with a file already attached.
  const [activeJobId, setActiveJobId]       = useState<string | null>(null)
  const [activeFilename, setActiveFilename] = useState('')
  const [selectedId, setSelectedId]         = useState<string | null>(null)
  const [modalOpen, setModalOpen]           = useState(false)
  const [pendingFile, setPendingFile]       = useState<File | null>(null)
  const [pageDrag, setPageDrag]             = useState(false)

  // ── Queries & mutations ──────────────────────────────────────────────────

  const { data: jobs = [], isLoading } = useQuery({
    queryKey: ['jobs'],
    queryFn: fetchJobs,
    refetchInterval: 3000,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteJob(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['jobs'] }),
    onError:   () => alert('Could not delete job — check server logs'),
  })

  // ── Handlers (existing logic, unchanged) ─────────────────────────────────

  const openModal = useCallback((file?: File | null) => {
    setPendingFile(file ?? null)
    setModalOpen(true)
  }, [])

  // Closing always clears pendingFile: without it, a file dropped once would be
  // re-attached by the modal's initialFile effect the next time ⌘N opens it.
  const closeModal = useCallback(() => {
    setModalOpen(false)
    setPendingFile(null)
  }, [])

  // ⌘N / Ctrl+N opens the modal; Escape clears the drag overlay.  The modal
  // owns its own Escape handling, so this one only unsticks the overlay.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'n') {
        e.preventDefault()
        setModalOpen(true)
      } else if (e.key === 'Escape') {
        setPageDrag(false)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  const handlePageDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    setPageDrag(true)
  }

  // relatedTarget is null only when the pointer leaves the window entirely.
  // Clearing on every child boundary makes the overlay flicker as the cursor
  // crosses cards on the way to the drop.
  const handlePageDragLeave = (e: React.DragEvent) => {
    e.preventDefault()
    if (e.relatedTarget === null) setPageDrag(false)
  }

  const handlePageDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setPageDrag(false)
    const f = e.dataTransfer.files?.[0]
    if (f) openModal(f)
  }

  const handleAnalyse = async (job: Job) => {
    if (job.status === 'for_review') {
      await updateJobStatus(job.id, 'reviewing')
      qc.invalidateQueries({ queryKey: ['jobs'] })
    }
    navigate(`/review/${job.id}`)
  }

  const handleDownload = async (job: Job) => {
    try {
      const bundle = await fetchBundle(job.id)
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${job.original_filename.replace(/\.[^.]+$/, '')}_bundle.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      // Defer revocation so the browser has time to start the download before
      // the blob URL is invalidated (revoking synchronously breaks Firefox).
      setTimeout(() => URL.revokeObjectURL(url), 100)
    } catch {
      alert('Bundle not yet available')
    }
  }

  // ── Derived data ─────────────────────────────────────────────────────────

  // Activity strip: jobs that are not yet actionable in the kanban
  const activityJobs = jobs.filter(j =>
    j.status === 'processing' || j.status === 'uploaded' || j.status === 'failed'
  )
  // Kanban: jobs that are fully extracted and ready for review
  const kanbanJobs = (col: JobStatus) => jobs.filter(j => j.status === col)

  // Stat ribbon — computed from live jobs array, real fields only
  const awaitingCount   = jobs.filter(j => j.status === 'for_review').length
  const inProgressCount = jobs.filter(j =>
    j.status === 'reviewing' || j.status === 'processing' || j.status === 'uploaded'
  ).length
  const completedCount  = jobs.filter(j => j.status === 'completed').length
  const totalEntities   = jobs.reduce((s, j) => s + (j.entity_count ?? 0), 0)
  const avgTurnaround   = computeAvgTurnaround(jobs)

  // ── Style objects ────────────────────────────────────────────────────────

  const s = {
    topbar: {
      borderBottom: '1px solid var(--rule)',
      padding: '11px 26px',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      background: 'var(--bg-elev)',
      flexShrink: 0,
    } as React.CSSProperties,

    body: {
      flex: 1,
      overflowY: 'auto' as const,
      padding: '26px 30px 60px',
      display: 'flex', flexDirection: 'column' as const,
      gap: 22,
    },

    ribbon: {
      display: 'flex',
      background: 'var(--bg-elev)',
      border: '1px solid var(--rule)',
      borderRadius: 14,
      padding: 6,
      boxShadow: 'var(--shadow-card)',
    } as React.CSSProperties,

    kanbanGrid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(3, 1fr)',
      gap: 14,
      alignItems: 'start',
    } as React.CSSProperties,

    kanbanCol: {
      background: 'var(--bg-elev)',
      border: '1px solid var(--rule)',
      borderRadius: 12,
      overflow: 'hidden',
      display: 'flex', flexDirection: 'column' as const,
    },
  }

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div
      style={{ height: '100%', display: 'flex', flexDirection: 'column' }}
      onDragOver={handlePageDragOver}
      onDragLeave={handlePageDragLeave}
      onDrop={handlePageDrop}
    >

      {/* ── Top bar ── */}
      <div style={s.topbar}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--ink)' }}>Dashboard</span>
          <span style={{ fontSize: 13, color: 'var(--ink-4)' }}>/</span>
          <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--ink-2)' }}>Reports</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 28, height: 28, borderRadius: '50%',
            background: 'var(--accent-soft)', color: 'var(--accent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 11, fontWeight: 700, flexShrink: 0,
          }}>
            U
          </div>
        </div>
      </div>

      {/* ── Scrolling body ── */}
      <div style={s.body}>

        {/* Page head ─────────────────────────────────────────────────────── */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
        <div>
          <h1 style={{
            margin: '0 0 5px',
            fontFamily: SERIF,
            fontSize: 26, fontWeight: 700,
            letterSpacing: '-0.015em', lineHeight: 1.1,
            color: 'var(--ink)',
          }}>
            Threat reports
          </h1>
          <p style={{ margin: 0, fontSize: 13, color: 'var(--ink-3)' }}>
            Triage extracted intelligence and finalize STIX 2.1 bundles.
          </p>
        </div>

          {/* Makes the page-wide drop target discoverable — without it the
              behaviour exists but nothing announces it. */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0,
            fontSize: 11.5, color: 'var(--ink-4)',
          }}>
            <span style={{
              width: 14, height: 9, flexShrink: 0,
              border: '1px dashed var(--ink-4)', borderRadius: 2,
            }} />
            Drop a PDF anywhere on this page to start
          </div>
        </div>

        {/* Stat ribbon ────────────────────────────────────────────────────── */}
        <div style={s.ribbon}>
          <StatTile
            n={awaitingCount}
            label="Awaiting review"
            tone="var(--warn)"
          />
          <StatTile
            n={inProgressCount}
            label="In progress"
            tone="var(--accent)"
            borderLeft
          />
          <StatTile
            n={completedCount}
            label="Completed"
            tone="var(--ok)"
            borderLeft
          />
          <StatTile
            n={totalEntities.toLocaleString()}
            label="Entities extracted"
            borderLeft
          />
          {/* avgTurnaround was computed but never rendered — display it so
              the value is actually useful to the analyst. */}
          {avgTurnaround && (
            <StatTile
              n={avgTurnaround}
              label="Avg turnaround"
              sub="completed jobs"
              borderLeft
            />
          )}
        </div>

        {/* Action row — the single entry point for ingestion (ADR-0029). */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button
            className="btn-primary"
            onClick={() => openModal(null)}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '7px 12px 7px 11px',
              fontSize: 12.5, fontWeight: 600, borderRadius: 7,
              letterSpacing: '.01em', cursor: 'pointer',
            }}
          >
            <Plus size={14} strokeWidth={2.4} />
            New report
            {NEW_REPORT_HINT && (
              <span style={{
                fontFamily: MONO, fontSize: 10,
                padding: '1px 4px', borderRadius: 4,
                background: 'rgba(255,255,255,.16)',
                border: '1px solid rgba(255,255,255,.22)',
              }}>
                {NEW_REPORT_HINT}
              </span>
            )}
          </button>
          <span style={{ fontSize: 11, fontFamily: MONO, color: 'var(--ink-3)' }}>
            {jobs.length} reports
          </span>
        </div>

        {/* Activity strip ─────────────────────────────────────────────────── */}
        {activityJobs.length > 0 && (
          <div>
            <div style={{
              fontSize: 10, fontWeight: 600,
              letterSpacing: '.12em', textTransform: 'uppercase',
              color: 'var(--ink-3)', marginBottom: 8,
            }}>
              Activity
            </div>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(330px, 1fr))',
              gap: 10,
            }}>
              {activityJobs.map(job => (
                <ActivityCard
                  key={job.id}
                  job={job}
                  relTime={relTime}
                  onViewProgress={() => {
                    setActiveJobId(job.id)
                    setActiveFilename(job.original_filename)
                  }}
                  onDelete={() => deleteMutation.mutate(job.id)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Kanban board ───────────────────────────────────────────────────── */}
        {isLoading ? (
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            padding: '48px 0', gap: 8, color: 'var(--ink-4)',
          }}>
            <Loader2 size={18} className="animate-spin" />
            Loading…
          </div>
        ) : (
          <div style={s.kanbanGrid}>
            {KANBAN_COLS.map(col => {
              const list = kanbanJobs(col.id)
              return (
                <div key={col.id} style={s.kanbanCol}>

                  {/* Column header */}
                  <div style={{
                    borderTop: `3px solid ${col.accent}`,
                    padding: '11px 14px',
                    background: 'var(--bg-soft)',
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    flexShrink: 0,
                  }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--ink)' }}>
                      {col.label}
                    </span>
                    <span style={{
                      fontSize: 11, fontFamily: MONO,
                      padding: '1px 8px', borderRadius: 20,
                      background: 'var(--bg)',
                      color: 'var(--ink-3)',
                      border: '1px solid var(--rule-soft)',
                    }}>
                      {list.length}
                    </span>
                  </div>

                  {/* Column body */}
                  <div style={{
                    padding: 9,
                    display: 'flex', flexDirection: 'column', gap: 8,
                    minHeight: 120,
                  }}>
                    {list.length === 0 ? (
                      <p style={{
                        margin: 0,
                        fontSize: 12, fontStyle: 'italic',
                        color: 'var(--ink-4)', textAlign: 'center',
                        padding: '16px 0',
                      }}>
                        Nothing here
                      </p>
                    ) : (
                      list.map(job => (
                        <KanbanCard
                          key={job.id}
                          job={job}
                          selected={selectedId === job.id}
                          relTime={relTime}
                          onSelect={() =>
                            setSelectedId(prev => prev === job.id ? null : job.id)
                          }
                          onAnalyse={() => handleAnalyse(job)}
                          onDelete={() => deleteMutation.mutate(job.id)}
                          onDownload={() => handleDownload(job)}
                          onGraph={() => navigate(`/graph/${job.id}`)}
                          onCoverage={() => navigate(`/coverage/${job.id}`)}
                        />
                      ))
                    )}
                  </div>

                </div>
              )
            })}
          </div>
        )}

      </div>{/* end scrolling body */}

      {/* Progress modal ─────────────────────────────────────────────────────── */}
      <NewReportModal
        open={modalOpen}
        initialFile={pendingFile}
        onClose={closeModal}
        onJobCreated={(jobId, filename) => {
          setActiveJobId(jobId)
          setActiveFilename(filename)
        }}
      />

      {/* Full-screen drop affordance.  pointer-events: none so it never eats
          the drop it is advertising. */}
      {pageDrag && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 80,
          background: 'color-mix(in oklab, var(--accent) 12%, rgba(250,247,241,.86))',
          backdropFilter: 'blur(2px)',
          pointerEvents: 'none',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          animation: 'dashFadeIn .12s ease',
        }}>
          <div style={{
            border: '2px dashed var(--accent)', borderRadius: 16,
            padding: '36px 56px', background: 'var(--bg-elev)',
            boxShadow: 'var(--shadow-pop)', textAlign: 'center',
          }}>
            <div style={{ fontFamily: SERIF, fontSize: 22, fontWeight: 600, color: 'var(--ink)' }}>
              Drop to start a report
            </div>
            <div style={{ fontFamily: MONO, fontSize: 12, color: 'var(--ink-3)', marginTop: 6 }}>
              PDF · DOCX · HTML · TXT · MD
            </div>
          </div>
        </div>
      )}

      {activeJobId && (
        <ProgressModal
          jobId={activeJobId}
          filename={activeFilename}
          onClose={() => {
            setActiveJobId(null)
            qc.invalidateQueries({ queryKey: ['jobs'] })
          }}
        />
      )}
    </div>
  )
}
