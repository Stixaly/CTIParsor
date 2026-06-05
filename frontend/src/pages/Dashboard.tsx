import { useState, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Upload, Trash2, Eye, GitGraph, Download, FileText,
  Loader2, X, Play, Clock, AlertTriangle,
} from 'lucide-react'
import { fetchJobs, uploadFile, updateJobStatus, deleteJob, fetchBundle } from '../api/client'
import type { Job, JobStatus } from '../types'
import ProgressModal from '../components/ProgressModal'

// ── Design tokens (fonts as constants — avoids repeating the fallback stack) ──

const SERIF = "'Source Serif 4', Georgia, serif"
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

// ── StatusPill ────────────────────────────────────────────────────────────────

const STATUS_META: Record<JobStatus, { label: string; color: string }> = {
  uploaded:   { label: 'Queued',      color: 'var(--ink-4)' },
  processing: { label: 'Processing',  color: 'var(--accent)' },
  for_review: { label: 'For review',  color: 'var(--warn)' },
  reviewing:  { label: 'Reviewing',   color: 'var(--accent)' },
  completed:  { label: 'Completed',   color: 'var(--ok)' },
  failed:     { label: 'Failed',      color: 'var(--no)' },
}

function StatusPill({ status }: { status: JobStatus }) {
  const m = STATUS_META[status]
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      fontSize: 10, fontWeight: 600, letterSpacing: '0.03em',
      padding: '2px 7px', borderRadius: 20,
      color: m.color,
      background: `color-mix(in oklab, ${m.color} 13%, transparent)`,
      flexShrink: 0,
    }}>
      <span style={{
        width: 5, height: 5, borderRadius: '50%',
        background: m.color, flexShrink: 0,
      }} />
      {m.label}
    </span>
  )
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

// ── Small action button ───────────────────────────────────────────────────────

const SM: React.CSSProperties = {
  fontSize: 11, padding: '5px 9px', gap: 5,
  display: 'flex', alignItems: 'center',
}

function ActBtn({ label, icon, onClick, primary, danger }: {
  label?: string
  icon: React.ReactNode
  onClick: (e: React.MouseEvent) => void
  primary?: boolean
  danger?: boolean
}) {
  return (
    <button
      className={primary ? 'btn-primary' : 'btn-ghost'}
      style={{ ...SM, ...(danger ? { color: 'var(--no)' } : {}) }}
      onClick={e => { e.stopPropagation(); onClick(e) }}
    >
      {icon}
      {label}
    </button>
  )
}

// ── KanbanCard ────────────────────────────────────────────────────────────────

function KanbanCard({ job, selected, onSelect, onAnalyse, onDelete, onDownload, onGraph }: {
  job: Job
  selected: boolean
  onSelect: () => void
  onAnalyse: () => void
  onDelete: () => void
  onDownload: () => void
  onGraph: () => void
}) {
  const [hovered, setHovered] = useState(false)
  const hasCounts = job.entity_count !== undefined

  return (
    <article
      onClick={onSelect}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: 'var(--bg)',
        border: `1px solid ${
          selected ? 'var(--accent)' : hovered ? 'var(--rule)' : 'var(--rule-soft)'
        }`,
        borderRadius: 9,
        padding: 12,
        cursor: 'pointer',
        display: 'flex', flexDirection: 'column', gap: 9,
        transition: 'border-color .12s ease, box-shadow .12s ease, transform .12s ease',
        boxShadow: selected
          ? '0 0 0 2px color-mix(in oklab, var(--accent) 22%, transparent)'
          : hovered ? 'var(--shadow-card)' : 'none',
      }}
    >
      {/* File icon + title */}
      <header style={{ display: 'flex', alignItems: 'flex-start', gap: 6, minWidth: 0 }}>
        <FileText size={13} style={{ color: 'var(--ink-4)', flexShrink: 0, marginTop: 2 }} />
        <h3 style={{
          margin: 0, minWidth: 0,
          fontFamily: SERIF, fontSize: 15, fontWeight: 600, lineHeight: 1.3,
          color: 'var(--ink)',
          // 2-line clamp
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical' as const,
          overflow: 'hidden',
        } as React.CSSProperties}>
          {job.original_filename}
        </h3>
      </header>

      {/* Meta: entities · relationships */}
      <div style={{ fontSize: 10.5, fontFamily: MONO, color: 'var(--ink-3)' }}>
        {hasCounts
          ? `${job.entity_count} entities · ${job.relationship_count ?? 0} relationships`
          : 'awaiting extraction'
        }
      </div>

      {/* Footer: relative time + status pill */}
      <footer style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6,
      }}>
        <span style={{
          display: 'flex', alignItems: 'center', gap: 4,
          fontSize: 11, fontFamily: MONO, color: 'var(--ink-4)',
        }}>
          <Clock size={11} />
          {relTime(job.updated_at)}
        </span>
        <StatusPill status={job.status} />
      </footer>

      {/* Status-aware actions */}
      <div
        style={{ display: 'flex', gap: 5, flexWrap: 'wrap', alignItems: 'center' }}
        onClick={e => e.stopPropagation()}
      >
        {job.status === 'for_review' && (
          <ActBtn
            label="Analyse" primary
            icon={<Play size={10} />}
            onClick={onAnalyse}
          />
        )}
        {job.status === 'reviewing' && (
          <ActBtn
            label="Resume" primary
            icon={<Eye size={10} />}
            onClick={onAnalyse}
          />
        )}
        {job.status === 'completed' && (
          <>
            <ActBtn
              label="Open" primary
              icon={<Eye size={10} />}
              onClick={onAnalyse}
            />
            <ActBtn
              icon={<GitGraph size={10} />}
              onClick={onGraph}
            />
            <ActBtn
              icon={<Download size={10} />}
              onClick={onDownload}
            />
          </>
        )}
        {/* Trash — always last */}
        <ActBtn
          icon={<Trash2 size={10} />}
          onClick={onDelete}
          danger
          {...{ style: { marginLeft: 'auto' } }}
        />
      </div>
    </article>
  )
}

// ── ActivityCard ──────────────────────────────────────────────────────────────

function ActivityCard({ job, onViewProgress, onDelete }: {
  job: Job
  onViewProgress: () => void
  onDelete: () => void
}) {
  const isFailed = job.status === 'failed'
  return (
    <div style={{
      background: isFailed
        ? 'color-mix(in oklab, var(--no) 4%, var(--bg-elev))'
        : 'var(--bg-elev)',
      border: `1px solid ${isFailed
        ? 'color-mix(in oklab, var(--no) 40%, var(--rule))'
        : 'var(--rule)'}`,
      borderRadius: 10,
      padding: '11px 13px',
      display: 'flex', flexDirection: 'column', gap: 7,
    }}>
      {/* Top row: status icon + filename + dismiss */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
        {isFailed
          ? <AlertTriangle size={13} style={{ color: 'var(--no)', flexShrink: 0 }} />
          : <Loader2 size={13} className="animate-spin" style={{ color: 'var(--accent)', flexShrink: 0 }} />
        }
        <span style={{
          flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          fontSize: 12.5, fontWeight: 600, color: 'var(--ink)',
        }}>
          {job.original_filename}
        </span>
        <button
          onClick={onDelete}
          title="Remove job"
          style={{
            background: 'none', border: 'none', padding: 3, cursor: 'pointer',
            color: 'var(--ink-4)', display: 'flex', flexShrink: 0,
          }}
        >
          <X size={12} />
        </button>
      </div>

      {/* Processing: "View progress" link → opens ProgressModal */}
      {!isFailed && (
        <button
          onClick={onViewProgress}
          style={{
            background: 'none', border: 'none', padding: 0, cursor: 'pointer',
            fontSize: 11, color: 'var(--accent)',
            textAlign: 'left', textDecoration: 'underline',
          }}
        >
          View progress →
        </button>
      )}

      {/* Failed: timestamp */}
      {isFailed && (
        <span style={{ fontSize: 11.5, color: 'var(--ink-3)' }}>
          Pipeline failed · {relTime(job.updated_at)}
          {/* Retry requires a backend re-queue endpoint — not yet implemented */}
        </span>
      )}
    </div>
  )
}

// ── Dashboard page ────────────────────────────────────────────────────────────

export default function Dashboard() {
  const navigate = useNavigate()
  const qc = useQueryClient()

  // Local state
  const [activeJobId, setActiveJobId]       = useState<string | null>(null)
  const [activeFilename, setActiveFilename] = useState('')
  const [dragOver, setDragOver]             = useState(false)
  const [selectedId, setSelectedId]         = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  // ── Queries & mutations ──────────────────────────────────────────────────

  const { data: jobs = [], isLoading } = useQuery({
    queryKey: ['jobs'],
    queryFn: fetchJobs,
    refetchInterval: 3000,
  })

  const uploadMutation = useMutation({
    mutationFn: uploadFile,
    onSuccess: (data) => {
      setActiveJobId(data.job_id)
      setActiveFilename(data.filename)
      qc.invalidateQueries({ queryKey: ['jobs'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteJob(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['jobs'] }),
    onError:   () => alert('Could not delete job — check server logs'),
  })

  // ── Handlers (existing logic, unchanged) ─────────────────────────────────

  const handleFiles = useCallback((files: FileList | null) => {
    if (!files?.length) return
    uploadMutation.mutate(files[0])
  }, [uploadMutation])

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    // Guard: don't start a second upload while one is already in progress
    if (!isPending) handleFiles(e.dataTransfer.files)
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

  const isPending = uploadMutation.isPending

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

    dropzone: (over: boolean): React.CSSProperties => ({
      display: 'flex', alignItems: 'center', gap: 16,
      padding: '16px 20px',
      border: `1.5px dashed ${over ? 'var(--accent)' : 'var(--rule)'}`,
      borderRadius: 12,
      background: over ? 'var(--accent-soft)' : 'var(--bg-soft)',
      cursor: 'pointer',
      transition: 'border-color .15s ease, background .15s ease',
    }),

    iconTile: {
      width: 42, height: 42, borderRadius: 10, flexShrink: 0,
      background: 'var(--bg-elev)',
      border: '1px solid var(--rule)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      color: 'var(--accent)',
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
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>

      {/* ── Top bar ── */}
      <div style={s.topbar}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--ink)' }}>Dashboard</span>
          <span style={{ fontSize: 13, color: 'var(--ink-4)' }}>/</span>
          <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--ink-2)' }}>Reports</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 11, fontFamily: MONO, color: 'var(--ink-3)' }}>
            {jobs.length} reports
          </span>
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

        {/* Upload zone ────────────────────────────────────────────────────── */}
        <input
          ref={fileRef}
          type="file"
          className="hidden"
          accept=".pdf,.docx,.html,.htm,.txt,.md"
          onChange={e => handleFiles(e.target.files)}
        />
        <div
          style={s.dropzone(dragOver)}
          onDrop={handleDrop}
          onDragOver={e => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onClick={() => !isPending && fileRef.current?.click()}
        >
          <div style={s.iconTile}>
            {isPending
              ? <Loader2 size={18} className="animate-spin" />
              : <Upload size={18} />
            }
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 13, color: 'var(--ink-2)', lineHeight: 1.4 }}>
              {isPending ? (
                <span>Uploading…</span>
              ) : (
                <>
                  <strong style={{ fontWeight: 600 }}>Drop a CTI report</strong>
                  {' '}
                  <span style={{ color: 'var(--accent)', fontWeight: 600 }}>or browse</span>
                </>
              )}
            </div>
            <div style={{ fontSize: 11, fontFamily: MONO, color: 'var(--ink-4)', marginTop: 2 }}>
              PDF · DOCX · HTML · TXT · MD
            </div>
          </div>
          <button
            className="btn-primary"
            style={{ ...SM, flexShrink: 0 }}
            disabled={isPending}
            onClick={e => { e.stopPropagation(); fileRef.current?.click() }}
          >
            <Upload size={12} />
            Browse files
          </button>
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
                    padding: 11,
                    display: 'flex', flexDirection: 'column', gap: 11,
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
                          onSelect={() =>
                            setSelectedId(prev => prev === job.id ? null : job.id)
                          }
                          onAnalyse={() => handleAnalyse(job)}
                          onDelete={() => deleteMutation.mutate(job.id)}
                          onDownload={() => handleDownload(job)}
                          onGraph={() => navigate(`/graph/${job.id}`)}
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
