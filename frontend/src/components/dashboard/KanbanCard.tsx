import { useState } from 'react'
import { GitGraph, ShieldCheck, Download, Trash2 } from 'lucide-react'
import type { Job, JobStatus } from '../../types'

const MONO  = "'JetBrains Mono', ui-monospace, monospace"
const SERIF = "'Source Serif 4', Georgia, serif"

const MARKING_TONE: Record<string, string> = {
  WHITE: 'var(--ink-3)',
  GREEN: 'var(--ok)',
  AMBER: 'var(--warn)',
  RED:   'var(--no)',
}

const STATUS_DOT: Record<string, string> = {
  for_review: 'var(--warn)',
  reviewing:  'var(--accent)',
  completed:  'var(--ok)',
}

// Hoisted to module scope on purpose.  Declared inside KanbanCard they would be
// a NEW component type on every render, so React would unmount and remount them
// -- discarding their hover state.  The dashboard refetches every 3s, so that
// remount happens constantly and hover would never stick.
const TextBtn = ({ label, onClick }: { label: string; onClick: () => void }) => {
  const [h, setH] = useState(false)
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setH(true)}
      onMouseLeave={() => setH(false)}
      style={{
        background: h ? 'var(--accent-soft)' : 'transparent',
        border: '1px solid ' + (h ? 'var(--accent)' : 'var(--rule)'),
        color: 'var(--accent)',
        fontSize: 10.5,
        fontWeight: 600,
        padding: '3px 8px',
        borderRadius: 5,
        cursor: 'pointer',
        whiteSpace: 'nowrap',
      }}
    >
      {label}
    </button>
  )
}

const IconBtn = ({ icon, label, onClick }: { icon: React.ReactNode; label: string; onClick: () => void }) => {
  const [h, setH] = useState(false)
  return (
    <button
      title={label}
      aria-label={label}
      onClick={onClick}
      onMouseEnter={() => setH(true)}
      onMouseLeave={() => setH(false)}
      style={{
        width: 22,
        height: 22,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: h ? 'var(--bg-soft)' : 'transparent',
        border: '1px solid ' + (h ? 'var(--rule)' : 'var(--rule-soft)'),
        borderRadius: 5,
        color: h ? 'var(--ink)' : 'var(--ink-3)',
        cursor: 'pointer',
      }}
    >
      {icon}
    </button>
  )
}

interface Props {
  job: Job
  selected: boolean
  relTime: (iso: string) => string
  onSelect: () => void
  onAnalyse: () => void
  onDelete: () => void
  onDownload: () => void
  onGraph: () => void
  onCoverage: () => void
}

export default function KanbanCard({ job, selected, relTime, onSelect, onAnalyse, onDelete, onDownload, onGraph, onCoverage }: Props) {
  const [hovered, setHovered] = useState(false)

  const actionLabel = job.status === 'for_review' ? 'Analyse' : job.status === 'reviewing' ? 'Resume' : 'Open'

  const tone = MARKING_TONE[job.tlp_level ?? ''] ?? 'var(--ink-3)'

  return (
    <article
      onClick={onSelect}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: 'var(--bg)',
        borderRadius: 9,
        padding: '9px 10px',
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
        cursor: 'pointer',
        transition: 'border-color .12s ease, box-shadow .12s ease',
        border: '1px solid ' + (selected ? 'var(--accent)' : hovered ? 'var(--rule)' : 'var(--rule-soft)'),
        boxShadow: selected ? '0 0 0 2px color-mix(in oklab, var(--accent) 20%, transparent)' : 'none',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 7, minWidth: 0 }}>
        <div
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            marginTop: 5,
            flexShrink: 0,
            background: STATUS_DOT[job.status] ?? 'var(--ink-4)',
          }}
        />
        <h3
          style={{
            margin: 0,
            minWidth: 0,
            fontFamily: SERIF,
            fontSize: 14,
            fontWeight: 600,
            lineHeight: 1.28,
            color: 'var(--ink)',
            display: '-webkit-box',
            WebkitLineClamp: 2,
            WebkitBoxOrient: 'vertical',
            overflow: 'hidden',
          } as React.CSSProperties}
        >
          {job.original_filename}
        </h3>
      </div>

      {/* nowrap on purpose: at a 250px column the body is ~232px, and a fourth item
          wraps to a second line — which costs exactly the density this card is for. */}
      <div
        style={{
          paddingLeft: 13,
          display: 'flex',
          alignItems: 'center',
          gap: 5,
          fontFamily: MONO,
          fontSize: 10,
          color: 'var(--ink-3)',
          flexWrap: 'nowrap',
          overflow: 'hidden',
        }}
      >
        <span style={{ whiteSpace: 'nowrap' }}>
          {job.entity_count !== undefined
            ? `${job.entity_count} ent · ${job.relationship_count ?? 0} rel`
            : 'awaiting extraction'}
        </span>
        <span style={{ whiteSpace: 'nowrap', color: 'var(--ink-4)' }}>·</span>
        <span style={{ whiteSpace: 'nowrap', color: 'var(--ink-4)' }}>{relTime(job.updated_at)}</span>
      </div>

      <div
        style={{ paddingLeft: 13, display: 'flex', alignItems: 'center', gap: 3 }}
        onClick={(e: React.MouseEvent) => e.stopPropagation()}
      >
        <TextBtn label={actionLabel} onClick={onAnalyse} />

        {job.status === 'completed' && (
          <>
            <IconBtn icon={<GitGraph size={12} />} label="Graph" onClick={onGraph} />
            <IconBtn icon={<ShieldCheck size={12} />} label="Coverage" onClick={onCoverage} />
            <IconBtn icon={<Download size={12} />} label="Download bundle" onClick={onDownload} />
          </>
        )}

        <div style={{ flex: 1 }} />

        {job.tlp_level && (
          <span
            style={{
              fontFamily: MONO,
              fontSize: 9.5,
              padding: '1px 4px',
              borderRadius: 3,
              letterSpacing: '.03em',
              whiteSpace: 'nowrap',
              color: tone,
              border: '1px solid color-mix(in oklab, ' + tone + ' 30%, var(--rule-soft))',
            }}
          >
            {`TLP:${job.tlp_level}`}
          </span>
        )}

        <DeleteBtn onClick={onDelete} />
      </div>
    </article>
  )
}

function DeleteBtn({ onClick }: { onClick: () => void }) {
  const [h, setH] = useState(false)
  return (
    <button
      title="Delete"
      aria-label="Delete report"
      onClick={onClick}
      onMouseEnter={() => setH(true)}
      onMouseLeave={() => setH(false)}
      style={{
        width: 22,
        height: 22,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'transparent',
        border: '1px solid ' + (h ? 'color-mix(in oklab, var(--no) 30%, transparent)' : 'transparent'),
        borderRadius: 5,
        color: h ? 'var(--no)' : 'var(--ink-4)',
        cursor: 'pointer',
      }}
    >
      <Trash2 size={12} />
    </button>
  )
}
