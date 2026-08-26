import { useState } from 'react'
import { Loader2, AlertTriangle, X } from 'lucide-react'
import { useSSE } from '../../hooks/useSSE'
import type { Job } from '../../types'

const MONO = "'JetBrains Mono', ui-monospace, monospace"

function ProgressRail({ jobId }: { jobId: string }) {
  const { latestStage } = useSSE(jobId)
  const stage = latestStage?.stage ?? 0
  const pct = Math.min(100, Math.max(6, (stage / 5) * 100))

  return (
    <div style={{ height: 3, borderRadius: 2, background: 'var(--rule-soft)', overflow: 'hidden' }}>
      <div
        style={{
          height: '100%',
          width: pct + '%',
          background: 'var(--accent)',
          borderRadius: 2,
          transition: 'width 240ms ease',
        }}
      />
    </div>
  )
}

interface Props {
  job: Job
  relTime: (iso: string) => string
  onViewProgress: () => void
  onDelete: () => void
}

export default function ActivityCard({ job, relTime, onViewProgress, onDelete }: Props) {
  const isFailed = job.status === 'failed'

  return (
    <div
      style={{
        background: isFailed ? 'color-mix(in oklab, var(--no) 4%, var(--bg-elev))' : 'var(--bg-elev)',
        border: '1px solid ' + (isFailed ? 'color-mix(in oklab, var(--no) 35%, var(--rule))' : 'var(--rule)'),
        borderRadius: 10,
        padding: '10px 12px',
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
        {isFailed ? (
          <AlertTriangle size={14} style={{ color: 'var(--no)', flexShrink: 0 }} />
        ) : (
          <Loader2 size={14} className="animate-spin" style={{ color: 'var(--accent)', flexShrink: 0 }} />
        )}
        <span
          style={{
            flex: 1,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            fontSize: 12.5,
            fontWeight: 600,
            color: 'var(--ink)',
          }}
        >
          {job.original_filename}
        </span>
        <button
          title="Remove job"
          aria-label="Remove job"
          onClick={onDelete}
          style={{
            background: 'none',
            border: 'none',
            padding: 3,
            cursor: 'pointer',
            color: 'var(--ink-4)',
            display: 'flex',
            flexShrink: 0,
          }}
        >
          <X size={12} />
        </button>
      </div>

      {!isFailed && <ProgressRail jobId={job.id} />}

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {!isFailed ? (
          <button
            onClick={onViewProgress}
            style={{
              background: 'none',
              border: 'none',
              padding: 0,
              cursor: 'pointer',
              fontSize: 11,
              color: 'var(--accent)',
              textAlign: 'left',
              textDecoration: 'underline',
            }}
          >
            View progress →
          </button>
        ) : (
          <span style={{ fontSize: 11.5, color: 'var(--ink-3)' }}>
            Pipeline failed · {relTime(job.updated_at)}
          </span>
        )}

        <div style={{ flex: 1 }} />

        {job.tlp_level && (
          <span
            style={{
              fontFamily: MONO,
              fontSize: 10,
              color: 'var(--ink-4)',
              border: '1px solid var(--rule-soft)',
              borderRadius: 4,
              padding: '1px 5px',
              whiteSpace: 'nowrap',
            }}
          >
            {`TLP:${job.tlp_level}`}
          </span>
        )}
      </div>
    </div>
  )
}
