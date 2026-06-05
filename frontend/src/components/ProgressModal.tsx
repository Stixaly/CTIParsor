import { useSSE } from '../hooks/useSSE'
import { X, Loader2, CheckCircle2, AlertCircle } from 'lucide-react'

const STAGES = [
  { n: 1, label: 'Ingestion' },
  { n: 2, label: 'Extraction' },
  { n: 3, label: 'LLM Enrichment' },
  { n: 4, label: 'STIX Mapping' },
  { n: 5, label: 'Validation' },
]

interface Props {
  jobId: string
  filename: string
  onClose: () => void
}

export default function ProgressModal({ jobId, filename, onClose }: Props) {
  const { events, done } = useSSE(jobId)

  const completedStages = new Set(events.filter(e => e.stage).map(e => e.stage!))
  const latest = events.filter(e => e.stage !== undefined).slice(-1)[0]
  const failed = events.some(e => e.status === 'failed')
  const currentStageN = latest?.stage ?? 0

  // Latest event for a given stage (used for completed detail lines)
  const latestForStage = (n: number) =>
    [...events].reverse().find(e => e.stage === n)

  // All events for stage 3 — we want the latest running totals
  const latestStage3 = latestForStage(3)

  const getStageDetail = (n: number): string => {
    const ev = latestForStage(n)
    if (!ev) return ''

    if (n === 1) {
      return `${ev.chars?.toLocaleString() ?? '?'} chars → ${ev.chunks ?? '?'} chunks`
    }

    if (n === 2) {
      const parts: string[] = [`${ev.entities ?? 0} entities`]
      if (ev.gazetteer)     parts.push(`${ev.gazetteer} gazetteer`)
      if (ev.semantic_ttps) parts.push(`${ev.semantic_ttps} semantic TTPs`)
      if (ev.cyner)         parts.push(`${ev.cyner} CyNER`)
      if (ev.gliner)        parts.push(`${ev.gliner} GLiNER`)
      return parts.join(' · ')
    }

    if (n === 3) {
      const chunkPart = ev.total ? `chunk ${ev.chunk}/${ev.total}` : ''
      const entityParts: string[] = []
      if ((ev.malware ?? 0) > 0)        entityParts.push(`${ev.malware} malware`)
      if ((ev.actors  ?? 0) > 0)        entityParts.push(`${ev.actors} actors`)
      if ((ev.tools   ?? 0) > 0)        entityParts.push(`${ev.tools} tools`)
      if ((ev.relationships ?? 0) > 0)  entityParts.push(`${ev.relationships} rels`)
      return [chunkPart, entityParts.join(' · ')].filter(Boolean).join('  ·  ')
    }

    if (n === 4) return `${ev.objects ?? 0} STIX objects`
    if (n === 5) return ev.valid ? 'Valid ✓' : 'Validation warnings'
    return ''
  }

  // Live sub-detail shown while Stage 3 is active (entity accumulation ticker)
  const stage3Live = (() => {
    if (!latestStage3 || currentStageN !== 3) return null
    const parts: string[] = []
    if ((latestStage3.malware ?? 0) > 0)       parts.push(`${latestStage3.malware} malware`)
    if ((latestStage3.actors  ?? 0) > 0)       parts.push(`${latestStage3.actors} actors`)
    if ((latestStage3.tools   ?? 0) > 0)       parts.push(`${latestStage3.tools} tools`)
    if ((latestStage3.relationships ?? 0) > 0) parts.push(`${latestStage3.relationships} rels`)
    return parts.length ? parts.join(' · ') : null
  })()

  return (
    <div style={{
      position: 'fixed', inset: 0,
      background: 'rgba(0,0,0,0.55)',
      backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 100,
    }}>
      <div style={{
        background: 'var(--bg-elev)',
        border: '1px solid var(--rule)',
        borderRadius: 16,
        boxShadow: 'var(--shadow-pop)',
        width: '100%',
        maxWidth: 420,
        padding: '24px 24px 20px',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--ink)' }}>Processing report</div>
            <div style={{ fontSize: 12, color: 'var(--ink-3)', marginTop: 3, maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {filename}
            </div>
          </div>
          {/* Always visible — closing dismisses the progress display but does
              NOT stop the pipeline, which keeps running in the background. */}
          <button
            onClick={onClose}
            className="back"
            style={{ width: 28, height: 28, flexShrink: 0 }}
            title={done ? 'Close' : 'Dismiss — pipeline continues in background'}
          >
            <X size={15} />
          </button>
        </div>

        {/* Stage list */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {STAGES.map(stage => {
            // A stage is "complete" when either:
            //   a) the pipeline is fully done (`done`=true from the SSE "done" event), OR
            //   b) a later stage has already started (currentStageN > stage.n).
            // We must also check `done` because otherwise the LAST stage (5) can
            // never satisfy `currentStageN > stage.n` and would display "active" forever.
            const isComplete = completedStages.has(stage.n) && (done || currentStageN > stage.n)
            const isActive   = !done && currentStageN === stage.n
            const detail = getStageDetail(stage.n)

            return (
              <div key={stage.n} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                {/* Icon */}
                <div style={{ width: 22, height: 22, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  {isComplete ? (
                    <CheckCircle2 size={18} style={{ color: 'var(--ok)' }} />
                  ) : isActive ? (
                    <Loader2 size={18} className="animate-spin" style={{ color: 'var(--accent)' }} />
                  ) : (
                    <div style={{ width: 14, height: 14, borderRadius: '50%', border: '2px solid var(--rule)' }} />
                  )}
                </div>

                {/* Label + detail */}
                <div style={{ flex: 1 }}>
                  <div style={{
                    fontSize: 13,
                    fontWeight: isActive ? 600 : 400,
                    color: isComplete ? 'var(--ink)' : isActive ? 'var(--accent)' : 'var(--ink-4)',
                  }}>
                    Stage {stage.n} — {stage.label}
                  </div>
                  {/* Completed detail */}
                  {isComplete && detail && (
                    <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                      {detail}
                    </div>
                  )}
                  {/* Active: chunk progress line */}
                  {isActive && detail && (
                    <div style={{ fontSize: 11, color: 'var(--accent)', marginTop: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                      {detail}
                    </div>
                  )}
                  {/* Active Stage 3: running entity accumulation */}
                  {isActive && stage.n === 3 && stage3Live && (
                    <div style={{ fontSize: 10.5, color: 'var(--ink-3)', marginTop: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                      {stage3Live}
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>

        {/* Footer status */}
        <div style={{ marginTop: 18, paddingTop: 14, borderTop: '1px solid var(--rule)' }}>
          {failed ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--no)' }}>
              <AlertCircle size={15} />
              Pipeline failed — check server logs
            </div>
          ) : done ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--ok)' }}>
              <CheckCircle2 size={15} />
              Complete — ready for review
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--ink-3)' }}>
              <Loader2 size={15} className="animate-spin" />
              Running pipeline…
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
