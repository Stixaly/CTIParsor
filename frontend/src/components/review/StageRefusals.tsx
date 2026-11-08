import { AlertTriangle } from 'lucide-react'
import type { StageRecord } from '../../types'

interface Props {
  stages: StageRecord[] | undefined
}

const refusedEgress = (s: StageRecord) => s.egress?.allowed === false

function StageLine({ s }: { s: StageRecord }) {
  const loud = refusedEgress(s) || s.status === 'failed'
  return (
    <li style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}
        data-egress-refusal={refusedEgress(s) ? 'true' : undefined}>
      <AlertTriangle size={13} aria-hidden="true"
                     style={{ flexShrink: 0, marginTop: 2, color: loud ? 'var(--warn)' : 'var(--ink-3)' }} />
      <span>
        <strong style={{ fontWeight: loud ? 700 : 600 }}>
          Stage {s.stage}{s.label ? ` — ${s.label}` : ''}: {s.status}
        </strong>
        {' — '}{s.reason}
      </span>
    </li>
  )
}

const LIST = { margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 3 } as const

/** The stages that did not run, and why (ADR-0059).  A failed stage and an egress refusal
 *  (ADR-0097) stay in view: the refusal is why a bundle has no LLM content, so it says what
 *  to do about it.  The other skips (a disabled stage, one with nothing to do, one after a
 *  stage that did not run) fold into one line: an install without the optional models
 *  skips a dozen, and listing them all would push the review out of the window. */
export default function StageRefusals({ stages }: Props) {
  const notRun = (stages ?? []).filter(s => s.status !== 'ran' && s.reason)
  if (notRun.length === 0) return null
  const loud = notRun.filter(s => refusedEgress(s) || s.status === 'failed')
  const quiet = notRun.filter(s => !loud.includes(s))
  const refused = loud.some(refusedEgress)
  return (
    <div role="region" aria-label="Stages that did not run" className="stage-refusals"
         style={{
           padding: '6px 22px', fontSize: 12.5, color: 'var(--ink-2)', flexShrink: 0,
           maxHeight: '30vh', overflowY: 'auto',
           background: loud.length
             ? 'color-mix(in oklab, var(--warn) 8%, var(--bg-soft))'
             : 'var(--bg-soft)',
           borderBottom: '1px solid var(--rule)',
         }}>
      {loud.length > 0 && <ul style={LIST}>{loud.map(s => <StageLine key={s.stage} s={s} />)}</ul>}
      {refused && (
        <div style={{ marginTop: 4, color: 'var(--ink-3)' }}>
          This is why the bundle holds no LLM extraction. Mark the report CLEAR or GREEN if that is allowed,
          or configure a local model (vllm, ollama or lmstudio on this machine or network).
        </div>
      )}
      {quiet.length > 0 && (
        <details style={{ marginTop: loud.length ? 4 : 0 }}>
          <summary style={{ cursor: 'pointer', color: 'var(--ink-3)' }}>
            {quiet.length} {quiet.length === 1 ? 'stage' : 'stages'} skipped
            {' '}({quiet.map(s => s.stage).join(', ')})
          </summary>
          <ul style={{ ...LIST, marginTop: 4 }}>{quiet.map(s => <StageLine key={s.stage} s={s} />)}</ul>
        </details>
      )}
    </div>
  )
}
