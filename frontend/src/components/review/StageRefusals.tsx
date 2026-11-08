import { AlertTriangle } from 'lucide-react'
import type { StageRecord } from '../../types'

interface Props {
  stages: StageRecord[] | undefined
}

/** The stages that did not run, and why (ADR-0059).  An egress refusal (ADR-0097) is
 *  the reason a bundle has no LLM content, so it says what to do about it. */
export default function StageRefusals({ stages }: Props) {
  const notRun = (stages ?? []).filter(s => s.status !== 'ran' && s.reason)
  if (notRun.length === 0) return null
  const refused = notRun.some(s => s.egress?.allowed === false)
  return (
    <div role="region" aria-label="Stages that did not run" className="stage-refusals"
         style={{
           padding: '8px 22px', fontSize: 12.5, color: 'var(--ink-2)', flexShrink: 0,
           background: 'color-mix(in oklab, var(--warn) 8%, var(--bg-soft))',
           borderBottom: '1px solid var(--rule)',
         }}>
      <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 3 }}>
        {notRun.map(s => (
          <li key={s.stage} style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}
              data-egress-refusal={s.egress?.allowed === false ? 'true' : undefined}>
            <AlertTriangle size={13} aria-hidden="true" style={{ flexShrink: 0, marginTop: 2, color: 'var(--warn)' }} />
            <span>
              <strong style={{ fontWeight: s.egress?.allowed === false ? 700 : 600 }}>
                Stage {s.stage}{s.label ? ` — ${s.label}` : ''}: {s.status}
              </strong>
              {' — '}{s.reason}
            </span>
          </li>
        ))}
      </ul>
      {refused && (
        <div style={{ marginTop: 4, color: 'var(--ink-3)' }}>
          This is why the bundle holds no LLM extraction. Mark the report CLEAR or GREEN if that is allowed,
          or configure a local model (vllm, ollama or lmstudio on this machine or network).
        </div>
      )}
    </div>
  )
}
