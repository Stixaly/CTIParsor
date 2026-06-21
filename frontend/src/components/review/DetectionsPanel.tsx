import { useQuery } from '@tanstack/react-query'
import { ShieldCheck, ExternalLink } from 'lucide-react'

import { fetchCoverageReportRules } from '../../api/client'
import type { CoverageRule } from '../../types'

/** Lists the Sigma rules that can be linked to this report, grouped by the
 *  ATT&CK technique they cover. Read-only, metadata-only (ADR-0006) — it shows
 *  detection *readiness*, not that a rule was tested against live telemetry. */
export default function DetectionsPanel({ jobId }: { jobId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['coverage-rules', jobId],
    queryFn: () => fetchCoverageReportRules(jobId),
    enabled: !!jobId,
  })

  if (isLoading) return <Wrap><p style={dim}>Loading detections…</p></Wrap>
  if (isError) return <Wrap><p style={{ ...dim, color: 'var(--no)' }}>Could not load detections.</p></Wrap>

  const groups = data?.techniques ?? []
  if (groups.length === 0) {
    return (
      <Wrap>
        <div style={{ textAlign: 'center', color: 'var(--ink-3)', padding: '50px 20px' }}>
          <ShieldCheck size={36} style={{ color: 'var(--ink-4)' }} />
          <p style={{ margin: '12px 0 4px', fontSize: 14, color: 'var(--ink-2)' }}>
            No Sigma rules match this report's techniques.
          </p>
          <p style={{ margin: 0, fontSize: 12 }}>
            Accept some ATT&amp;CK techniques, or download rule corpora in
            {' '}<strong>Settings</strong> and rebuild the index.
          </p>
        </div>
      </Wrap>
    )
  }

  return (
    <Wrap>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 12 }}>
        <h2 style={{ fontSize: 15, margin: 0, color: 'var(--ink)' }}>Linkable Sigma rules</h2>
        <span style={{ fontSize: 12, color: 'var(--ink-3)' }}>
          {data!.rule_total} rule{data!.rule_total === 1 ? '' : 's'} across {data!.technique_total} technique
          {data!.technique_total === 1 ? '' : 's'}
        </span>
      </div>
      <p style={{ fontSize: 11.5, color: 'var(--ink-4)', margin: '0 0 14px', lineHeight: 1.5 }}>
        Detection <strong>readiness</strong>: which public rules exist for the techniques extracted from this
        report — not that any rule was tested against live telemetry. Respect each rule's license before redistributing.
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {groups.map(g => (
          <div key={g.technique_id}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6,
              paddingBottom: 4, borderBottom: '1px solid var(--rule)',
            }}>
              <span style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 600, color: 'var(--accent)' }}>
                {g.technique_id}
              </span>
              <span style={{ fontSize: 11, color: 'var(--ink-3)' }}>
                {g.rules.length} rule{g.rules.length === 1 ? '' : 's'}
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {g.rules.map(r => <RuleRow key={r.id} rule={r} />)}
            </div>
          </div>
        ))}
      </div>
    </Wrap>
  )
}

function RuleRow({ rule }: { rule: CoverageRule }) {
  const isUrl = /^https?:\/\//i.test(rule.source_ref ?? '')
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10,
      padding: '7px 10px', borderRadius: 7,
      border: '1px solid var(--rule-soft)', background: 'var(--bg-elev)',
    }}>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ fontSize: 13, color: 'var(--ink)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {rule.title || rule.id}
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 3 }}>
          <Badge>{rule.corpus}</Badge>
          {rule.severity && <Badge>{rule.severity}</Badge>}
          <Badge subtle>{rule.license}</Badge>
          {rule.also_in && rule.also_in.length > 0 && (
            <span style={{ fontSize: 10.5, color: 'var(--ink-4)' }}>also in {rule.also_in.join(', ')}</span>
          )}
        </div>
      </div>
      {isUrl && (
        <a href={rule.source_ref} target="_blank" rel="noopener noreferrer"
          title="Open rule source" style={{ color: 'var(--ink-3)', flexShrink: 0, display: 'flex' }}>
          <ExternalLink size={14} />
        </a>
      )}
    </div>
  )
}

function Badge({ children, subtle }: { children: React.ReactNode; subtle?: boolean }) {
  return (
    <span style={{
      fontSize: 10.5, padding: '1px 6px', borderRadius: 5,
      background: subtle ? 'transparent' : 'var(--bg-soft)',
      border: '1px solid var(--rule)',
      color: subtle ? 'var(--ink-4)' : 'var(--ink-2)',
      fontFamily: 'monospace',
    }}>
      {children}
    </span>
  )
}

function Wrap({ children }: { children: React.ReactNode }) {
  return <div style={{ padding: '14px 56px 40px', overflowY: 'auto' }}>{children}</div>
}

const dim: React.CSSProperties = { color: 'var(--ink-3)', fontSize: 13, padding: '20px 0' }
