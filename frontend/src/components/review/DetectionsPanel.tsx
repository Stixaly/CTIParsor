import { useState } from 'react'

import { useQuery } from '@tanstack/react-query'
import { ShieldCheck, ExternalLink, AlertTriangle } from 'lucide-react'

import { fetchDetectionProposals } from '../../api/client'
import type { ProposalMatch, ProposalTier, RuleProposal } from '../../types'
import { typeInk, typeSoft } from './tokens'

/** Detection rules ranked by what this report actually contains — hashes,
 *  domains, binaries, paths, registry keys, CVEs — and by platform, not by
 *  ATT&CK tag alone (ADR-0014). Read-only and metadata-only: it shows detection
 *  *readiness*, not that a rule was tested against live telemetry. */
export default function DetectionsPanel({ jobId }: { jobId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['detection-proposals', jobId],
    queryFn: () => fetchDetectionProposals(jobId),
    enabled: !!jobId,
  })

  if (isLoading) return <Wrap><p style={dim}>Ranking detections…</p></Wrap>
  if (isError) return <Wrap><p style={{ ...dim, color: 'var(--no)' }}>Could not load detections.</p></Wrap>

  const proposals = data?.proposals ?? []
  if (proposals.length === 0) {
    return (
      <Wrap>
        {data && !data.atom_index_built && <AtomIndexWarning />}
        <div style={{ textAlign: 'center', color: 'var(--ink-3)', padding: '50px 20px' }}>
          <ShieldCheck size={36} style={{ color: 'var(--ink-4)' }} />
          <p style={{ margin: '12px 0 4px', fontSize: 14, color: 'var(--ink-2)' }}>
            No rule matches this report.
          </p>
          <p style={{ margin: 0, fontSize: 12 }}>
            Accept some techniques or IoCs, or download rule corpora in
            {' '}<strong>Settings</strong> and rebuild the index.
          </p>
        </div>
      </Wrap>
    )
  }

  const counts = data!.counts
  const groups: Array<{ tier: ProposalTier; label: string; hint: string }> = [
    { tier: 'direct', label: 'Matched this report', hint: 'a rule field matches an observable extracted from the report' },
    { tier: 'behavioural', label: 'Behavioural', hint: 'ATT&CK technique match only, compatible with the report platform' },
    { tier: 'weak', label: 'Off-platform', hint: 'technique match, but the rule targets another OS than this report' },
  ]

  return (
    <Wrap>
      {!data!.atom_index_built && <AtomIndexWarning />}

      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
        <h2 style={{ fontSize: 15, margin: 0, color: 'var(--ink)' }}>Proposed detections</h2>
        <span style={{ fontSize: 12, color: 'var(--ink-3)' }}>
          top {data!.returned} of {data!.candidate_total} candidates
          {' · '}{counts.direct} matched on {data!.observables_total} observable
          {data!.observables_total === 1 ? '' : 's'}
        </span>
      </div>

      <p style={{ fontSize: 11.5, color: 'var(--ink-4)', margin: '0 0 6px', lineHeight: 1.5 }}>
        Ranked by overlap with this report's technical content and by platform — not by
        ATT&amp;CK tag alone. Detection <strong>readiness</strong>: these rules exist, they were not
        tested against live telemetry. Respect each rule's license before redistributing.
      </p>
      {data!.platform && (
        <p style={{ fontSize: 11.5, color: 'var(--ink-3)', margin: '0 0 14px' }}>
          Report platform: <strong>{data!.platform}</strong>
          {data!.platform === 'multi'
            ? ' — mixed evidence, no platform demotion applied.'
            : ' — rules written for another OS are demoted.'}
        </p>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
        {groups.map(g => {
          const rows = proposals.filter(p => p.tier === g.tier)
          if (rows.length === 0) return null
          return (
            <TierSection key={g.tier} label={g.label} hint={g.hint} total={counts[g.tier] ?? rows.length}>
              {rows}
            </TierSection>
          )
        })}
      </div>
    </Wrap>
  )
}

/** One tier of proposals, collapsed to a preview when long. */
function TierSection({ label, hint, total, children }: {
  label: string; hint: string; total: number; children: RuleProposal[]
}) {
  const PREVIEW = 12
  const [expanded, setExpanded] = useState(false)
  const shown = expanded ? children : children.slice(0, PREVIEW)

  return (
    <div>
      <div style={{
        display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 6,
        paddingBottom: 4, borderBottom: '1px solid var(--rule)',
      }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--ink)' }}>{label}</span>
        <span style={{ fontSize: 11, color: 'var(--ink-3)' }}>{total}</span>
        <span style={{ fontSize: 10.5, color: 'var(--ink-4)', marginLeft: 'auto', textAlign: 'right' }}>{hint}</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {shown.map(p => <ProposalRow key={p.id} proposal={p} />)}
      </div>
      {children.length > PREVIEW && (
        <button
          onClick={() => setExpanded(v => !v)}
          style={{
            marginTop: 8, fontSize: 11.5, color: 'var(--ink-3)', background: 'none',
            border: '1px solid var(--rule)', borderRadius: 6, padding: '3px 10px', cursor: 'pointer',
          }}
        >
          {expanded ? 'Show less' : `Show ${children.length - PREVIEW} more`}
        </button>
      )}
    </div>
  )
}

function ProposalRow({ proposal: r }: { proposal: RuleProposal }) {
  const isUrl = /^https?:\/\//i.test(r.source_ref ?? '')
  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: 10,
      padding: '7px 10px', borderRadius: 7,
      border: '1px solid var(--rule-soft)', background: 'var(--bg-elev)',
    }}>
      <ScorePill score={r.score} />
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ fontSize: 13, color: 'var(--ink)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {r.title || r.id}
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 3, alignItems: 'center' }}>
          <Badge>{r.corpus}</Badge>
          {r.severity && r.severity !== 'unknown' && <Badge>{r.severity}</Badge>}
          {r.platform && <Badge>{r.platform}</Badge>}
          <Badge subtle>{r.license}</Badge>
          {r.techniques.slice(0, 3).map(t => (
            <span key={t} style={{ fontSize: 10.5, fontFamily: 'monospace', color: 'var(--accent)' }}>{t}</span>
          ))}
          {r.techniques.length > 3 && (
            <span style={{ fontSize: 10.5, color: 'var(--ink-4)' }}>+{r.techniques.length - 3}</span>
          )}
        </div>
        {r.matches.length > 0 && (
          <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 5 }}>
            {r.matches.map((m, i) => <EvidenceChip key={`${m.value}-${m.field}-${i}`} match={m} />)}
          </div>
        )}
      </div>
      {isUrl && (
        <a href={r.source_ref} target="_blank" rel="noopener noreferrer"
          title="Open rule source" style={{ color: 'var(--ink-3)', flexShrink: 0, display: 'flex', marginTop: 2 }}>
          <ExternalLink size={14} />
        </a>
      )}
    </div>
  )
}

/** Observable class → the entity type whose colour it borrows, so evidence
 *  chips read in the same palette as the document highlights. */
const OBS_TYPE: Record<string, string> = {
  hash: 'sha256', ip: 'ipv4', domain: 'domain', url: 'url',
  file: 'file', image: 'file', registry: 'registry_key',
  user: 'user_account', port: 'network_traffic', name: 'tool', cve: 'cve',
}

function EvidenceChip({ match: m }: { match: ProposalMatch }) {
  const t = OBS_TYPE[m.obs_class] ?? 'file'
  return (
    <span
      title={`${m.exact ? 'Exact' : 'Partial'} match — rule field "${m.field}" ${m.exact ? 'is' : 'contains'} ${m.display}`}
      style={{
        fontSize: 10.5, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 5,
        background: typeSoft(t), color: typeInk(t),
        border: `1px solid ${m.exact ? 'transparent' : 'var(--rule)'}`,
        borderStyle: m.exact ? 'solid' : 'dashed',
        maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }}
    >
      {m.field} {m.exact ? '≡' : '⊃'} {m.display}
    </span>
  )
}

function ScorePill({ score }: { score: number }) {
  const pct = Math.round(score * 100)
  // 0 → neutral blue, 1 → green: the same hue ramp as the coverage matrix.
  const hue = 250 - Math.round(score * 100)
  return (
    <span
      title={`Relevance ${pct}%`}
      style={{
        flexShrink: 0, minWidth: 34, textAlign: 'center', marginTop: 1,
        fontSize: 10.5, fontFamily: 'monospace', padding: '2px 5px', borderRadius: 5,
        background: `oklch(0.93 0.06 ${hue})`, color: `oklch(0.32 0.13 ${hue})`,
        border: `1px solid oklch(0.70 0.10 ${hue})`,
      }}
    >
      {pct}
    </span>
  )
}

function AtomIndexWarning() {
  return (
    <div style={{
      display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 14,
      padding: '8px 11px', borderRadius: 7,
      border: '1px solid var(--rule)', background: 'var(--bg-soft)',
    }}>
      <AlertTriangle size={14} style={{ color: 'var(--ink-3)', flexShrink: 0, marginTop: 2 }} />
      <p style={{ margin: 0, fontSize: 11.5, color: 'var(--ink-2)', lineHeight: 1.5 }}>
        The detection-atom index is empty, so rules can only be ranked by ATT&amp;CK technique.
        Run <code>python scripts/build_rule_atoms.py</code> to index what each rule looks for.
      </p>
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
