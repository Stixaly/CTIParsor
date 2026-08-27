import { useState } from 'react'

import { useQuery } from '@tanstack/react-query'
import { ShieldCheck, ExternalLink, AlertTriangle } from 'lucide-react'

import { fetchDetectionProposals } from '../../api/client'
import { usePromotedRules } from '../../hooks/usePromotedRules'
import type { DetectionFormat, ProposalMatch } from '../../types'
import { DETECTION_FORMATS } from '../../types'
import RuleBodyDrawer from './RuleBodyDrawer'
import { typeInk, typeSoft, FORMAT_STYLE, formatDot, formatInk } from './tokens'

/** Grid template shared by the header row and every proposal row — they must
 *  stay in step or the columns drift apart. */
const GRID = '26px 44px 84px 1fr 180px 140px'

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

  const [fmtFilter, setFmtFilter] = useState<'all' | DetectionFormat>('all')
  const [showAll, setShowAll] = useState(false)
  // A proposal is not in the coverage rule set — measured, 199 of 200 on one
  // real report — so promoting it is an ADDITION, tracked apart from the
  // coverage page's exclusion-based selection.
  const promoted = usePromotedRules(jobId)
  const [openRuleId, setOpenRuleId] = useState<string | null>(null)

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
  const filtered = fmtFilter === 'all' ? proposals : proposals.filter(p => p.format === fmtFilter)
  const shown = showAll ? filtered : filtered.slice(0, 30)

  return (
    <Wrap>
      {data && !data.atom_index_built && <AtomIndexWarning />}

      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
        <h2 style={{ fontSize: 15, margin: 0, color: 'var(--ink)' }}>Proposed detections</h2>
        <span style={{ fontSize: 12, color: 'var(--ink-3)' }}>
          top {data!.returned} of {data!.candidate_total} candidates
          {' · '}{counts.direct} matched on {data!.observables_total} observable
          {data!.observables_total === 1 ? '' : 's'}
          {data!.corroborated_total > 0 && (
            <span
              style={{ color: 'var(--accent)' }}
              title="Rules holding at least two distinct discriminating report values"
            >
              {' · '}{data!.corroborated_total} corroborated
            </span>
          )}
          {promoted.count > 0 && (
            <span
              style={{ color: 'var(--accent)' }}
              title="Added to the coverage selection — they will be in the export"
            >
              {' · '}{promoted.count} added to coverage
            </span>
          )}
        </span>
        <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
          <FilterChip
            active={fmtFilter === 'all'}
            label="All"
            count={proposals.length}
            dotColor="var(--ink-4)"
            onClick={() => { setFmtFilter('all'); setShowAll(false) }}
          />
          {DETECTION_FORMATS.map(f => (
            <FilterChip
              key={f}
              active={fmtFilter === f}
              label={FORMAT_STYLE[f].label}
              count={proposals.filter(p => p.format === f).length}
              dotColor={formatDot(f)}
              onClick={() => { setFmtFilter(f); setShowAll(false) }}
            />
          ))}
        </div>
      </div>

      <p style={{ fontSize: 11.5, color: 'var(--ink-4)', margin: '0 0 12px', lineHeight: 1.5 }}>
        One ranked list; format is a column, not a section — so the top of the list is the top of the list regardless of which tool the rule belongs to.
      </p>

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

      <div style={{
        display: 'grid',
        gridTemplateColumns: GRID,
        gap: '0 12px',
        alignItems: 'center',
        fontSize: 10.5,
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
        color: 'var(--ink-3)',
        paddingBottom: 6,
        borderBottom: '1px solid var(--rule)',
      }}>
        <span title="Add to the coverage selection and the export">Add</span>
        <span>Rank</span>
        <span>Format</span>
        <span>Rule</span>
        <span>Evidence</span>
        <span>Corpus · license</span>
      </div>

      {filtered.length === 0 ? (
        <p style={{ ...dim, padding: '14px 0' }}>
          No {FORMAT_STYLE[fmtFilter as DetectionFormat].label} rule matches this report.
        </p>
      ) : (
        <>
          {shown.map(p => (
            <div
              key={p.id}
              style={{
                display: 'grid',
                gridTemplateColumns: GRID,
                gap: '0 12px',
                alignItems: 'center',
                padding: '8px 0',
                borderBottom: '1px solid var(--rule-soft)',
              }}
            >
              <input
                type="checkbox"
                checked={promoted.isPromoted(p.id)}
                onChange={() => promoted.toggle(p.id)}
                title={
                  promoted.isPromoted(p.id)
                    ? 'Added to coverage — it will be selected and exported'
                    : 'Add this rule to the coverage selection'
                }
                style={{ cursor: 'pointer', margin: 0 }}
              />
              <div style={{ textAlign: 'center' }}>
                <ScorePill score={p.score} />
              </div>
              <span style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
                fontSize: 11.5,
                fontWeight: 600,
                color: formatInk(p.format),
              }}>
                <span style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: formatDot(p.format),
                  flexShrink: 0,
                }} />
                {FORMAT_STYLE[p.format].label}
              </span>
              <div style={{ minWidth: 0 }}>
                <button
                  onClick={() => setOpenRuleId(p.id)}
                  title="Open the rule body — read it before trusting the rank"
                  style={{
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    color: 'var(--ink)',
                    background: 'none',
                    border: 'none',
                    padding: 0,
                    margin: 0,
                    fontFamily: 'inherit',
                    fontSize: 12.5,
                    textAlign: 'left',
                    cursor: 'pointer',
                    width: '100%',
                    textDecoration: 'underline',
                    textDecorationColor: 'var(--rule)',
                    textUnderlineOffset: 3,
                  }}
                >
                  {p.title || p.id}
                </button>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 2 }}>
                  {p.techniques[0] && (
                    <span style={{ fontSize: 10.5, fontFamily: 'monospace', color: 'var(--accent)' }}>
                      {p.techniques[0]}
                    </span>
                  )}
                  <span style={{ fontSize: 10.5, color: 'var(--ink-4)' }}>{p.tier}</span>
                  <span style={{ fontSize: 10.5, fontFamily: 'monospace', color: 'var(--ink-4)' }}>
                    {FORMAT_STYLE[p.format].ext}
                  </span>
                  {p.source_ref && /^https?:\/\//.test(p.source_ref) && (
                    <a
                      href={p.source_ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      title="Open rule source"
                      style={{ color: 'var(--ink-3)', display: 'inline-flex', alignItems: 'center' }}
                    >
                      <ExternalLink size={12} />
                    </a>
                  )}
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, minWidth: 0 }}>
                {p.matches.length > 0
                  ? <EvidenceChip match={p.matches[0]} />
                  : <span style={{ fontSize: 10.5, color: 'var(--ink-4)' }}>—</span>}
                {p.evidence_count > 1 && (
                  <span
                    title={`${p.evidence_count} distinct report values corroborate this rule`}
                    style={{
                      flexShrink: 0, fontSize: 10, fontWeight: 700, fontFamily: 'monospace',
                      padding: '1px 5px', borderRadius: 4,
                      background: 'var(--accent-soft)', color: 'var(--accent)',
                    }}
                  >
                    ×{p.evidence_count}
                  </span>
                )}
              </div>
              <span style={{ fontSize: 11, color: 'var(--ink-2)' }}>
                {p.corpus} ·{' '}
                <span style={{ color: p.license === 'none' ? 'var(--warn)' : 'var(--ink-3)' }}>
                  {p.license}
                </span>
              </span>
            </div>
          ))}
          {filtered.length > 30 && (
            <button
              onClick={() => setShowAll(s => !s)}
              style={{
                marginTop: 8,
                fontSize: 11.5,
                color: 'var(--ink-3)',
                background: 'none',
                border: '1px solid var(--rule)',
                borderRadius: 6,
                padding: '3px 10px',
                cursor: 'pointer',
                fontFamily: 'inherit',
              }}
            >
              {showAll ? 'Show less' : `Show ${filtered.length - 30} more`}
            </button>
          )}
        </>
      )}

      <RuleBodyDrawer ruleId={openRuleId} onClose={() => setOpenRuleId(null)} />
    </Wrap>
  )
}

function FilterChip({
  active,
  label,
  count,
  dotColor,
  onClick,
}: {
  active: boolean
  label: string
  count: number
  dotColor: string
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        fontSize: 11.5,
        fontFamily: 'inherit',
        padding: '4px 10px',
        borderRadius: 5,
        fontWeight: 600,
        cursor: 'pointer',
        background: active ? 'var(--accent-soft)' : 'var(--bg-elev)',
        border: active ? '1px solid var(--accent)' : '1px solid var(--rule)',
        color: active ? 'var(--accent)' : 'var(--ink-2)',
      }}
    >
      <span style={{
        width: 6,
        height: 6,
        borderRadius: '50%',
        background: dotColor,
        flexShrink: 0,
      }} />
      {label}
      <span style={{
        fontFamily: 'monospace',
        fontSize: 10,
        fontWeight: 500,
        opacity: 0.75,
      }}>
        {count}
      </span>
    </button>
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

function Wrap({ children }: { children: React.ReactNode }) {
  return <div style={{ padding: '14px 56px 40px', overflowY: 'auto' }}>{children}</div>
}

const dim: React.CSSProperties = { color: 'var(--ink-3)', fontSize: 13, padding: '20px 0' }
