import { useState } from 'react'

import type { RuleSelection, SelectableRule } from '../../hooks/useRuleSelection'
import type { ProposalMatch } from '../../types'
import { DETECTION_FORMATS } from '../../types'
import { COVERAGE_LABEL, FORMAT_STYLE, fmtBytes, formatDot, typeInk, typeSoft } from '../review/tokens'
import type { TechEntry } from './model'
import TriCheckbox from './TriCheckbox'

// Same mapping as DetectionsPanel's evidence chips — kept local because the two
// panels render evidence independently.
const OBS_TYPE: Record<string, string> = {
  hash: 'sha256', ip: 'ipv4', domain: 'domain', url: 'url',
  file: 'file', image: 'file', registry: 'registry_key',
  user: 'user_account', port: 'network_traffic', name: 'tool', cve: 'cve',
}

/** The strip under the matrix: the drilled-in technique's rules, one column per
 *  format (a missing format stays visible as an absence), every rule
 *  individually selectable. */
export default function DrillInStrip({ tech, selection, rulesById, evidence }: {
  tech: TechEntry | null                              // null until coverage loads
  selection: RuleSelection
  rulesById: ReadonlyMap<string, SelectableRule>
  evidence: ReadonlyMap<string, ProposalMatch>        // rule id → strongest match
}) {
  // "Show all" is per (technique, format) pair. Declared before the null guard —
  // hooks must run on every render.
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})

  if (tech === null) return null

  const sel = selection.selectedOf(tech.ruleIds)
  const total = tech.ruleIds.length
  const corpora = new Set(
    tech.ruleIds.map(id => rulesById.get(id)?.corpus).filter((c): c is string => c !== undefined),
  ).size
  const size = fmtBytes(selection.bytesOf(tech.ruleIds))
  const allSelected = total > 0 && sel === total

  const btnLabel = total === 0 ? 'Nothing to select' : allSelected ? 'Clear technique' : 'Select technique'
  const btnStyle: React.CSSProperties = total === 0
    ? { border: '1px solid var(--rule)', color: 'var(--ink-4)', background: 'var(--bg-elev)', cursor: 'default' }
    : allSelected
      ? { background: 'var(--accent-soft)', border: '1px solid var(--accent)', color: 'var(--accent)', cursor: 'pointer' }
      : { background: 'var(--bg-elev)', border: '1px solid var(--accent)', color: 'var(--accent)', cursor: 'pointer' }

  return (
    <div style={{ border: '1px solid var(--rule)', background: 'var(--bg-elev)', borderRadius: 8, padding: '13px 15px', marginBottom: 14 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap', marginBottom: 10 }}>
        <span style={{ fontFamily: '"JetBrains Mono",monospace', fontSize: 12.5, fontWeight: 600, color: 'var(--accent)' }}>{tech.id}</span>
        <span style={{ fontFamily: '"Source Serif 4",Georgia,serif', fontSize: 16, fontWeight: 600 }}>{tech.name}</span>
        <span style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--ink-3)' }}>{tech.tactics.join(' · ')}</span>
        <span style={{ fontSize: 12, color: 'var(--ink-3)', marginLeft: 'auto' }}>
          {total === 0
            ? COVERAGE_LABEL[tech.score]
            : `${sel} of ${total} rules selected · ${corpora} corpora · ${size}`}
        </span>
        <button
          style={{ fontSize: 11.5, borderRadius: 5, padding: '3px 9px', fontFamily: 'inherit', ...btnStyle }}
          onClick={total === 0 ? undefined : () => selection.toggleScope(tech.ruleIds)}
        >
          {btnLabel}
        </button>
      </div>

      {/* Always all three formats, in display order — an absent format must be
          visible as an absence, not silently omitted. */}
      <div className="cov-drill-cols">
        {DETECTION_FORMATS.map(f => {
          const ids = tech.byFormat[f]
          const gSel = selection.selectedOf(ids)
          const key = `${tech.id}|${f}`
          const isExpanded = !!expanded[key]
          const shown = isExpanded ? ids : ids.slice(0, 5)

          return (
            <div key={f}>
              <div
                style={{
                  display: 'flex', alignItems: 'center', gap: 7, padding: '2px 2px 4px',
                  borderBottom: '1px solid var(--rule-soft)', marginBottom: 6, cursor: 'pointer',
                }}
                onClick={() => selection.toggleScope(ids)}
              >
                <TriCheckbox sel={gSel} total={ids.length} size={14} onToggle={() => selection.toggleScope(ids)} />
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: formatDot(f), flexShrink: 0 }} />
                <span style={{ fontSize: 12, fontWeight: 600 }}>{FORMAT_STYLE[f].label}</span>
                <span style={{ fontFamily: '"JetBrains Mono",monospace', fontSize: 10.5, color: 'var(--ink-3)', marginLeft: 'auto' }}>
                  {ids.length > 0 ? `${gSel}/${ids.length} · ${FORMAT_STYLE[f].ext}` : '—'}
                </span>
              </div>

              {ids.length === 0 ? (
                <div style={{ fontSize: 11, color: 'var(--ink-3)', fontStyle: 'italic', padding: '4px 0' }}>
                  No rule in this format.
                </div>
              ) : (
                <>
                  {/* A real technique holds up to 6,172 Suricata rules: an expanded
                      column is capped and scrolls, and each row is layout-skipped
                      until visible via content-visibility. */}
                  <div style={{
                    display: 'flex', flexDirection: 'column', gap: 4,
                    ...(isExpanded ? { maxHeight: 480, overflowY: 'auto' as const } : {}),
                  }}>
                    {shown.map(id => {
                      const r = rulesById.get(id)
                      if (!r) return null
                      const on = selection.isSelected(id)
                      const m = evidence.get(id)
                      return (
                        <div
                          key={id}
                          onClick={() => selection.toggleScope([id])}
                          style={{
                            display: 'flex', gap: 7, alignItems: 'flex-start', padding: '5px 7px',
                            borderRadius: 5, cursor: 'pointer',
                            border: on ? '1px solid var(--accent)' : '1px solid var(--rule-soft)',
                            background: on ? 'var(--accent-soft)' : 'var(--bg)',
                            contentVisibility: 'auto',
                            containIntrinsicSize: 'auto 52px',
                          }}
                        >
                          <div style={{ marginTop: 1 }}>
                            <TriCheckbox sel={on ? 1 : 0} total={1} size={14} onToggle={() => selection.toggleScope([id])} />
                          </div>
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <div style={{ fontSize: 11.5, lineHeight: 1.3, color: on ? 'var(--ink)' : 'var(--ink-3)' }}>
                              {r.title}
                            </div>
                            <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 3 }}>
                              <span style={{ fontFamily: '"JetBrains Mono",monospace', fontSize: 10, color: 'var(--ink-3)' }}>{r.corpus}</span>
                              <span style={{ fontFamily: '"JetBrains Mono",monospace', fontSize: 10, color: 'var(--ink-3)' }}>{r.severity}</span>
                              <span style={{
                                fontFamily: '"JetBrains Mono",monospace', fontSize: 10,
                                color: r.license === 'none' ? 'var(--warn)' : 'var(--ink-3)',
                              }}>{r.license}</span>
                              <span style={{ fontFamily: '"JetBrains Mono",monospace', fontSize: 10, color: 'var(--ink-4)', marginLeft: 'auto' }}>
                                {FORMAT_STYLE[f].ext}
                              </span>
                            </div>
                            {m && (
                              <span style={{
                                marginTop: 4, fontFamily: '"JetBrains Mono",monospace', fontSize: 10,
                                padding: '1px 5px', borderRadius: 4, border: '1px dashed var(--rule)',
                                background: typeSoft(OBS_TYPE[m.obs_class] ?? 'file'),
                                color: typeInk(OBS_TYPE[m.obs_class] ?? 'file'),
                                display: 'inline-block', maxWidth: '100%', overflow: 'hidden',
                                textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                              }}>
                                {m.field} {m.exact ? '≡' : '⊃'} {m.display}
                              </span>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>

                  {ids.length > 5 && (
                    <button
                      style={{
                        marginTop: 4, fontSize: 11, color: 'var(--ink-2)', background: 'none',
                        border: '1px solid var(--rule)', borderRadius: 5, padding: '3px 8px',
                        cursor: 'pointer', fontFamily: 'inherit',
                      }}
                      onClick={() => setExpanded(prev => ({ ...prev, [key]: !prev[key] }))}
                    >
                      {isExpanded ? 'Show fewer' : `Show ${ids.length - 5} more`}
                    </button>
                  )}
                </>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
