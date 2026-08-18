import { useMemo } from 'react'

import type { RuleSelection, SelectableRule } from '../../hooks/useRuleSelection'
import type { DetectionFormat } from '../../types'
import { DETECTION_FORMATS } from '../../types'
import { FORMAT_STYLE, fmtBytes, formatDot, formatInk, formatLine, formatSoft } from '../review/tokens'
import type { TechEntry } from './model'
import TriCheckbox from './TriCheckbox'

/** Three cards, one per format — clicking a card toggles the whole format's
 *  selection. The tick band shows, per technique, whether this format has any
 *  rule and whether any of them is selected. */
export default function FormatBoard({ techs, rules, selection }: {
  techs: TechEntry[]                       // matrix order, one per technique
  rules: readonly SelectableRule[]         // the distinct rule set
  selection: RuleSelection
}) {
  // Distinct rule ids per format, derived from the rule set (not techs) so a
  // rule covering two techniques is counted once per format. `rules` is already
  // distinct by id, so a plain push suffices — no membership scan.
  const formatIds = useMemo<Record<DetectionFormat, string[]>>(() => {
    const acc: Record<DetectionFormat, string[]> = { sigma: [], suricata: [], yara: [] }
    for (const r of rules) acc[r.format]?.push(r.id)
    return acc
  }, [rules])

  return (
    <div className="cov-board">
      {DETECTION_FORMATS.map(f => {
        const ids = formatIds[f]
        const sel = selection.selectedOf(ids)
        const on = sel > 0
        const covered = techs.filter(t => t.byFormat[f].length > 0).length
        return (
          <div
            key={f}
            onClick={() => selection.toggleScope(ids)}
            style={{
              border: '1px solid ' + (on ? formatLine(f) : 'var(--rule)'),
              background: on ? 'var(--bg-elev)' : 'var(--bg-soft)',
              borderRadius: 8,
              padding: '11px 13px',
              cursor: 'pointer',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <TriCheckbox sel={sel} total={ids.length} size={16} onToggle={() => selection.toggleScope(ids)} />
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: formatDot(f), flexShrink: 0 }} />
              <span style={{ fontSize: 13, fontWeight: 600 }}>{FORMAT_STYLE[f].label}</span>
              <span style={{
                fontFamily: '"JetBrains Mono",monospace', fontSize: 10.5, color: 'var(--ink-2)',
                background: 'var(--bg-soft)', border: '1px solid var(--rule)', borderRadius: 4,
                padding: '1px 5px',
              }}>{FORMAT_STYLE[f].ext}</span>
              <span style={{ fontSize: 10.5, color: 'var(--ink-4)', marginLeft: 'auto' }}>{FORMAT_STYLE[f].dest}</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 8 }}>
              <span style={{
                fontFamily: '"Source Serif 4",Georgia,serif', fontSize: 24, fontWeight: 600,
                lineHeight: 1, color: formatInk(f),
              }}>{sel}</span>
              <span style={{ fontSize: 11.5, color: 'var(--ink-3)' }}>of {ids.length} rules selected</span>
              <span style={{
                fontFamily: '"JetBrains Mono",monospace', fontSize: 11, color: 'var(--ink-2)',
                marginLeft: 'auto',
              }}>{fmtBytes(selection.bytesOf(ids))}</span>
            </div>

            <div style={{ display: 'flex', gap: 2, marginTop: 9 }}>
              {techs.map(t => {
                const has = t.byFormat[f].length > 0
                const anySel = has && selection.selectedOf(t.byFormat[f]) > 0
                return (
                  <span
                    key={t.id}
                    title={has ? `${t.id} — ${t.byFormat[f].length} rule(s)` : `${t.id} — no rule`}
                    style={{
                      flex: 1, height: 8, borderRadius: 2,
                      background: anySel ? formatLine(f) : has ? formatSoft(f) : 'var(--rule-soft)',
                      border: '1px solid ' + (has ? formatLine(f) : 'var(--rule)'),
                    }}
                  />
                )
              })}
            </div>

            <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 7 }}>
              {covered} of {techs.length} techniques have a {FORMAT_STYLE[f].label} rule
            </div>
          </div>
        )
      })}
    </div>
  )
}
