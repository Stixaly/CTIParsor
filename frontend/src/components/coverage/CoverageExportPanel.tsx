import { useMemo, useState } from 'react'
import type { DetectionFormat } from '../../types'
import { DETECTION_FORMATS } from '../../types'
import type { SelectableRule, RuleSelection } from '../../hooks/useRuleSelection'
import type { TechEntry } from './model'
import {
  FORMAT_STYLE,
  formatDot,
  formatLine,
  formatSoft,
  formatInk,
  fmtBytes,
  COVERAGE_LABEL,
  coverageColor,
} from '../review/tokens'
import TriCheckbox from './TriCheckbox'
import { detectionsExportUrl, downloadExportSelection } from '../../api/client'

const mono = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace'

const GRID = {
  display: 'grid',
  gridTemplateColumns: '22px 1.5fr 118px 62px 74px 1fr',
  gap: '0 10px',
  alignItems: 'center',
} as const

interface Props {
  jobId: string
  reportName: string
  columns: Array<{ tactic: string; label: string; techs: TechEntry[] }>
  rules: readonly SelectableRule[]
  rulesById: ReadonlyMap<string, SelectableRule>
  selection: RuleSelection
  /** True when at least one rule was promoted from the proposals panel. Such a
   *  rule is an addition the server-side selection cannot reproduce, so the
   *  streaming GET export must not be used. */
  hasPromoted: boolean
}

export default function CoverageExportPanel({
  jobId,
  reportName,
  columns,
  rules,
  rulesById,
  selection,
  hasPromoted,
}: Props): JSX.Element {
  const [view, setView] = useState<'tactic' | 'format'>('tactic')
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState(false)

  // Distinct rule ids grouped by format, plus per-format corpus buckets.
  const { formatIds, byCorpus, corporaTotal, totalBytes } = useMemo(() => {
    const formatIds: Record<DetectionFormat, string[]> = { sigma: [], suricata: [], yara: [] }
    const byCorpus: Record<DetectionFormat, Array<{ corpus: string; license: string; ids: string[] }>> = {
      sigma: [],
      suricata: [],
      yara: [],
    }
    const corpusSet = new Set<string>()
    let totalBytes = 0
    for (const r of rules) {
      formatIds[r.format].push(r.id)
      corpusSet.add(r.corpus)
      totalBytes += r.bytes
    }
    for (const f of DETECTION_FORMATS) {
      const map = new Map<string, { corpus: string; license: string; ids: string[] }>()
      for (const id of formatIds[f]) {
        const r = rulesById.get(id)
        if (!r) continue
        const entry = map.get(r.corpus)
        if (entry) entry.ids.push(id)
        else map.set(r.corpus, { corpus: r.corpus, license: r.license, ids: [id] })
      }
      byCorpus[f] = Array.from(map.values()).sort((a, b) => b.ids.length - a.ids.length)
    }
    return { formatIds, byCorpus, corporaTotal: corpusSet.size, totalBytes }
  }, [rules, rulesById])

  // Selection-derived values, recomputed each render.
  const selRules = rules.filter((r) => selection.isSelected(r.id))
  const restricted = selRules.filter((r) => r.license === 'none').length
  const any = selection.selectedCount > 0

  // Small chip: counts rules of format f within scopeIds.
  const fmtChip = (scopeIds: string[], f: DetectionFormat) => {
    const set = scopeIds.filter((id) => rulesById.get(id)?.format === f)
    const sel = selection.selectedOf(set)
    const live = sel > 0
    return (
      <span
        key={f}
        title={`${FORMAT_STYLE[f].label}: ${sel} of ${set.length} selected`}
        style={{
          fontFamily: mono,
          fontSize: 9.5,
          fontWeight: 600,
          padding: '1px 4px',
          borderRadius: 3,
          background: live ? formatSoft(f) : 'transparent',
          color: live ? formatInk(f) : 'var(--ink-4)',
          border: '1px solid ' + (live ? formatLine(f) : 'var(--rule)'),
        }}
      >
        {FORMAT_STYLE[f].letter} {set.length ? sel : '—'}
      </span>
    )
  }

  // Generic selectable row (group or child).
  const Row = ({
    ids,
    dot,
    label,
    sub,
    indent = 0,
    group = false,
    right,
    rightColor,
    bg,
  }: {
    ids: string[]
    dot: string
    label: string
    sub?: string
    indent?: number
    group?: boolean
    right: string
    rightColor: string
    bg?: string
  }) => {
    const sel = selection.selectedOf(ids)
    const total = ids.length
    const live = sel > 0
    return (
      <div
        style={{
          ...GRID,
          padding: '6px 0',
          borderBottom: '1px solid var(--rule-soft)',
          cursor: 'pointer',
          background: bg,
        }}
        onClick={() => selection.toggleScope(ids)}
      >
        <TriCheckbox sel={sel} total={total} size={16} onToggle={() => selection.toggleScope(ids)} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, minWidth: 0, paddingLeft: indent }}>
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: dot,
              flexShrink: 0,
            }}
          />
          <span
            style={{
              fontSize: 12.5,
              fontWeight: group ? 600 : 400,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              color: live ? (group ? 'var(--ink)' : 'var(--ink-2)') : 'var(--ink-4)',
            }}
          >
            {label}
          </span>
          {sub ? (
            <span style={{ fontFamily: mono, fontSize: 10.5, color: 'var(--ink-3)', flexShrink: 0 }}>{sub}</span>
          ) : null}
        </div>
        <div style={{ display: 'flex', gap: 3 }}>
          {view === 'tactic'
            ? DETECTION_FORMATS.map((f) => fmtChip(ids, f))
            : fmtChip(ids, (rulesById.get(ids[0])?.format ?? 'sigma') as DetectionFormat)}
        </div>
        <span style={{ fontFamily: mono, fontSize: 11.5, textAlign: 'right' }}>
          {total ? `${sel}/${total}` : '—'}
        </span>
        <span style={{ fontFamily: mono, fontSize: 11, textAlign: 'right', color: 'var(--ink-2)' }}>
          {total ? fmtBytes(selection.bytesOf(ids)) : '—'}
        </span>
        <span
          style={{
            fontSize: 11,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            color: rightColor,
          }}
        >
          {right}
        </span>
      </div>
    )
  }

  // Build the archive preview lines.
  const archiveLines = useMemo(() => {
    // Mirror of the API-side _safe_slug: strip extension, slugify, cap length.
    const stem =
      (reportName.replace(/\.[^.]+$/, '') || 'report')
        .replace(/[^\w-]+/g, '_')
        .replace(/^_+|_+$/g, '')
        .slice(0, 80) || 'report'
    const slug = (t: string) =>
      t
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '')
        .slice(0, 40) || 'rule'

    const lines: Array<{ text: string; color: string }> = [
      { text: `${stem}_detection_rules.zip`, color: 'var(--ink)' },
    ]

    let formatsWithSel = 0
    for (const f of DETECTION_FORMATS) {
      const set = formatIds[f].filter((id) => selection.isSelected(id))
      if (set.length === 0) continue
      formatsWithSel += 1
      lines.push({ text: `├─ rules/${f}/  · ${set.length} × ${FORMAT_STYLE[f].ext}`, color: formatInk(f) })
      for (const id of set.slice(0, 2)) {
        const r = rulesById.get(id)
        if (!r) continue
        lines.push({ text: `│   ├─ ${r.corpus}__${slug(r.title)}${FORMAT_STYLE[f].ext}`, color: 'var(--ink-3)' })
      }
      if (set.length > 2) lines.push({ text: `│   └─ … ${set.length - 2} more`, color: 'var(--ink-4)' })
    }
    if (formatsWithSel === 0) lines.push({ text: '(nothing selected)', color: 'var(--ink-4)' })
    lines.push({ text: '├─ MANIFEST.json  · license + source per rule', color: 'var(--ink-2)' })
    lines.push({ text: '└─ README.txt  · formats present, excluded counts', color: 'var(--ink-2)' })
    return { lines, formatsWithSel }
  }, [reportName, formatIds, selection, rulesById])

  if (rules.length === 0) {
    return (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 14,
          padding: 20,
          background: 'var(--bg-elev)',
          border: '1px solid var(--rule-soft)',
          borderRadius: 8,
        }}
      >
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Export detection rules</h3>
        <p style={{ fontSize: 14, color: 'var(--ink-3)', padding: '12px 0', margin: 0 }}>
          No detection rules match this report.
        </p>
      </div>
    )
  }

  const segBtn = (key: 'tactic' | 'format', label: string) => (
    <button
      type="button"
      onClick={() => setView(key)}
      style={{
        fontSize: 11.5,
        fontWeight: 600,
        padding: '4px 10px',
        borderRadius: 5,
        cursor: 'pointer',
        fontFamily: 'inherit',
        background: view === key ? 'var(--accent-soft)' : 'var(--bg-elev)',
        border: '1px solid ' + (view === key ? 'var(--accent)' : 'var(--rule)'),
        color: view === key ? 'var(--accent)' : 'var(--ink-2)',
      }}
    >
      {label}
    </button>
  )

  const ghostBtn = (label: string, onClick: () => void) => (
    <button
      type="button"
      onClick={onClick}
      style={{
        fontSize: 11.5,
        background: 'var(--bg-elev)',
        border: '1px solid var(--rule)',
        color: 'var(--ink-2)',
        borderRadius: 5,
        padding: '3px 9px',
        cursor: 'pointer',
        fontFamily: 'inherit',
      }}
    >
      {label}
    </button>
  )

  const primaryStyle: React.CSSProperties = {
    padding: '8px 16px',
    background: 'var(--accent)',
    color: '#fff',
    borderRadius: 4,
    fontSize: 14,
    fontWeight: 500,
    textDecoration: 'none',
    display: 'inline-block',
  }

  const handleDownload = async () => {
    setError(false)
    setDownloading(true)
    try {
      const ids = rules.filter((r) => selection.isSelected(r.id)).map((r) => r.id)
      const { blob, filename } = await downloadExportSelection(jobId, ids)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      setError(true)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
        padding: 20,
        background: 'var(--bg-elev)',
        border: '1px solid var(--rule-soft)',
        borderRadius: 8,
      }}
    >
      {/* 1. Title row */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Export detection rules</h3>
        <p style={{ fontSize: 12, color: 'var(--ink-3)', margin: 0 }}>
          {`${rules.length} rules match this report · ${fmtBytes(totalBytes)} · 3 formats, ${corporaTotal} corpora`}
        </p>
        <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
          {segBtn('tactic', 'By ATT&CK tactic')}
          {segBtn('format', 'By format · corpus')}
        </div>
      </div>

      {/* 2. Selection summary bar */}
      <div
        style={{
          padding: '8px 11px',
          borderRadius: 7,
          background: 'var(--bg-soft)',
          border: '1px solid var(--rule)',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          flexWrap: 'wrap',
        }}
      >
        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent)' }}>
          {`${selection.selectedCount} of ${rules.length} rules selected`}
        </span>
        {DETECTION_FORMATS.map((f) => {
          const n = selection.selectedOf(formatIds[f])
          const live = n > 0
          return (
            <span key={f} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
              <span
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: live ? formatLine(f) : 'var(--rule)',
                }}
              />
              <span style={{ color: live ? formatInk(f) : 'var(--ink-4)' }}>
                {`${FORMAT_STYLE[f].label} ${n}`}
              </span>
            </span>
          )
        })}
        {restricted > 0 ? (
          <span style={{ fontSize: 11.5, color: 'var(--warn)' }}>
            {`${restricted} all-rights-reserved — local use only`}
          </span>
        ) : any ? (
          <span style={{ fontSize: 11.5, color: 'var(--ok)' }}>All selected rules are redistributable</span>
        ) : null}
        <div style={{ display: 'flex', gap: 6, marginLeft: 'auto' }}>
          {ghostBtn('Select all', () => selection.selectAll())}
          {ghostBtn('Clear', () => selection.clearAll())}
        </div>
      </div>

      {/* 3. Two-pane body */}
      <div className="cov-export-body">
        {/* Left: selection table. `alignSelf` keeps it full-width once the
            archive preview stacks underneath it below 1180px. */}
        <div style={{ flex: 1, minWidth: 0, alignSelf: 'stretch' }}>
          <div style={{ minWidth: 0, overflowX: 'auto' }}>
            <div
              style={{
                ...GRID,
                fontSize: 10.5,
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                color: 'var(--ink-3)',
                paddingBottom: 6,
                borderBottom: '1px solid var(--rule)',
              }}
            >
              <span />
              <span>{view === 'tactic' ? 'Tactic · technique' : 'Format · corpus'}</span>
              <span>Formats</span>
              <span style={{ textAlign: 'right' }}>Rules</span>
              <span style={{ textAlign: 'right' }}>Size</span>
              <span>{view === 'tactic' ? 'Corpora / license flags' : 'License'}</span>
            </div>
            <div style={{ maxHeight: 520, overflowY: 'auto' }}>
              {view === 'tactic'
                ? columns.map((col) => {
                    const ids = Array.from(new Set(col.techs.flatMap((t) => t.ruleIds)))
                    const selIds = ids.filter((id) => selection.isSelected(id))
                    const corpora = new Set(selIds.map((id) => rulesById.get(id)?.corpus).filter(Boolean)).size
                    return (
                      <div key={col.tactic}>
                        <Row
                          ids={ids}
                          dot="var(--accent)"
                          label={col.label}
                          sub={`${col.techs.length} technique${col.techs.length === 1 ? '' : 's'}`}
                          group
                          right={`${corpora} corpora`}
                          rightColor="var(--ink-3)"
                          bg="var(--bg-soft)"
                        />
                        {col.techs.map((t) => {
                          const selT = t.ruleIds.filter((id) => selection.isSelected(id))
                          const k = selT.filter((id) => rulesById.get(id)?.license === 'none').length
                          const corporaT = new Set(
                            t.ruleIds.map((id) => rulesById.get(id)?.corpus).filter(Boolean),
                          ).size
                          let right: string
                          let rightColor: string
                          if (t.ruleIds.length === 0) {
                            right = COVERAGE_LABEL[t.score]
                            rightColor = 'var(--ink-4)'
                          } else if (k > 0) {
                            right = `${k} all-rights-reserved`
                            rightColor = 'var(--warn)'
                          } else {
                            right = `${corporaT} corpora`
                            rightColor = 'var(--ink-3)'
                          }
                          return (
                            <Row
                              key={t.id}
                              ids={t.ruleIds}
                              dot={coverageColor(t.score).border}
                              label={`${t.id} · ${t.name}`}
                              indent={14}
                              right={right}
                              rightColor={rightColor}
                            />
                          )
                        })}
                      </div>
                    )
                  })
                : DETECTION_FORMATS.map((f) => {
                    const licenses = new Set(
                      formatIds[f].map((id) => rulesById.get(id)?.license).filter(Boolean),
                    ).size
                    return (
                      <div key={f}>
                        <Row
                          ids={formatIds[f]}
                          dot={formatDot(f)}
                          label={FORMAT_STYLE[f].label}
                          sub={FORMAT_STYLE[f].dest}
                          group
                          right={`${licenses} licenses · ${FORMAT_STYLE[f].ext}`}
                          rightColor="var(--ink-3)"
                          bg="var(--bg-soft)"
                        />
                        {byCorpus[f].map((c) => {
                          // Each rule already lists the techniques it covers — never
                          // rescan every TechEntry (O(ids x techs x ruleIds) at 8k rules).
                          const techsCovered = new Set(
                            c.ids.flatMap((id) => rulesById.get(id)?.techniques ?? []),
                          ).size
                          const none = c.license === 'none'
                          return (
                            <Row
                              key={c.corpus}
                              ids={c.ids}
                              dot={formatSoft(f)}
                              label={c.corpus}
                              sub={`${techsCovered} techniques`}
                              indent={14}
                              right={none ? 'none — all rights reserved' : c.license}
                              rightColor={none ? 'var(--warn)' : 'var(--ink-3)'}
                              bg={none ? 'color-mix(in oklab, var(--warn) 5%, transparent)' : undefined}
                            />
                          )
                        })}
                      </div>
                    )
                  })}
            </div>
          </div>
        </div>

        {/* Right: archive preview — drops under the table below 1180px. */}
        <div
          className="cov-archive"
          style={{
            background: 'var(--bg-soft)',
            border: '1px solid var(--rule)',
            borderRadius: 8,
            padding: '12px 14px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <span
              style={{
                fontSize: 10.5,
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.06em',
                color: 'var(--ink-3)',
              }}
            >
              ARCHIVE CONTENTS
            </span>
            <span style={{ fontFamily: mono, fontSize: 10.5, color: 'var(--ink-2)', marginLeft: 'auto' }}>
              {`${archiveLines.formatsWithSel} format${archiveLines.formatsWithSel === 1 ? '' : 's'}`}
            </span>
          </div>
          <div style={{ fontFamily: mono, fontSize: 11, lineHeight: 1.75 }}>
            {archiveLines.lines.map((l, i) => (
              <div
                key={i}
                style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: l.color }}
              >
                {l.text}
              </div>
            ))}
          </div>
          <p style={{ margin: '10px 0 0', fontSize: 11, color: 'var(--ink-3)', lineHeight: 1.5 }}>
            Each rule keeps the extension its tool requires, and <code>MANIFEST.json</code> records what was
            excluded — an export that silently dropped rules would look identical to one where they never matched.
          </p>
        </div>
      </div>

      {/* 4. Action row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        {!any ? (
          <span
            style={{
              padding: '8px 16px',
              background: 'var(--bg-soft)',
              color: 'var(--ink-4)',
              border: '1px solid var(--rule)',
              borderRadius: 4,
              fontSize: 14,
              fontWeight: 500,
            }}
          >
            Nothing selected
          </span>
        ) : selection.excluded.size === 0 && !hasPromoted ? (
          // Full set rides the GET so the browser streams it — no blob in memory.
          //
          // Only valid when the selection IS the server's own set. A promoted
          // rule is an ADDITION the server-side selection does not know about,
          // so the GET would silently ship the report's rules and drop every
          // promotion — the bug this guard exists for.
          <a href={detectionsExportUrl(jobId)} download style={primaryStyle}>
            {`Download ZIP · ${selection.selectedCount} rules`}
          </a>
        ) : (
          <button
            type="button"
            disabled={downloading}
            onClick={handleDownload}
            style={{
              ...primaryStyle,
              border: 'none',
              cursor: downloading ? 'wait' : 'pointer',
              fontFamily: 'inherit',
            }}
          >
            {downloading ? 'Preparing ZIP…' : `Download ZIP · ${selection.selectedCount} rules`}
          </button>
        )}
        {error ? (
          <span style={{ fontSize: 12, color: 'var(--no)' }}>Download failed — try again</span>
        ) : null}
        <span style={{ fontSize: 12, color: 'var(--ink-3)' }}>
          {`${fmtBytes(selection.selectedBytes)} · ${rules.length - selection.selectedCount} excluded, recorded in MANIFEST.json`}
        </span>
        <button
          type="button"
          onClick={() => selection.selectAll()}
          style={{
            fontSize: 12,
            color: 'var(--ink-3)',
            background: 'none',
            border: 'none',
            padding: 0,
            cursor: 'pointer',
            textDecoration: 'underline',
            fontFamily: 'inherit',
          }}
        >
          Reset
        </button>
      </div>

      {/* 5. Footer */}
      <p style={{ margin: 0, fontSize: 11.5, color: 'var(--ink-4)', lineHeight: 1.5 }}>
        Selection is per rule and rolls up through technique, ATT&CK tactic, corpus and format — every level shows a
        dash when only part of it is selected. Each rule retains its original license; rules marked{' '}
        <em>all rights reserved</em> must not be redistributed.
      </p>
    </div>
  )
}
