import { useEffect, useMemo, useState } from 'react'

import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import {
  fetchCoverageReportRules,
  fetchDetectionProposals,
  fetchJob,
} from '../api/client'
import {
  COVERAGE_LABEL,
  coverageColor,
  FORMAT_STYLE,
  formatLine,
  formatSoft,
} from '../components/review/tokens'
import { useCoverage } from '../hooks/useCoverage'
import { useRuleSelection } from '../hooks/useRuleSelection'
import type { SelectableRule } from '../hooks/useRuleSelection'
import type { ProposalMatch } from '../types'
import { DETECTION_FORMATS } from '../types'
import DrillInStrip from '../components/coverage/DrillInStrip'
import FormatBoard from '../components/coverage/FormatBoard'
import TriCheckbox from '../components/coverage/TriCheckbox'
import CoverageExportPanel from '../components/coverage/CoverageExportPanel'
import type { TechEntry } from '../components/coverage/model'

// ATT&CK enterprise tactics in kill-chain order (column order).
const TACTIC_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
]
const TACTIC_LABEL: Record<string, string> = {
  'reconnaissance': 'Reconnaissance', 'resource-development': 'Resource Dev',
  'initial-access': 'Initial Access', 'execution': 'Execution', 'persistence': 'Persistence',
  'privilege-escalation': 'Priv Esc', 'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access', 'discovery': 'Discovery',
  'lateral-movement': 'Lateral Movement', 'collection': 'Collection',
  'command-and-control': 'Command & Control', 'exfiltration': 'Exfiltration',
  'impact': 'Impact', 'other': 'Other',
}

interface TechMeta { name: string; tactics: string[] }
interface MitreTech { id?: string; name?: string; tactics?: string[] }

export default function Coverage() {
  const { jobId } = useParams<{ jobId: string }>()
  const { data: job } = useQuery({
    queryKey: ['job', jobId],
    queryFn: () => fetchJob(jobId!),
    enabled: !!jobId,
  })
  const { data: coverage, isLoading, isError } = useCoverage(jobId)
  const [meta, setMeta] = useState<Record<string, TechMeta>>({})

  // ATT&CK index (already served to the frontend) → technique → name + tactics.
  useEffect(() => {
    fetch('/mitre_index.json')
      .then(r => r.json() as Promise<{ techniques?: MitreTech[] }>)
      .then(idx => {
        const m: Record<string, TechMeta> = {}
        for (const t of idx.techniques ?? []) {
          if (t.id) m[t.id.toUpperCase()] = { name: t.name ?? t.id, tactics: t.tactics ?? [] }
        }
        setMeta(m)
      })
      .catch(() => { /* names degrade to ids — non-fatal */ })
  }, [])

  const { data: reportRules, isLoading: rulesLoading } = useQuery({
    queryKey: ['coverage-report-rules', jobId],
    queryFn: () => fetchCoverageReportRules(jobId!),
    enabled: !!jobId,
  })
  // Evidence enrichment for the drill-in chips: the strongest proposal match per
  // rule id. Optional — the strip renders without it.
  const { data: proposals } = useQuery({
    queryKey: ['detection-proposals', jobId, 1000],
    queryFn: () => fetchDetectionProposals(jobId!, 1000),
    enabled: !!jobId,
  })

  // Flatten rules: a single rule may cover MULTIPLE techniques, so it must
  // become ONE selection entry (deduped by id) while each technique keeps a
  // reference to it.
  const { rules, rulesById, techRuleIds } = useMemo(() => {
    const byId = new Map<string, SelectableRule>()
    const techRuleIds = new Map<string, string[]>()
    for (const g of reportRules?.techniques ?? []) {
      const ids: string[] = []
      for (const r of g.rules) {
        ids.push(r.id)
        const seen = byId.get(r.id)
        if (seen) { seen.techniques.push(g.technique_id) }
        else {
          byId.set(r.id, {
            id: r.id, format: r.format, corpus: r.corpus,
            license: r.license ?? 'unknown', severity: r.severity ?? 'unknown',
            title: r.title || r.id, bytes: r.bytes ?? 0,
            techniques: [g.technique_id],
          })
        }
      }
      techRuleIds.set(g.technique_id, ids)
    }
    return { rules: [...byId.values()], rulesById: byId, techRuleIds }
  }, [reportRules])

  const selection = useRuleSelection(jobId, rules)

  // One TechEntry per coverage cell, in cell order (already sorted by score
  // desc on the API side).
  const techs = useMemo<TechEntry[]>(() => {
    const out: TechEntry[] = []
    for (const cell of coverage?.cells ?? []) {
      const id = cell.technique_id
      const tactics = (meta[id]?.tactics ?? []).filter(t => TACTIC_ORDER.includes(t))
      const ruleIds = techRuleIds.get(id) ?? []
      const byFormat: Record<string, string[]> = {
        sigma: [], suricata: [], yara: [],
      }
      for (const rid of ruleIds) {
        const f = rulesById.get(rid)?.format
        if (f && f in byFormat) byFormat[f].push(rid)
      }
      out.push({
        id,
        name: meta[id]?.name ?? id,
        tactics: tactics.length ? tactics : ['other'],
        score: cell.score,
        ruleIds,
        byFormat: byFormat as TechEntry['byFormat'],
      })
    }
    return out
  }, [coverage, meta, techRuleIds, rulesById])

  const techsById = useMemo(() => new Map(techs.map(t => [t.id, t])), [techs])

  // Group techniques by tactic (kill-chain order) for the matrix columns.
  const columns = useMemo(() => {
    const byTactic: Record<string, TechEntry[]> = {}
    for (const t of techs) {
      for (const tac of t.tactics) {
        const key = TACTIC_ORDER.includes(tac) ? tac : 'other'
        ;(byTactic[key] ??= []).push(t)
      }
    }
    return [...TACTIC_ORDER, 'other']
      .filter(t => byTactic[t]?.length)
      .map(t => ({ tactic: t, label: TACTIC_LABEL[t] ?? t, techs: byTactic[t] }))
  }, [techs])

  // Strongest proposal match per rule id (matches arrive sorted by weight desc).
  const evidence = useMemo(() => {
    const m = new Map<string, ProposalMatch>()
    for (const p of proposals?.proposals ?? []) {
      if (p.matches.length > 0) m.set(p.id, p.matches[0])
    }
    return m
  }, [proposals])

  const [drillId, setDrillId] = useState<string | null>(null)
  // Default to the first (highest-scoring) technique once coverage arrives.
  const drillTech = (drillId ? techsById.get(drillId) : undefined) ?? techs[0] ?? null

  if (!jobId) return null

  return (
    <div className="cov-page" style={{ padding: '20px 28px', maxWidth: '100%', color: 'var(--ink)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 8 }}>
        <Link to={`/review/${jobId}`} className="link">← Review</Link>
        <Link to={`/graph/${jobId}`} className="link">Graph</Link>
        <h1 style={{ fontSize: 18, margin: 0 }}>Detection Coverage</h1>
        {job && <span style={{ color: 'var(--ink-3)', fontSize: 13 }}>{job.original_filename}</span>}
      </div>

      <div style={{
        background: 'var(--accent-soft)', color: 'var(--ink-2)', borderRadius: 8,
        padding: '8px 12px', fontSize: 12.5, marginBottom: 14,
      }}>
        <strong>Readiness, not validation.</strong> Cells show whether (and from how many
        independent rule corpora) a detection exists for each extracted technique — not that
        a rule was tested against live telemetry.
      </div>

      {techs.length > 0 && (
        <FormatBoard techs={techs} rules={rules} selection={selection} />
      )}

      {isLoading && <p style={{ color: 'var(--ink-3)' }}>Computing coverage…</p>}
      {isError && <p style={{ color: 'var(--no)' }}>Could not load coverage.</p>}
      {coverage && coverage.techniques_total === 0 && (
        <p style={{ color: 'var(--ink-3)' }}>No ATT&CK techniques were extracted from this report.</p>
      )}

      {coverage && coverage.techniques_total > 0 && (
        <div style={{ display: 'flex', gap: 10, overflowX: 'auto', paddingBottom: 12 }}>
          {columns.map(({ tactic, label, techs: colTechs }) => {
            // Union of rule ids across the column (a rule under two techniques
            // of the same tactic counts once).
            const colIds = [...new Set(colTechs.flatMap(t => t.ruleIds))]
            const colSel = selection.selectedOf(colIds)
            return (
              <div key={tactic} style={{ minWidth: 196, flex: '0 0 auto' }}>
                <div
                  onClick={() => selection.toggleScope(colIds)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    padding: '3px 4px 5px', borderBottom: '1px solid var(--rule)',
                    marginBottom: 6, cursor: 'pointer',
                  }}
                >
                  <TriCheckbox
                    sel={colSel}
                    total={colIds.length}
                    size={14}
                    onToggle={() => selection.toggleScope(colIds)}
                  />
                  <span style={{
                    fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
                    letterSpacing: '0.3px', color: 'var(--ink-3)',
                  }}>{label}</span>
                  <span style={{
                    fontFamily: '"JetBrains Mono",monospace', fontSize: 10, color: 'var(--ink-4)',
                    marginLeft: 'auto',
                  }}>{colIds.length ? `${colSel}/${colIds.length}` : '—'}</span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {colTechs.map(t => {
                    const cc = coverageColor(t.score)
                    const tSel = selection.selectedOf(t.ruleIds)
                    const present = DETECTION_FORMATS
                      .filter(f => t.byFormat[f].length > 0)
                      .map(f => `${FORMAT_STYLE[f].label} ${t.byFormat[f].length}`)
                    const cellTitle = present.length
                      ? `${COVERAGE_LABEL[t.score]} · ${present.join(' · ')}`
                      : `${COVERAGE_LABEL[t.score]} · no rule in any format`
                    return (
                      <div
                        key={t.id}
                        onClick={() => setDrillId(t.id)}
                        title={cellTitle}
                        style={{
                          background: cc.background, color: cc.color,
                          border: `1px solid ${cc.border}`,
                          outline: drillTech?.id === t.id ? '2px solid var(--accent)' : 'none',
                          borderRadius: 5, padding: '5px 7px',
                          display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer',
                        }}
                      >
                        <TriCheckbox
                          sel={tSel}
                          total={t.ruleIds.length}
                          size={14}
                          title={t.ruleIds.length
                            ? `${tSel} of ${t.ruleIds.length} rules selected`
                            : 'No rules to select'}
                          onToggle={() => selection.toggleScope(t.ruleIds)}
                        />
                        <span style={{
                          fontFamily: '"JetBrains Mono",monospace', fontSize: 10.5, fontWeight: 600,
                          flexShrink: 0,
                        }}>{t.id}</span>
                        <span style={{
                          fontSize: 11, lineHeight: 1.2, minWidth: 0,
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        }}>{t.name}</span>
                        <span style={{
                          display: 'flex', gap: 2, marginLeft: 'auto', flexShrink: 0,
                        }}>
                          {DETECTION_FORMATS.map(f => {
                            const has = t.byFormat[f].length > 0
                            const anySel = has && selection.selectedOf(t.byFormat[f]) > 0
                            return (
                              <span
                                key={f}
                                title={`${FORMAT_STYLE[f].label}: ${t.byFormat[f].length} rule(s)`}
                                style={{
                                  width: 5, height: 14, borderRadius: 1.5,
                                  background: anySel ? formatLine(f) : has ? formatSoft(f) : 'transparent',
                                  border: `1px solid ${has ? formatLine(f) : 'var(--rule)'}`,
                                }}
                              />
                            )
                          })}
                        </span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {rulesLoading
        ? <p style={{ color: 'var(--ink-3)' }}>Loading rules…</p>
        : (
          <>
            <DrillInStrip
              tech={drillTech}
              selection={selection}
              rulesById={rulesById}
              evidence={evidence}
            />
            <CoverageExportPanel
              jobId={jobId}
              reportName={job?.original_filename ?? ''}
              columns={columns}
              rules={rules}
              rulesById={rulesById}
              selection={selection}
            />
          </>
        )}
    </div>
  )
}
