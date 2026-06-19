import { useEffect, useMemo, useState } from 'react'

import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { fetchJob } from '../api/client'
import { COVERAGE_LABEL, coverageColor } from '../components/review/tokens'
import { useCoverage } from '../hooks/useCoverage'
import type { CoverageCell } from '../types'

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
  const { data: job } = useQuery({ queryKey: ['job', jobId], queryFn: () => fetchJob(jobId!), enabled: !!jobId })
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

  const columns = useMemo(() => {
    const byTactic: Record<string, CoverageCell[]> = {}
    for (const c of coverage?.cells ?? []) {
      const tactics = meta[c.technique_id]?.tactics ?? []
      const targets = tactics.length ? tactics : ['other']
      for (const t of targets) {
        const key = TACTIC_ORDER.includes(t) ? t : 'other'
        ;(byTactic[key] ??= []).push(c)
      }
    }
    return [...TACTIC_ORDER, 'other']
      .filter(t => byTactic[t]?.length)
      .map(t => ({ tactic: t, cells: byTactic[t] }))
  }, [coverage, meta])

  if (!jobId) return null

  const by = coverage?.by_score ?? {}

  return (
    <div style={{ padding: '20px 28px', maxWidth: '100%', color: 'var(--ink)' }}>
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

      {/* summary + legend */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 18 }}>
        {[3, 2, 1, 0].map(s => {
          const col = coverageColor(s)
          return (
            <span key={s} style={{
              display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12,
              background: col.background, color: col.color, border: `1px solid ${col.border}`,
              borderRadius: 6, padding: '3px 9px',
            }}>
              <strong>{by[String(s)] ?? 0}</strong> {COVERAGE_LABEL[s]}
            </span>
          )
        })}
      </div>

      {isLoading && <p style={{ color: 'var(--ink-3)' }}>Computing coverage…</p>}
      {isError && <p style={{ color: 'var(--no)' }}>Could not load coverage.</p>}
      {coverage && coverage.techniques_total === 0 && (
        <p style={{ color: 'var(--ink-3)' }}>No ATT&CK techniques were extracted from this report.</p>
      )}

      <div style={{ display: 'flex', gap: 12, overflowX: 'auto', paddingBottom: 12 }}>
        {columns.map(({ tactic, cells }) => (
          <div key={tactic} style={{ minWidth: 190, flex: '0 0 auto' }}>
            <div style={{
              fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.3,
              color: 'var(--ink-3)', marginBottom: 6, paddingBottom: 4,
              borderBottom: '1px solid var(--rule)',
            }}>
              {TACTIC_LABEL[tactic] ?? tactic}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {cells.map(c => {
                const col = coverageColor(c.score)
                const name = meta[c.technique_id]?.name
                const title = c.corpora.length
                  ? `${COVERAGE_LABEL[c.score]} · ${c.rule_count} rule(s) · ${c.corpora.join(', ')}`
                  : COVERAGE_LABEL[c.score]
                return (
                  <Link
                    key={`${tactic}:${c.technique_id}`}
                    to={`/review/${jobId}`}
                    title={title}
                    style={{
                      background: col.background, color: col.color,
                      border: `1px solid ${col.border}`, borderRadius: 6,
                      padding: '6px 8px', textDecoration: 'none', display: 'block',
                    }}
                  >
                    <div style={{ fontSize: 11, fontWeight: 600, fontFamily: 'monospace' }}>{c.technique_id}</div>
                    {name && <div style={{ fontSize: 11.5, lineHeight: 1.25 }}>{name}</div>}
                    {c.rule_count > 0 && (
                      <div style={{ fontSize: 10.5, opacity: 0.85, marginTop: 2 }}>
                        {c.rule_count} rule{c.rule_count > 1 ? 's' : ''} · {c.corpora.length} corpus
                        {c.corpora.length > 1 ? 'es' : ''}
                      </div>
                    )}
                  </Link>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
