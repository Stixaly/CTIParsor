/**
 * The bundle against the analyst's own STIX bundle (ADR-0090, enrich jobs):
 * what CTIParsor added to it, what matched an object the analyst already had,
 * what was left out and why, and the analyst's Report as it was re-issued.
 * A row picks its node or link when the bundle draws it, as DiffPanel does.
 */
import { useMemo, useState } from 'react'
import { BASELINE_REASON_LABEL, type BundleLedger, type Entity, type Job, type Relationship } from '../../types'
import type { BundleGraphData } from './buildBundleGraph'
import { EDGE_ORIGIN_LABEL, OBJECT_ORIGIN_LABEL, entityReason, isFromBaseline, reasonRef } from './provenance'
import { Note, PanelHeader } from './BundlePanels'
import { typeLabel } from '../review/tokens'

const MONO: React.CSSProperties = { fontFamily: "'JetBrains Mono', ui-monospace, monospace" }
const ROW_TITLE: React.CSSProperties = { fontSize: 11, color: 'var(--ink)', lineHeight: 1.4, wordBreak: 'break-word' }
const ROW_SUB: React.CSSProperties = { fontSize: 10.5, color: 'var(--ink-3)', lineHeight: 1.4 }

type Section = 'added' | 'matched' | 'left' | 'report'

/** A STIX id's type and the first eight digits of its uuid: the only label a
 *  removed object has, since it is no longer in the bundle to read a name from. */
const typeOf = (id: string) => id.split('--')[0]
const shortId = (id: string) => (id.split('--').pop() ?? id).slice(0, 8)
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`

export function BaselinePanel({
  job, ledger, data, labelOf, onClose, onPickNode, onPickEdge, entities = [], relationships = [],
}: {
  job: Job
  /** The review rows: an object that left the bundle is named by the row it came from. */
  entities?: Entity[]
  relationships?: Relationship[]
  ledger: BundleLedger
  data: BundleGraphData
  labelOf: (id: string) => string
  onClose: () => void
  onPickNode: (id: string) => void
  onPickEdge: (id: string) => void
}) {
  const [open, setOpen] = useState<Set<Section>>(() => new Set<Section>(['added', 'matched', 'left', 'report']))
  const intake = job.enrichment?.intake ?? null
  const excluded = intake?.excluded ?? []
  const excludedTotal = intake?.excluded_total ?? excluded.length

  // Added: what ships and was not in the analyst's bundle.  The bundle's
  // metadata (report, author identity, markings) is not in data.nodes.
  const added = useMemo(() => ({
    nodes: data.nodes.filter(n => !n.ghost && !isFromBaseline(data.nodeInfo.get(n.id)?.origin)),
    edges: data.edges.filter(e => {
      const info = data.edgeInfo.get(e.id)
      return !!info?.sro && !isFromBaseline(info.origin)
    }),
  }), [data])

  // Matched: the ledger names the baseline object that replaced each CTIParsor
  // object, but not the CTIParsor object's name.  That name is the value of the
  // review row apply_baseline_merge re-pointed to the same baseline object.
  const matched = useMemo(() => {
    const values = new Map<string, string[]>()
    for (const e of ledger.entities) {
      if (e.reason !== 'baseline_match' || !e.stix_id) continue
      values.set(e.stix_id, [...(values.get(e.stix_id) ?? []), e.value])
    }
    return ledger.removed
      .filter(r => r.kind === 'object' && r.reason === 'baseline_match')
      .map(r => ({
        from: values.get(r.replaced_by ?? '')?.shift() ?? `${typeOf(r.stix_id)} ${shortId(r.stix_id)}`,
        to: r.replaced_by ?? '',
      }))
  }, [ledger])

  // Left out: the baseline objects the ledger removed (the ledger's kind
  // 'baseline'), then the intake's exclusions, which are counted in full.
  const leftOut = useMemo(() => ledger.removed.filter(r => r.kind === 'baseline'), [ledger])
  const rowName = useMemo(() => {
    const names = new Map<string, string>()
    for (const e of entities) if (e.baseline_stix_id) names.set(e.baseline_stix_id, e.value)
    for (const r of relationships) {
      if (r.baseline_stix_id) names.set(r.baseline_stix_id, `${r.source_value} ${r.relationship_type} ${r.target_value}`)
    }
    return (id: string) => names.get(id) ?? `${typeLabel(typeOf(id))} ${shortId(id)}`
  }, [entities, relationships])
  const leftCount = leftOut.length + excludedTotal

  // The analyst's Report, re-issued under its own id with CTIParsor's additions.
  const reissued = useMemo(() => {
    const hit = Object.entries(ledger.objects).find(([, o]) => o.origin === 'baseline_report_upsert')
    if (!hit) return null
    const [id, info] = hit
    return {
      id,
      added: info.added_refs ?? 0,
      removed: info.removed_refs?.length ?? 0,
    }
  }, [ledger])

  const toggle = (k: Section) => setOpen(prev => {
    const next = new Set(prev)
    if (next.has(k)) next.delete(k); else next.add(k)
    return next
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PanelHeader
        kicker={<span style={{ fontSize: 10, color: 'var(--ink-3)' }}>Your STIX bundle → this bundle</span>}
        title="Against your STIX bundle"
        sub={intake?.bundle_id}
        onClose={onClose}
      />
      <div style={{ flex: 1, overflowY: 'auto', padding: '10px 12px' }}>

        <Block title="Added by CTIParsor" tone="ok" count={added.nodes.length + added.edges.length}
          hint="Objects and links that ship and were not in your bundle: built from the report."
          isOpen={open.has('added')} onToggle={() => toggle('added')}>
          {added.nodes.map(n => (
            <PickRow key={n.id} onPick={() => onPickNode(n.id)}>
              <div style={ROW_TITLE}>{n.name}</div>
              <div style={ROW_SUB}>
                {typeLabel(n.type)} · {OBJECT_ORIGIN_LABEL[data.nodeInfo.get(n.id)?.origin ?? ''] ?? data.nodeInfo.get(n.id)?.origin}
              </div>
            </PickRow>
          ))}
          {added.edges.map(e => (
            <PickRow key={e.id} onPick={() => onPickEdge(e.id)}>
              <div style={ROW_TITLE}>
                {data.byId.get(e.source)?.name ?? e.source} <span style={MONO}>{e.rel}</span> {data.byId.get(e.target)?.name ?? e.target}
              </div>
              <div style={ROW_SUB}>
                {EDGE_ORIGIN_LABEL[data.edgeInfo.get(e.id)?.origin ?? ''] ?? data.edgeInfo.get(e.id)?.origin}
              </div>
            </PickRow>
          ))}
        </Block>

        <Block title="Matched to your objects" tone="info" count={matched.length}
          hint="CTIParsor found an object your bundle already has: yours ships in its place."
          isOpen={open.has('matched')} onToggle={() => toggle('matched')}>
          {matched.map((m, i) => (
            <PickRow key={i} onPick={data.byId.has(m.to) ? () => onPickNode(m.to) : undefined}>
              <div style={ROW_TITLE}>{m.from} → your {labelOf(m.to)}</div>
              <div style={ROW_SUB}>{entityReason('baseline_match')}</div>
            </PickRow>
          ))}
        </Block>

        <Block title="Left out of your bundle" tone="no" count={leftCount}
          hint="Objects of your bundle that this one does not ship, and why."
          isOpen={open.has('left')} onToggle={() => toggle('left')}>
          {leftOut.map(r => (
            <PickRow key={r.stix_id}>
              <div style={ROW_TITLE}>{rowName(r.stix_id)}</div>
              <div style={ROW_SUB}>
                {entityReason(r.reason)}{reasonRef(r.reason) ? ` (${rowName(reasonRef(r.reason)!)})` : ''}
              </div>
            </PickRow>
          ))}
          {excluded.map((x, i) => (
            <div key={`x${i}`} title={x.detail} style={{ padding: '5px 8px', borderRadius: 6, background: 'var(--bg-soft)' }}>
              <div style={ROW_TITLE}>{typeLabel(x.type)} {shortId(x.id)}</div>
              <div style={ROW_SUB}>{BASELINE_REASON_LABEL[x.reason] ?? x.reason}</div>
            </div>
          ))}
          {excludedTotal > excluded.length && (
            <div style={{ ...ROW_SUB, margin: '2px 8px' }}>and {excludedTotal - excluded.length} more</div>
          )}
          {leftCount > 0 && (
            <Note tone="info">
              A rejection removes the object from this bundle only: OpenCTI’s upsert never removes a reference,
              so a report OpenCTI already holds keeps it.
            </Note>
          )}
        </Block>

        {reissued && (
          <Block title="Your report, re-issued" tone="info" count={1}
            hint="Your Report under its own id, with what the document adds to it."
            isOpen={open.has('report')} onToggle={() => toggle('report')}>
            <PickRow>
              <div style={ROW_TITLE}>{labelOf(reissued.id)}</div>
              <div style={ROW_SUB}>
                {plural(reissued.added, 'reference')} added · {plural(reissued.removed, 'reference')} dropped from this bundle’s copy (OpenCTI keeps them)
              </div>
            </PickRow>
          </Block>
        )}
      </div>
    </div>
  )
}

/** A collapsible group with its count, styled as DiffPanel's groups. */
function Block({ title, tone, count, hint, isOpen, onToggle, children }: {
  title: string; tone: 'ok' | 'info' | 'no'; count: number; hint: string
  isOpen: boolean; onToggle: () => void; children: React.ReactNode
}) {
  return (
    <section style={{ marginBottom: 10 }}>
      <button onClick={onToggle} aria-expanded={isOpen}
        style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', border: 'none', background: 'none',
                 cursor: 'pointer', padding: '4px 4px', textAlign: 'left' }}>
        <span style={{ width: 8, height: 8, borderRadius: 2, flexShrink: 0,
                       background: tone === 'info' ? 'var(--frost)' : `var(--${tone})` }} />
        <span style={{ flex: 1, fontSize: 12, fontWeight: 600, color: 'var(--ink)' }}>{title}</span>
        <span style={{ fontSize: 10.5, color: 'var(--ink-4)', ...MONO }}>{count}</span>
      </button>
      {isOpen && (
        <>
          <div style={{ fontSize: 10.5, color: 'var(--ink-4)', margin: '0 4px 6px 18px' }}>{hint}</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>{children}</div>
        </>
      )}
    </section>
  )
}

/** One row.  A row the bundle does not draw has nothing to pick. */
function PickRow({ onPick, children }: { onPick?: () => void; children: React.ReactNode }) {
  return (
    <button disabled={!onPick} onClick={onPick}
      style={{ textAlign: 'left', border: 'none', borderRadius: 6, padding: '5px 8px',
               background: 'var(--bg-soft)', cursor: onPick ? 'pointer' : 'default' }}>
      {children}
    </button>
  )
}
