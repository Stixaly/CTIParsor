/**
 * Panels of the bundle view (ADR-0061): the provenance legend, the bundle's
 * metadata, node and edge detail with where each came from, and the list of
 * everything Stage 4 did to the review rows.
 */
import { useMemo, useState } from 'react'
import { X, ArrowRight } from 'lucide-react'
import type { LedgerRelationship, StixObject } from '../../types'
import type { EdgeKind, GraphEdge, GraphNode } from './graphLayout'
import type { BundleEdgeInfo, BundleNodeInfo, DiffItem, DiffKind } from './buildBundleGraph'
import { stixLabel } from './buildBundleGraph'
import {
  EDGE_KIND_ORDER, EDGE_KIND_STYLE, EDGE_ORIGIN_LABEL, OBJECT_ORIGIN_LABEL,
  describeChange, describeTime, entityReason, relationshipReason,
} from './provenance'

/** One row of an SRO's x_temporal_assertions (ADR-0063), as shipped. */
type ShippedTime = {
  id?: string; role?: string; time_text?: string; value?: string; precision?: string
  status?: string; reason?: string; origin?: string; native?: string; projection?: string
}

function shippedTimes(sro: StixObject | null): ShippedTime[] {
  const raw = sro?.x_temporal_assertions
  return Array.isArray(raw) ? (raw as ShippedTime[]) : []
}
import { typeDot, typeInk, typeLabel, typeSoft } from '../review/tokens'

const MONO: React.CSSProperties = { fontFamily: "'JetBrains Mono', ui-monospace, monospace" }
const SERIF: React.CSSProperties = { fontFamily: "'Source Serif 4', Georgia, serif" }
const HEAD: React.CSSProperties = {
  fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase',
  color: 'var(--ink-3)', marginBottom: 7,
}

function KindSwatch({ kind }: { kind: EdgeKind }) {
  const s = EDGE_KIND_STYLE[kind]
  return (
    <svg width={22} height={8} style={{ flexShrink: 0 }} aria-hidden>
      <line x1={1} y1={4} x2={21} y2={4} stroke={s.stroke} strokeWidth={2}
        strokeDasharray={s.dash} strokeLinecap="round" />
    </svg>
  )
}

// ── Left rail: edge provenance legend ─────────────────────────────────────────

export function ProvenanceLegend({
  kindCounts, hiddenKinds, onToggle, changedCount,
}: {
  kindCounts: Partial<Record<EdgeKind, number>>
  hiddenKinds: Set<EdgeKind>
  onToggle: (k: EdgeKind) => void
  changedCount: number
}) {
  const kinds = EDGE_KIND_ORDER.filter(k => (kindCounts[k] ?? 0) > 0)
  return (
    <div>
      <div style={HEAD}>Links · why they exist</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
        {kinds.map(k => {
          const on = !hiddenKinds.has(k)
          return (
            <button key={k} onClick={() => onToggle(k)} title={EDGE_KIND_STYLE[k].hint}
              aria-pressed={on}
              style={{
                display: 'flex', alignItems: 'center', gap: 6, padding: '3px 5px',
                borderRadius: 5, border: 'none', background: 'none', cursor: 'pointer',
                opacity: on ? 1 : 0.35, textAlign: 'left', width: '100%',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-soft)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
            >
              <KindSwatch kind={k} />
              <span style={{ flex: 1, fontSize: 11, color: 'var(--ink-2)' }}>{EDGE_KIND_STYLE[k].label}</span>
              <span style={{ fontSize: 10, color: 'var(--ink-4)', ...MONO }}>{kindCounts[k]}</span>
            </button>
          )
        })}
        {changedCount > 0 && (
          <div title="A row whose verb or endpoint Stage 4 rewrote" style={{
            display: 'flex', alignItems: 'center', gap: 6, padding: '3px 5px', fontSize: 11, color: 'var(--ink-2)',
          }}>
            <svg width={22} height={8} aria-hidden>
              <line x1={1} y1={4} x2={21} y2={4} stroke="var(--warn)" strokeWidth={2} strokeLinecap="round" />
            </svg>
            <span style={{ flex: 1 }}>Rewritten by Stage 4</span>
            <span style={{ fontSize: 10, color: 'var(--ink-4)', ...MONO }}>{changedCount}</span>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Left rail: what else the bundle carries ───────────────────────────────────

export function BundleMeta({ meta }: { meta: StixObject[] }) {
  if (meta.length === 0) return null
  const line = (o: StixObject) => {
    switch (o.type) {
      case 'report': {
        const n = Array.isArray(o.object_refs) ? o.object_refs.length : 0
        return `Report “${String(o.name ?? '')}” — references ${n} objects`
      }
      case 'marking-definition': return `Marking: ${String(o.name ?? (o.definition as { tlp?: string } | undefined)?.tlp ?? o.definition_type ?? 'statement')}`
      case 'identity':           return `Author: ${String(o.name ?? '')}`
      case 'artifact': {
        const size = typeof o.payload_bin === 'string' ? Math.round(o.payload_bin.length * 0.75 / 1024) : 0
        return `Source document embedded (${String(o.mime_type ?? 'file')}, ${size} KB)`
      }
      default: return `${o.type}`
    }
  }
  return (
    <div>
      <div style={HEAD}>Also in the bundle</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        {meta.map(o => (
          <div key={o.id} title={o.id} style={{ fontSize: 10.5, color: 'var(--ink-3)', lineHeight: 1.35 }}>
            {line(o)}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Shared bits ───────────────────────────────────────────────────────────────

function PanelHeader({ kicker, title, sub, onClose }: {
  kicker: React.ReactNode; title: React.ReactNode; sub?: React.ReactNode; onClose: () => void
}) {
  return (
    <div style={{ padding: '14px 16px 12px', borderBottom: '1px solid var(--rule)', flexShrink: 0 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ marginBottom: 4 }}>{kicker}</div>
          <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--ink)', lineHeight: 1.3, wordBreak: 'break-word', ...SERIF }}>
            {title}
          </div>
          {sub && <div style={{ fontSize: 10, color: 'var(--ink-3)', marginTop: 3, wordBreak: 'break-all', ...MONO }}>{sub}</div>}
        </div>
        <button onClick={onClose} aria-label="Close"
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--ink-4)', display: 'flex', flexShrink: 0, padding: 2 }}>
          <X size={14} />
        </button>
      </div>
    </div>
  )
}

function TypeChip({ type }: { type: string }) {
  return (
    <span style={{ fontSize: 10, fontWeight: 600, color: typeInk(type), background: typeSoft(type),
                   display: 'inline-block', padding: '1px 6px', borderRadius: 4 }}>
      {typeLabel(type)}
    </span>
  )
}

function Note({ tone, children }: { tone: 'no' | 'warn' | 'ok' | 'info'; children: React.ReactNode }) {
  const c = tone === 'info' ? 'var(--frost)' : `var(--${tone})`
  return (
    <div style={{
      fontSize: 11, color: 'var(--ink-2)', lineHeight: 1.45,
      background: `color-mix(in oklab, ${c} 8%, transparent)`,
      borderLeft: `2px solid ${c}`, borderRadius: 4, padding: '6px 8px', marginBottom: 8,
    }}>{children}</div>
  )
}

function Row({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', gap: 8, fontSize: 11 }}>
      <dt style={{ color: 'var(--ink-4)', flexShrink: 0, width: 82, paddingTop: 1 }}>{k}</dt>
      <dd style={{ margin: 0, color: 'var(--ink)', wordBreak: 'break-word', flex: 1 }}>{children}</dd>
    </div>
  )
}

function EdgeLine({ e, fromId, byId, onPick }: {
  e: GraphEdge; fromId: string; byId: Map<string, GraphNode>; onPick: (edgeId: string) => void
}) {
  const out = e.source === fromId
  const other = byId.get(out ? e.target : e.source)
  if (!other) return null
  const kind = e.kind ?? 'unknown'
  return (
    <button onClick={() => onPick(e.id)}
      style={{
        display: 'flex', alignItems: 'center', gap: 6, padding: '5px 7px', borderRadius: 6,
        border: 'none', background: 'var(--bg-soft)', cursor: 'pointer', textAlign: 'left', fontSize: 11,
      }}
      onMouseEnter={ev => (ev.currentTarget.style.background = 'var(--bg)')}
      onMouseLeave={ev => (ev.currentTarget.style.background = 'var(--bg-soft)')}
      title={EDGE_KIND_STYLE[kind].label}
    >
      <KindSwatch kind={kind} />
      <span style={{ color: out ? 'var(--accent)' : 'var(--ink-3)', flexShrink: 0, fontSize: 13 }}>{out ? '→' : '←'}</span>
      <span style={{
        color: kind === 'dropped' ? 'var(--no)' : e.changed ? 'var(--warn)' : 'var(--ink-3)',
        textDecoration: kind === 'dropped' ? 'line-through' : undefined,
        flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', ...MONO, fontSize: 10,
      }}>{e.rel}</span>
      <span style={{ width: 7, height: 7, borderRadius: '50%', background: typeDot(other.type), flexShrink: 0 }} />
      <span style={{ color: 'var(--ink)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 100 }}>
        {other.name}
      </span>
    </button>
  )
}

// ── Right panel: one object ───────────────────────────────────────────────────

const SHOWN_PROPS = ['value', 'name', 'pattern', 'pattern_type', 'key', 'user_id', 'number',
                     'country', 'identity_class', 'is_family', 'mime_type', 'description']

export function BundleNodeDetail({
  node, info, edges, byId, onClose, onPickEdge,
}: {
  node: GraphNode
  info: BundleNodeInfo | undefined
  edges: GraphEdge[]
  byId: Map<string, GraphNode>
  onClose: () => void
  onPickEdge: (id: string) => void
}) {
  const incident = edges.filter(e => e.source === node.id || e.target === node.id)
  const o = info?.object ?? null
  const hashes = o?.hashes && typeof o.hashes === 'object' ? Object.entries(o.hashes) : []
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PanelHeader
        kicker={<TypeChip type={node.type} />}
        title={node.name}
        sub={o ? o.id : 'not in the bundle'}
        onClose={onClose}
      />
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }}>
        {node.ghost ? (
          <Note tone={info?.ghostReason === 'added_since_build' ? 'warn' : 'no'}>
            {info?.ghostReason === 'added_since_build'
              ? 'This entity was added or restored after the bundle was built. Rebuild the bundle to include it.'
              : <>This review entity is <b>not in the bundle</b>: {entityReason(info?.ghostReason)}.</>}
          </Note>
        ) : (
          <div style={{ marginBottom: 14 }}>
            <div style={HEAD}>Why it is in the bundle</div>
            <div style={{ fontSize: 11.5, color: 'var(--ink)' }}>
              {OBJECT_ORIGIN_LABEL[info?.origin ?? ''] ?? info?.origin ?? 'Unrecorded'}
            </div>
            {typeof info?.originInfo.ioc_value === 'string' && (
              <div style={{ fontSize: 10.5, color: 'var(--ink-3)', marginTop: 2 }}>from IoC {info.originInfo.ioc_value}</div>
            )}
            {typeof info?.originInfo.no_indicator === 'string' && (
              <Note tone="warn">No Indicator was built for this observable: no STIX pattern exists for it.</Note>
            )}
          </div>
        )}

        {info && info.rows.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div style={HEAD}>Review rows · {info.rows.length}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {info.rows.map(({ entity, ledger }) => (
                <div key={entity.id} style={{ fontSize: 11, color: 'var(--ink-2)', lineHeight: 1.4 }}>
                  <span style={{ color: 'var(--ink)' }}>{entity.value}</span>
                  <span style={{ color: 'var(--ink-4)' }}> · {typeLabel(entity.entity_type)} · {entity.source}</span>
                  {ledger.outcome === 'merged' && <div style={{ color: 'var(--warn)' }}>merged: {entityReason(ledger.reason)}</div>}
                  {ledger.outcome === 'emitted' && ledger.reason === 'alias_canonical' && (
                    <div style={{ color: 'var(--warn)' }}>renamed “{ledger.stix_name}”: {entityReason(ledger.reason)}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {o && (
          <div style={{ marginBottom: 14 }}>
            <div style={HEAD}>STIX properties</div>
            <dl style={{ display: 'flex', flexDirection: 'column', gap: 4, margin: 0 }}>
              {SHOWN_PROPS.filter(p => o[p] !== undefined && o[p] !== '').map(p => (
                <Row key={p} k={p}>
                  <span style={p === 'pattern' ? MONO : undefined}>
                    {p === 'description' ? String(o[p]).slice(0, 400) : String(o[p])}
                  </span>
                </Row>
              ))}
              {hashes.map(([alg, h]) => <Row key={alg} k={alg}><span style={MONO}>{String(h)}</span></Row>)}
              {node.mitre_id && <Row k="external id"><span style={MONO}>{node.mitre_id}</span></Row>}
            </dl>
          </div>
        )}

        <div>
          <div style={HEAD}>Links · {incident.length}</div>
          {incident.length === 0 && <p style={{ fontSize: 11, color: 'var(--ink-4)', margin: 0 }}>No links</p>}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {incident.map(e => <EdgeLine key={e.id} e={e} fromId={node.id} byId={byId} onPick={onPickEdge} />)}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Right panel: one edge ─────────────────────────────────────────────────────

export function EdgeDetail({
  edge, info, byId, onClose, onPick, onPickEdge, labelOf,
}: {
  edge: GraphEdge
  info: BundleEdgeInfo | undefined
  byId: Map<string, GraphNode>
  onClose: () => void
  onPick: (nodeId: string) => void
  onPickEdge: (edgeId: string) => void
  labelOf: (stixId: string) => string
}) {
  const src = byId.get(edge.source), tgt = byId.get(edge.target)
  const sro = info?.sro ?? null
  const kind = edge.kind ?? 'unknown'
  const premises = Array.isArray(sro?.x_inferred_from) ? sro!.x_inferred_from as string[] : []
  const endpoint = (n: GraphNode | undefined) => n && (
    <button onClick={() => onPick(n.id)}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 7px', borderRadius: 4, border: 'none',
               cursor: 'pointer', background: typeSoft(n.type), color: typeInk(n.type), fontSize: 11, fontWeight: 500,
               maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: typeDot(n.type), flexShrink: 0 }} />
      {n.name}
    </button>
  )
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PanelHeader
        kicker={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 10, color: 'var(--ink-3)' }}>
          <KindSwatch kind={kind} /> {EDGE_KIND_STYLE[kind].label}</span>}
        title={<span style={{ ...MONO, fontSize: 14, textDecoration: kind === 'dropped' ? 'line-through' : undefined }}>{edge.rel}</span>}
        sub={sro ? sro.id : kind === 'embedded' ? `property ${info?.property}` : 'not in the bundle'}
        onClose={onClose}
      />
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
          {endpoint(src)} <ArrowRight size={12} style={{ color: 'var(--ink-4)' }} /> {endpoint(tgt)}
        </div>

        {kind === 'dropped' && info?.rows[0] && (
          <Note tone="no">
            This review row is <b>not in the bundle</b>: {relationshipReason(info.rows[0].ledger.reason)}.
          </Note>
        )}

        {sro && (
          <div style={{ marginBottom: 14 }}>
            <div style={HEAD}>Why it is in the bundle</div>
            <div style={{ fontSize: 11.5, color: 'var(--ink)', marginBottom: 6 }}>
              {EDGE_ORIGIN_LABEL[info?.origin ?? 'unknown'] ?? info?.origin}
            </div>
            <dl style={{ display: 'flex', flexDirection: 'column', gap: 4, margin: 0 }}>
              {typeof sro.x_evidence_label === 'string' && <Row k="evidence">{sro.x_evidence_label}</Row>}
              {typeof sro.confidence === 'number' && <Row k="confidence">{sro.confidence}</Row>}
              {typeof sro.x_policy_rule === 'string' && <Row k="policy rule"><span style={MONO}>{sro.x_policy_rule}</span></Row>}
              {typeof sro.x_pin_evidence === 'string' && <Row k="pin evidence">{sro.x_pin_evidence}</Row>}
              {typeof sro.x_inference_rule === 'string' && <Row k="rule"><span style={MONO}>{sro.x_inference_rule}</span></Row>}
              {typeof sro.start_time === 'string' && <Row k="start_time">{sro.start_time}</Row>}
              {typeof sro.stop_time === 'string' && <Row k="stop_time">{sro.stop_time}</Row>}
            </dl>
            {shippedTimes(sro).length > 0 && (
              <div style={{ marginTop: 8 }}>
                <div style={{ fontSize: 10.5, color: 'var(--ink-3)', marginBottom: 3 }}>
                  Dates (x_temporal_assertions)
                </div>
                {shippedTimes(sro).map((t, i) => (
                  <div key={t.id ?? i} style={{ fontSize: 11, lineHeight: 1.45, color: 'var(--ink-2)' }}
                       title={t.reason ? `${t.status}: ${t.reason}` : t.status}>
                    <span style={MONO}>{t.role}</span>{' '}
                    {t.time_text ? <i>“{t.time_text}”</i> : <span style={{ color: 'var(--ink-3)' }}>{t.origin}</span>}{' '}
                    <span style={MONO}>{t.value ?? '—'}{t.precision ? ` · ${t.precision}` : ''}</span>{' '}
                    <span style={{ color: t.status === 'verified' ? 'var(--ok)' : t.status === 'conflict' ? 'var(--no)' : 'var(--warn)' }}>
                      {t.status}
                    </span>
                    {t.native && <span style={{ color: 'var(--ink-3)' }}> → {t.native}{t.projection ? ' (projected)' : ''}</span>}
                  </div>
                ))}
              </div>
            )}
            {premises.length > 0 && (
              <div style={{ marginTop: 8 }}>
                <div style={{ fontSize: 10.5, color: 'var(--ink-3)', marginBottom: 3 }}>Composed from</div>
                {premises.map(p => (
                  <button key={p} onClick={() => onPickEdge(p)}
                    style={{ display: 'block', fontSize: 10.5, color: 'var(--accent)', background: 'none', border: 'none',
                             padding: '1px 0', cursor: 'pointer', textAlign: 'left', ...MONO }}>
                    {labelOf(p)}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        {(typeof sro?.description === 'string' || typeof sro?.x_evidence_text === 'string' || edge.evidence) && (
          <div style={{ marginBottom: 14 }}>
            <div style={HEAD}>Quoted evidence</div>
            <blockquote style={{ margin: 0, fontSize: 11.5, color: 'var(--ink-2)', lineHeight: 1.5,
                                 borderLeft: '2px solid var(--rule)', paddingLeft: 8, ...SERIF }}>
              {String(sro?.description ?? sro?.x_evidence_text ?? edge.evidence)}
            </blockquote>
          </div>
        )}

        {info && info.rows.length > 0 && kind !== 'dropped' && (
          <div>
            <div style={HEAD}>Review rows behind it · {info.rows.length}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {info.rows.map(({ rel, ledger }, i) => (
                <div key={rel?.id ?? i} style={{ fontSize: 11, lineHeight: 1.45, color: 'var(--ink-2)',
                                                 background: 'var(--bg-soft)', borderRadius: 6, padding: '6px 8px' }}>
                  <div style={{ color: 'var(--ink)' }}>
                    {ledger.source_value} <span style={MONO}>{ledger.relationship_type}</span> {ledger.target_value}
                  </div>
                  {ledger.outcome === 'merged' && (
                    <div style={{ color: 'var(--ink-3)' }}>Same edge as another row or a Stage 4 edge — merged into this one.</div>
                  )}
                  {ledger.changes.map((c, j) => (
                    <div key={j} style={{ color: 'var(--warn)' }}>{describeChange(c, labelOf)}</div>
                  ))}
                  {(ledger.times ?? []).map((t, j) => (
                    <div key={`t${j}`} style={{ color: t.outcome === 'withheld' ? 'var(--ink-3)' : 'var(--ink-2)' }}>
                      {describeTime(t)}
                    </div>
                  ))}
                  {rel === null && <div style={{ color: 'var(--no)' }}>Rejected or deleted since the bundle was built.</div>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Right panel: everything Stage 4 did to the review rows ────────────────────

const DIFF_GROUPS: Array<{ kind: DiffKind; title: string; hint: string; tone: 'no' | 'warn' | 'info' }> = [
  { kind: 'stale',   title: 'Not yet in the stored bundle', tone: 'warn',
    hint: 'Review changes made after the bundle was built. Rebuild to apply them.' },
  { kind: 'dropped', title: 'Dropped from the bundle', tone: 'no',
    hint: 'Review rows Stage 4 did not ship.' },
  { kind: 'changed', title: 'Rewritten', tone: 'warn',
    hint: 'Rows that ship with another verb, or with an observable replaced by its Indicator.' },
  { kind: 'merged',  title: 'Merged', tone: 'info',
    hint: 'Rows that resolved to an object or an edge that already existed (duplicates, aliases).' },
  { kind: 'removed', title: 'Removed after creation', tone: 'no',
    hint: 'Objects and edges the Stage 4b alias merge absorbed.' },
]

function diffReason(d: DiffItem, labelOf: (id: string) => string): string {
  if (d.reason === 'added_since_build') return 'added or restored after the build'
  if (d.reason === 'removed_since_build') return 'rejected or deleted after the build — still in the stored bundle'
  if (d.reason === 'dates_changed_since_build') return 'its dates changed after the build'
  if (d.reason === 'merged_into_edge') return 'same edge as another row or a Stage 4 edge'
  if (d.kind === 'changed' && d.ledgerRel) return d.ledgerRel.changes.map(c => describeChange(c, labelOf)).join(' · ')
  if (d.subject === 'entity' || d.subject === 'object') return entityReason(d.reason)
  return relationshipReason(d.reason)
}

export function DiffPanel({
  diff, onClose, onPickNode, onPickEdge, labelOf,
}: {
  diff: DiffItem[]
  onClose: () => void
  onPickNode: (id: string) => void
  onPickEdge: (id: string) => void
  labelOf: (id: string) => string
}) {
  const [open, setOpen] = useState<Set<DiffKind>>(() => new Set(['stale', 'dropped', 'changed']))
  const groups = useMemo(() => DIFF_GROUPS.map(g => ({ ...g, items: diff.filter(d => d.kind === g.kind) }))
    .filter(g => g.items.length > 0), [diff])
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PanelHeader
        kicker={<span style={{ fontSize: 10, color: 'var(--ink-3)' }}>Review rows → bundle</span>}
        title="What Stage 4 changed"
        onClose={onClose}
      />
      <div style={{ flex: 1, overflowY: 'auto', padding: '10px 12px' }}>
        {groups.length === 0 && (
          <p style={{ fontSize: 11.5, color: 'var(--ink-3)', margin: '12px 4px' }}>
            Every review row ships as drawn: nothing was dropped, rewritten or merged.
          </p>
        )}
        {groups.map(g => {
          const isOpen = open.has(g.kind)
          return (
            <section key={g.kind} style={{ marginBottom: 10 }}>
              <button
                onClick={() => setOpen(prev => { const n = new Set(prev); if (n.has(g.kind)) n.delete(g.kind); else n.add(g.kind); return n })}
                aria-expanded={isOpen}
                style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', border: 'none', background: 'none',
                         cursor: 'pointer', padding: '4px 4px', textAlign: 'left' }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, flexShrink: 0,
                               background: g.tone === 'info' ? 'var(--frost)' : `var(--${g.tone})` }} />
                <span style={{ flex: 1, fontSize: 12, fontWeight: 600, color: 'var(--ink)' }}>{g.title}</span>
                <span style={{ fontSize: 10.5, color: 'var(--ink-4)', ...MONO }}>{g.items.length}</span>
              </button>
              {isOpen && (
                <>
                  <div style={{ fontSize: 10.5, color: 'var(--ink-4)', margin: '0 4px 6px 18px' }}>{g.hint}</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    {g.items.map((d, i) => {
                      const target = d.edgeId ?? d.nodeId
                      return (
                        <button key={i} disabled={!target}
                          onClick={() => d.edgeId ? onPickEdge(d.edgeId) : d.nodeId && onPickNode(d.nodeId)}
                          style={{ textAlign: 'left', border: 'none', borderRadius: 6, padding: '5px 8px',
                                   background: 'var(--bg-soft)', cursor: target ? 'pointer' : 'default' }}>
                          <div style={{ fontSize: 11, color: 'var(--ink)', wordBreak: 'break-word' }}>
                            {d.subject === 'object' ? labelOf(d.title) : d.title}
                          </div>
                          <div style={{ fontSize: 10.5, color: 'var(--ink-3)', lineHeight: 1.4 }}>{diffReason(d, labelOf)}</div>
                        </button>
                      )
                    })}
                  </div>
                </>
              )}
            </section>
          )
        })}
      </div>
    </div>
  )
}

// ── Right panel: one review row, and what the bundle made of it ──────────────

export function ReviewEdgeDetail({
  edge, fate, hasLedger, byId, onClose, onPick, onShowInBundle, labelOf,
}: {
  edge: GraphEdge
  fate: LedgerRelationship | undefined
  hasLedger: boolean
  byId: Map<string, GraphNode>
  onClose: () => void
  onPick: (nodeId: string) => void
  onShowInBundle: (stixId: string) => void
  labelOf: (id: string) => string
}) {
  const src = byId.get(edge.source), tgt = byId.get(edge.target)
  const status = edge.accepted === false ? 'rejected' : edge.accepted === null ? 'pending' : 'accepted'
  const endpoint = (n: GraphNode | undefined) => n && (
    <button onClick={() => onPick(n.id)}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 7px', borderRadius: 4, border: 'none',
               cursor: 'pointer', background: typeSoft(n.type), color: typeInk(n.type), fontSize: 11, fontWeight: 500 }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: typeDot(n.type) }} />
      {n.name}
    </button>
  )
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PanelHeader
        kicker={<span style={{ fontSize: 10, color: 'var(--ink-3)' }}>Review row · {status}</span>}
        title={<span style={{ ...MONO, fontSize: 14 }}>{edge.rel}</span>}
        onClose={onClose}
      />
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
          {endpoint(src)} <ArrowRight size={12} style={{ color: 'var(--ink-4)' }} /> {endpoint(tgt)}
        </div>
        <div style={HEAD}>In the bundle</div>
        {!hasLedger ? (
          <Note tone="info">The stored bundle predates provenance tracking — rebuild it to see what it does with this row.</Note>
        ) : edge.accepted === false ? (
          <Note tone="info">Rejected: not sent to the bundle.</Note>
        ) : !fate ? (
          <Note tone="warn">Added or restored after the bundle was built — the next rebuild includes it.</Note>
        ) : fate.outcome === 'dropped' ? (
          <Note tone="no"><b>Not in the bundle</b>: {relationshipReason(fate.reason)}.</Note>
        ) : (
          <>
            <Note tone={fate.changes.length ? 'warn' : 'ok'}>
              {fate.outcome === 'merged' ? 'Merged into an edge that already exists' : 'Ships'} as{' '}
              <span style={MONO}>{fate.final_type}</span>
              {fate.source_ref && fate.target_ref && <> — {labelOf(fate.source_ref)} → {labelOf(fate.target_ref)}</>}
              {fate.changes.map((c, i) => <div key={i} style={{ marginTop: 4 }}>{describeChange(c, labelOf)}</div>)}
            </Note>
            {fate.stix_id && (
              <button onClick={() => onShowInBundle(fate.stix_id!)} className="btn-ghost" style={{ fontSize: 11 }}>
                Show it in the bundle view
              </button>
            )}
          </>
        )}
        {edge.evidence && (
          <div style={{ marginTop: 14 }}>
            <div style={HEAD}>Quoted evidence</div>
            <blockquote style={{ margin: 0, fontSize: 11.5, color: 'var(--ink-2)', lineHeight: 1.5,
                                 borderLeft: '2px solid var(--rule)', paddingLeft: 8, ...SERIF }}>
              {edge.evidence}
            </blockquote>
          </div>
        )}
      </div>
    </div>
  )
}

/** A review row's fate in the stored bundle, for the review graph's lists. */
export function FateChip({ fate, hasLedger, rejected, labelOf }: {
  fate: LedgerRelationship | undefined
  hasLedger: boolean
  rejected?: boolean
  labelOf: (id: string) => string
}) {
  if (!hasLedger || rejected) return null
  let text: string, tone: string, title: string
  if (!fate) {
    text = 'not built yet'; tone = 'var(--warn)'
    title = 'Added or restored after the bundle was built — the next rebuild includes it.'
  } else if (fate.outcome === 'dropped') {
    text = 'not in bundle'; tone = 'var(--no)'; title = relationshipReason(fate.reason)
  } else if (fate.changes.length > 0) {
    text = `ships as ${fate.final_type}`; tone = 'var(--warn)'
    title = fate.changes.map(c => describeChange(c, labelOf)).join('\n')
  } else if (fate.outcome === 'merged') {
    text = 'merged'; tone = 'var(--frost)'; title = 'Same edge as another row or a Stage 4 edge'
  } else {
    text = 'in bundle'; tone = 'var(--ok)'; title = 'Ships as drawn'
  }
  return (
    <span title={title} style={{
      fontSize: 9, color: tone, ...MONO, border: `1px solid color-mix(in oklab, ${tone} 35%, transparent)`,
      borderRadius: 4, padding: '0 4px', whiteSpace: 'nowrap', flexShrink: 0,
    }}>{text}</span>
  )
}

/** Label for any STIX id: the drawn node's name, else the object's own. */
export function makeLabelOf(byId: Map<string, GraphNode>, objects: StixObject[]) {
  const byStix = new Map(objects.map(o => [o.id, o]))
  return (id: string) => {
    const n = byId.get(id)
    if (n) return n.name
    const o = byStix.get(id)
    if (!o) return id
    if (o.type === 'relationship') {
      const s = byStix.get(String(o.source_ref)), t = byStix.get(String(o.target_ref))
      return `${s ? stixLabel(s) : o.source_ref} ${o.relationship_type} ${t ? stixLabel(t) : o.target_ref}`
    }
    return stixLabel(o)
  }
}
